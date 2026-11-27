"""TLS certificates for the dashboard.

Three modes, picked by app.py:
  * your own files  (NETLAB_TLS_CERT + NETLAB_TLS_KEY)
  * Let's Encrypt    (NETLAB_PUBLIC_HOST = a public IP or DNS name that reaches port 80 of this host)
  * self-signed      (default, generated once and kept in the data volume)

Let's Encrypt uses the HTTP-01 challenge. The app serves the challenge tokens
itself from the dict passed in, so no web server is needed.
"""
import datetime
import ipaddress
import logging
import os

log = logging.getLogger('netlab.certs')

PROD = 'https://acme-v02.api.letsencrypt.org/directory'
STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory'


def _write(path, data, mode=0o600):
    tmp = path + '.new'
    with open(tmp, 'wb') as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def ensure_self_signed(cert_path, key_path):
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'NetLab self-signed')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    _write(key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    _write(cert_path, cert.public_bytes(serialization.Encoding.PEM), 0o644)
    log.info('generated a self-signed certificate in %s', os.path.dirname(cert_path))


def needs_renewal(cert_path, host):
    """True when there is no usable certificate for host, or less than a third of its lifetime is left."""
    if not os.path.exists(cert_path):
        return True
    from cryptography import x509
    try:
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(v) for v in sans.get_values_for_type(x509.DNSName)]
        names += [str(v) for v in sans.get_values_for_type(x509.IPAddress)]
    except Exception:
        return True
    if host not in names:
        return True
    now = datetime.datetime.now(datetime.timezone.utc)
    life = cert.not_valid_after_utc - cert.not_valid_before_utc
    return cert.not_valid_after_utc - now < life / 3


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def issue(host, out_dir, challenges_store, staging=False):
    """Get a certificate for host from Let's Encrypt. Blocking: run it in a thread.

    challenges_store is a dict the web app serves at /.well-known/acme-challenge/<token>.
    Writes fullchain.pem and privkey.pem into out_dir.
    """
    import josepy as jose
    from acme import challenges, client, crypto_util, errors, messages
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    os.makedirs(out_dir, exist_ok=True)
    acct_path = os.path.join(out_dir, 'account%s.pem' % ('-staging' if staging else ''))
    if os.path.exists(acct_path):
        with open(acct_path, 'rb') as f:
            acct_key = serialization.load_pem_private_key(f.read(), None)
    else:
        acct_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _write(acct_path, acct_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()))
    jwk = jose.JWKRSA(key=acct_key)
    net = client.ClientNetwork(jwk, user_agent='netlab-acme/1.0')
    directory = client.ClientV2.get_directory(STAGING if staging else PROD, net)
    acme = client.ClientV2(directory, net)
    try:
        acme.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True))
    except errors.ConflictError as e:  # account already exists for this key
        acme.query_registration(messages.RegistrationResource(uri=e.location, body=messages.Registration()))

    key = ec.generate_private_key(ec.SECP256R1())
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    if is_ip(host):
        # Let's Encrypt only issues IP-address certificates under the short-lived (about 6 days) profile.
        csr = crypto_util.make_csr(key_pem, ipaddrs=[ipaddress.ip_address(host)])
        order = acme.new_order(csr, profile='shortlived')
    else:
        csr = crypto_util.make_csr(key_pem, domains=[host])
        order = acme.new_order(csr)
    tokens = []
    try:
        for authz in order.authorizations:
            for chall in authz.body.challenges:
                if isinstance(chall.chall, challenges.HTTP01):
                    response, validation = chall.response_and_validation(jwk)
                    token = chall.chall.encode('token')
                    challenges_store[token] = validation
                    tokens.append(token)
                    acme.answer_challenge(chall, response)
                    break
        deadline = datetime.datetime.now() + datetime.timedelta(seconds=180)
        order = acme.poll_and_finalize(order, deadline=deadline)
    finally:
        for t in tokens:
            challenges_store.pop(t, None)
    _write(os.path.join(out_dir, 'privkey.pem'), key_pem)
    _write(os.path.join(out_dir, 'fullchain.pem'), order.fullchain_pem.encode(), 0o644)
    log.info('Let\'s Encrypt certificate for %s written to %s%s', host, out_dir, ' (staging)' if staging else '')
