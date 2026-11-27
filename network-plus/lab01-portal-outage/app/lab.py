"""Per-student lab environments.

Topology (identical addressing for every student, fully isolated per student):

  LAN 10.10.10.0/24 (switch "lan", learning off = every port sees all traffic, like a SPAN port)
     FIN-WS07  10.10.10.50   student workstation (Docker container, gw misconfigured as .254, DNS .53)
     RTR-01    10.10.10.1    router, telnet CLI, ACL LAN-IN applied inbound on Gi0/0
     PRN-01    10.10.10.20   printer, embedded web page with known-good config (flag 1)
     ADMIN-PC  10.10.10.30   logs in to RTR-01 over telnet every ~30 s (cleartext creds)
  SERVERS 172.16.20.0/24 (switch "srv")
     RTR-01    172.16.20.1
     DNS01     172.16.20.53  dnsmasq, TXT record on portal.corp.local (flag 2)
     PORTAL    172.16.20.80  intranet web page (flag 4), blocked by ACL line 50

Only the workstation is a container. The other devices are plain network
namespaces whose services are run by this process (sockets opened inside the
namespace), which keeps memory use low.
"""
import asyncio
import json
import logging
import os
import random
import socket
import time

import rtrcli

log = logging.getLogger('netlab.lab')

WS_IMAGE = os.environ.get('NETLAB_WS_IMAGE', 'nplus-lab01-workstation:latest')
STATE_DIR = os.environ.get('NETLAB_STATE', '/var/lib/netlab')
# Label on every workstation container this deployment creates, so cleanup never touches anything else.
INSTANCE = os.environ.get('NETLAB_INSTANCE', 'nplus-lab01')
ROLES = ['sw', 'rtr', 'prn', 'adm', 'dns', 'web']
OUI = {'rtr0': '00:00:0c', 'rtr1': '00:00:0c', 'prn': '00:1b:78', 'adm': '00:14:22',
       'ws': '00:1b:21', 'dns': '00:50:56', 'web': '00:50:56'}


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


def new_secrets():
    def tag():
        return os.urandom(3).hex()
    macs = {k: '%s:%02x:%02x:%02x' % (v, random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
            for k, v in OUI.items()}
    return {
        'flags': {
            '1': 'NPLUS{known_good_baseline_%s}' % tag(),
            '2': 'NPLUS{dns_txt_tells_all_%s}' % tag(),
            '3': 'NPLUS{telnet_is_cleartext_%s}' % tag(),
            '4': 'NPLUS{acl_fixed_portal_up_%s}' % tag(),
        },
        'rtr_password': 'C0rpNet!%04d' % random.randint(1000, 9999),
        'macs': macs,
    }


PRINTER_PAGE = """<!DOCTYPE html>
<html><head><title>HP LaserJet M507 - PRN-01</title></head><body>
<pre>
 HP LaserJet Enterprise M507dn  |  Embedded Web Server  |  PRN-01
 ==================================================================
 Device status  : Ready
 Toner (black)  : 64%%
 Jobs today     : 213

 Network configuration (TCP/IPv4)
 ------------------------------------------------------------------
 Host name        : PRN-01
 IPv4 address     : 10.10.10.20
 Subnet mask      : 255.255.255.0
 Default gateway  : 10.10.10.1
 Primary DNS      : 172.16.20.53
 DNS suffix       : corp.local
 Config method    : Manual (set by IT, CHG-1180)
 Connectivity     : OK (print server on 172.16.20.0/24 reachable)

 Asset notes
 ------------------------------------------------------------------
 flag 1: %s
</pre>
</body></html>
"""

PORTAL_PAGE = """<!DOCTYPE html>
<html><head><title>CorpNet Intranet Portal</title></head><body>
<pre>
  CorpNet Intranet Portal
  ==========================================================
  Welcome! The portal is reachable from the Finance LAN again.

  Ticket INC-4471 can now be closed. Good troubleshooting.

  flag 4: %s

  Quick links:  Payroll  |  Leave requests  |  IT Service Desk
</pre>
</body></html>
"""

NOT_FOUND = b"<!DOCTYPE html><html><body><pre>404 Not Found</pre></body></html>\n"


class Env:
    def __init__(self, mgr, student):
        self.mgr = mgr
        self.sid = student['sid']
        self.username = student['username']
        self.password = student['password']
        sec = json.loads(student['secrets'])
        self.flags = sec['flags']
        self.rtr_password = sec['rtr_password']
        self.macs = sec['macs']
        self.started = student['env_started'] or time.time()
        self.expires = student['env_expires'] or (self.started + 3600)
        self.router_state = json.loads(student['router']) if student['router'] else rtrcli.fresh_state()
        self.rtr_ns = self.ns('rtr')
        self.router = rtrcli.Router(self)
        self.servers = []
        self.tasks = []
        self.dnsmasq = None
        self.run = run

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

    def save_router(self, state):
        self.mgr.store.save_router(self.sid, state)

    # ------------------------------------------------------------ build
    async def build(self):
        await self.teardown()
        os.makedirs(self.env_dir, exist_ok=True)
        await run('docker', 'run', '-d', '--name', self.container, '--hostname', 'fin-ws07',
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
            if r == 'rtr':
                sysctls.append('net.ipv4.ip_forward=1')
            await run('ip', 'netns', 'exec', self.ns(r), 'sysctl', '-q', '-w', *sysctls)
        await run('ip', 'netns', 'exec', self.ns('sw'), 'sysctl', '-q', '-w',
                  'net.bridge.bridge-nf-call-iptables=0', check=False)

        n = self.ns
        b = ['link set lo up',
             'link add lan type bridge stp_state 0',
             'link add srv type bridge stp_state 0',
             'link add ws type veth peer name eth0 netns %s' % n('ws'),
             'link add rtr0 type veth peer name eth0 netns %s' % n('rtr'),
             'link add rtr1 type veth peer name eth1 netns %s' % n('rtr'),
             'link add prn type veth peer name eth0 netns %s' % n('prn'),
             'link add adm type veth peer name eth0 netns %s' % n('adm'),
             'link add dns type veth peer name eth0 netns %s' % n('dns'),
             'link add web type veth peer name eth0 netns %s' % n('web')]
        for p in ('ws', 'rtr0', 'prn', 'adm'):
            b += ['link set %s master lan' % p, 'link set dev %s type bridge_slave learning off' % p,
                  'link set %s up' % p]
        for p in ('rtr1', 'dns', 'web'):
            b += ['link set %s master srv' % p, 'link set %s up' % p]
        b += ['link set lan up', 'link set srv up']
        await run('ip', '-n', n('sw'), '-batch', '-', input=('\n'.join(b) + '\n').encode())

        m = self.macs
        hosts = {
            'ws': ([('eth0', m['ws'], '10.10.10.50/24')], '10.10.10.254'),   # wrong gateway on purpose
            'rtr': ([('eth0', m['rtr0'], '10.10.10.1/24'), ('eth1', m['rtr1'], '172.16.20.1/24')], None),
            'prn': ([('eth0', m['prn'], '10.10.10.20/24')], '10.10.10.1'),
            'adm': ([('eth0', m['adm'], '10.10.10.30/24')], '10.10.10.1'),
            'dns': ([('eth0', m['dns'], '172.16.20.53/24')], '172.16.20.1'),
            'web': ([('eth0', m['web'], '172.16.20.80/24')], '172.16.20.1'),
        }
        for role, (ifs, gw) in hosts.items():
            b = ['link set lo up']
            for dev, mac, cidr in ifs:
                b += ['link set %s address %s' % (dev, mac), 'addr add %s dev %s' % (cidr, dev),
                      'link set %s up' % dev]
            if gw:
                b.append('route add default via %s' % gw)
            await run('ip', '-n', n(role), '-batch', '-', input=('\n'.join(b) + '\n').encode())

        await run('docker', 'exec', '-i', self.container, '/usr/local/sbin/ws-setup', self.username,
                  input=(self.password + '\n').encode())
        await self.router.apply()
        await self.start_services()

    def is_intact(self):
        return all(os.path.exists(self.ns_path(r)) for r in ROLES + ['ws'])

    async def container_running(self):
        rc, out, _ = await run('docker', 'inspect', '-f', '{{.State.Running}}', self.container, check=False)
        return rc == 0 and out.strip() == 'true'

    # --------------------------------------------------------- services
    async def start_services(self):
        self.servers.append(await self._tcp_server('prn', 80, lambda r, w: self._http(r, w, self._printer)))
        self.servers.append(await self._tcp_server('prn', 9100, self._jetdirect))
        self.servers.append(await self._tcp_server('web', 80, lambda r, w: self._http(r, w, self._portal)))
        self.servers.append(await self._tcp_server('rtr', 23, self.router.handle))
        self.tasks.append(asyncio.create_task(self._admin_loop()))
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
            'domain=corp.local', 'local-ttl=300',
            'host-record=portal.corp.local,172.16.20.80',
            'host-record=dns01.corp.local,172.16.20.53',
            'host-record=rtr-01.corp.local,10.10.10.1',
            'host-record=prn-01.corp.local,10.10.10.20',
            'host-record=admin-pc.corp.local,10.10.10.30',
            'host-record=fin-ws07.corp.local,10.10.10.50',
            'cname=intranet.corp.local,portal.corp.local',
            'txt-record=portal.corp.local,"flag 2: %s"' % self.flags['2'],
            'txt-record=corp.local,"v=spf1 -all"',
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

    async def _http(self, reader, writer, render):
        try:
            head = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 15)
            parts = head.split(b'\r\n', 1)[0].decode('latin-1').split()
            method = parts[0] if parts else 'GET'
            path = parts[1] if len(parts) > 1 else '/'
            status, body, server = render(method, path)
            hdr = ('HTTP/1.1 %s\r\nServer: %s\r\nContent-Type: text/html; charset=utf-8\r\n'
                   'Content-Length: %d\r\nConnection: close\r\n\r\n' % (status, server, len(body)))
            writer.write(hdr.encode() + (b'' if method == 'HEAD' else body))
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def _printer(self, method, path):
        server = 'HP HTTP Server; HP LaserJet Enterprise M507 - 1PV87A'
        if path.split('?')[0] in ('/', '/index.html', '/hp/device/info'):
            return '200 OK', (PRINTER_PAGE % self.flags['1']).encode(), server
        return '404 Not Found', NOT_FOUND, server

    def _portal(self, method, path):
        server = 'CorpNet-Portal/2.1'
        if path.split('?')[0] in ('/', '/index.html'):
            return '200 OK', (PORTAL_PAGE % self.flags['4']).encode(), server
        return '404 Not Found', NOT_FOUND, server

    async def _jetdirect(self, reader, writer):
        try:
            await asyncio.wait_for(reader.read(4096), 5)
        except Exception:
            pass
        finally:
            writer.close()

    async def _admin_loop(self):
        await asyncio.sleep(random.uniform(3, 8))
        while True:
            try:
                await asyncio.wait_for(self._admin_once(), 30)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.debug('admin-pc %s: %r', self.sid, e)
            await asyncio.sleep(random.uniform(25, 35))

    async def _admin_once(self):
        loop = asyncio.get_running_loop()
        s = netns_socket(self.ns_path('adm'))
        s.setblocking(False)
        try:
            await asyncio.wait_for(loop.sock_connect(s, ('10.10.10.1', 23)), 5)
        except BaseException:
            s.close()
            raise
        reader, writer = await asyncio.open_connection(sock=s)
        buf = bytearray()

        async def expect(token):
            nonlocal buf
            while token not in buf:
                chunk = await asyncio.wait_for(reader.read(4096), 8)
                if not chunk:
                    raise EOFError
                buf += chunk
            buf = buf[buf.index(token) + len(token):]

        try:
            await expect(b'Username:')
            await asyncio.sleep(0.4)
            writer.write(b'netadmin\r\n')
            await expect(b'Password:')
            await asyncio.sleep(0.4)
            writer.write(self.rtr_password.encode() + b'\r\n')
            await expect(b'#')
            await asyncio.sleep(0.5)
            writer.write(b'show ip interface brief\r\n')
            await expect(b'brief')
            await expect(b'#')
            await asyncio.sleep(0.5)
            writer.write(b'exit\r\n')
            await writer.drain()
            await asyncio.sleep(0.3)
        finally:
            writer.close()

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
        asyncio.create_task(self._launch(sid, reset_router))

    async def _launch(self, sid, reset_router):
        env = None
        try:
            async with self.sem:
                old = self.envs.pop(sid, None)
                if old:
                    await old.teardown()
                if reset_router:
                    self.store.save_router(sid, rtrcli.fresh_state())
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
                st = self.store.student_by_sid(sid)
                env = Env(self, st)
            await env.teardown()
        except Exception:
            log.exception('stop %s', sid)
        finally:
            self.store.set_env(sid, 'none', msg)
            self.busy.discard(sid)

    async def reconcile(self):
        """On startup: re-attach environments that survived a restart, clean up the rest."""
        known = set()
        for st in self.store.students():
            sid = st['sid']
            known.add(sid)
            if st['env_state'] in ('running', 'starting', 'stopping'):
                env = Env(self, st)
                try:
                    if st['env_state'] == 'running' and env.is_intact() and await env.container_running():
                        await env.router.apply()
                        await env.start_services()
                        self.envs[sid] = env
                        log.info('re-attached env %s', sid)
                        continue
                except Exception:
                    log.exception('re-attach %s', sid)
                await env.teardown()
                self.store.set_env(sid, 'none', 'Your machine was stopped by a server restart. Launch it again.')
        # orphans: workstation containers of this deployment that no running lab owns
        _, out, _ = await run('docker', 'ps', '-a', '--filter', 'label=netlab.instance=%s' % INSTANCE,
                              '--format', '{{.Names}} {{.Label "netlab.sid"}}', check=False)
        orphans = [ln.split()[0] for ln in out.splitlines()
                   if ln.split() and (len(ln.split()) < 2 or ln.split()[1] not in self.envs)]
        if orphans:
            log.info('removing %d leftover workstation container(s)', len(orphans))
            await run('docker', 'rm', '-f', *orphans, check=False, timeout=120)
        if os.path.isdir('/run/netns'):
            for nsname in os.listdir('/run/netns'):
                if nsname.startswith('nl') and '-' in nsname:
                    sid = nsname[2:].split('-')[0]
                    if sid not in self.envs:
                        await run('ip', 'netns', 'del', nsname, check=False)

    async def shutdown(self):
        """Container is stopping: the namespaces die with it, so remove every lab machine now."""
        envs = list(self.envs.values())
        self.envs.clear()
        for env in envs:
            try:
                await env.stop_services()
            except Exception:
                log.exception('stop services %s', env.sid)
            self.store.set_env(env.sid, 'none', 'Your machine was stopped because the lab server restarted. '
                                                'Launch it again.')
        for sid in list(self.busy):
            self.store.set_env(sid, 'none', 'Your machine was stopped because the lab server restarted. '
                                            'Launch it again.')
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
