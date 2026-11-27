"""IOS-style router CLI served over telnet.

The ACL state is real: every change is compiled to iptables rules inside the
router's network namespace, so fixing (or breaking) the ACL changes what
traffic the router forwards.
"""
import asyncio
import copy
import ipaddress
import re
import time

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
OPT_ECHO, OPT_SGA = 1, 3

PORT_NAMES = {
    'www': 80, 'http': 80, 'domain': 53, 'telnet': 23, 'ftp': 21, 'ftp-data': 20,
    'smtp': 25, 'pop3': 110, 'tftp': 69, 'snmp': 161, 'ntp': 123, 'bootps': 67,
    'bootpc': 68, 'syslog': 514, 'https': 443, 'ssh': 22, 'isakmp': 500,
}
PORT_DISPLAY = {80: 'www', 53: 'domain', 23: 'telnet', 21: 'ftp', 20: 'ftp-data',
                25: 'smtp', 110: 'pop3', 69: 'tftp', 161: 'snmp', 123: 'ntp',
                67: 'bootps', 68: 'bootpc', 514: 'syslog', 500: 'isakmp'}
ICMP_TYPES = {'echo': 'echo-request', 'echo-reply': 'echo-reply',
              'unreachable': 'destination-unreachable', 'time-exceeded': 'time-exceeded'}

IFACES = {
    'GigabitEthernet0/0': {'linux': 'eth0', 'ip': '10.10.10.1', 'mask': '255.255.255.0',
                           'desc': 'LAN - Finance (SW-ACC-01 Gi1/0/24)'},
    'GigabitEthernet0/1': {'linux': 'eth1', 'ip': '172.16.20.1', 'mask': '255.255.255.0',
                           'desc': 'SERVERS - Datacenter'},
    'GigabitEthernet0/2': {'linux': None, 'ip': None, 'mask': None, 'desc': ''},
}


class CLIError(Exception):
    pass


def initial_state():
    aces = [
        (10, 'remark', 'Finance LAN inbound policy'),
        (20, 'ace', 'permit icmp 10.10.10.0 0.0.0.255 any'),
        (30, 'ace', 'permit udp 10.10.10.0 0.0.0.255 host 172.16.20.53 eq domain'),
        (40, 'ace', 'permit tcp 10.10.10.0 0.0.0.255 host 172.16.20.53 eq domain'),
        (45, 'remark', 'CHG-2231 jsmith: block portal during maintenance window. REMOVE AFTER!'),
        (50, 'ace', 'deny tcp 10.10.10.0 0.0.0.255 host 172.16.20.80 eq www'),
        (60, 'ace', 'permit ip 10.10.10.0 0.0.0.255 any'),
    ]
    entries = []
    for seq, kind, text in aces:
        if kind == 'ace':
            entries.append({'seq': seq, 'kind': 'ace', 'text': canon(parse_ace(text.split()))})
        else:
            entries.append({'seq': seq, 'kind': 'remark', 'text': text})
    return {
        'hostname': 'RTR-01',
        'acls': {'LAN-IN': entries},
        'groups': {'GigabitEthernet0/0': {'in': 'LAN-IN'}, 'GigabitEthernet0/1': {}},
        'desc': {k: v['desc'] for k, v in IFACES.items()},
        'log': [],
    }


# ---------------------------------------------------------------- ACE parsing

def _ip(tok):
    try:
        return ipaddress.IPv4Address(tok)
    except ValueError:
        raise CLIError("%% Invalid input detected: '%s' is not an IPv4 address" % tok)


def parse_addr(toks, i):
    if i >= len(toks):
        raise CLIError('% Incomplete command.')
    t = toks[i].lower()
    if t == 'any':
        return ('any', None, 0), i + 1
    if t == 'host':
        if i + 1 >= len(toks):
            raise CLIError('% Incomplete command.')
        a = _ip(toks[i + 1])
        return ('host', str(a), 32), i + 2
    a = _ip(toks[i])
    if i + 1 >= len(toks):
        raise CLIError('%% Incomplete command. (expected a wildcard mask after %s)' % toks[i])
    w = int(_ip(toks[i + 1]))
    if (w + 1) & w:
        raise CLIError('%% Invalid wildcard mask %s (bits must be contiguous)' % toks[i + 1])
    prefix = 32 - w.bit_length()
    net = ipaddress.IPv4Address(int(a) & ~w & 0xFFFFFFFF)
    if prefix == 32:
        return ('host', str(net), 32), i + 2
    if prefix == 0:
        return ('any', None, 0), i + 2
    return ('net', str(net), prefix), i + 2


def _port(tok):
    t = tok.lower()
    if t in PORT_NAMES:
        return PORT_NAMES[t]
    if t.isdigit() and 0 <= int(t) <= 65535:
        return int(t)
    raise CLIError("%% Invalid port '%s'" % tok)


def parse_port(toks, i):
    if i >= len(toks):
        return None, i
    op = toks[i].lower()
    if op in ('eq', 'neq', 'gt', 'lt'):
        if i + 1 >= len(toks):
            raise CLIError('% Incomplete command.')
        return (op, _port(toks[i + 1])), i + 2
    if op == 'range':
        if i + 2 >= len(toks):
            raise CLIError('% Incomplete command.')
        return ('range', _port(toks[i + 1]), _port(toks[i + 2])), i + 3
    return None, i


def parse_ace(toks):
    if len(toks) < 2:
        raise CLIError('% Incomplete command.')
    action = toks[0].lower()
    if action not in ('permit', 'deny'):
        raise CLIError("%% Invalid input detected at '%s'" % toks[0])
    proto = toks[1].lower()
    if proto not in ('ip', 'tcp', 'udp', 'icmp'):
        raise CLIError("%% Unsupported protocol '%s' (use ip, tcp, udp or icmp)" % toks[1])
    i = 2
    src, i = parse_addr(toks, i)
    sport = None
    if proto in ('tcp', 'udp'):
        sport, i = parse_port(toks, i)
    dst, i = parse_addr(toks, i)
    dport = None
    if proto in ('tcp', 'udp'):
        dport, i = parse_port(toks, i)
    icmp_type = None
    established = False
    while i < len(toks):
        t = toks[i].lower()
        if t in ('log', 'log-input'):
            pass
        elif t == 'established' and proto == 'tcp':
            established = True
        elif proto == 'icmp' and t in ICMP_TYPES and icmp_type is None:
            icmp_type = t
        else:
            raise CLIError("%% Invalid input detected at '%s'" % toks[i])
        i += 1
    return {'action': action, 'proto': proto, 'src': src, 'sport': sport, 'dst': dst,
            'dport': dport, 'icmp': icmp_type, 'est': established}


def _addr_txt(a):
    kind, ip, prefix = a
    if kind == 'any':
        return 'any'
    if kind == 'host':
        return 'host ' + ip
    wild = ipaddress.IPv4Address((1 << (32 - prefix)) - 1)
    return '%s %s' % (ip, wild)


def _port_txt(p):
    if not p:
        return ''
    if p[0] == 'range':
        return ' range %s %s' % (PORT_DISPLAY.get(p[1], p[1]), PORT_DISPLAY.get(p[2], p[2]))
    return ' %s %s' % (p[0], PORT_DISPLAY.get(p[1], p[1]))


def canon(a):
    s = '%s %s %s%s %s%s' % (a['action'], a['proto'], _addr_txt(a['src']), _port_txt(a['sport']),
                            _addr_txt(a['dst']), _port_txt(a['dport']))
    if a['icmp']:
        s += ' ' + a['icmp']
    if a['est']:
        s += ' established'
    return s


def _ipt_addr(flag, a):
    kind, ip, prefix = a
    if kind == 'any':
        return []
    return [flag, '%s/%d' % (ip, prefix)]


def _ipt_port(flag, p):
    if not p:
        return []
    op = p[0]
    if op == 'eq':
        return [flag, str(p[1])]
    if op == 'neq':
        return ['!', flag, str(p[1])]
    if op == 'gt':
        return [flag, '%d:65535' % (p[1] + 1)]
    if op == 'lt':
        return [flag, '0:%d' % max(p[1] - 1, 0)]
    return [flag, '%d:%d' % (p[1], p[2])]


def ace_to_ipt(text):
    a = parse_ace(text.split())
    args = []
    if a['proto'] != 'ip':
        args += ['-p', a['proto']]
    args += _ipt_addr('-s', a['src']) + _ipt_addr('-d', a['dst'])
    if a['proto'] in ('tcp', 'udp'):
        args += _ipt_port('--sport', a['sport']) + _ipt_port('--dport', a['dport'])
    if a['icmp']:
        args += ['--icmp-type', ICMP_TYPES[a['icmp']]]
    if a['est']:
        args += ['!', '--syn']
    args += ['-j', 'ACCEPT' if a['action'] == 'permit' else 'DROP']
    return args


def chain_name(acl):
    return 'ACL-' + acl[:24]


def build_ruleset(state):
    lines = ['*filter', ':INPUT ACCEPT [0:0]', ':FORWARD ACCEPT [0:0]', ':OUTPUT ACCEPT [0:0]']
    for name in state['acls']:
        lines.append(':%s - [0:0]' % chain_name(name))
    for ifname, g in state['groups'].items():
        linux = IFACES[ifname]['linux']
        if not linux:
            continue
        for direction, acl in g.items():
            if acl and acl in state['acls']:
                flag = '-i' if direction == 'in' else '-o'
                lines.append('-A FORWARD %s %s -j %s' % (flag, linux, chain_name(acl)))
    for name, entries in state['acls'].items():
        for e in entries:
            if e['kind'] == 'ace':
                lines.append('-A %s %s' % (chain_name(name), ' '.join(ace_to_ipt(e['text']))))
        lines.append('-A %s -j DROP' % chain_name(name))  # implicit deny
    lines.append('COMMIT')
    return '\n'.join(lines) + '\n'


# ------------------------------------------------------------- telnet plumbing

class TelnetIO:
    def __init__(self, reader, writer):
        self.r, self.w = reader, writer
        self.pending = bytearray()
        self.iac = 0
        self.esc = 0
        self.skip_lf = False

    def start(self):
        self.w.write(bytes([IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA]))

    def out(self, text):
        self.w.write(text.replace('\r\n', '\n').replace('\n', '\r\n').encode('utf-8', 'replace'))

    def _strip(self, data):
        out = bytearray()
        for b in data:
            s = self.iac
            if s == 0:
                if b == IAC:
                    self.iac = 1
                else:
                    out.append(b)
            elif s == 1:
                if b == IAC:
                    out.append(b)
                    self.iac = 0
                elif b in (WILL, WONT, DO, DONT):
                    self.iac = 2
                elif b == SB:
                    self.iac = 3
                else:
                    self.iac = 0
            elif s == 2:
                self.iac = 0
            elif s == 3:
                if b == IAC:
                    self.iac = 4
            elif s == 4:
                self.iac = 0 if b == SE else 3
        return out

    async def _byte(self):
        while not self.pending:
            await self.w.drain()
            data = await self.r.read(1024)
            if not data:
                raise EOFError
            self.pending.extend(self._strip(data))
        return self.pending.pop(0)

    async def readline(self, echo=True, on_help=None, prompt=''):
        line = bytearray()
        while True:
            b = await self._byte()
            if self.skip_lf:
                self.skip_lf = False
                if b in (0, 10):
                    continue
            if self.esc == 1:
                self.esc = 2 if b in (0x5b, 0x4f) else 0
                continue
            if self.esc == 2:
                if 0x40 <= b <= 0x7e:
                    self.esc = 0
                continue
            if b == 27:
                self.esc = 1
                continue
            if b == 13 or b == 10:
                self.skip_lf = (b == 13)
                self.out('\n')
                return line.decode('utf-8', 'replace')
            if b in (8, 127):
                if line:
                    line.pop()
                    if echo:
                        self.w.write(b'\b \b')
                continue
            if b == 3:
                self.out('^C\n')
                return None
            if b == 26:  # Ctrl-Z
                self.out('^Z\n')
                return '\x1a'
            if b == 4 and not line:
                raise EOFError
            if b == 21:
                if echo:
                    self.w.write(b'\b \b' * len(line))
                line.clear()
                continue
            if b == 63 and echo and on_help:  # '?'
                self.out('?\n' + on_help(line.decode('utf-8', 'replace')) + prompt)
                self.w.write(bytes(line))
                continue
            if b == 9 or b < 32:
                continue
            line.append(b)
            if echo:
                self.w.write(bytes([b]))


# --------------------------------------------------------------- the router

def _kw(tokens, words):
    if len(tokens) < len(words):
        return None
    for t, w in zip(tokens, words):
        if not w.startswith(t.lower()):
            return None
    return tokens[len(words):]


def _depth(tokens, words):
    d = 0
    for t, w in zip(tokens, words):
        if not w.startswith(t.lower()):
            break
        d += 1
    return d


def norm_iface(name):
    m = re.match(r'^([a-z]+)0/([0-2])$', re.sub(r'\s+', '', name.lower()))
    if not m or not 'gigabitethernet'.startswith(m.group(1)):
        return None
    return 'GigabitEthernet0/' + m.group(2)


class Router:
    """One per student environment."""

    def __init__(self, env):
        self.env = env            # provides: rtr_ns, rtr_password, flag3, started, save_router(), run()
        self.state = env.router_state
        self.sessions = {}        # id -> dict(user, host, since)
        self._sid = 0

    # ---- persistence / dataplane
    async def apply(self):
        await self.env.run('ip', 'netns', 'exec', self.env.rtr_ns, 'iptables-restore',
                           input=build_ruleset(self.state).encode())

    async def counters(self, acl):
        rc, out, _ = await self.env.run('ip', 'netns', 'exec', self.env.rtr_ns, 'iptables', '-L',
                                        chain_name(acl), '-n', '-v', '-x', check=False)
        if rc != 0:
            return []
        res = []
        for ln in out.splitlines()[2:]:
            parts = ln.split()
            if parts and parts[0].isdigit():
                res.append(int(parts[0]))
        return res

    def save(self):
        self.env.save_router(self.state)

    def log(self, msg):
        ts = time.strftime('%b %d %H:%M:%S', time.gmtime())
        self.state['log'].append('*%s.%03d: %s' % (ts, int(time.time() * 1000) % 1000, msg))
        self.state['log'] = self.state['log'][-40:]

    # ---- output helpers
    def show_ip_int_brief(self):
        rows = ['Interface              IP-Address      OK? Method Status                Protocol']
        for name, i in IFACES.items():
            if i['ip']:
                rows.append('%-22s %-15s YES NVRAM  %-21s %s' % (name, i['ip'], 'up', 'up'))
            else:
                rows.append('%-22s %-15s YES NVRAM  %-21s %s' % (name, 'unassigned', 'administratively down', 'down'))
        return '\n'.join(rows)

    def show_ip_route(self):
        return ('Codes: L - local, C - connected, S - static, R - RIP, O - OSPF, B - BGP\n'
                '       * - candidate default\n\n'
                'Gateway of last resort is not set\n\n'
                '      10.0.0.0/8 is variably subnetted, 2 subnets, 2 masks\n'
                'C        10.10.10.0/24 is directly connected, GigabitEthernet0/0\n'
                'L        10.10.10.1/32 is directly connected, GigabitEthernet0/0\n'
                '      172.16.0.0/16 is variably subnetted, 2 subnets, 2 masks\n'
                'C        172.16.20.0/24 is directly connected, GigabitEthernet0/1\n'
                'L        172.16.20.1/32 is directly connected, GigabitEthernet0/1')

    async def show_acl(self, only=None):
        out = []
        for name, entries in self.state['acls'].items():
            if only and only != name:
                continue
            cnt = await self.counters(name)
            out.append('Extended IP access list %s' % name)
            k = 0
            for e in entries:
                if e['kind'] != 'ace':
                    continue
                n = cnt[k] if k < len(cnt) else 0
                k += 1
                out.append('    %d %s%s' % (e['seq'], e['text'], (' (%d match%s)' % (n, 'es' if n != 1 else '')) if n else ''))
        return '\n'.join(out)

    async def show_arp(self):
        rc, out, _ = await self.env.run('ip', '-n', self.env.rtr_ns, 'neigh', 'show', check=False)
        rows = ['Protocol  Address          Age (min)  Hardware Addr   Type   Interface']
        own = {'eth0': ('10.10.10.1', self.env.macs['rtr0'], 'GigabitEthernet0/0'),
               'eth1': ('172.16.20.1', self.env.macs['rtr1'], 'GigabitEthernet0/1')}
        for dev, (ip, mac, ifn) in own.items():
            rows.append('Internet  %-16s %9s  %-14s  ARPA   %s' % (ip, '-', _cmac(mac), ifn))
        for ln in out.splitlines():
            p = ln.split()
            if 'lladdr' in p and 'dev' in p:
                ip, dev, mac = p[0], p[p.index('dev') + 1], p[p.index('lladdr') + 1]
                ifn = 'GigabitEthernet0/0' if dev == 'eth0' else 'GigabitEthernet0/1'
                rows.append('Internet  %-16s %9s  %-14s  ARPA   %s' % (ip, '0', _cmac(mac), ifn))
        return '\n'.join(rows)

    def show_run(self):
        s = self.state
        out = ['Building configuration...', '', 'Current configuration : 2048 bytes', '!',
               'version 15.9', 'service timestamps log datetime msec', 'no service password-encryption', '!',
               'hostname %s' % s['hostname'], '!',
               'username netadmin privilege 15 secret 9 $9$nL4bQe8vXr2Wk1$Zq0cJ5tUu3hK9mYpR7sVd2Lw', '!']
        for name, i in IFACES.items():
            out.append('interface %s' % name)
            if s['desc'].get(name):
                out.append(' description %s' % s['desc'][name])
            if i['ip']:
                out.append(' ip address %s %s' % (i['ip'], i['mask']))
                for d, acl in s['groups'].get(name, {}).items():
                    if acl:
                        out.append(' ip access-group %s %s' % (acl, d))
                out.append(' no shutdown')
            else:
                out.append(' no ip address')
                out.append(' shutdown')
            out.append('!')
        for name, entries in s['acls'].items():
            out.append('ip access-list extended %s' % name)
            for e in entries:
                if e['kind'] == 'remark':
                    out.append(' remark %s' % e['text'])
                else:
                    out.append(' %d %s' % (e['seq'], e['text']))
            out.append('!')
        out += ['banner motd ^C Authorized access only. RTR-01 is managed by CorpNet IT. ^C', '!',
                'line con 0', ' logging synchronous', 'line vty 0 4', ' login local',
                ' transport input telnet', '!', 'end']
        return '\n'.join(out)

    def show_version(self):
        up = int(time.time() - self.env.started) + 86400 * 41 + 3600 * 5
        d, r = divmod(up, 86400)
        h, r = divmod(r, 3600)
        return ('NetLab virtual router (IOS-style CLI), Version 15.9(3)M7\n'
                'ROM: NetLab Bootstrap\n\n'
                '%s uptime is %d weeks, %d days, %d hours, %d minutes\n'
                'System image file is "flash:netlab-universalk9.SPA.159-3.M7.bin"\n\n'
                '3 Gigabit Ethernet interfaces\n'
                'Configuration register is 0x2102' % (self.state['hostname'], d // 7, d % 7, h, r // 60))

    def show_logging(self):
        base = self.env.started
        hist = [
            (base - 3300, '%SYS-5-CONFIG_I: Configured from console by jsmith on vty0 (10.10.10.30)'),
            (base - 3290, '%PARSER-5-CFGLOG_LOGGEDCMD: User:jsmith  logged command:ip access-list extended LAN-IN'),
            (base - 3280, '%PARSER-5-CFGLOG_LOGGEDCMD: User:jsmith  logged command:remark CHG-2231 jsmith: block portal during maintenance window. REMOVE AFTER!'),
            (base - 3270, '%PARSER-5-CFGLOG_LOGGEDCMD: User:jsmith  logged command:50 deny tcp 10.10.10.0 0.0.0.255 host 172.16.20.80 eq www'),
            (base - 3260, '%SYS-5-CONFIG_I: Configured from console by jsmith on vty0 (10.10.10.30)'),
            (base - 900, '%SYS-6-LOGGINGHOST_STARTSTOP: Logging to host 172.16.20.53 port 514 started'),
        ]
        rows = ['Syslog logging: enabled (0 messages dropped, 0 flushes)',
                '    Console logging: level debugging', '    Buffer logging:  level debugging', '',
                'Log Buffer (8192 bytes):']
        for t, m in hist:
            ts = time.strftime('%b %d %H:%M:%S', time.gmtime(t))
            rows.append('*%s.%03d: %s' % (ts, int(t * 1000) % 1000, m))
        rows += self.state['log']
        return '\n'.join(rows)

    def show_users(self, me):
        rows = ['    Line       User       Host(s)              Idle       Location']
        for n, (sid, s) in enumerate(sorted(self.sessions.items())):
            idle = int(time.time() - s['last'])
            mark = '*' if sid == me else ' '
            rows.append('%s %3d vty %d     %-10s idle                 %02d:%02d:%02d %s' % (
                mark, n + 2, n, s['user'], idle // 3600, (idle // 60) % 60, idle % 60, s['host']))
        return '\n'.join(rows)

    async def ping(self, args):
        if not args:
            raise CLIError('% Incomplete command.')
        try:
            target = str(ipaddress.IPv4Address(args[0]))
        except ValueError:
            raise CLIError('% Unrecognized host or address, or protocol not running.')
        rc, out, _ = await self.env.run('ip', 'netns', 'exec', self.env.rtr_ns, 'ping', '-n', '-c', '5',
                                        '-W', '1', '-i', '0.2', '-s', '72', target, check=False, timeout=15)
        m = re.search(r'(\d+) received', out)
        got = int(m.group(1)) if m else 0
        rtt = re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)', out)
        res = ('Type escape sequence to abort.\n'
               'Sending 5, 100-byte ICMP Echos to %s, timeout is 2 seconds:\n%s\n'
               'Success rate is %d percent (%d/5)' % (target, '!' * got + '.' * (5 - got), got * 20, got))
        if rtt and got:
            res += ', round-trip min/avg/max = %d/%d/%d ms' % tuple(max(1, round(float(x))) for x in rtt.groups())
        return res

    # ---- help text
    HELP = {
        'exec': ['configure terminal   Enter configuration mode', 'exit                 Exit from the EXEC',
                 'ping <ip>            Send echo messages', 'show access-lists    List access lists and hit counters',
                 'show interfaces      Interface status', 'show ip arp          ARP table',
                 'show ip interface brief', 'show ip route        Routing table',
                 'show logging         Log buffer', 'show running-config  Current configuration',
                 'show users           Logged in users', 'show version         System information',
                 'write memory         Save the configuration'],
        'config': ['interface <name>                 Select an interface (Gi0/0, Gi0/1)',
                   'ip access-list extended <name>   Edit a named extended ACL',
                   'no ip access-list extended <name>', 'hostname <name>', 'do <exec command>',
                   'end                              Return to EXEC mode', 'exit'],
        'nacl': ['<seq> permit|deny <proto> <src> [port] <dst> [port]   Add an entry',
                 'permit|deny ...      Add an entry at the end', 'no <seq>             Delete an entry',
                 'remark <text>        Add a comment', 'do <exec command>', 'end', 'exit'],
        'if': ['ip access-group <acl> in|out', 'no ip access-group <acl> in|out', 'description <text>',
               'do <exec command>', 'end', 'exit'],
    }

    # ---- the session
    async def handle(self, reader, writer):
        peer = writer.get_extra_info('peername')
        host = peer[0] if peer else '?'
        t = TelnetIO(reader, writer)
        self._sid += 1
        me = self._sid
        try:
            t.start()
            t.out('\n\nAuthorized access only. RTR-01 is managed by CorpNet IT.\n\n\nUser Access Verification\n\n')
            for attempt in range(3):
                t.out('Username: ')
                u = await asyncio.wait_for(t.readline(True), 120)
                t.out('Password: ')
                p = await asyncio.wait_for(t.readline(False), 120)
                if u is not None and p is not None and u.strip() == 'netadmin' and p == self.env.rtr_password:
                    break
                await asyncio.sleep(1.0)
                t.out('% Login invalid\n\n')
            else:
                t.out('% Bad passwords\n')
                await writer.drain()
                return
            self.sessions[me] = {'user': 'netadmin', 'host': host, 'last': time.time()}
            if host != '10.10.10.30':
                t.out('\n' + '*' * 62 + '\n'
                      '  %s  core router  |  CorpNet IT\n'
                      '  Welcome, netadmin.\n'
                      '  NOTE: telnet is scheduled to be replaced by SSH (CHG-2302).\n\n'
                      '  flag 3: %s\n' % (self.state['hostname'], self.env.flags['3']) + '*' * 62 + '\n\n')
            mode, ctx = 'exec', None
            while True:
                prompt = self.prompt(mode, ctx)
                t.out(prompt)
                line = await asyncio.wait_for(
                    t.readline(True, on_help=lambda partial, m=mode: self.help(m), prompt=prompt), 900)
                self.sessions[me]['last'] = time.time()
                if line is None:
                    continue
                if line == '\x1a':
                    if mode != 'exec':
                        mode, ctx = 'exec', None
                        self.end_config(host)
                    continue
                try:
                    res = await self.dispatch(mode, ctx, line, me, host)
                except CLIError as e:
                    t.out(str(e) + '\n')
                    continue
                if res is None:
                    continue
                if res[0] == 'quit':
                    break
                if res[0] == 'mode':
                    mode, ctx = res[1], res[2]
                    if len(res) > 3 and res[3]:
                        t.out(res[3] + '\n')
                elif res[0] == 'out' and res[1]:
                    t.out(res[1] + '\n')
                await writer.drain()
        except (EOFError, ConnectionError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        finally:
            self.sessions.pop(me, None)
            try:
                writer.close()
            except Exception:
                pass

    def prompt(self, mode, ctx):
        h = self.state['hostname']
        return {'exec': '%s#' % h, 'config': '%s(config)#' % h, 'nacl': '%s(config-ext-nacl)#' % h,
                'if': '%s(config-if)#' % h}[mode]

    def help(self, mode):
        return '\n'.join('  ' + x for x in self.HELP[mode]) + '\n\n'

    def end_config(self, host):
        self.log('%%SYS-5-CONFIG_I: Configured from console by netadmin on vty0 (%s)' % host)
        self.save()

    def invalid(self, line, tokens, pats, prompt_len):
        best = 0
        for words, _ in pats:
            best = max(best, _depth(tokens, words))
        # incomplete?
        for words, _ in pats:
            if len(tokens) < len(words) and _depth(tokens, words) == len(tokens):
                return CLIError('% Incomplete command.')
        pos = 0
        parts = re.finditer(r'\S+', line)
        for n, m in enumerate(parts):
            if n == best:
                pos = m.start()
                break
        return CLIError(' ' * (prompt_len + pos) + '^\n% Invalid input detected at \'^\' marker.')

    async def dispatch(self, mode, ctx, line, me, host):
        tokens = line.split()
        if not tokens or tokens[0].startswith('!'):
            return None
        plen = len(self.prompt(mode, ctx))
        low0 = tokens[0].lower()
        if mode != 'exec':
            if 'end'.startswith(low0) and len(low0) >= 2 and len(tokens) == 1:
                self.end_config(host)
                return ('mode', 'exec', None)
            if low0 == 'exit' and len(tokens) == 1:
                if mode == 'config':
                    self.end_config(host)
                    return ('mode', 'exec', None)
                return ('mode', 'config', None)
            if low0 == 'do' and len(tokens) > 1:
                return await self.exec_cmd(line.split(None, 1)[1], tokens[1:], me, host, plen + 3)
            if mode == 'config':
                return await self.config_cmd(line, tokens, host, plen)
            if mode == 'nacl':
                return await self.nacl_cmd(ctx, line, tokens, host, plen)
            if mode == 'if':
                return await self.if_cmd(ctx, line, tokens, host, plen)
        return await self.exec_cmd(line, tokens, me, host, plen)

    async def exec_cmd(self, line, tokens, me, host, plen):
        pats = [
            (['show', 'ip', 'interface', 'brief'], lambda r: self.show_ip_int_brief()),
            (['show', 'ip', 'route'], lambda r: self.show_ip_route()),
            (['show', 'ip', 'access-lists'], 'acl'),
            (['show', 'access-lists'], 'acl'),
            (['show', 'ip', 'arp'], 'arp'),
            (['show', 'arp'], 'arp'),
            (['show', 'interfaces'], lambda r: self.show_ip_int_brief()),
            (['show', 'running-config'], lambda r: self.show_run()),
            (['show', 'startup-config'], lambda r: self.show_run()),
            (['show', 'version'], lambda r: self.show_version()),
            (['show', 'logging'], lambda r: self.show_logging()),
            (['show', 'users'], lambda r: self.show_users(me)),
            (['show', 'clock'], lambda r: time.strftime('*%H:%M:%S.000 UTC %a %b %d %Y', time.gmtime())),
            (['ping'], 'ping'),
            (['configure', 'terminal'], 'conf'),
            (['enable'], lambda r: ''),
            (['terminal', 'length'], lambda r: ''),
            (['write', 'memory'], 'wr'),
            (['copy', 'running-config', 'startup-config'], 'wr'),
            (['write'], 'wr'),
            (['exit'], 'quit'), (['logout'], 'quit'), (['quit'], 'quit'),
            (['help'], lambda r: self.help('exec')),
        ]
        if tokens[0].lower() == 'show' and len(tokens) == 1:
            raise CLIError('% Type "show ?" for a list of subcommands')
        for words, fn in pats:
            rest = _kw(tokens, words)
            if rest is None:
                continue
            if fn == 'acl':
                return ('out', await self.show_acl(rest[0] if rest else None))
            if fn == 'arp':
                return ('out', await self.show_arp())
            if fn == 'ping':
                return ('out', await self.ping(rest))
            if fn == 'conf':
                return ('mode', 'config', None, 'Enter configuration commands, one per line.  End with CNTL/Z.')
            if fn == 'wr':
                self.save()
                return ('out', 'Building configuration...\n[OK]')
            if fn == 'quit':
                return ('quit',)
            return ('out', fn(rest))
        if _kw(tokens, ['configure']) is not None and len(tokens) == 1:
            return ('mode', 'config', None, 'Enter configuration commands, one per line.  End with CNTL/Z.')
        if tokens[0].lower() in ('traceroute', 'telnet', 'ssh'):
            raise CLIError('%% %s is not available on this lab router. Use ping, or run it from your workstation.' % tokens[0])
        raise self.invalid(line, tokens, pats, plen)

    async def config_cmd(self, line, tokens, host, plen):
        s = self.state
        low = [x.lower() for x in tokens]
        if _kw(tokens, ['interface']) is not None:
            if len(tokens) < 2:
                raise CLIError('% Incomplete command.')
            name = norm_iface(''.join(tokens[1:]))
            if not name:
                raise CLIError('% Invalid interface. Valid: GigabitEthernet0/0, GigabitEthernet0/1, GigabitEthernet0/2')
            return ('mode', 'if', name)
        rest = _kw(tokens, ['ip', 'access-list', 'extended'])
        if rest is not None:
            if len(rest) != 1:
                raise CLIError('% Incomplete command.')
            name = self._acl_name(rest[0])
            if name not in s['acls']:
                s['acls'][name] = []
            self.log('%%PARSER-5-CFGLOG_LOGGEDCMD: User:netadmin  logged command:%s' % line.strip())
            return ('mode', 'nacl', name)
        rest = _kw(tokens, ['no', 'ip', 'access-list', 'extended'])
        if rest is not None:
            if len(rest) != 1:
                raise CLIError('% Incomplete command.')
            name = self._acl_name(rest[0])
            if name not in s['acls']:
                raise CLIError('%% Access list %s does not exist' % rest[0])
            del s['acls'][name]
            await self.apply()
            self.log('%%PARSER-5-CFGLOG_LOGGEDCMD: User:netadmin  logged command:%s' % line.strip())
            return None
        if low[0] == 'access-list':
            raise CLIError('% This lab router uses named ACLs: ip access-list extended <name>')
        rest = _kw(tokens, ['hostname'])
        if rest is not None:
            if len(rest) != 1 or not re.match(r'^[A-Za-z][A-Za-z0-9-]{0,30}$', rest[0]):
                raise CLIError('% Invalid hostname')
            s['hostname'] = rest[0]
            self.log('%%PARSER-5-CFGLOG_LOGGEDCMD: User:netadmin  logged command:%s' % line.strip())
            return None
        if low[0] in ('line', 'ip', 'router', 'banner', 'username', 'enable', 'service', 'logging'):
            raise CLIError('% That part of the configuration is locked in this lab. Focus on interfaces and ACLs.')
        raise self.invalid(line, tokens, [(['interface'], 0), (['ip', 'access-list', 'extended'], 0),
                                          (['hostname'], 0), (['end'], 0), (['exit'], 0), (['do'], 0)], plen)

    def _acl_name(self, raw):
        for k in self.state['acls']:
            if k.lower() == raw.lower():
                return k
        if not re.match(r'^[A-Za-z][A-Za-z0-9_-]{0,23}$', raw):
            raise CLIError('% Invalid access-list name')
        return raw

    async def nacl_cmd(self, acl, line, tokens, host, plen):
        entries = self.state['acls'].setdefault(acl, [])
        low0 = tokens[0].lower()
        logline = '%%PARSER-5-CFGLOG_LOGGEDCMD: User:netadmin  logged command:%s' % line.strip()
        if low0 == 'no':
            if len(tokens) < 2:
                raise CLIError('% Incomplete command.')
            if tokens[1].isdigit():
                seq = int(tokens[1])
                before = len(entries)
                entries[:] = [e for e in entries if e['seq'] != seq]
                if len(entries) == before:
                    raise CLIError('%% Sequence number %d not found in %s' % (seq, acl))
            else:
                if tokens[1].lower() == 'remark':
                    txt = line.strip().split(None, 2)[2] if len(tokens) > 2 else ''
                    keep = [e for e in entries if not (e['kind'] == 'remark' and e['text'] == txt)]
                else:
                    txt = canon(parse_ace(tokens[1:]))
                    keep = [e for e in entries if not (e['kind'] == 'ace' and e['text'] == txt)]
                if len(keep) == len(entries):
                    raise CLIError('% Entry not found')
                entries[:] = keep
            await self.apply()
            self.log(logline)
            return None
        seq = None
        toks = tokens
        if low0.isdigit():
            seq = int(low0)
            if not 1 <= seq <= 2147483647:
                raise CLIError('% Invalid sequence number')
            toks = tokens[1:]
            if not toks:
                raise CLIError('% Incomplete command.')
        if seq is not None and any(e['seq'] == seq for e in entries):
            raise CLIError('% Duplicate sequence number')
        if seq is None:
            seq = (max([e['seq'] for e in entries]) + 10) if entries else 10
        kind = toks[0].lower()
        if 'remark'.startswith(kind) and len(kind) >= 3:
            text = line.strip().split(None, 2 if line.strip().split()[0].isdigit() else 1)[-1]
            entries.append({'seq': seq, 'kind': 'remark', 'text': text})
        elif kind in ('permit', 'deny'):
            text = canon(parse_ace(toks))
            ace_to_ipt(text)  # validate
            entries.append({'seq': seq, 'kind': 'ace', 'text': text})
        else:
            raise self.invalid(line, tokens, [(['permit'], 0), (['deny'], 0), (['no'], 0), (['remark'], 0),
                                              (['end'], 0), (['exit'], 0), (['do'], 0)], plen)
        entries.sort(key=lambda e: e['seq'])
        await self.apply()
        self.log(logline)
        return None

    async def if_cmd(self, iface, line, tokens, host, plen):
        s = self.state
        logline = '%%PARSER-5-CFGLOG_LOGGEDCMD: User:netadmin  logged command:%s' % line.strip()
        neg = tokens[0].lower() == 'no'
        body = tokens[1:] if neg else tokens
        rest = _kw(body, ['ip', 'access-group'])
        if rest is not None:
            if not IFACES[iface]['ip']:
                raise CLIError('%% Interface %s has no IP address; ACLs do nothing here.' % iface)
            if len(rest) == 1 and rest[0].lower() in ('in', 'out') and neg:
                name, direction = None, rest[0].lower()
            elif len(rest) == 2 and rest[1].lower() in ('in', 'out'):
                name, direction = rest[0], rest[1].lower()
            else:
                raise CLIError('% Incomplete command. Usage: ip access-group <name> in|out')
            g = s['groups'].setdefault(iface, {})
            if neg:
                g.pop(direction, None)
            else:
                g[direction] = self._acl_name(name)
            await self.apply()
            self.log(logline)
            return None
        rest = _kw(body, ['description'])
        if rest is not None:
            s['desc'][iface] = '' if neg else ' '.join(rest)
            return None
        if _kw(body, ['shutdown']) is not None:
            if neg:
                return None
            raise CLIError('% Shutting down interfaces is disabled in this lab (you would lock yourself out).')
        if _kw(body, ['ip', 'address']) is not None:
            raise CLIError('% Interface addressing is locked in this lab.')
        raise self.invalid(line, tokens, [(['ip', 'access-group'], 0), (['no'], 0), (['description'], 0),
                                          (['shutdown'], 0), (['end'], 0), (['exit'], 0), (['do'], 0)], plen)


def _cmac(mac):
    h = mac.replace(':', '').lower()
    return '%s.%s.%s' % (h[0:4], h[4:8], h[8:12])


def fresh_state():
    return copy.deepcopy(initial_state())
