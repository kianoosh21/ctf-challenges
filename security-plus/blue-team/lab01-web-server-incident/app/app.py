#!/usr/bin/env python3
"""Network+ lab dashboard: per-browser-session credentials, per-student lab, web terminal."""
import asyncio
import hmac
import json
import logging
import os
import random
import secrets
import sqlite3
import time

import signal
import ssl

import asyncssh
from aiohttp import WSMsgType, web

import certs
import content
import lab

BASE = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = lab.STATE_DIR
# Cookie names include the lab id so two labs on the same host (different ports) never share a session.
COOKIE = content.LAB_ID + '_session'
ADMIN_COOKIE = content.LAB_ID + '_admin'
HTTP_PORT = int(os.environ.get('NETLAB_HTTP_PORT', '8080'))
HTTPS_PORT = int(os.environ.get('NETLAB_HTTPS_PORT', '8443'))
# Ports as seen from outside the container (only used for log messages and the HTTP->HTTPS redirect).
PUBLIC_HTTP_PORT = int(os.environ.get('NETLAB_PUBLIC_HTTP_PORT') or HTTP_PORT)
PUBLIC_HTTPS_PORT = int(os.environ.get('NETLAB_PUBLIC_HTTPS_PORT') or HTTPS_PORT)
PUBLIC_HOST = os.environ.get('NETLAB_PUBLIC_HOST', '').strip()
ACME_STAGING = os.environ.get('NETLAB_ACME_STAGING', '0') == '1'
TLS_CERT = os.environ.get('NETLAB_TLS_CERT', '').strip()
TLS_KEY = os.environ.get('NETLAB_TLS_KEY', '').strip()
TRUST_PROXY = os.environ.get('NETLAB_TRUST_PROXY', '0') == '1'
ADMIN_KEY_FILE = os.path.join(STATE_DIR, 'admin.key')
MAX_TERMS = 4

log = logging.getLogger('netlab')

WORDS_USER = ['packet', 'subnet', 'router', 'switch', 'vlan', 'octet', 'frame', 'ping', 'hop', 'port',
              'socket', 'trunk', 'bridge', 'proxy', 'relay', 'beacon', 'cable', 'fiber', 'patch', 'stack']
WORDS_PASS = ['amber', 'falcon', 'cobalt', 'maple', 'orbit', 'harbor', 'copper', 'willow', 'meteor', 'canyon',
              'velvet', 'tundra', 'pixel', 'lantern', 'glacier', 'summit', 'ember', 'quartz', 'nebula', 'raven',
              'cedar', 'delta', 'harvest', 'lotus', 'marble', 'onyx', 'prairie', 'sable', 'timber', 'zephyr']


# ------------------------------------------------------------------ storage

class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS students(
            id INTEGER PRIMARY KEY, sid TEXT UNIQUE, username TEXT UNIQUE, password TEXT,
            created REAL, secrets TEXT, solved TEXT DEFAULT '{}', env_state TEXT DEFAULT 'none',
            env_msg TEXT DEFAULT '', env_started REAL, router TEXT, last_seen REAL);
        CREATE TABLE IF NOT EXISTS sessions(
            token TEXT PRIMARY KEY, student_id INTEGER, created REAL, last_seen REAL, ip TEXT);
        CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
        ''')
        cols = [r[1] for r in self.db.execute('PRAGMA table_info(students)')]
        if 'env_expires' not in cols:   # databases created before the lab timer existed
            self.db.execute('ALTER TABLE students ADD COLUMN env_expires REAL')

    def q(self, sql, *a):
        return self.db.execute(sql, a)

    def setting(self, k, default=None):
        r = self.q('SELECT v FROM settings WHERE k=?', k).fetchone()
        return r['v'] if r else default

    def set_setting(self, k, v):
        self.q('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v', k, v)

    def session(self, tok):
        return self.q('SELECT * FROM sessions WHERE token=?', tok).fetchone()

    def create_session(self, tok, ip):
        self.q('INSERT INTO sessions(token, student_id, created, last_seen, ip) VALUES(?,?,?,?,?)',
               tok, None, time.time(), time.time(), ip)

    def touch_session(self, tok):
        self.q('UPDATE sessions SET last_seen=? WHERE token=?', time.time(), tok)

    def bind_session(self, tok, student_id):
        self.q('UPDATE sessions SET student_id=? WHERE token=?', student_id, tok)

    def student(self, student_id):
        return self.q('SELECT * FROM students WHERE id=?', student_id).fetchone()

    def student_by_sid(self, sid):
        return self.q('SELECT * FROM students WHERE sid=?', sid).fetchone()

    def student_by_username(self, u):
        return self.q('SELECT * FROM students WHERE username=?', u).fetchone()

    def students(self):
        return self.q('SELECT * FROM students ORDER BY id').fetchall()

    def create_student(self):
        for _ in range(200):
            sid = secrets.token_hex(3)
            user = '%s%02d' % (random.choice(WORDS_USER), random.randint(10, 99))
            if self.student_by_sid(sid) or self.student_by_username(user):
                continue
            pw = '%s-%s-%02d' % (random.choice(WORDS_PASS), random.choice(WORDS_PASS), random.randint(10, 99))
            cur = self.q('INSERT INTO students(sid, username, password, created, secrets, last_seen) '
                         'VALUES(?,?,?,?,?,?)', sid, user, pw, time.time(), json.dumps(lab.new_secrets()), time.time())
            return self.student(cur.lastrowid)
        raise RuntimeError('could not allocate a username')

    def set_env(self, sid, state, msg=''):
        self.q('UPDATE students SET env_state=?, env_msg=? WHERE sid=?', state, msg, sid)

    def set_env_started(self, sid, ts):
        self.q('UPDATE students SET env_started=? WHERE sid=?', ts, sid)

    def set_env_expires(self, sid, ts):
        self.q('UPDATE students SET env_expires=? WHERE sid=?', ts, sid)

    def save_router(self, sid, state):
        self.q('UPDATE students SET router=? WHERE sid=?', json.dumps(state), sid)

    def solve(self, student_id, stage):
        st = self.student(student_id)
        solved = json.loads(st['solved'])
        if stage not in solved:
            solved[stage] = time.time()
            self.q('UPDATE students SET solved=? WHERE id=?', json.dumps(solved), student_id)
        return solved

    def touch_student(self, student_id):
        self.q('UPDATE students SET last_seen=? WHERE id=?', time.time(), student_id)


def score_of(solved):
    pts = {s['id']: s['points'] for s in content.STAGES}
    return sum(pts.get(k, 0) for k in solved)


def scoreboard(store):
    rows = []
    for st in store.students():
        solved = json.loads(st['solved'])
        if not solved:
            continue
        rows.append({'username': st['username'], 'score': score_of(solved), 'flags': len(solved),
                     'last': max(solved.values())})
    rows.sort(key=lambda r: (-r['score'], r['last']))
    return rows[:25]


# ------------------------------------------------------------------ helpers

def client_ip(request):
    if TRUST_PROXY:
        fwd = request.headers.get('X-Real-IP') or request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
        if fwd:
            return fwd
    return request.remote or ''


def is_https(request):
    if TRUST_PROXY and request.headers.get('X-Forwarded-Proto'):
        return request.headers['X-Forwarded-Proto'].lower() == 'https'
    return request.secure


def same_origin(request):
    origin = request.headers.get('Origin')
    return origin is None or origin == '%s://%s' % ('https' if is_https(request) else 'http', request.host)


def check_post(request):
    if request.headers.get('X-Requested-With') != 'netlab' or not same_origin(request):
        raise web.HTTPForbidden(text='bad request origin')


def set_session_cookie(request, resp, tok):
    resp.set_cookie(COOKIE, tok, max_age=30 * 86400, path='/dashboard', secure=is_https(request), httponly=True,
                    samesite='Lax')


def current(request):
    """Return (token, session_row, student_row)."""
    store = request.app['store']
    tok = request.cookies.get(COOKIE)
    s = store.session(tok) if tok else None
    if not s:
        return None, None, None
    st = store.student(s['student_id']) if s['student_id'] else None
    return tok, s, st


def require_student(request):
    tok, s, st = current(request)
    if not st:
        raise web.HTTPUnauthorized(text=json.dumps({'error': 'no credentials claimed in this session'}),
                                   content_type='application/json')
    return tok, st


class RateLimit:
    def __init__(self, n, per):
        self.n, self.per, self.hits = n, per, {}

    def ok(self, key):
        now = time.time()
        h = [t for t in self.hits.get(key, []) if now - t < self.per]
        if len(h) >= self.n:
            self.hits[key] = h
            return False
        h.append(now)
        self.hits[key] = h
        return True


# ------------------------------------------------------------------ pages

@web.middleware
async def https_redirect_mw(request, handler):
    """With a public host name and a real certificate, send plain-HTTP visitors to HTTPS."""
    if (PUBLIC_HOST and not is_https(request) and request.path != '/healthz'
            and not request.path.startswith('/.well-known/acme-challenge/')):
        port = '' if PUBLIC_HTTPS_PORT == 443 else ':%d' % PUBLIC_HTTPS_PORT
        host = '[%s]' % PUBLIC_HOST if ':' in PUBLIC_HOST else PUBLIC_HOST
        raise web.HTTPMovedPermanently('https://%s%s%s' % (host, port, request.rel_url))
    return await handler(request)


async def acme_challenge(request):
    v = request.app['acme_tokens'].get(request.match_info['token'])
    if v is None:
        raise web.HTTPNotFound()
    return web.Response(text=v, content_type='application/octet-stream')


@web.middleware
async def headers_mw(request, handler):
    resp = await handler(request)
    if isinstance(resp, web.WebSocketResponse) or resp.prepared:
        return resp
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('Referrer-Policy', 'no-referrer')
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    resp.headers.setdefault('Cache-Control', 'no-store')
    resp.headers.setdefault('Content-Security-Policy',
                            "default-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; "
                            "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    return resp


async def page_index(request):
    resp = web.FileResponse(os.path.join(BASE, 'static', 'index.html'))
    tok, s, _ = current(request)
    if not s:
        tok = secrets.token_urlsafe(32)
        request.app['store'].create_session(tok, client_ip(request))
        set_session_cookie(request, resp, tok)
    return resp


async def page_admin(request):
    return web.FileResponse(os.path.join(BASE, 'static', 'admin.html'))


async def redirect_dashboard(request):
    raise web.HTTPFound('/dashboard/')


async def healthz(request):
    return web.Response(text='ok\n')


# ------------------------------------------------------------------ student API

def env_view(st, mgr):
    started = st['env_started']
    env = mgr.envs.get(st['sid'])
    expires = env.expires if env else (st['env_expires'] or ((started + mgr.lab_seconds) if started else None))
    running = st['env_state'] == 'running'
    left = (expires - time.time()) if (running and expires) else None
    return {'state': st['env_state'], 'msg': st['env_msg'] or '', 'started': started, 'expires': expires,
            'seconds_left': max(0, int(left)) if left is not None else None,
            'can_extend': bool(running and mgr.allow_extend and left is not None and left <= mgr.extend_window),
            'lab_minutes': int(mgr.lab_minutes), 'extend_minutes': int(mgr.extend_window // 60)}


async def api_state(request):
    store, mgr = request.app['store'], request.app['mgr']
    tok, s, st = current(request)
    data = {'title': content.TITLE, 'briefing': content.BRIEFING, 'claimed': False, 'ui': content.UI,
            'claims_open': store.setting('claims_open', '1') == '1', 'max_score': content.MAX_SCORE}
    solved = {}
    if s:
        store.touch_session(tok)
    if st:
        store.touch_student(st['id'])
        solved = json.loads(st['solved'])
        data.update(claimed=True, username=st['username'], password=st['password'], env=env_view(st, mgr),
                    score=score_of(solved))
    last = request.app['check_results']
    data['stages'] = [{'id': x['id'], 'points': x['points'], 'title': x['title'], 'tag': x['tag'],
                       'desc': x['desc'], 'hints': x['hints'], 'solved': x['id'] in solved,
                       'solved_at': solved.get(x['id']), 'kind': x.get('kind', 'flag'),
                       'checks': [c[1] for c in x.get('checks', [])],
                       'last_check': last.get((st['id'], x['id'])) if st else None} for x in content.STAGES]
    data['scoreboard'] = scoreboard(store)
    resp = web.json_response(data)
    if not s:
        tok = secrets.token_urlsafe(32)
        store.create_session(tok, client_ip(request))
        set_session_cookie(request, resp, tok)
    return resp


async def api_claim(request):
    check_post(request)
    store = request.app['store']
    tok, s, st = current(request)
    if not s:
        raise web.HTTPBadRequest(text='reload the page first')
    if st:
        return web.json_response({'ok': True})
    if store.setting('claims_open', '1') != '1':
        return web.json_response({'ok': False, 'error': 'New credentials are closed. Ask your instructor.'})
    if not request.app['claim_rl'].ok('global'):
        return web.json_response({'ok': False, 'error': 'Too many claims right now, try again in a minute.'})
    st = store.create_student()
    store.bind_session(tok, st['id'])
    log.info('claimed %s (sid %s) from %s', st['username'], st['sid'], client_ip(request))
    return web.json_response({'ok': True})


async def api_login(request):
    check_post(request)
    store = request.app['store']
    tok, s, _ = current(request)
    if not s:
        raise web.HTTPBadRequest(text='reload the page first')
    if not request.app['login_rl'].ok(client_ip(request)):
        return web.json_response({'ok': False, 'error': 'Too many attempts. Wait a minute.'})
    body = await request.json()
    u = str(body.get('username', '')).strip().lower()
    p = str(body.get('password', '')).strip()
    st = store.student_by_username(u)
    if not st or not hmac.compare_digest(st['password'], p):
        return web.json_response({'ok': False, 'error': 'Username or password is wrong.'})
    store.bind_session(tok, st['id'])
    return web.json_response({'ok': True})


async def api_logout(request):
    check_post(request)
    tok, s, _ = current(request)
    if s:
        request.app['store'].bind_session(tok, None)
    return web.json_response({'ok': True})


async def api_launch(request):
    check_post(request)
    mgr = request.app['mgr']
    _, st = require_student(request)
    body = await request.json() if request.can_read_body else {}
    reset = bool(body.get('reset'))
    if st['env_state'] in ('starting', 'stopping'):
        return web.json_response({'ok': True})
    if st['env_state'] == 'running' and not reset:
        return web.json_response({'ok': True})
    err = mgr.capacity_error(st['sid'])
    if err:
        return web.json_response({'ok': False, 'error': err})
    mgr.launch(st['sid'], reset_router=True)
    return web.json_response({'ok': True})


async def api_extend(request):
    check_post(request)
    _, st = require_student(request)
    expires, err = request.app['mgr'].extend(st['sid'])
    if err:
        return web.json_response({'ok': False, 'error': err})
    log.info('%s extended their lab', st['username'])
    return web.json_response({'ok': True, 'expires': expires})


async def api_stop(request):
    check_post(request)
    _, st = require_student(request)
    request.app['mgr'].stop(st['sid'])
    return web.json_response({'ok': True})


async def api_flag(request):
    check_post(request)
    store = request.app['store']
    _, st = require_student(request)
    if not request.app['flag_rl'].ok(st['id']):
        return web.json_response({'ok': False, 'error': 'Slow down: too many submissions. Wait a minute.'})
    body = await request.json()
    flag = str(body.get('flag', '')).strip()
    flags = json.loads(st['secrets'])['flags']
    for stage, value in flags.items():
        if hmac.compare_digest(flag.encode(), value.encode()):
            already = stage in json.loads(st['solved'])
            store.solve(st['id'], stage)
            title = next(x['title'] for x in content.STAGES if x['id'] == stage)
            log.info('%s solved stage %s', st['username'], stage)
            return web.json_response({'ok': True, 'stage': stage, 'already': already,
                                      'msg': ('Already solved: ' if already else 'Correct! Stage %s solved: ' % stage) + title})
    return web.json_response({'ok': False, 'error': 'That is not one of your flags. Flags are unique to each student.'})


async def api_check(request):
    """Run the live checks for a remediation stage and solve it when every check passes."""
    check_post(request)
    store, mgr = request.app['store'], request.app['mgr']
    _, st = require_student(request)
    body = await request.json()
    stage = next((x for x in content.STAGES if x['id'] == str(body.get('stage'))), None)
    if not stage or stage.get('kind') != 'check':
        return web.json_response({'ok': False, 'error': 'This stage is solved with a flag, not a check.'})
    env = mgr.envs.get(st['sid'])
    if not env or st['env_state'] != 'running':
        return web.json_response({'ok': False, 'error': 'Your lab is not running.'})
    if not request.app['check_rl'].ok(st['id']):
        return web.json_response({'ok': False, 'error': 'Checks take a few seconds. Wait a moment and try again.'})
    try:
        results = await asyncio.wait_for(env.check(stage['id']), 40)
    except Exception as e:
        log.warning('check %s stage %s failed: %r', st['sid'], stage['id'], e)
        return web.json_response({'ok': False, 'error': 'The check could not run. Try again in a moment.'})
    labels = dict(stage['checks'])
    out = [{'label': labels[k], 'ok': bool(results.get(k))} for k, _ in stage['checks']]
    passed = all(r['ok'] for r in out)
    request.app['check_results'][(st['id'], stage['id'])] = {'at': time.time(), 'results': out}
    already = stage['id'] in json.loads(st['solved'])
    if passed:
        store.solve(st['id'], stage['id'])
        if not already:
            log.info('%s solved stage %s (checks)', st['username'], stage['id'])
    n = sum(r['ok'] for r in out)
    msg = (('Already solved: ' if already else 'All checks passed. Stage %s solved: ' % stage['id']) + stage['title']
           if passed else '%d of %d checks pass. Keep going.' % (n, len(out)))
    return web.json_response({'ok': True, 'passed': passed, 'results': out, 'msg': msg})


# ------------------------------------------------------------------ terminal

class TermSession:
    BANNER = ('\r\n\x1b[1;36m  %s\x1b[0m  %s\r\n'
              '  Log in with the username and password from your dashboard.\r\n\r\n'
              % (content.UI['console'], content.UI['console_sub']))

    def __init__(self, ws, env, cols, rows):
        self.ws, self.env = ws, env
        self.cols, self.rows = cols, rows
        self.q = asyncio.Queue()

    async def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        if not self.ws.closed:
            await self.ws.send_bytes(data)

    async def reader(self):
        try:
            async for msg in self.ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        m = json.loads(msg.data)
                    except ValueError:
                        continue
                    if m.get('t') == 'i':
                        await self.q.put(('i', str(m.get('d', ''))[:65536]))
                    elif m.get('t') == 'r':
                        try:
                            c = max(20, min(400, int(m.get('c', 80))))
                            r = max(5, min(200, int(m.get('r', 24))))
                        except (TypeError, ValueError):
                            continue
                        self.cols, self.rows = c, r
                        await self.q.put(('r', c, r))
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                    break
        finally:
            await self.q.put(None)

    async def readline(self, echo=True):
        buf = ''
        while True:
            ev = await self.q.get()
            if ev is None:
                raise ConnectionError
            if ev[0] != 'i':
                continue
            for ch in ev[1]:
                if ch in '\r\n':
                    await self.send('\r\n')
                    return buf
                if ch in '\x7f\x08':
                    if buf:
                        buf = buf[:-1]
                        if echo:
                            await self.send('\b \b')
                elif ch == '\x03':
                    await self.send('^C\r\n')
                    return None
                elif ch == '\x15':
                    if echo:
                        await self.send('\b \b' * len(buf))
                    buf = ''
                elif ch >= ' ' and ch != '\x7f':
                    if len(buf) < 128:
                        buf += ch
                        if echo:
                            await self.send(ch)

    async def run(self):
        rt = asyncio.create_task(self.reader())
        try:
            await self.send(self.BANNER)
            fails = 0
            while True:
                await self.send(content.UI['hostname'] + ' login: ')
                user = await self.readline(True)
                if user is None or not user.strip():
                    continue
                await self.send('Password: ')
                pw = await self.readline(False)
                if pw is None:
                    continue
                res = await self.shell(user.strip().lower(), pw)
                if res == 'denied':
                    fails += 1
                    await asyncio.sleep(min(1 + fails, 5))
                    await self.send('\r\nLogin incorrect\r\n\r\n')
                    continue
                if res == 'error':
                    await self.send('\r\n\x1b[31mCould not reach the workstation. If you just reset or stopped '
                                    'your lab, wait for it to be Running and press Enter.\x1b[0m\r\n\r\n')
                    await self.readline(True)
                    continue
                fails = 0
                await self.send('\r\n\x1b[33m[session closed]\x1b[0m Press Enter to log in again.\r\n')
                await self.readline(True)
                await self.send('\r\n')
        except ConnectionError:
            pass
        finally:
            rt.cancel()
            if not self.ws.closed:
                await self.ws.close()

    async def shell(self, user, pw):
        loop = asyncio.get_running_loop()
        try:
            sock = lab.netns_socket(self.env.ns_path('ws'))
            sock.setblocking(False)
            await asyncio.wait_for(loop.sock_connect(sock, ('127.0.0.1', 22)), 5)
            conn = await asyncio.wait_for(asyncssh.connect(
                sock=sock, username=user, password=pw, known_hosts=None, client_keys=None,
                agent_path=None, config=None, preferred_auth='password', login_timeout=20,
                keepalive_interval=30), 25)
        except asyncssh.PermissionDenied:
            return 'denied'
        except Exception as e:
            log.info('terminal connect failed for %s: %r', self.env.sid, e)
            return 'error'
        pump = None
        try:
            proc = await conn.create_process(term_type='xterm-256color', term_size=(self.cols, self.rows),
                                             encoding=None)

            async def pump_out():
                while True:
                    data = await proc.stdout.read(32768)
                    if not data:
                        break
                    await self.send(data)

            pump = asyncio.create_task(pump_out())
            while True:
                getter = asyncio.create_task(self.q.get())
                done, _ = await asyncio.wait({getter, pump}, return_when=asyncio.FIRST_COMPLETED)
                if getter not in done:
                    getter.cancel()
                    break
                ev = getter.result()
                if ev is None:
                    raise ConnectionError
                if ev[0] == 'i':
                    proc.stdin.write(ev[1].encode('utf-8', 'replace'))
                elif ev[0] == 'r':
                    proc.change_terminal_size(ev[1], ev[2])
                if pump.done():
                    break
            return 'closed'
        except ConnectionError:
            raise
        except Exception as e:
            log.info('terminal session error %s: %r', self.env.sid, e)
            return 'closed'
        finally:
            if pump and not pump.done():
                pump.cancel()
            conn.close()


async def ws_term(request):
    if not same_origin(request):
        raise web.HTTPForbidden()
    mgr = request.app['mgr']
    tok, s, st = current(request)
    ws = web.WebSocketResponse(heartbeat=25, max_msg_size=1 << 20)
    await ws.prepare(request)
    if not st:
        await ws.send_bytes(b'\r\nNo credentials in this browser session. Claim or sign in on the dashboard.\r\n')
        await ws.close()
        return ws
    env = mgr.envs.get(st['sid'])
    if not env or st['env_state'] != 'running':
        await ws.send_bytes(b'\r\nYour lab machine is not running. Click "Launch lab" on the dashboard.\r\n')
        await ws.close()
        return ws
    counts = request.app['term_counts']
    if counts.get(st['sid'], 0) >= MAX_TERMS:
        await ws.send_bytes(b'\r\nToo many terminals open. Close one first (or use tmux).\r\n')
        await ws.close()
        return ws
    try:
        cols = max(20, min(400, int(request.query.get('cols', 100))))
        rows = max(5, min(200, int(request.query.get('rows', 30))))
    except ValueError:
        cols, rows = 100, 30
    counts[st['sid']] = counts.get(st['sid'], 0) + 1
    request.app['websockets'].add(ws)
    try:
        await TermSession(ws, env, cols, rows).run()
    finally:
        counts[st['sid']] -= 1
        request.app['websockets'].discard(ws)
    return ws


# ------------------------------------------------------------------ admin

def admin_ok(request):
    tok = request.cookies.get(ADMIN_COOKIE)
    return bool(tok) and tok in request.app['admin_tokens']


async def api_admin_login(request):
    check_post(request)
    if not request.app['login_rl'].ok('admin:' + client_ip(request)):
        return web.json_response({'ok': False, 'error': 'Too many attempts. Wait a minute.'})
    body = await request.json()
    if not hmac.compare_digest(str(body.get('key', '')).strip().encode(), request.app['admin_key'].encode()):
        return web.json_response({'ok': False, 'error': 'Wrong key'})
    tok = secrets.token_urlsafe(32)
    request.app['admin_tokens'].add(tok)
    resp = web.json_response({'ok': True})
    resp.set_cookie(ADMIN_COOKIE, tok, max_age=12 * 3600, path='/dashboard', secure=is_https(request),
                    httponly=True, samesite='Strict')
    return resp


async def api_admin_state(request):
    if not admin_ok(request):
        return web.json_response({'auth': False})
    store, mgr = request.app['store'], request.app['mgr']
    sess = {}
    for r in store.q('SELECT student_id, COUNT(*) c, MAX(last_seen) l FROM sessions WHERE student_id IS NOT NULL '
                     'GROUP BY student_id').fetchall():
        sess[r['student_id']] = (r['c'], r['l'])
    rows = []
    for st in store.students():
        solved = json.loads(st['solved'])
        rows.append({'username': st['username'], 'password': st['password'], 'sid': st['sid'],
                     'created': st['created'], 'env': env_view(st, mgr), 'solved': sorted(solved),
                     'score': score_of(solved), 'sessions': sess.get(st['id'], (0, None))[0],
                     'last_seen': st['last_seen'], 'terms': request.app['term_counts'].get(st['sid'], 0)})
    return web.json_response({'auth': True, 'students': rows, 'mem': lab.mem_status(),
                              'running': len(mgr.envs), 'max_envs': mgr.max_envs,
                              'lab_minutes': int(mgr.lab_minutes),
                              'stage_ids': [x['id'] for x in content.STAGES],
                              'claims_open': store.setting('claims_open', '1') == '1'})


async def api_admin_action(request):
    check_post(request)
    if not admin_ok(request):
        raise web.HTTPUnauthorized()
    store, mgr = request.app['store'], request.app['mgr']
    body = await request.json()
    action = body.get('action')
    if action == 'claims':
        store.set_setting('claims_open', '1' if body.get('value') else '0')
    elif action in ('reset', 'stop', 'extend'):
        st = store.student_by_username(str(body.get('username', '')))
        if not st:
            return web.json_response({'ok': False, 'error': 'unknown user'})
        if action == 'reset':
            mgr.launch(st['sid'], reset_router=True)
        elif action == 'extend':
            _, err = mgr.extend(st['sid'], by_instructor=True)
            if err:
                return web.json_response({'ok': False, 'error': err})
        else:
            mgr.stop(st['sid'], 'Your instructor stopped your lab.')
    elif action == 'stopall':
        for sid in list(mgr.envs):
            mgr.stop(sid)
    else:
        return web.json_response({'ok': False, 'error': 'unknown action'})
    return web.json_response({'ok': True})


# ------------------------------------------------------------------ main

async def on_startup(app):
    await app['mgr'].preflight()
    await app['mgr'].reconcile()
    app['maint'] = asyncio.create_task(app['mgr'].maintenance())


async def on_shutdown(app):
    for ws in list(app['websockets']):
        await ws.close(code=1001, message=b'server shutting down')


async def on_cleanup(app):
    app['maint'].cancel()
    await app['mgr'].shutdown()


def load_admin_key():
    key = os.environ.get('NETLAB_ADMIN_KEY', '').strip()
    if key:
        return key
    if os.path.exists(ADMIN_KEY_FILE):
        with open(ADMIN_KEY_FILE) as f:
            key = f.read().strip()
    if not key:
        key = secrets.token_urlsafe(18)
        fd = os.open(ADMIN_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(key + '\n')
    return key


class Tls:
    """Holds the server SSLContext and keeps a Let's Encrypt certificate fresh when asked to."""

    def __init__(self, acme_tokens):
        self.acme_tokens = acme_tokens
        self.ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        tls_dir = os.path.join(STATE_DIR, 'tls')
        self.self_cert = os.path.join(tls_dir, 'selfsigned.crt')
        self.self_key = os.path.join(tls_dir, 'selfsigned.key')
        self.le_dir = os.path.join(tls_dir, 'letsencrypt-staging' if ACME_STAGING else 'letsencrypt')
        if TLS_CERT and TLS_KEY:
            self.mode = 'own'
            self.ctx.load_cert_chain(TLS_CERT, TLS_KEY)
            self.own_mtime = self._mtime()
            self.desc = 'your certificate (%s)' % TLS_CERT
        elif PUBLIC_HOST:
            self.mode = 'acme'
            self.desc = "Let's Encrypt for %s%s" % (PUBLIC_HOST, ' (STAGING, not trusted)' if ACME_STAGING else '')
            if certs.needs_renewal(os.path.join(self.le_dir, 'fullchain.pem'), PUBLIC_HOST):
                self._load_self_signed()
            else:
                self._load_le()
        else:
            self.mode = 'self'
            self._load_self_signed()
            self.desc = 'self-signed (browsers show a warning once)'

    def _load_self_signed(self):
        certs.ensure_self_signed(self.self_cert, self.self_key)
        self.ctx.load_cert_chain(self.self_cert, self.self_key)

    def _load_le(self):
        self.ctx.load_cert_chain(os.path.join(self.le_dir, 'fullchain.pem'), os.path.join(self.le_dir, 'privkey.pem'))

    def _mtime(self):
        try:
            return max(os.stat(TLS_CERT).st_mtime, os.stat(TLS_KEY).st_mtime)
        except OSError:
            return None

    async def watch_own(self):
        """Pick up renewed certificate files without a restart."""
        while True:
            await asyncio.sleep(600)
            m = self._mtime()
            if m and m != self.own_mtime:
                try:
                    self.ctx.load_cert_chain(TLS_CERT, TLS_KEY)
                    self.own_mtime = m
                    log.info('reloaded the certificate from %s', TLS_CERT)
                except Exception as e:
                    log.error('could not reload %s: %s', TLS_CERT, e)

    async def acme_loop(self):
        while True:
            delay = 12 * 3600
            try:
                if certs.needs_renewal(os.path.join(self.le_dir, 'fullchain.pem'), PUBLIC_HOST):
                    log.info("requesting a Let's Encrypt certificate for %s", PUBLIC_HOST)
                    await asyncio.to_thread(certs.issue, PUBLIC_HOST, self.le_dir, self.acme_tokens, ACME_STAGING)
                    self._load_le()
                    log.info("now serving the Let's Encrypt certificate for %s", PUBLIC_HOST)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.error("Let's Encrypt request for %s failed: %s. Check that port 80 on %s reaches this "
                          "container (HTTP_PORT=80). Retrying in 1 hour.", PUBLIC_HOST, str(e)[:300], PUBLIC_HOST)
                delay = 3600
            await asyncio.sleep(delay)


def make_app():
    os.makedirs(STATE_DIR, exist_ok=True)
    os.makedirs(os.path.join(STATE_DIR, 'envs'), exist_ok=True)
    store = Store(os.path.join(STATE_DIR, 'netlab.db'))
    app = web.Application(middlewares=[https_redirect_mw, headers_mw], client_max_size=64 * 1024)
    app['store'] = store
    minutes = os.environ.get('NETLAB_LAB_MINUTES', '').strip()
    if not minutes and os.environ.get('NETLAB_MAX_HOURS', '').strip():   # older setting, in hours
        minutes = str(float(os.environ['NETLAB_MAX_HOURS']) * 60)
    app['mgr'] = lab.Manager(store, max_envs=int(os.environ.get('NETLAB_MAX_ENVS', '30')),
                             lab_minutes=max(5.0, float(minutes or '60')),
                             allow_extend=os.environ.get('NETLAB_EXTEND', '1') != '0')
    app['admin_key'] = load_admin_key()
    app['acme_tokens'] = {}
    app['tls'] = Tls(app['acme_tokens'])
    app['websockets'] = set()
    app['admin_tokens'] = set()
    app['term_counts'] = {}
    app['claim_rl'] = RateLimit(60, 60)
    app['login_rl'] = RateLimit(20, 60)
    app['flag_rl'] = RateLimit(20, 60)
    app['check_rl'] = RateLimit(8, 60)
    app['check_results'] = {}
    r = app.router
    r.add_get('/.well-known/acme-challenge/{token}', acme_challenge)
    r.add_get('/healthz', healthz)
    r.add_get('/', redirect_dashboard)
    r.add_get('/dashboard', redirect_dashboard)
    r.add_get('/dashboard/', page_index)
    r.add_get('/dashboard/admin', page_admin)
    r.add_get('/dashboard/api/state', api_state)
    r.add_post('/dashboard/api/claim', api_claim)
    r.add_post('/dashboard/api/login', api_login)
    r.add_post('/dashboard/api/logout', api_logout)
    r.add_post('/dashboard/api/launch', api_launch)
    r.add_post('/dashboard/api/stop', api_stop)
    r.add_post('/dashboard/api/extend', api_extend)
    r.add_post('/dashboard/api/flag', api_flag)
    r.add_post('/dashboard/api/check', api_check)
    r.add_get('/dashboard/ws/term', ws_term)
    r.add_post('/dashboard/api/admin/login', api_admin_login)
    r.add_get('/dashboard/api/admin/state', api_admin_state)
    r.add_post('/dashboard/api/admin/action', api_admin_action)
    r.add_static('/dashboard/static/', os.path.join(BASE, 'static'), follow_symlinks=True)
    app.on_startup.append(on_startup)
    app.on_shutdown.append(on_shutdown)
    app.on_cleanup.append(on_cleanup)
    return app


def banner(app):
    host = PUBLIC_HOST or '<this-machine>'
    http = 'http://%s%s/dashboard' % (host, '' if PUBLIC_HTTP_PORT == 80 else ':%d' % PUBLIC_HTTP_PORT)
    https = 'https://%s%s/dashboard' % (host, '' if PUBLIC_HTTPS_PORT == 443 else ':%d' % PUBLIC_HTTPS_PORT)
    lines = ['NetLab is up.']
    if PUBLIC_HOST:
        lines += ['  Students:        ' + https, '  Instructor view: ' + https + '/admin']
    else:
        lines += ['  Students:        %s  or  %s' % (http, https),
                  '  Instructor view: %s/admin' % http,
                  '  (<this-machine> = localhost on this computer, or its LAN IP for other computers)']
    key_src = 'set by ADMIN_KEY' if os.environ.get('NETLAB_ADMIN_KEY', '').strip() else 'saved in the data volume'
    lines += ['  Instructor key:  %s  (%s)' % (app['admin_key'], key_src),
              '  TLS certificate: ' + app['tls'].desc]
    width = max(len(x) for x in lines) + 2
    log.info('\n' + '=' * width + '\n' + '\n'.join(lines) + '\n' + '=' * width)


async def serve():
    app = make_app()
    runner = web.AppRunner(app, access_log=None, handle_signals=False)
    await runner.setup()
    await web.TCPSite(runner, '0.0.0.0', HTTP_PORT).start()
    await web.TCPSite(runner, '0.0.0.0', HTTPS_PORT, ssl_context=app['tls'].ctx).start()
    banner(app)
    tls = app['tls']
    acme = (asyncio.create_task(tls.acme_loop()) if tls.mode == 'acme'
            else asyncio.create_task(tls.watch_own()) if tls.mode == 'own' else None)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    log.info('shutting down: removing all lab machines')
    if acme:
        acme.cancel()
    await runner.cleanup()
    log.info('stopped')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    logging.getLogger('asyncssh').setLevel(logging.WARNING)
    logging.getLogger('aiohttp.access').setLevel(logging.WARNING)
    asyncio.run(serve())
