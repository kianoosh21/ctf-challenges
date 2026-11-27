'use strict';
(function () {
  const $ = (s) => document.querySelector(s);
  const el = (tag, attrs, ...kids) => {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === 'class') e.className = v;
      else if (k === 'text') e.textContent = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v);
    }
    for (const c of kids) if (c != null) e.append(c);
    return e;
  };

  async function api(path, body) {
    const opt = body === undefined
      ? { credentials: 'same-origin' }
      : { method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'netlab' },
          body: JSON.stringify(body) };
    try {
      const r = await fetch('/dashboard/api/' + path, opt);
      const txt = await r.text();
      try { return JSON.parse(txt); } catch (e) { return { ok: false, error: txt || ('HTTP ' + r.status) }; }
    } catch (e) {
      return { ok: false, error: 'Network error, check your connection.' };
    }
  }

  let toastTimer;
  function toast(msg) {
    const t = $('#toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 3500);
  }

  let state = null, pollTimer = null, lastEnvState = null;

  async function refresh() {
    const s = await api('state');
    if (s && s.stages) { state = s; render(); }
    schedule();
  }
  function schedule() {
    clearTimeout(pollTimer);
    const busy = state && state.env && ['starting', 'stopping'].includes(state.env.state);
    pollTimer = setTimeout(refresh, busy ? 1500 : 8000);
  }

  function fmtTime(ts) {
    if (!ts) return '';
    return new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function render() {
    $('#title').textContent = state.title;
    document.title = state.title;
    $('#ticket').textContent = state.ui.ticket;
    $('#launchText').textContent = state.ui.launch_text;
    $('#workText').textContent = state.ui.work_text;
    document.querySelectorAll('.hn').forEach((e) => { e.textContent = state.ui.hostname; });
    $('#flagIn').placeholder = state.ui.flag_example;
    if (!state.claimed) {
      $('#welcome').classList.remove('hidden');
      $('#dash').classList.add('hidden');
      $('#briefing').textContent = state.briefing;
      $('#btnClaim').disabled = !state.claims_open;
      if (!state.claims_open) $('#claimErr').textContent = 'New credentials are closed right now. Ask your instructor.';
      $('#who').textContent = '';
      return;
    }
    $('#welcome').classList.add('hidden');
    $('#dash').classList.remove('hidden');
    $('#who').replaceChildren(el('span', { class: 'chip', text: state.username }),
                              el('span', { text: state.score + ' pts' }));
    $('#cUser').textContent = state.username;
    $('#cPass').textContent = state.password;

    // machine
    const env = state.env;
    const pill = $('#envPill');
    const label = { none: 'not running', starting: 'starting...', running: 'running', error: 'error', stopping: 'stopping...' }[env.state] || env.state;
    pill.textContent = label;
    pill.className = 'pill ' + env.state;
    $('#envMsg').textContent = env.msg || (env.state === 'running' ? 'Your private network is up. Log in from the terminal.' : '');
    $('#btnLaunch').classList.toggle('hidden', env.state === 'running');
    $('#btnLaunch').disabled = ['starting', 'stopping'].includes(env.state);
    $('#btnReset').classList.toggle('hidden', env.state !== 'running');
    $('#btnStop').classList.toggle('hidden', env.state !== 'running');
    $('#btnExtend').classList.toggle('hidden', !env.can_extend);
    $('#btnExtend').textContent = 'Extend ' + env.lab_minutes + ' min';
    renderTimer();

    const ov = $('#overlay');
    if (env.state === 'running') {
      ov.classList.add('hidden');
      if (terms.length === 0) newTerm();
    } else {
      ov.classList.remove('hidden');
      $('#ovTitle').textContent = env.state === 'starting' ? 'Building your network...' :
        env.state === 'stopping' ? 'Stopping your lab...' : env.state === 'error' ? 'Something went wrong' : 'Your lab is not running';
      $('#ovText').textContent = env.state === 'starting' ? state.ui.building_text :
        env.state === 'error' ? (env.msg + ' Try Launch again, or ask your instructor.') :
        env.state === 'stopping' ? 'One moment.' : (env.msg ||
        'Click Launch lab to build your private network. It takes about 10 to 30 seconds.');
    }
    if (lastEnvState && lastEnvState !== 'running' && env.state === 'running') {
      terms.forEach((t) => { if (!t.ws) connect(t); });
    }
    lastEnvState = env.state;

    // flags
    $('#score').textContent = state.score + ' / ' + state.max_score;
    $('#bar').style.width = Math.round(100 * state.score / state.max_score) + '%';

    // stages
    const box = $('#stages');
    box.replaceChildren(...state.stages.map(renderStage));

    // scoreboard
    const tb = $('#board');
    const rows = state.scoreboard.map((r, i) => el('tr', { class: r.username === state.username ? 'me' : '' },
      el('td', { text: String(i + 1) }), el('td', { text: r.username }), el('td', { text: r.flags + '/' + state.stages.length }),
      el('td', { text: String(r.score) })));
    if (!rows.length) rows.push(el('tr', {}, el('td', { colspan: '4', class: 'muted', text: 'No flags yet. Be the first!' })));
    tb.replaceChildren(...rows);
  }

  // Lab timer: countdown under the machine card, warnings near the end.
  const warned = {};
  function renderTimer() {
    const env = state && state.env;
    const box = $('#envTimes');
    if (!env || env.state !== 'running' || !env.expires) { box.textContent = ''; box.classList.remove('warn'); return; }
    const left = Math.max(0, Math.round(env.expires - Date.now() / 1000));
    const mins = Math.ceil(left / 60);
    box.textContent = 'Stops at ' + fmtTime(env.expires) + ' (' + (left < 60 ? 'less than a minute' : mins + ' min') +
      ' left). Labs stop after ' + env.lab_minutes + ' minutes to free resources.' +
      (env.can_extend ? ' Still working? Click Extend.' : '');
    box.classList.toggle('warn', left <= 10 * 60);
    for (const m of [10, 2]) {
      const key = env.expires + ':' + m;
      if (left <= m * 60 && left > 0 && !warned[key]) {
        warned[key] = true;
        toast('Your lab stops in ' + m + ' minutes.' + (env.can_extend ? ' Click Extend on the left to keep working.' : ''));
      }
    }
  }
  setInterval(() => { if (state && state.claimed) renderTimer(); }, 15000);

  function hintKey(stage) { return 'nl_hints_' + state.username + '_' + stage; }

  function renderStage(s) {
    const shown = parseInt(localStorage.getItem(hintKey(s.id)) || '0', 10);
    const hints = s.hints.slice(0, shown).map((h, i) => el('div', { class: 'hint', text: 'Hint ' + (i + 1) + ': ' + h }));
    const more = shown < s.hints.length
      ? el('button', { class: 'hintbtn', text: 'Show hint ' + (shown + 1) + ' of ' + s.hints.length,
          onclick: () => { localStorage.setItem(hintKey(s.id), String(shown + 1)); render(); } })
      : null;
    return el('div', { class: 'stage' + (s.solved ? ' solved' : '') },
      el('div', { class: 'head' },
        el('div', { class: 'name' }, el('span', { class: 'num', text: s.id + '.' }), s.title),
        el('div', { class: 'pts', text: s.solved ? ('solved ' + fmtTime(s.solved_at) + '  +' + s.points) : (s.points + ' pts') })),
      el('div', { class: 'tag', text: s.tag }),
      el('p', { class: 'desc', text: s.desc }),
      s.kind === 'check' ? renderChecks(s) : null,
      ...hints, more);
  }

  // Remediation stages: a checklist that the server verifies against the live lab.
  const checking = new Set();   // stages with a check in flight (survives re-renders)
  function renderChecks(s) {
    const res = s.last_check ? s.last_check.results : null;
    const items = s.checks.map((label, i) => {
      const r = res ? res[i] : null;
      const mark = r ? (r.ok ? 'ok' : 'bad') : 'todo';
      return el('li', { class: 'chk ' + mark }, el('span', { class: 'box', text: r ? (r.ok ? '\u2713' : '\u2717') : '\u2022' }), label);
    });
    const busy = checking.has(s.id);
    const btn = el('button', { class: 'btn primary small', text: busy ? 'Checking...' : 'Check my work' });
    btn.disabled = busy;
    btn.addEventListener('click', async () => {
      checking.add(s.id);
      render();
      const r = await api('check', { stage: s.id });
      checking.delete(s.id);
      toast(r.ok ? r.msg : (r.error || 'Check failed'));
      await refresh();
    });
    const when = s.last_check ? el('span', { class: 'muted small', text: 'last checked ' + fmtTime(s.last_check.at) }) : null;
    return el('div', { class: 'checks' }, el('ul', {}, ...items), el('div', { class: 'row' }, btn, when));
  }

  // ---------------------------------------------------------------- terminals
  const terms = [];
  let activeTerm = null, termSeq = 0;

  function newTerm() {
    if (terms.length >= 4) { toast('Up to 4 terminals. Tip: tmux gives you more windows in one.'); return; }
    const id = ++termSeq;
    const pane = el('div', { class: 'pane' });
    $('#panes').append(pane);
    const term = new Terminal({
      cursorBlink: true, fontSize: 14, scrollback: 5000, convertEol: false,
      fontFamily: 'ui-monospace, "JetBrains Mono", "Cascadia Mono", Menlo, Consolas, monospace',
      theme: { background: '#0b1220', foreground: '#d6e2f0', cursor: '#7dd3fc', selectionBackground: '#33507a' },
    });
    const fit = new FitAddon.FitAddon();
    term.loadAddon(fit);
    term.open(pane);
    const t = { id, term, fit, pane, ws: null };
    const tab = el('button', { class: 'tab', onclick: () => activate(t) }, 'Terminal ' + id,
      el('span', { class: 'x', title: 'Close', text: '×', onclick: (e) => { e.stopPropagation(); closeTerm(t); } }));
    t.tab = tab;
    $('#tabs').insertBefore(tab, $('#btnNewTerm'));
    term.attachCustomKeyEventHandler((e) => {
      if (e.type === 'keydown' && e.ctrlKey && e.shiftKey && e.code === 'KeyC') {
        const sel = term.getSelection();
        if (sel) copyText(sel);
        return false;
      }
      return true;
    });
    term.onData((d) => {
      if (t.ws && t.ws.readyState === 1) t.ws.send(JSON.stringify({ t: 'i', d }));
      else if (d === '\r' && !t.ws) connect(t);
    });
    term.onResize(({ cols, rows }) => {
      if (t.ws && t.ws.readyState === 1) t.ws.send(JSON.stringify({ t: 'r', c: cols, r: rows }));
    });
    terms.push(t);
    activate(t);
    connect(t);
  }

  function activate(t) {
    activeTerm = t;
    terms.forEach((x) => { x.pane.classList.toggle('active', x === t); x.tab.classList.toggle('active', x === t); });
    requestAnimationFrame(() => { try { t.fit.fit(); } catch (e) {} t.term.focus(); });
  }

  function closeTerm(t) {
    if (t.ws) { t.closing = true; t.ws.close(); }
    t.term.dispose();
    t.pane.remove();
    t.tab.remove();
    terms.splice(terms.indexOf(t), 1);
    if (activeTerm === t) { activeTerm = null; if (terms.length) activate(terms[terms.length - 1]); }
  }

  function connect(t) {
    try { t.fit.fit(); } catch (e) {}
    const url = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/dashboard/ws/term?cols=' + t.term.cols + '&rows=' + t.term.rows;
    const ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer';
    t.ws = ws;
    ws.onmessage = (e) => t.term.write(typeof e.data === 'string' ? e.data : new Uint8Array(e.data));
    ws.onclose = () => {
      if (t.ws === ws) t.ws = null;
      if (!t.closing) t.term.write('\r\n\x1b[90m[disconnected] Press Enter to reconnect.\x1b[0m\r\n');
    };
  }

  new ResizeObserver(() => { if (activeTerm) { try { activeTerm.fit.fit(); } catch (e) {} } }).observe($('#panes'));

  // navigator.clipboard only exists on HTTPS or localhost; fall back to execCommand on plain HTTP.
  function copyText(v) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(v).then(() => true, () => false);
    }
    const ta = document.createElement('textarea');
    ta.value = v;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    ta.remove();
    if (activeTerm) activeTerm.term.focus();
    return Promise.resolve(ok);
  }

  // ---------------------------------------------------------------- actions
  $('#btnClaim').addEventListener('click', async () => {
    $('#btnClaim').disabled = true;
    const r = await api('claim', {});
    $('#btnClaim').disabled = false;
    if (!r.ok) { $('#claimErr').textContent = r.error || 'Could not claim credentials.'; return; }
    await refresh();
    toast('Credentials claimed. Next: Launch lab.');
  });

  $('#loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const r = await api('login', { username: $('#liUser').value, password: $('#liPass').value });
    if (!r.ok) { $('#loginErr').textContent = r.error; return; }
    await refresh();
  });

  $('#btnLaunch').addEventListener('click', async () => {
    $('#btnLaunch').disabled = true;
    const r = await api('launch', {});
    if (!r.ok) { toast(r.error || 'Launch failed'); $('#btnLaunch').disabled = false; return; }
    await refresh();
  });

  $('#btnReset').addEventListener('click', async () => {
    if (!confirm('Reset rebuilds your whole network in its original broken state. Your solved flags are kept. Continue?')) return;
    const r = await api('launch', { reset: true });
    if (!r.ok) { toast(r.error || 'Reset failed'); return; }
    await refresh();
  });

  $('#btnExtend').addEventListener('click', async () => {
    const r = await api('extend', {});
    toast(r.ok ? 'Extended. Your lab now stops at ' + fmtTime(r.expires) + '.' : (r.error || 'Could not extend.'));
    await refresh();
  });

  $('#btnStop').addEventListener('click', async () => {
    if (!confirm('Stop your lab machine? You can launch it again later (it starts fresh).')) return;
    await api('stop', {});
    await refresh();
  });

  $('#flagForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const v = $('#flagIn').value.trim();
    if (!v) return;
    const r = await api('flag', { flag: v });
    const m = $('#flagMsg');
    m.className = 'msg ' + (r.ok ? 'ok' : 'bad');
    m.textContent = r.ok ? r.msg : r.error;
    if (r.ok) { $('#flagIn').value = ''; await refresh(); }
  });

  $('#btnNewTerm').addEventListener('click', () => {
    if (!state || !state.env || state.env.state !== 'running') { toast('Launch your lab first.'); return; }
    newTerm();
  });

  document.querySelectorAll('.copy').forEach((b) => b.addEventListener('click', () => {
    const v = $('#' + b.dataset.copy).textContent;
    copyText(v).then((ok) => toast(ok ? 'Copied' : 'Copy failed: select the text and copy it by hand'));
  }));

  $('#lnkLogout').addEventListener('click', async (e) => {
    e.preventDefault();
    if (!confirm('Sign this browser out? You will need your username and password to sign back in.')) return;
    terms.slice().forEach(closeTerm);
    await api('logout', {});
    await refresh();
  });

  refresh();
})();
