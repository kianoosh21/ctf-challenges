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
    const opt = body === undefined ? { credentials: 'same-origin' } : {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'netlab' }, body: JSON.stringify(body) };
    const r = await fetch('/dashboard/api/admin/' + path, opt);
    try { return await r.json(); } catch (e) { return { ok: false, error: 'HTTP ' + r.status }; }
  }
  const ago = (ts) => {
    if (!ts) return '';
    const s = Math.round(Date.now() / 1000 - ts);
    return s < 60 ? s + 's ago' : s < 3600 ? Math.round(s / 60) + 'm ago' : Math.round(s / 3600) + 'h ago';
  };
  let claimsOpen = true;

  async function load() {
    const s = await api('state');
    if (!s.auth) { $('#loginBox').classList.remove('hidden'); $('#panel').classList.add('hidden'); return; }
    $('#loginBox').classList.add('hidden');
    $('#panel').classList.remove('hidden');
    claimsOpen = s.claims_open;
    $('#btnClaims').textContent = claimsOpen ? 'Close new claims' : 'Open new claims';
    const ids = s.stage_ids || ['1', '2', '3', '4'];
    const done = s.students.filter((x) => x.solved.length === ids.length).length;
    $('#stats').replaceChildren(
      stat('Students', s.students.length), stat('Machines running', s.running + ' / ' + s.max_envs),
      stat('Finished (all stages)', done), stat('RAM available', s.mem.mem_avail_mb + ' MB'),
      stat('Swap free', s.mem.swap_free_mb + ' MB'), stat('New claims', claimsOpen ? 'open' : 'closed'),
      stat('Lab time limit', s.lab_minutes + ' min'));
    $('#rows').replaceChildren(...s.students.map((st) => el('tr', {},
      el('td', {}, el('code', { text: st.username })),
      el('td', {}, el('code', { text: st.password })),
      el('td', {}, ...ids.map((n) => el('span', { class: 'fl' + (st.solved.includes(n) ? ' on' : ''), text: n }))),
      el('td', { text: String(st.score) }),
      el('td', {}, el('span', { class: 'pill ' + st.env.state, text: st.env.state }),
        st.env.seconds_left != null ? el('div', { class: 'muted small', text: Math.ceil(st.env.seconds_left / 60) + ' min left' }) : null,
        st.env.msg ? el('div', { class: 'muted small', text: st.env.msg }) : null),
      el('td', { text: String(st.terms) }),
      el('td', { class: 'muted', text: ago(st.last_seen) }),
      el('td', {}, el('div', { class: 'row' },
        st.env.state === 'running' ? el('button', { class: 'btn', text: '+' + s.lab_minutes + ' min', onclick: () => act('extend', st.username) }) : null,
        el('button', { class: 'btn', text: 'Reset', onclick: () => act('reset', st.username) }),
        el('button', { class: 'btn ghost', text: 'Stop', onclick: () => act('stop', st.username) }))))));
  }
  function stat(label, val) { return el('div', { class: 'stat' }, el('b', { text: String(val) }), el('span', { class: 'muted small', text: label })); }
  async function act(action, username) {
    if (action !== 'extend' && !confirm(action + ' lab for ' + username + '?')) return;
    const r = await api('action', { action, username });
    if (r && r.ok === false && r.error) alert(r.error);
    load();
  }
  $('#keyForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const r = await api('login', { key: $('#key').value });
    if (!r.ok) { $('#keyErr').textContent = r.error; return; }
    load();
  });
  $('#btnClaims').addEventListener('click', async () => { await api('action', { action: 'claims', value: !claimsOpen }); load(); });
  $('#btnStopAll').addEventListener('click', async () => {
    if (!confirm('Stop every running lab machine?')) return;
    await api('action', { action: 'stopall' }); load();
  });
  load();
  setInterval(load, 5000);
})();
