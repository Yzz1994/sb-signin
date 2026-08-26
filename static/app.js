// 烧饼论坛签到助手 - 前端逻辑
'use strict';

let state = { accounts: [], settings: {}, logs: [], next_run: '' };
let editingId = null; // null=添加, 否则为编辑的账号 ID
let authToken = localStorage.getItem('sb_token') || '';

const $ = (id) => document.getElementById(id);

// ---------- 工具 ----------
function toast(msg, ok = true) {
  const el = $('toast');
  el.textContent = msg;
  el.className = 'toast show ' + (ok ? 'ok' : 'err');
  clearTimeout(el._t);
  el._t = setTimeout(() => (el.className = 'toast'), 2600);
}

// 显示/隐藏安全码登录门
function requireAuth() {
  authToken = '';
  localStorage.removeItem('sb_token');
  $('auth-mask').classList.add('show');
  $('auth-token').focus();
}
function hideAuth() {
  $('auth-mask').classList.remove('show');
}

async function api(method, url, body) {
  const opts = { method, headers: { 'X-Auth-Token': authToken } };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(url, opts);
  const data = await r.json().catch(() => ({}));
  if (r.status === 401) {
    requireAuth();
    throw new Error(data.error || '安全码无效');
  }
  if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
  return data;
}

// 解析 Cookie 字符串：支持 "a=b; c=d"、"Cookie: a=b; c=d"、curl 命令
function parseCookies(text) {
  const cookies = {};
  if (!text) return cookies;
  // 去掉 curl 命令行里的转义引号等，提取所有 name=value 对
  const re = /([A-Za-z0-9_\-\.]+)=([^;\s"']+)/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const name = m[1];
    const val = m[2];
    if (!(name in cookies)) cookies[name] = val; // 首个优先
  }
  return cookies;
}

function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

// 格式化时间，处理零值/无效日期
function fmtTime(s) {
  if (!s) return '—';
  const d = new Date(s);
  if (isNaN(d.getTime()) || d.getFullYear() < 2000) return '—';
  return d.toLocaleString('zh-CN', { hour12: false });
}

// 判断时间是否为今天（按 UTC 日期，与论坛签到判断一致）
function isTodayUTC(s) {
  if (!s) return false;
  const d = new Date(s);
  if (isNaN(d.getTime())) return false;
  const now = new Date();
  return d.getUTCFullYear() === now.getUTCFullYear()
    && d.getUTCMonth() === now.getUTCMonth()
    && d.getUTCDate() === now.getUTCDate();
}

// 是否今日已签到
function signedToday(acc) {
  return acc.last_result === 'success' && isTodayUTC(acc.last_signin);
}

// ---------- 渲染 ----------
function resultBadge(acc, today) {
  if (today) return '<span class="badge success today-badge">✓ 今日已签到</span>';
  if (!acc.last_result) return '<span class="badge idle">未签到</span>';
  const map = { success: ['success', '成功'], fail: ['fail', '失败'], expired: ['expired', '失效'] };
  const [cls, txt] = map[acc.last_result] || ['idle', acc.last_result];
  return `<span class="badge ${cls}">${txt}</span>`;
}

function renderAccounts() {
  const grid = $('account-grid');
  $('account-count').textContent = state.accounts.length;
  $('empty-tip').style.display = state.accounts.length ? 'none' : 'block';

  // 更新“今日已签到”计数
  const signedN = state.accounts.filter(signedToday).length;
  const enabledN = state.accounts.filter(a => a.enabled).length;
  const sc = $('signed-count');
  if (signedN > 0) {
    sc.textContent = `✓ 今日已签到 ${signedN}/${enabledN}`;
  } else {
    sc.textContent = '';
  }

  grid.innerHTML = state.accounts.map((a) => {
    const lastTime = fmtTime(a.last_signin);
    const today = signedToday(a);
    return `
    <div class="card ${a.enabled ? '' : 'disabled'} ${today ? 'signed-today' : ''}" data-id="${a.id}">
      <div class="card-head">
        <div class="avatar">${escapeHtml((a.name || '?').slice(0, 1))}</div>
        <div class="card-name">${escapeHtml(a.name || '未命名')}</div>
        ${resultBadge(a, today)}
        <label class="switch" title="启用/停用">
          <input type="checkbox" data-toggle="${a.id}" ${a.enabled ? 'checked' : ''}>
          <span class="slider"></span>
        </label>
      </div>
      <div class="stats">
        <div class="stat"><b>${a.streak ?? 0}</b><span>连续</span></div>
        <div class="stat"><b>${a.month ?? 0}</b><span>本月</span></div>
        <div class="stat"><b>${a.total ?? 0}</b><span>累计</span></div>
        <div class="stat"><b>${a.longest ?? 0}</b><span>最长</span></div>
      </div>
      <div class="lastmsg">上次签到：${lastTime}${a.last_message ? ' · ' + escapeHtml(a.last_message) : ''}</div>
      <div class="card-actions">
        <button class="btn sm primary" data-signin="${a.id}" ${today || !a.enabled ? 'disabled' : ''}>${today ? '✓ 今日已签到' : '立即签到'}</button>
        <button class="btn sm" data-edit="${a.id}">编辑</button>
        <button class="btn sm danger" data-del="${a.id}">删除</button>
      </div>
    </div>`;
  }).join('');
}

function renderLogs() {
  const box = $('logbox');
  if (!state.logs || !state.logs.length) {
    box.innerHTML = '<div class="empty">暂无日志</div>';
    return;
  }
  const cls = { success: 'ok', fail: 'err', expired: 'exp' };
  box.innerHTML = [...state.logs].reverse().map((l) => {
    const t = new Date(l.time).toLocaleString('zh-CN', { hour12: false });
    const c = cls[l.result] || '';
    return `<div class="log-line"><span class="t">[${t}]</span> <span class="${c}">${escapeHtml(l.account)}</span> ${escapeHtml(l.message)}</div>`;
  }).join('');
}

function renderHeader() {
  $('next-run').textContent = state.next_run || '--';
  $('now-time').textContent = state.now || '';
}

function refresh() {
  return api('GET', '/api/state').then((d) => {
    state = d;
    renderAccounts();
    renderLogs();
    renderHeader();
  }).catch(() => { /* 401 已由 requireAuth 处理，其余静默 */ });
}

// ---------- 事件绑定 ----------
function bindEvents() {
  // 添加账号
  $('btn-add').onclick = () => openAccountModal();
  $('btn-cancel').onclick = closeAccountModal;
  $('btn-save').onclick = saveAccount;

  // 弹窗 tab 切换
  document.querySelectorAll('#cookie-tabs .tab').forEach((t) => {
    t.onclick = () => {
      document.querySelectorAll('#cookie-tabs .tab').forEach((x) => x.classList.remove('active'));
      t.classList.add('active');
      const manual = t.dataset.tab === 'manual';
      $('paste-field').style.display = manual ? 'none' : '';
      $('manual-field').style.display = manual ? '' : 'none';
      $('manual-csrf-field').style.display = manual ? '' : 'none';
    };
  });

  // 粘贴框实时解析
  $('f-cookie-paste').oninput = () => {
    const cookies = parseCookies($('f-cookie-paste').value);
    const hasSession = !!cookies['__Host-bbs_session'];
    const r = $('parse-result');
    const rt = $('parse-result-text');
    if (Object.keys(cookies).length === 0) {
      r.style.display = 'none';
      return;
    }
    r.style.display = '';
    const color = hasSession ? 'var(--green)' : 'var(--yellow)';
    rt.innerHTML =
      `识别到 <b>${Object.keys(cookies).length}</b> 个 Cookie：` +
      `${hasSession ? '✅ 已找到登录态 <code>__Host-bbs_session</code>' : '⚠️ 未找到 <code>__Host-bbs_session</code>（登录态）'}` +
      `<br><span style="color:${color}">` + Object.keys(cookies).map(k => `<code>${escapeHtml(k)}</code>`).join('、') + '</span>';
  };

  // 设置
  $('btn-settings').onclick = () => {
    $('s-hour').value = state.settings.run_hour;
    $('s-minute').value = state.settings.run_minute;
    $('s-runonstart').checked = !!state.settings.run_on_start;
    $('s-notify-enabled').checked = !!state.settings.notify_enabled;
    $('s-sendkey').value = state.settings.notify_send_key || '';
    $('s-telegram-enabled').checked = !!state.settings.telegram_enabled;
    $('s-tg-token').value = state.settings.telegram_bot_token || '';
    $('s-tg-chatid').value = state.settings.telegram_chat_id || '';
    $('settings-modal').classList.add('show');
  };
  $('btn-settings-cancel').onclick = () => $('settings-modal').classList.remove('show');

  // 修改安全码
  $('btn-set-token').onclick = async () => {
    const newTok = $('s-new-token').value.trim();
    if (newTok.length < 6) {
      toast('安全码至少 6 位', false);
      return;
    }
    try {
      await api('POST', '/api/token', { new_token: newTok });
      // 更新本地保存的安全码，后续请求用新码
      authToken = newTok;
      localStorage.setItem('sb_token', newTok);
      $('s-new-token').value = '';
      toast('安全码已修改，下次登录请用新码');
    } catch (e) {
      toast('修改失败: ' + e.message, false);
    }
  };

  // 自动获取 Telegram Chat ID
  $('btn-discover-chatid').onclick = async () => {
    const token = $('s-tg-token').value.trim();
    if (!token) {
      toast('请先填写 Bot Token', false);
      return;
    }
    const btn = $('btn-discover-chatid');
    btn.disabled = true;
    const old = btn.textContent;
    btn.textContent = '等待中(60s)...';
    toast('请现在去 Telegram 给你的 Bot 发送任意一条消息（60 秒内）');
    try {
      const data = await api('POST', '/api/telegram/discover-chat-id', { bot_token: token });
      if (data.chat_id) {
        $('s-tg-chatid').value = data.chat_id;
        toast('已获取 Chat ID: ' + data.chat_id);
      }
    } catch (e) {
      toast('获取失败: ' + e.message, false);
    } finally {
      btn.disabled = false;
      btn.textContent = old;
    }
  };

  $('btn-settings-save').onclick = async () => {
    try {
      await api('PUT', '/api/settings', {
        run_hour: +$('s-hour').value,
        run_minute: +$('s-minute').value,
        run_on_start: $('s-runonstart').checked,
        notify_enabled: $('s-notify-enabled').checked,
        notify_send_key: $('s-sendkey').value.trim(),
        telegram_enabled: $('s-telegram-enabled').checked,
        telegram_bot_token: $('s-tg-token').value.trim(),
        telegram_chat_id: $('s-tg-chatid').value.trim(),
      });
      $('settings-modal').classList.remove('show');
      toast('设置已保存');
      refresh();
    } catch (e) { toast(e.message, false); }
  };

  // 全部签到
  $('btn-signin-all').onclick = async () => {
    const btn = $('btn-signin-all');
    btn.disabled = true;
    btn.innerHTML = '<span class="spin"></span> 签到中...';
    try {
      const results = await api('POST', '/api/signin-all');
      const ok = results.filter(r => r.result === 'success').length;
      const exp = results.filter(r => r.result === 'expired').length;
      let msg = `完成：成功 ${ok}，失败 ${results.length - ok}`;
      if (exp > 0) msg += `，其中 ${exp} 个登录态失效`;
      toast(msg, exp === 0 && ok === results.length);
      refresh();
    } catch (e) { toast(e.message, false); }
    finally { btn.disabled = false; btn.innerHTML = '全部签到'; }
  };

  // 账号卡片上的按钮（事件委托）
  $('account-grid').addEventListener('click', async (e) => {
    const t = e.target.closest('[data-signin],[data-edit],[data-del]');
    if (!t) return;
    const id = t.dataset.signin || t.dataset.edit || t.dataset.del;
    if (t.dataset.signin) {
      // 立即签到
      t.disabled = true;
      const old = t.innerHTML;
      t.innerHTML = '<span class="spin"></span>';
      try {
        const res = await api('POST', `/api/accounts/${id}/signin`);
        toast(res.message, res.result === 'success');
      } catch (e) { toast(e.message, false); }
      finally { t.disabled = false; t.innerHTML = old; }
      refresh();
    } else if (t.dataset.edit) {
      const acc = state.accounts.find(x => x.id === id);
      openAccountModal(acc);
    } else if (t.dataset.del) {
      if (!confirm('确定删除该账号？')) return;
      try {
        await api('DELETE', `/api/accounts/${id}`);
        toast('已删除');
        refresh();
      } catch (e) { toast(e.message, false); }
    }
  });

  // 启用/停用开关
  $('account-grid').addEventListener('change', async (e) => {
    const t = e.target.closest('[data-toggle]');
    if (!t) return;
    const id = t.dataset.toggle;
    try {
      await api('PUT', `/api/accounts/${id}`, { enabled: t.checked });
      toast(t.checked ? '已启用' : '已停用');
      refresh();
    } catch (e) { toast(e.message, false); }
  });

  // 点击遮罩关闭弹窗
  document.querySelectorAll('.modal-mask').forEach((mask) => {
    mask.addEventListener('click', (e) => { if (e.target === mask) mask.classList.remove('show'); });
  });
}

// ---------- 账号弹窗 ----------
function openAccountModal(acc) {
  editingId = acc ? acc.id : null;
  $('account-modal-title').textContent = acc ? '编辑账号' : '添加账号';
  $('f-name').value = acc ? acc.name : '';
  $('f-cookie-paste').value = '';
  $('f-session').value = acc ? acc.session : '';
  $('f-csrf').value = acc ? acc.csrf : '';
  $('parse-result').style.display = 'none';
  // 默认切到粘贴 tab
  document.querySelectorAll('#cookie-tabs .tab').forEach((x) => x.classList.remove('active'));
  document.querySelector('#cookie-tabs .tab[data-tab="paste"]').classList.add('active');
  $('paste-field').style.display = '';
  $('manual-field').style.display = 'none';
  $('manual-csrf-field').style.display = 'none';
  $('account-modal').classList.add('show');
}

function closeAccountModal() {
  $('account-modal').classList.remove('show');
}

async function saveAccount() {
  const name = $('f-name').value.trim();
  // 从粘贴框或手动框解析
  const manualTab = document.querySelector('#cookie-tabs .tab.active').dataset.tab === 'manual';
  let session, csrf;
  if (manualTab) {
    session = $('f-session').value.trim();
    csrf = $('f-csrf').value.trim();
  } else {
    const cookies = parseCookies($('f-cookie-paste').value);
    session = cookies['__Host-bbs_session'] || '';
    csrf = cookies['__Host-bbs_csrf'] || '';
  }
  if (!session) {
    toast('缺少登录态 Cookie（__Host-bbs_session）', false);
    return;
  }
  try {
    if (editingId) {
      await api('PUT', `/api/accounts/${editingId}`, { name, session, csrf });
      toast('已更新');
    } else {
      await api('POST', '/api/accounts', { name, session, csrf });
      toast('已添加账号');
    }
    closeAccountModal();
    refresh();
  } catch (e) { toast(e.message, false); }
}

// ---------- 安全码登录门 ----------
function bindAuth() {
  const submit = () => {
    const tok = $('auth-token').value.trim();
    if (!tok) return;
    $('auth-submit').disabled = true;
    // 直接校验安全码
    fetch('/api/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: tok }),
    }).then(async (r) => {
      const d = await r.json().catch(() => ({}));
      if (r.ok) {
        authToken = tok;
        localStorage.setItem('sb_token', tok);
        hideAuth();
        $('auth-err').textContent = '';
        $('auth-token').value = '';
        refresh();
      } else {
        $('auth-err').textContent = d.error || '安全码错误';
      }
    }).catch(() => {
      $('auth-err').textContent = '网络错误，请重试';
    }).finally(() => {
      $('auth-submit').disabled = false;
    });
  };
  $('auth-submit').onclick = submit;
  $('auth-token').addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
}

// ---------- 启动 ----------
function boot() {
  if (authToken) {
    hideAuth();
    refresh();
  } else {
    requireAuth();
  }
}

bindEvents();
bindAuth();
boot();
setInterval(() => refresh(), 30000); // 每 30 秒刷新
