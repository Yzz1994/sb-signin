// 烧饼论坛签到 Cookie 助手 - popup 逻辑
'use strict';

const $ = (id) => document.getElementById(id);

function setStatus(msg, ok) {
  const el = $('status');
  el.textContent = msg;
  el.className = ok ? 'ok' : 'err';
}

$('go').addEventListener('click', async () => {
  const btn = $('go');
  const server = $('server').value.trim().replace(/\/+$/, '');
  const token = $('token').value.trim();
  const name = $('name').value.trim();

  if (!token) {
    setStatus('请先填写安全码（程序控制台显示，或 -show-token 查看）', false);
    return;
  }

  btn.disabled = true;
  btn.textContent = '读取中...';
  setStatus('正在读取 Cookie...', true);

  try {
    // 读取 sb.sb 的所有 Cookie（含 HttpOnly）
    const cookies = await chrome.cookies.getAll({ domain: 'sb.sb' });
    const map = {};
    for (const c of cookies) map[c.name] = c.value;

    const session = map['__Host-bbs_session'];
    const csrf = map['__Host-bbs_csrf'];

    if (!session) {
      setStatus('未找到登录态 Cookie（__Host-bbs_session）。请确认你已登录 sb.sb，然后重试。', false);
      return;
    }

    setStatus('已读取登录态，正在发送到本地服务...', true);

    // 回传到本地签到服务（带安全码）
    const resp = await fetch(server + '/api/accounts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Auth-Token': token },
      body: JSON.stringify({ name: name || '浏览器导入账号', session, csrf }),
    });

    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.error || ('HTTP ' + resp.status));

    setStatus('✅ 成功！账号「' + (data.name || name || '浏览器导入账号') + '」已导入本地服务。', true);
  } catch (e) {
    setStatus('失败：' + e.message + '\n请确认本地签到服务已启动（' + server + '）且安全码正确。', false);
  } finally {
    btn.disabled = false;
    btn.textContent = '获取并发送 Cookie';
  }
});

// 保存上次填写的服务地址和安全码
$('server').value = localStorage.getItem('server') || 'http://127.0.0.1:8080';
$('token').value = localStorage.getItem('token') || '';
$('server').addEventListener('change', () => localStorage.setItem('server', $('server').value.trim()));
$('token').addEventListener('change', () => localStorage.setItem('token', $('token').value.trim()));
