'use strict';
const $ = (id) => document.getElementById(id);
const examples = {
  client: 'Клиент Иванов Иван Иванович, дата рождения: 15.03.1990.\nПаспорт: 4509 123456.\nТелефон: +7 (999) 123-45-67\nEmail: ivan.petrov@example.ru\nАдрес: г. Москва, ул. Лесная, д. 12, кв. 34.',
  payment: 'Получатель Петрова Анна Сергеевна.\nНомер карты: 4111 1111 1111 1111\nИмя держателя карты: ANNA PETROVA\nCVV: 123; ПИН-код: 5678\nИНН: 7707083893',
  public: 'Поэт Александр Пушкин написал роман «Евгений Онегин».\nОтделение банка находится по адресу: г. Москва, ул. Лесная, д. 12.',
};
const CATEGORY_BY_TYPE = {
  FIO: 'fio',
  PASSPORT: 'doc', DRIVER: 'doc', INN: 'doc', CITIZENSHIP: 'doc', ISSUER: 'doc',
  DEPT_CODE: 'doc', DATE: 'doc', DATE_TEXT: 'doc', BIRTH_PLACE: 'doc',
  ADDRESS: 'addr',
  EMAIL: 'contact', PHONE: 'contact',
  CARD: 'pay', CVV: 'pay', PIN: 'pay', CARDHOLDER: 'pay',
};
const CATEGORY_LABEL = { fio: 'ФИО', doc: 'Документы', addr: 'Адрес', contact: 'Контакты', pay: 'Платёжные данные' };
const categoryOf = (type) => CATEGORY_BY_TYPE[type] || 'doc';

function newId() {
  if (window.crypto && typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  // crypto.randomUUID needs a secure context (HTTPS or localhost); this page can be
  // served over plain HTTP on an IP address, where it is simply undefined.
  return 'id-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 12);
}
const SESSION_KEY = 'pii:last-mask';

function saveMaskSession(payloadId, maskedText) {
  try {
    sessionStorage.setItem(SESSION_KEY, JSON.stringify({ systemId: state.systemId, payloadId, maskedText }));
  } catch { /* private mode */ }
}

function loadMaskSession() {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

const state = { systemId: 'default', systems: {}, payloadId: null, maskedText: null };
let toastTimer;
function toast(message) { $('toast').textContent = message; $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('toast').hidden = true; }, 3000); }
function error(id, message = '') { $(id).textContent = message; $(id).hidden = !message; }

function apiError(data, status) {
  const detail = data?.detail;
  if (typeof detail === 'string') {
    if (status === 409) return 'Не удалось восстановить: текст не совпадает с сохранённой маской. Защитите данные заново.';
    if (status === 503 && detail.includes('decrypt')) return 'Сессия восстановления устарела или ключ шифрования сменился. Защитите текст заново.';
    return detail;
  }
  if (Array.isArray(detail)) return detail.map((item) => item.msg || String(item)).join('; ');
  return 'Проверьте формат запроса.';
}

function maskMode() {
  const el = $('mask-mode');
  return el && el.value === 'synthetic' ? 'synthetic' : 'format';
}

async function api(path, body) {
  const headers = { 'Content-Type': 'application/json', 'X-System-Id': state.systemId };
  if (body) headers['X-Mask-Mode'] = maskMode();
  const response = await fetch(path, {
    method: body ? 'POST' : 'GET',
    headers,
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(apiError(data, response.status));
  return data;
}

function setExample(name) {
  $('source-text').value = examples[name];
  document.querySelectorAll('[data-example]').forEach((el) => el.classList.toggle('active', el.dataset.example === name));
  updateCount();
}
function updateCount() { $('char-count').textContent = `${Array.from($('source-text').value).length.toLocaleString('ru')} символов`; }

function markClass(type) {
  const cat = categoryOf(type);
  return { fio: 'mark-fio', doc: 'mark-doc', addr: 'mark-addr', contact: 'mark-contact', pay: 'mark-pay' }[cat] || 'mark-other';
}

function renderHighlight(text, entities) {
  const el = $('source-highlight');
  el.replaceChildren();
  if (!entities?.length) {
    el.className = 'highlight-text muted';
    el.textContent = text || 'После защиты здесь будут отмечены найденные фрагменты.';
    return;
  }
  el.className = 'highlight-text';
  const spans = entities
    .filter((e) => Number.isInteger(e.start) && Number.isInteger(e.end) && e.end > e.start)
    .sort((a, b) => a.start - b.start);
  let cursor = 0;
  for (const span of spans) {
    if (span.start < cursor) continue;
    if (span.start > cursor) el.append(document.createTextNode(text.slice(cursor, span.start)));
    el.append(Object.assign(document.createElement('mark'), {
      className: markClass(span.type),
      textContent: text.slice(span.start, span.end),
    }));
    cursor = span.end;
  }
  if (cursor < text.length) el.append(document.createTextNode(text.slice(cursor)));
}

function renderLegend(types) {
  const el = $('entity-legend');
  el.replaceChildren();
  if (!types.length) {
    el.append(Object.assign(document.createElement('p'), { className: 'muted', textContent: 'Персональные данные не найдены — текст останется без изменений.' }));
    $('entity-badge').textContent = '0';
    return;
  }
  const counts = new Map();
  for (const t of types) counts.set(categoryOf(t), (counts.get(categoryOf(t)) || 0) + 1);
  for (const [cat, count] of counts) {
    const chip = document.createElement('span');
    chip.className = `legend-chip legend-${cat}`;
    chip.append(document.createElement('i'), document.createTextNode(`${CATEGORY_LABEL[cat]} · ${count}`));
    el.append(chip);
  }
  $('entity-badge').textContent = String(types.length);
}

function resetResult() {
  const container = $('result-text');
  container.className = 'result-text empty';
  container.replaceChildren(
    Object.assign(document.createElement('span'), { className: 'empty-symbol', textContent: '⟐' }),
    Object.assign(document.createElement('strong'), { textContent: 'Безопасный текст появится здесь' }),
    Object.assign(document.createElement('p'), { innerHTML: 'Добавьте текст и запустите защиту.<br>Вы увидите ровно то, что уйдёт дальше.' }),
  );
  $('result-heading').textContent = 'Защищённый текст';
  $('copy-result').disabled = true;
  $('restore-button').disabled = true;
  $('entity-count').textContent = '—';
  $('entity-detail').textContent = 'Ожидание обработки';
  $('latency').replaceChildren(document.createTextNode('—'), Object.assign(document.createElement('small'), { textContent: ' мс' }));
  renderLegend([]);
  renderHighlight('', []);
  state.payloadId = null;
  state.maskedText = null;
}

async function protect() {
  if (!$('source-text').value.trim()) { error('playground-error', 'Добавьте текст для обработки.'); return; }
  const button = $('protect-button');
  button.disabled = true;
  error('playground-error');
  try {
    const payloadId = newId();
    const data = await api('/process', { payload: $('source-text').value, payload_id: payloadId });
    state.payloadId = payloadId;
    state.maskedText = data.result;
    saveMaskSession(payloadId, data.result);
    const container = $('result-text');
    container.className = 'result-text';
    container.textContent = data.result;
    $('result-heading').textContent = 'Защищённый текст';
    $('entity-count').textContent = String(data.types.length);
    const groups = new Set(data.types.map(categoryOf));
    $('entity-detail').textContent = `${groups.size} категорий персональных данных`;
    $('latency').replaceChildren(document.createTextNode(String(data.elapsed_ms)), Object.assign(document.createElement('small'), { textContent: ' мс' }));
    $('copy-result').disabled = false;
    const demaskAllowed = state.systems[state.systemId]?.demask !== false;
    $('restore-button').disabled = !demaskAllowed;
    $('restore-status').textContent = demaskAllowed ? 'Обратимое' : 'Отключено для этой системы';
    $('result-caption').textContent = 'Готово к безопасной отправке дальше';
    renderLegend(data.types);
    renderHighlight($('source-text').value, data.entities || []);
  } catch (e) { error('playground-error', e.message); } finally { button.disabled = false; }
}

async function restore() {
  const saved = loadMaskSession();
  const payloadId = state.payloadId || saved?.payloadId;
  const maskedText = state.maskedText || saved?.maskedText;
  if (!payloadId || !maskedText) {
    error('playground-error', 'Сначала нажмите «Защитить данные».');
    return;
  }
  if (saved?.systemId) state.systemId = saved.systemId;
  $('restore-button').disabled = true;
  error('playground-error');
  try {
    const data = await api('/process', { payload: maskedText, payload_id: payloadId });
    if (data.direction !== 'demask') {
      throw new Error('Восстановление не выполнено. Сначала «Защитить данные», затем сразу «Восстановить» без изменений.');
    }
    state.payloadId = payloadId;
    state.maskedText = maskedText;
    const container = $('result-text');
    container.className = 'result-text';
    container.textContent = data.result;
    $('source-text').value = data.result;
    updateCount();
    $('result-heading').textContent = 'Восстановленный текст';
    $('restore-status').textContent = 'Восстановлено';
    $('result-caption').textContent = 'Исходный текст восстановлен по payload_id';
    toast('Исходные значения восстановлены');
  } catch (e) { error('playground-error', e.message); } finally {
    const demaskAllowed = state.systems[state.systemId]?.demask !== false;
    $('restore-button').disabled = !(demaskAllowed && state.payloadId && state.maskedText);
  }
}

async function loadSystems() {
  try {
    state.systems = await api('/systems');
  } catch { state.systems = { default: { demask: true } }; }
  const select = $('system-select');
  select.replaceChildren();
  for (const id of Object.keys(state.systems)) {
    select.append(Object.assign(document.createElement('option'), { value: id, textContent: id }));
  }
  if (!state.systems[state.systemId]) state.systemId = Object.keys(state.systems)[0] || 'default';
  select.value = state.systemId;
}

$('system-select').addEventListener('change', (e) => { state.systemId = e.target.value; resetResult(); });
if ($('mask-mode')) $('mask-mode').addEventListener('change', resetResult);
document.querySelectorAll('[data-example]').forEach((el) => el.addEventListener('click', () => setExample(el.dataset.example)));
$('source-text').addEventListener('input', updateCount);
$('clear-input').addEventListener('click', () => { $('source-text').value = ''; updateCount(); $('source-text').focus(); resetResult(); });
$('protect-button').addEventListener('click', protect);
$('restore-button').addEventListener('click', restore);
$('copy-result').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('result-text').textContent); toast('Текст скопирован'); }
  catch { toast('Браузер не разрешил копирование. Выделите текст вручную.'); }
});

setExample('client');
loadSystems();
fetch('/health').then((r) => r.json()).then((data) => {
  const el = $('service-status');
  el.replaceChildren(
    Object.assign(document.createElement('i'), { className: data.status === 'ok' ? 'dot' : 'dot bad' }),
    document.createTextNode(data.status === 'ok' ? 'Сервис доступен' : 'Сервис недоступен'),
  );
}).catch(() => {
  const el = $('service-status');
  el.replaceChildren(Object.assign(document.createElement('i'), { className: 'dot bad' }), document.createTextNode('Нет соединения'));
});
