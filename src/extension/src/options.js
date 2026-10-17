// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
import { Coexistence } from './coexistence.js';
import { DIAGNOSTICS_KEY, reasonCode } from './capture_diagnostics.js';
const check = new Coexistence({ permissions: chrome.permissions, management: { getAll: () => chrome.management.getAll() } });
const button = document.getElementById('check');
const result = document.getElementById('result');
button.addEventListener('click', async () => {
  button.disabled = true;
  try { result.textContent = await check.check(true); }
  finally { button.disabled = false; }
});

async function captureStatus() {
  const list = document.getElementById('capture-status');
  try {
    const rows = (await chrome.storage.session.get(DIAGNOSTICS_KEY))[DIAGNOSTICS_KEY];
    list.replaceChildren();
    for (const row of (Array.isArray(rows) ? rows : []).slice(-50).reverse()) {
      const entry = document.createElement('li');
      entry.textContent = `Download ${Number.isSafeInteger(row.id) ? row.id : '?'}: ${reasonCode(row.reason)} (${row.event === 'decision' ? 'decision' : 'browser event'})`;
      list.append(entry);
    }
    if (!list.children.length) list.textContent = 'No download decisions in this session.';
  } catch { list.textContent = 'Capture status unavailable.'; }
}
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'session' && changes[DIAGNOSTICS_KEY]) void captureStatus();
});
void captureStatus();
