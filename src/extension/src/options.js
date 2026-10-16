// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
import { Coexistence } from './coexistence.js';
const check = new Coexistence({ permissions: chrome.permissions, management: { getAll: () => chrome.management.getAll() } });
const button = document.getElementById('check');
const result = document.getElementById('result');
button.addEventListener('click', async () => {
  button.disabled = true;
  try { result.textContent = await check.check(true); }
  finally { button.disabled = false; }
});
