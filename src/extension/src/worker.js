// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
// MV3 service worker. Listeners are registered synchronously, as the platform requires, and the
// worker only ever uses the `runtime`, `storage` and `alarms` APIs (see test/manifest.test.mjs).
import { BridgeClient } from './bridge.js';

const origin = `chrome-extension://${chrome.runtime.id}/`;

export const client = new BridgeClient({
  connectNative: (host) => {
    const port = chrome.runtime.connectNative(host);
    // reading lastError marks it as handled, so Chrome does not log it as unchecked
    port.onDisconnect.addListener(() => void chrome.runtime.lastError);
    return port;
  },
  origin,
  storage: {
    get: async (key) => (await chrome.storage.local.get(key))[key],
    set: (key, value) => chrome.storage.local.set({ [key]: value }),
  },
});

const reach = () => {
  if (client.state !== 'ready') client.connect().catch(() => {});
};

chrome.runtime.onStartup.addListener(reach);
chrome.runtime.onInstalled.addListener(reach);
// the service worker can be stopped at any time; a watchdog brings the bridge back
chrome.alarms.create('velqra-watchdog', { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'velqra-watchdog') reach();
});
reach();
