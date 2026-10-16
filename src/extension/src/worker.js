// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
// MV3 service worker. Listeners are registered synchronously, as the platform requires, and the
// capture.js registers browser listeners before any asynchronous initialization.
import { BridgeClient } from './bridge.js';
import { installCapture } from './capture.js';
import { watchPort } from './port_lifecycle.js';

const origin = `chrome-extension://${chrome.runtime.id}/`;

let capture;
let currentPort;
export const client = new BridgeClient({
  connectNative: (host) => {
    const port = chrome.runtime.connectNative(host);
    currentPort = port;
    // reading lastError marks it as handled, so Chrome does not log it as unchecked
    port.onDisconnect.addListener(() => void chrome.runtime.lastError);
    watchPort(port, {
      isCurrent: () => currentPort === port,
      connect: () => client.connect(),
      onReady: () => { void capture.refresh(); },
      onDrop: () => capture?.disconnected(),
    });
    return port;
  },
  origin,
  storage: {
    get: async (key) => (await chrome.storage.local.get(key))[key],
    set: (key, value) => chrome.storage.local.set({ [key]: value }),
  },
});
capture = installCapture({ chrome, bridge: client });

const reach = () => {
  client.connect().then(() => capture.refresh()).catch(() => { if (client.state !== 'ready') capture.disconnected(); });
};

chrome.runtime.onStartup.addListener(reach);
chrome.runtime.onInstalled.addListener(reach);
// the service worker can be stopped at any time; a watchdog brings the bridge back
chrome.alarms.create('velqra-watchdog', { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'velqra-watchdog') reach();
});
reach();
