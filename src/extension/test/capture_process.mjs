// SPDX-License-Identifier: GPL-3.0-only
// Real native-messaging framing; no Chrome, registry registration or aria2.
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cleanupOwned, stopChild, reportCleanup, stopPid } from './process_cleanup.mjs';
import { BridgeClient } from '../src/bridge.js';

const bin = fileURLToPath(new URL('../../target/debug/', import.meta.url));
const HOST = join(bin, 'velqra-host.exe'), APP = join(bin, 'velqra-app.exe');
const origin = `chrome-extension://${JSON.parse(readFileSync(new URL('../dev-key.json', import.meta.url))).id}/`;
export const binaries = existsSync(HOST) && existsSync(APP);
if (!binaries) console.warn('SKIPPED C5 real processes: cargo build -p velqra-app --bins is required');

export async function until(ok, ms = 15000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await ok()) return; await new Promise(r => setTimeout(r, 20)); }
  throw Error('real-process wait timed out');
}

export class Processes {
  constructor(allowLoopback = true) {
    this.home = mkdtempSync(join(tmpdir(), 'velqra-capture-e2e-'));
    this.env = { ...process.env, VELQRA_HOME: this.home, VELQRA_PIPE: `capture-${process.pid}-${this.home.split('-').pop()}`, VELQRA_APP: APP, VELQRA_ALLOW_LOOPBACK: '1' };
    delete this.env.VELQRA_ARIA2; delete this.env.VELQRA_ALLOWED_ORIGINS;
    if (!allowLoopback) { delete this.env.VELQRA_ALLOW_LOOPBACK; this.env.VELQRA_ARIA2 = join(this.home, 'missing-aria2.exe'); }
    this.allowLoopback = allowLoopback;
    this.children = new Set(); this.clients = []; this.data = {};
  }
  port() {
    const child = spawn(HOST, [origin, '--parent-window=0'], { env: this.env, stdio: ['pipe', 'pipe', 'ignore'] });
    this.children.add(child); this.latest = child;
    const message = [], disconnect = []; let buffer = Buffer.alloc(0), closed = false;
    const close = () => { if (!closed) { closed = true; for (const f of disconnect) f(); } };
    child.on('exit', close); child.on('error', close); child.stdin.on('error', close);
    child.stdout.on('data', chunk => {
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= 4) {
        const n = buffer.readUInt32LE(0);
        if (n > 1024 * 1024) { child.kill(); close(); return; }
        if (buffer.length < n + 4) break;
        let m; try { m = JSON.parse(buffer.subarray(4, n + 4)); } catch { child.kill(); close(); return; }
        buffer = buffer.subarray(n + 4); for (const f of message) f(m);
      }
    });
    return {
      onMessage: { addListener: f => message.push(f) }, onDisconnect: { addListener: f => disconnect.push(f) },
      postMessage(m) { if (closed) throw Error('closed'); const b = Buffer.from(JSON.stringify(m)), h = Buffer.alloc(4); h.writeUInt32LE(b.length); child.stdin.write(Buffer.concat([h, b])); },
      disconnect() { child.stdin.end(); child.kill(); close(); },
    };
  }
  async connect() {
    this.client?.close();
    const data = this.data;
    this.client = new BridgeClient({ connectNative: () => this.port(), storage: { get: async k => data[k], set: async (k, v) => { data[k] = v; } }, origin });
    this.clients.push(this.client); await this.client.connect();
    const e = await this.client.request({ type: 'health', payload: {} }, { requestId: 'probe_health' });
    if (this.allowLoopback && e.body.payload.engine !== 'loopback') throw Error('real transfer engine forbidden');
    return e.session_id;
  }
  killCore() {
    let pid;
    try { pid = readFileSync(join(this.home, 'velqra-app.pid'), 'utf8').trim(); }
    catch (error) { if (error.code === 'ENOENT') return; throw error; }
    stopPid(pid);
  }
  async close() {
    for (const c of this.clients) c.close();
    const errors = await cleanupOwned({
      stop: async () => {
        for (const c of this.children) await stopChild(c);
        this.killCore();
      },
      remove: () => rmSync(this.home, { recursive: true, force: true }),
    });
    reportCleanup(errors); return errors;
  }
}
