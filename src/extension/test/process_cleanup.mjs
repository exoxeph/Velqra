// SPDX-License-Identifier: GPL-3.0-only
import { once } from 'node:events';
import { spawnSync } from 'node:child_process';
export async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  let timer;
  const closed = once(child, 'close');
  child.kill();
  try { await Promise.race([closed, new Promise((_, reject) => { timer = setTimeout(() => reject(Error('child did not stop')), 5000); })]); }
  finally { clearTimeout(timer); }
}
// Return cleanup diagnostics separately: never replace the case's assertion error.
export async function cleanupOwned({ stop, remove, delay = ms => new Promise(r => setTimeout(r, ms)) }) {
  try { await stop(); } catch { return ['owned process cleanup failed']; }
  for (let n = 0; n < 10; n++) {
    try { await remove(); return []; }
    catch (error) { if (n === 9) return [`temporary home removal failed after 10 attempts (${error.code ?? 'unknown'})`]; }
    await delay(Math.min(50 * 2 ** n, 500));
  }
  return [];
}
export function reportCleanup(errors) {
  for (const error of errors) console.error(`CLEANUP FAILURE (separate from case assertions): ${error}`);
}

export function stopPid(pid) {
  if (!/^[1-9][0-9]*$/.test(String(pid))) throw Error('invalid owned pid');
  const script = `$ownedProcess = Get-Process -Id ${pid} -ErrorAction SilentlyContinue; if ($ownedProcess) { $ownedProcess.Kill(); if (-not $ownedProcess.WaitForExit(5000)) { exit 2 } }`;
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, timeout: 10000, stdio: 'ignore' });
  if (result.status !== 0) throw Error('owned core did not stop');
}
