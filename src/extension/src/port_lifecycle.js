// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
/** One hint per native port; only connect() can prove authentication. Delayed
 * continuations from a replaced port must not refresh or close the new session.
 */
export function watchPort(port, { isCurrent, connect, onReady, onDrop }) {
  let observed = false;
  // No inbound payload is passed to this function or retained across its wait.
  function arm() {
    let result;
    try { result = connect(); } catch { if (isCurrent()) onDrop(); return; }
    Promise.resolve(result).then(() => { if (isCurrent()) onReady(); }, () => { if (isCurrent()) onDrop(); });
  }
  port.onDisconnect.addListener(() => { if (isCurrent()) onDrop(); });
  port.onMessage.addListener(m => {
    if (observed || m?.t !== 'ready' || !isCurrent()) return;
    observed = true;
    arm();
  });
}
