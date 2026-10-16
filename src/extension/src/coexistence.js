// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
import { BoundedSteps } from './bounded.js';

/** Options-page controller. Call check ONLY directly from the local button's
 * click handler. No runtime/page message can invoke this permission prompt.
 * Names are advisory hints, never a reason to disable or modify an extension.
 */
export class Coexistence {
  constructor({ permissions, management, timeoutMs = 1000 }) { this.permissions = permissions; this.management = management; this.steps = new BoundedSteps(1, timeoutMs); }
  async check(userGesture = false) {
    if (userGesture !== true) return 'Use the Check button to grant optional extension visibility.';
    try {
      // Call synchronously in the click stack, before the first await.
      const granted = await this.steps.run(() => this.permissions.request({ permissions: ['management'] }));
      if (!granted) return 'Permission declined. Other extensions were not inspected.';
      const extensions = await this.steps.run(() => this.management.getAll());
      if (!Array.isArray(extensions) || extensions.length > 256) return 'Extension list unavailable.';
      const known = new Set();
      for (const e of extensions) {
        if (!e.enabled || typeof e.name !== 'string') continue;
        for (const name of ['Internet Download Manager', 'Free Download Manager', 'Xtreme Download Manager', 'AB Download Manager', 'Neat Download Manager']) {
          if (e.name.toLowerCase().includes(name.toLowerCase()) || (name === 'Internet Download Manager' && /IDM Integration/i.test(e.name))) known.add(name);
        }
      }
      return known.size ? `Possible capture conflict: ${[...known].join(', ')}. Choose which manager handles downloads; Velqra changes nothing.` : 'No recognized competing manager found. Unrecognized managers may still be installed.';
    } catch { return 'Extension check unavailable; no extension was changed.'; }
  }
}
