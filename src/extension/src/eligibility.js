// SPDX-License-Identifier: GPL-3.0-only
// @ts-check
// Pure policy. Precedence: shape, completed/interrupted, extension, browser block,
// mode, bypass, readiness, scheme, method, correlation, credentials, replay risk,
// site exclusion/inclusion, suffix, minimum. No request probes or filename changes.
// Context is trusted worker observation, NEVER page-supplied policy evidence.

const object = (/** @type {any} */ x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const keep = (/** @type {string} */ reason) => ({ action: 'keep', reason });
/** Exact host or a proper subdomain; wildcard never matches the bare host. */
function matches(/** @type {string} */ host, /** @type {any} */ pattern) {
  if (typeof pattern !== 'string') return false;
  // A DNS absolute-name dot must not bypass an exclusion.
  host = host.replace(/\.$/, '');
  const p = pattern.toLowerCase().replace(/\.$/, '');
  return p.startsWith('*.') ? host.endsWith(`.${p.slice(2)}`) : host === p;
}

/**
 * settings follows SettingsSnapshot (snake_case); min_bytes is an optional local policy.
 * Missing observation/credential evidence fails closed. Does not infer replay safety from GET.
 * @param {any} item @param {any} settings @param {any} context
 * @returns {{action: string, reason: string}}
 */
export function decide(item, settings, context) {
  // Catch malformed JS as well as JSON: callers cannot turn a getter exception into capture.
  try {
    if (!object(item) || !object(settings) || !object(context)) return keep('invalid');
    if (item.state === 'complete') return keep('complete');
    if (item.state === 'interrupted') return keep('interrupted');
    if (item.byExtensionId) return keep('extension');
    if (item.danger !== 'safe' || item.policyBlocked || item.error) return keep('blocked');
    if (!['on', 'per_site'].includes(settings.mode)) return keep('disabled');
    if (context.bypass === true) return keep('bypass');
    if (context.appReady !== true) return keep('unavailable');
    if (typeof item.url !== 'string' || item.url.length > 8192) return keep('scheme');
    const url = new URL(item.url);
    if (!['http:', 'https:'].includes(url.protocol)) return keep('scheme');
    if (context.method !== 'GET') return keep('method');
    if (context.correlated !== true || context.ambiguous === true) return keep('correlation');
    if (context.credentialsSeen !== false || context.cookieSeen || context.authorizationSeen || context.loginRedirect || url.username || url.password) return keep('credentials');
    if (context.suspectedOneUse === true) return keep('replay_risk');
    if (!Array.isArray(settings.excluded_sites) || !Array.isArray(settings.allowed_sites)) return keep('site');
    if (settings.excluded_sites.some(p => matches(url.hostname, p))) return keep('site');
    if (settings.mode === 'per_site' && !settings.allowed_sites.some(p => matches(url.hostname, p))) return keep('site');
    const name = typeof item.filename === 'string' ? item.filename.split(/[\\/]/).pop() ?? '' : '';
    if (typeof item.filename !== 'string' || item.filename.length > 32768 || name.length > 255) return keep('invalid');
    const suffix = name.includes('.') ? name.slice(name.lastIndexOf('.') + 1).toLowerCase() : '';
    if (!suffix || !Array.isArray(settings.extensions) || !settings.extensions.some(x => typeof x === 'string' && x.toLowerCase() === suffix)) return keep('type');
    const min = settings.min_bytes ?? 0;
    if (!Number.isSafeInteger(min) || min < 0 || (min > 0 && (!Number.isSafeInteger(item.totalBytes) || item.totalBytes < min))) return keep('minimum');
    if (item.state !== 'in_progress' || !Number.isSafeInteger(item.id) || item.id < 0) return keep('invalid');
    return { action: 'capture', reason: 'eligible' };
  } catch {
    return keep('invalid');
  }
}
