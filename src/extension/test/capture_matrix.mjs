// SPDX-License-Identifier: GPL-3.0-only
import assert from 'node:assert/strict';
import { World, injection } from './capture_harness.mjs';
// The runner records all violations, rather than letting a first failure hide later coverage.
export async function matrices() {
  const base = await new World().run();
  const summary = { points: base.points.length, single: 0, pairs: 0, seeded: 0, faults: {}, failures: [], seeds: [], runs: [] };
  const run = async (plan, family, seed = null) => {
    summary.runs.push({ plan, family, seed });
    const w = new World(plan); let result;
    try { result = await w.run(); } catch (e) {
      summary.failures.push({ family, seed, plan, error: e.message, browser: structuredClone(w.browserItem), core: w.core,
        record: structuredClone(w.value?.records[0]), notices: structuredClone(w.notices) });
      result = { points: w.points, log: w.log };
    }
    assert.ok(w.plan.every(p => p.hit), `unfired plan ${JSON.stringify(w.plan)}`);
    for (const p of w.plan) {
      const n = summary.faults[p.kind] ??= { planned: 0, actual: 0 }; n.planned++; if (p.hit) n.actual++;
    }
    summary[family]++; return result;
  };
  const pairKinds = new Set(['restart', 'offline', 'user', 'erase', 'fail', 'lost', 'notApplied', 'session', 'danger']);
  for (const point of base.points) for (const kind of point.kinds) {
    const first = injection(point, kind);
    const r = await run([first], 'single');
    if (!pairKinds.has(kind)) continue;
    // Depth two, using the FIRST affected run's reachable suffix. For each second
    // kind, select its earliest applicable suffix point (kind-pair coverage, not
    // a claim of every boundary pair). Includes abort/reconcile/recovery writes.
    const at = r.points.findIndex(p => p.name === point.name && p.occurrence === point.occurrence);
    const picked = new Set(), selections = new Set();
    for (const p of r.points.slice(at + 1)) for (const k of p.kinds) {
      const recoveryWrite = p.name.startsWith('write.') && ['Returning', 'Returned', 'ReconcileRequired'].some(s => p.name.includes(s)) && ['fail', 'lost', 'restart'].includes(k);
      const recoveryIdentity = ['bridge.abort.after', 'bridge.reconcile.after'].includes(p.name) && ['session', 'request', 'generation', 'kind', 'task', 'fingerprint', 'state'].includes(k);
      const fallbackAPI = p.name.startsWith('browser.resume.') && ['fail', 'notApplied', 'lost', 'hang'].includes(k);
      if ((!pairKinds.has(k) && !recoveryIdentity && !fallbackAPI) || (picked.has(k) && !recoveryWrite && !recoveryIdentity && !fallbackAPI)) continue;
      const key = `${p.name}:${p.occurrence}:${k}`; if (selections.has(key)) continue;
      picked.add(k); selections.add(key); await run([first, injection(p, k)], 'pairs');
    }
  }
  const count = Number(process.env.VELQRA_CAPTURE_SEEDS ?? 200);
  const chosenSeed = process.env.VELQRA_CAPTURE_SEED;
  for (let i = 0; i < (chosenSeed === undefined ? count : 1); i++) {
    const seed = chosenSeed === undefined ? i : Number(chosenSeed); summary.seeds.push(seed);
    let x = (seed + 1) >>> 0;
    const rand = n => { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; return (x >>> 0) % n; };
    let points = base.points, plan = [], start = 0;
    // Adaptive prefix replay: select each next fault from an actually reached suffix.
    // Discovery runs are checked and counted too; unreachable planned faults are forbidden.
    for (let depth = 0; depth < 3 && start < points.length; depth++) {
      const index = start + rand(points.length - start), p = points[index];
      const k = p.kinds[rand(p.kinds.length)]; plan = [...plan, injection(p, k)];
      const r = await run(plan, 'seeded', seed); points = r.points;
      start = points.findIndex(q => q.name === p.name && q.occurrence === p.occurrence) + 1;
    }
  }
  return summary;
}

