// SPDX-License-Identifier: GPL-3.0-only
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CaptureDiagnostics, DIAGNOSTICS_KEY, reasonCode } from '../src/capture_diagnostics.js';
const tick=async()=>{for(let i=0;i<8;i++)await new Promise(r=>setImmediate(r));};
test('diagnostic reason codes cannot resolve object prototype properties',()=>{
  for(const reason of ['__proto__','constructor','toString',null,{}])assert.equal(reasonCode(reason),'capture_error');
});
test('session diagnostics restore bounded sanitized history and permit only numeric facts and enums',async()=>{
  let value;
  const d=new CaptureDiagnostics({get:async()=>({[DIAGNOSTICS_KEY]:Array.from({length:100},(_,id)=>({id,at:1,event:'decision',decision:'keep',reason:'credentials',url:'PRIVATE'}))}),set:async v=>{value=v[DIAGNOSTICS_KEY];}});
  d.record({id:500,event:'evil PRIVATE',decision:'evil',reason:'PRIVATE',candidateCount:1e8,timeGapBucket:NaN,urlsCount:100,url:'PRIVATE',headers:'PRIVATE'});await tick();
  assert.equal(value.length,50);assert.equal(value.at(-1).candidateCount,4096);assert.equal(value.at(-1).urlsCount,8);
  assert.equal(value.at(-1).timeGapBucket,-1);assert.equal(value.at(-1).reason,'capture_error');assert.doesNotMatch(JSON.stringify(value),/PRIVATE|evil/);
});
test('a hung diagnostic write has one writer and a bounded pending snapshot',async()=>{
  let release, calls=0, value;
  const d=new CaptureDiagnostics({get:async()=>({}),set:async v=>{calls++;value=v[DIAGNOSTICS_KEY];if(calls===1)await new Promise(r=>release=r);}});
  d.record({id:0});await tick();for(let id=1;id<=1000;id++)d.record({id,reason:'mode_off'});await tick();assert.equal(calls,1);
  release();await tick();assert.equal(calls,2);assert.equal(value.length,50);assert.equal(value.at(-1).id,1000);
});
