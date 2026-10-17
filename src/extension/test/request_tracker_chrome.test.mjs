// SPDX-License-Identifier: GPL-3.0-only
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { RequestTracker } from '../src/request_tracker.js';
const fixtures=JSON.parse(readFileSync(new URL('./fixtures/chrome144-capture.json',import.meta.url)));
const extensionFixture=JSON.parse(readFileSync(new URL('./fixtures/chrome144-extension-download.json',import.meta.url)));
test('real Chrome extension download has no usable request observation: manual intent cannot invent evidence',()=>{
  assert.equal(extensionFixture.usableHeadersObserved,false);
  const t=replay(extensionFixture);
  assert.equal(t.match(extensionFixture.item,{manualKey:'live-intent'}),null);
  assert.equal(t.facts(extensionFixture.item).reason,'unseen_request');
});
for(const fault of ['none','wrong-key','no-key','no-status','bad-status','missing-headers','credentials','consumed'])test('model manual no-tab tracker correlation: '+fault,()=>{
  const t=new RequestTracker(),wall=Date.now(),url='https://redacted.test/manual.zip';
  const d={requestId:'manual',url,method:'GET',type:'other',tabId:-1,frameId:-1,timeStamp:wall};
  t.before(d,{manualKey:'live'});
  if(fault!=='missing-headers')t.headers({...d,requestHeaders:fault==='credentials'?[{name:'Proxy-Authorization',value:'PRIVATE'}]:[]});
  t.response({...d,statusCode:fault==='no-status'?undefined:fault==='bad-status'?403:200});
  const i={id:99,url,startTime:new Date(wall+1).toISOString()},opts={manualKey:fault==='wrong-key'?'other':fault==='no-key'?undefined:'live'};
  if(fault==='consumed'){assert.equal(t.match(i,opts)?.correlated,true);i.id++;}
  const c=t.match(i,opts);
  assert.equal(c?.correlated===true,fault==='none'||fault==='credentials');
  if(fault==='credentials')assert.equal(c.credentialsSeen,true);
});
function replay(f, change = () => {}) {
  const tracker=new RequestTracker();
  for (const raw of f.events) {
    const {event,data}=structuredClone(raw);change(event,data);
    if(data.skip)continue;
    if (event==='onBeforeRequest')tracker.before(data);
    if (event==='onBeforeSendHeaders')tracker.headers({...data,requestHeaders:data.credentialHeader?[{name:'Cookie',value:'PRIVATE'}]:[]});
    if (event==='onBeforeRedirect')tracker.redirect(data);
    if (event==='onHeadersReceived')tracker.response?.(data);
  }
  return tracker;
}
for (const f of fixtures) test('real Chrome 144 response-to-download timing: '+f.label,()=>{
  const t=replay(f), c=t.match(f.item);assert.equal(c?.correlated,true);assert.equal(c.credentialsSeen,false);
});
test('a slow response is tied to final headers rather than a widened request-start window',()=>{
  const f=structuredClone(fixtures[0]);
  for(const e of f.events)if(e.event!=='onHeadersReceived')e.data.timeStamp-=5000;
  assert.equal(replay(f).match(f.item)?.correlated,true);
});
for(const [gap,accepted] of [[0,true],[50,true],[51,false],[-1,false]])test('response-to-download gap boundary '+gap,()=>{
  const f=structuredClone(fixtures[0]),start=Date.parse(f.item.startTime);
  for(const e of f.events)if(e.event==='onHeadersReceived')e.data.timeStamp=start-gap;else e.data.timeStamp-=1000;
  assert.equal(replay(f).match(f.item)?.correlated===true,accepted);
});
for (const mode of ['missing_response','stale_response','future_response','cache','other','no_tab','credentials','duplicate','consumed','wrong_url']) test('response correlation fails closed: '+mode,()=>{
  const f=fixtures[0];
  const t=replay(f,(event,d)=>{
    if(event==='onHeadersReceived') {
      if(mode==='missing_response')d.skip=true;
      if(mode==='stale_response')d.timeStamp-=100;
      if(mode==='future_response')d.timeStamp+=100;
      if(mode==='cache')d.fromCache=true;
    }
    if(mode==='other')d.type='other'; if(mode==='no_tab')d.tabId=-1;
    if(mode==='credentials'&&event==='onBeforeSendHeaders')d.credentialHeader=true;
  });
  if(mode==='duplicate')for(const e of f.events){const d={...e.data,requestId:'second'};if(e.event==='onBeforeRequest')t.before(d);if(e.event==='onBeforeSendHeaders')t.headers({...d,requestHeaders:[]});if(e.event==='onHeadersReceived')t.response?.(d);}
  let item={...f.item};if(mode==='consumed'){assert.equal(t.match(item)?.correlated,true);item.id++;}if(mode==='wrong_url')item.url+='other';
  const c=t.match(item);assert.ok(!c||!c.correlated||c.credentialsSeen!==false);
});
