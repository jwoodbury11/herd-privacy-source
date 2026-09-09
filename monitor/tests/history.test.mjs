import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import test from 'node:test';
import {canonicalJson, verifyReleaseHistory} from '../src/core.mjs';
import {assertWitnessHistory} from '../src/worker.mjs';
import {makeReleaseFixture} from '../../release/tests/fixture.mjs';
import {signCanonicalArtifact} from '../../release/lib/signature.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const type = 'application/vnd.herd.release-manifest.v1+json';
function chain({count=4, badSignatureAt=-1, mutate=()=>{}}={}) {
  const fixture=makeReleaseFixture({releaseStage:'candidate'});
  const records=new Map();const manifests=[];let previous=null;
  for(let i=0;i<count;i++) {
    const m=structuredClone(fixture.manifest);
    m.releaseId=`history-${i}`;m.sourceDateEpoch+=i*86400;
    m.createdAt=new Date(m.sourceDateEpoch*1000).toISOString();
    m.previousRelease=previous?{releaseId:previous.manifest.releaseId,manifestSha256:previous.hash}:null;
    m.evidence.transitions=[];
    if(previous) {
      const c={schemaVersion:1,previousManifest:{releaseId:previous.manifest.releaseId,sha256:previous.hash,url:previous.url,signatureUrl:previous.signatureUrl,signatureSha256:previous.signatureHash}};
      const bytes=Buffer.from(canonicalJson(c));const url=`https://evidence.example/history/${i}/continuity`;
      records.set(url,bytes);m.evidence.transitions.push({name:'release-continuity.json',mediaType:'application/vnd.herd.release-continuity.v1+json',size:bytes.length,sha256:sha(bytes),url});
    }
    mutate(m,i);
    const bytes=Buffer.from(canonicalJson(m));
    const key=fixture.keys.releaseSigning;
    const signature=signCanonicalArtifact({bytes,privateKey:key.privatePem,publicKey:key.publicPem,keyId:key.descriptor.keyId,signedAt:m.createdAt,artifactType:type});
    if(i===badSignatureAt) { const bytes=Buffer.from(signature.signature,"base64url");bytes[0]^=1;signature.signature=bytes.toString("base64url"); }
    const sigBytes=Buffer.from(canonicalJson(signature));
    const url=`https://evidence.example/history/${i}/manifest`;const signatureUrl=url+'.sig';
    records.set(url,bytes);records.set(signatureUrl,sigBytes);
    previous={manifest:m,hash:sha(bytes),url,signatureUrl,signatureHash:sha(sigBytes)};manifests.push(previous);
  }
  const last=manifests.at(-1);const first=manifests[0];
  const prior={releaseId:first.manifest.releaseId,manifestSha256:first.hash,releaseCreatedAt:first.manifest.createdAt};
  const fetchImpl=async url=>records.has(String(url))?new Response(records.get(String(url))):new Response('missing',{status:404});
  const run=(w=prior)=>verifyReleaseHistory(last.manifest,last.hash,w,fixture.target,fetchImpl);
  return {records,manifests,last,prior,run};
}

test('missed releases require a complete signed chain anchored at the durable witness',async()=>{
  const c=chain();const history=await c.run();assert.deepEqual(history.map(x=>x.releaseId),['history-0','history-1','history-2']);
  const prior={...c.prior,evaluatorKeyEpoch:history[0].evaluatorKeyEpoch};
  const result={releaseId:c.last.manifest.releaseId,previousRelease:c.last.manifest.previousRelease,manifestSha256:c.last.hash,releaseCreatedAt:c.last.manifest.createdAt,evaluatorKeyEpoch:history[0].evaluatorKeyEpoch,releaseHistory:history};
  assert.doesNotThrow(()=>assertWitnessHistory(prior,result));
  const changed=structuredClone(result);changed.releaseHistory[1].evaluatorKeyEpoch.sha256='ab'.repeat(32);
  assert.throws(()=>assertWitnessHistory(prior,changed),/existing evaluator epoch changed/);
  changed.releaseHistory.shift();assert.throws(()=>assertWitnessHistory(prior,changed),/does not start/);
  const rewound=structuredClone(result);rewound.releaseHistory[1].releaseCreatedAt=history[0].releaseCreatedAt;
  assert.throws(()=>assertWitnessHistory(prior,rewound),/timestamp/);
});

test('current and direct successor manifests do not fetch historical evidence',async()=>{
  const c=chain();assert.deepEqual(await c.run({...c.prior,manifestSha256:c.last.hash}),[]);
  const p=c.manifests.at(-2);assert.deepEqual(await c.run({releaseId:p.manifest.releaseId,manifestSha256:p.hash}),[]);
});

test('unavailable, tampered, and incorrectly signed historical evidence fails closed',async()=>{
  const missing=chain();missing.records.delete(missing.manifests[1].url);await assert.rejects(missing.run(),/404/);
  const changed=chain();changed.records.set(changed.manifests[1].url,Buffer.from('{}'));await assert.rejects(changed.run(),/digest mismatch/);
  await assert.rejects(chain({badSignatureAt:1}).run(),/signature/i);
});

test('history rejects an unreachable or changed witness and unapproved evidence origins',async()=>{
  const c=chain();await assert.rejects(c.run({...c.prior,manifestSha256:'ff'.repeat(32)}),/does not reach/);
  await assert.rejects(c.run({...c.prior,releaseCreatedAt:'2026-08-01T00:00:00.000Z'}),/anchor differs/);
  c.last.manifest.evidence.transitions[0].url='https://attacker.example/continuity';await assert.rejects(c.run(),/unapproved evidence origin/);
});

test('history rejects signed timestamp reversals and limits recovery depth',async()=>{
  await assert.rejects(chain({mutate:(m,i)=>{if(i===1){m.sourceDateEpoch-=172800;m.createdAt=new Date(m.sourceDateEpoch*1000).toISOString();}}}).run(),/timestamp/);
  await assert.rejects(chain({count:18}).run(),/16-manifest/);
});
