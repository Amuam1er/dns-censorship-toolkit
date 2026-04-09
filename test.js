/**
 * Validation Test Suite
 * Tests all 4 required cases from the spec
 * Run: node test.js
 */

const { classify, getRecommendation, isPrivateIP } = require('./detector');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.log(`  ✗ ${name}`);
    console.log(`    → ${err.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

console.log('\n=== DNS Censorship Toolkit — Validation Suite ===\n');

console.log('Case 1 — Normal domain (all resolvers match)');
test('status = accessible', () => {
  const r = classify('93.184.216.34', '93.184.216.34', '93.184.216.34');
  assert(r.status === 'accessible', `Expected accessible, got ${r.status}`);
});
test('method = none', () => {
  const r = classify('93.184.216.34', '93.184.216.34', '93.184.216.34');
  assert(r.method === 'none', `Expected none, got ${r.method}`);
});

console.log('\nCase 2 — Simulated IP mismatch (poisoning)');
test('status = blocked', () => {
  const r = classify('1.2.3.4', '93.184.216.34', '93.184.216.34');
  assert(r.status === 'blocked', `Expected blocked, got ${r.status}`);
});
test('method = poisoning', () => {
  const r = classify('1.2.3.4', '93.184.216.34', '93.184.216.34');
  assert(r.method === 'poisoning', `Expected poisoning, got ${r.method}`);
});

console.log('\nCase 3 — Timeout (ISP drops DNS queries)');
test('status = blocked', () => {
  const r = classify('TIMEOUT', '93.184.216.34', '93.184.216.34');
  assert(r.status === 'blocked', `Expected blocked, got ${r.status}`);
});
test('method = timeout', () => {
  const r = classify('TIMEOUT', '93.184.216.34', '93.184.216.34');
  assert(r.method === 'timeout', `Expected timeout, got ${r.method}`);
});

console.log('\nCase 4 — NXDOMAIN conflict (ISP lies about domain existence)');
test('status = blocked', () => {
  const r = classify('ENOTFOUND', '93.184.216.34', '93.184.216.34');
  assert(r.status === 'blocked', `Expected blocked, got ${r.status}`);
});
test('method = nxdomain', () => {
  const r = classify('ENOTFOUND', '93.184.216.34', '93.184.216.34');
  assert(r.method === 'nxdomain', `Expected nxdomain, got ${r.method}`);
});


console.log('\nBonus — Private IP hijacking (RFC 1918 full coverage)');
test('10.x.x.x = hijacking', () => {
  const r = classify('10.0.0.1', '93.184.216.34', '93.184.216.34');
  assert(r.method === 'hijacking', `Expected hijacking, got ${r.method}`);
});
test('192.168.x.x = hijacking', () => {
  const r = classify('192.168.1.1', '93.184.216.34', '93.184.216.34');
  assert(r.method === 'hijacking', `Expected hijacking, got ${r.method}`);
});
test('172.16.x.x = hijacking', () => {
  const r = classify('172.16.0.1', '93.184.216.34', '93.184.216.34');
  assert(r.method === 'hijacking', `Expected hijacking, got ${r.method}`);
});
test('172.31.x.x = hijacking', () => {
  const r = classify('172.31.255.1', '93.184.216.34', '93.184.216.34');
  assert(r.method === 'hijacking', `Expected hijacking, got ${r.method}`);
});
test('127.x.x.x = hijacking', () => {
  const r = classify('127.0.0.1', '93.184.216.34', '93.184.216.34');
  assert(r.method === 'hijacking', `Expected hijacking, got ${r.method}`);
});


console.log('\nRecommendations — all methods return actionable strings');
['poisoning', 'hijacking', 'nxdomain', 'timeout', 'inconclusive', 'none'].forEach(method => {
  test(`recommendation exists for: ${method}`, () => {
    const r = getRecommendation(method);
    assert(typeof r === 'string' && r.length > 10, `Empty or missing recommendation for ${method}`);
  });
});


console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
if (failed > 0) process.exit(1);
