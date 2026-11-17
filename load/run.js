// k6 load run of a Fetch mix at a constant arrival rate (open model): through
// the gateway (gateway), straight to each API with the caller's token
// (local, for built-in protection), or straight to each API with the
// identity headers a gateway would add (direct, nothing checked). Tokens come
// from the file demo tokens wrote before the run, so sign-in is never timed.
// Requests are spread evenly: the n-th request of a scenario takes the n-th
// class of a cycle that interleaves the classes by share, and the n-th
// customer of a seeded shuffle of the accounts, so no account's rate depends
// on chance. Start the Fetch host with demo up -role fetch -measure (with
// -local or -standalone for those modes).
//
// Environment: MODE gateway|local|direct, MIX (mix file, default mix.json),
// RATE (requests/s), WARMUP and DURATION (k6 durations), or STEPS
// (comma-separated rates of a capacity ramp after the warm-up at the first
// one) with STEP (each step's duration); GATEWAY (https origin), FETCH_IP,
// CERT and KEY (the gateway's client certificate), TOKENS (demo tokens file),
// CUSTOMERS (1 to 999), SEED.
import http from 'k6/http';
import exec from 'k6/execution';
import { Counter, Rate } from 'k6/metrics';

const env = (name, fallback) => __ENV[name] || fallback;
const mix = JSON.parse(open(env('MIX', './mix.json')));
const mode = env('MODE', 'gateway');
const rate = Number(env('RATE', '500'));
const customers = Number(env('CUSTOMERS', '999'));
const fetchIP = env('FETCH_IP', '127.0.0.3');
const gateway = env('GATEWAY', 'https://localhost:9480');
const seed = Number(env('SEED', '20261111'));
const tokens = mode === 'direct' ? null : JSON.parse(open(env('TOKENS', './tokens.json')));
const ports = { inventory: 9501, orders: 9502 };
const expected = new Rate('expected');
const answers = new Counter('answers');
// Statuses counted one by one; anything else is counted as other.
const statuses = ['0', '200', '201', '400', '401', '403', '404', '409', '429', '500', '502', '503', '504'];

if (!['gateway', 'local', 'direct'].includes(mode)) {
  throw new Error(`MODE ${mode}: gateway, local or direct`);
}

// One scenario per measured window: measured, or step-<rate> in a ramp.
const steps = env('STEPS', '').split(',').filter(Boolean).map(Number);
const scenario = (target, duration, start) => ({
  executor: 'constant-arrival-rate', rate: target, timeUnit: '1s', duration, startTime: start,
  preAllocatedVUs: Math.max(50, target / 5), maxVUs: Math.max(200, target), exec: 'request',
});
const warmup = env('WARMUP', '30s');
const scenarios = {};
if (steps.length > 0) {
  const seconds = (text) => Number(text.replace(/s$/, ''));
  scenarios.warmup = scenario(steps[0], warmup, '0s');
  steps.forEach((step, i) => {
    scenarios[`step-${step}`] = scenario(step, env('STEP', '40s'), `${seconds(warmup) + i * seconds(env('STEP', '40s'))}s`);
  });
} else {
  scenarios.warmup = scenario(rate, warmup, '0s');
  scenarios.measured = scenario(rate, env('DURATION', '120s'), warmup);
}

// Every series the summary must show is named by a threshold that always passes.
const thresholds = {};
for (const name of Object.keys(scenarios).filter((n) => n !== 'warmup')) {
  const own = `scenario:${name}`;
  for (const kind of mix.kinds) {
    thresholds[`http_req_duration{class:${kind.class},${own}}`] = ['max>=0'];
    thresholds[`expected{class:${kind.class},${own}}`] = ['rate>=0'];
  }
  for (const status of [...statuses, 'other']) {
    thresholds[`answers{status:${status},${own}}`] = ['count>=0'];
  }
  thresholds[`http_req_duration{${own}}`] = ['max>=0'];
  thresholds[`http_req_tls_handshaking{${own}}`] = ['max>=0'];
  thresholds[`http_req_connecting{${own}}`] = ['max>=0'];
  thresholds[`http_reqs{proto:HTTP/1.1,${own}}`] = ['count>=0'];
  thresholds[`http_reqs{proto:HTTP/2.0,${own}}`] = ['count>=0'];
  thresholds[`expected{${own}}`] = ['rate>=0'];
  thresholds[`dropped_iterations{${own}}`] = ['count>=0'];
}

export const options = {
  scenarios,
  thresholds,
  insecureSkipTLSVerify: true,
  tlsAuth: [{ domains: [fetchIP], cert: open(env('CERT', '/certs/client.pem')), key: open(env('KEY', '/certs/client-key.pem')) }],
  discardResponseBodies: true,
  summaryTrendStats: ['med', 'p(95)', 'p(99)', 'avg', 'min', 'max', 'count'],
};

// mulberry32 from seed: the same numbers in every VU and every run.
function stream(start) {
  let state = start >>> 0 || 1;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// The customers in a seeded shuffle (Fisher-Yates).
const order = Array.from({ length: customers }, (_, i) => i);
const shuffle = stream(seed);
for (let i = order.length - 1; i > 0; i--) {
  const j = Math.floor(shuffle() * (i + 1));
  [order[i], order[j]] = [order[j], order[i]];
}

// The class cycle: smooth weighted round-robin over the shares (in quarters),
// so each class recurs at even intervals instead of in runs.
const weights = mix.kinds.map((kind) => Math.round(kind.share * 4));
const cycle = [];
const credit = weights.map(() => 0);
const total = weights.reduce((sum, w) => sum + w, 0);
for (let n = 0; n < total; n++) {
  let best = 0;
  weights.forEach((w, i) => {
    credit[i] += w;
    if (credit[i] > credit[best]) {
      best = i;
    }
  });
  credit[best] -= total;
  cycle.push(mix.kinds[best]);
}

const pad = (n) => String(n).padStart(4, '0');
const merchantIDs = Object.keys(mix.merchant_items || {});
function caller(as, n) {
  const customer = order[n % customers];
  const merchant = Math.floor(n / cycle.length) % Math.max(1, merchantIDs.length);
  if (mode === 'direct') {
    switch (as) {
      case 'customer': return { id: `load-${pad(customer + 1)}`, roles: 'CUSTOMER' };
      case 'merchant': return { id: `merchant-00${merchantIDs[merchant].slice(-1)}`, roles: 'MERCHANT', merchant: merchantIDs[merchant] };
      case 'limited': return { id: 'load-1000', roles: 'CUSTOMER' };
      default: return null;
    }
  }
  switch (as) {
    case 'customer': return tokens.customers[customer];
    case 'merchant': return tokens.merchants.find((m) => m.merchant === merchantIDs[merchant]);
    case 'limited': return tokens.limited;
    default: return null;
  }
}

function origin(path) {
  if (mode === 'gateway') {
    return gateway;
  }
  return `https://${fetchIP}:${ports[path.split('/')[1]]}`;
}

const random = stream(seed ^ 0x5bd1e995);
export function request() {
  const n = exec.scenario.iterationInTest;
  const kind = cycle[n % cycle.length];
  const who = caller(kind.as, n);
  let path = kind.path;
  if (kind.as === 'merchant') {
    path = path.replace('{item}', mix.merchant_items[who.merchant]);
  }
  const headers = {};
  if (who && mode === 'direct') {
    headers['X-Gateway-Subject'] = who.id;
    headers['X-Gateway-Roles'] = who.roles;
  } else if (who) {
    headers.Authorization = `Bearer ${who.token}`;
  }
  let body = null;
  if (kind.body) {
    body = JSON.stringify(mix.bodies[kind.body]);
    headers['Content-Type'] = 'application/json';
    // Fetch admits keys of 16 to 64 letters, digits, underscores or hyphens.
    headers['Idempotency-Key'] = `load-${String(__VU).padStart(5, '0')}-${String(__ITER).padStart(9, '0')}-${Math.floor(random() * 1e9)}`;
  }
  const tags = { class: kind.class, expect: String(kind.expect) };
  const response = http.request(kind.method, origin(path) + path, body, { headers, tags });
  expected.add(response.status === kind.expect, tags);
  const status = String(response.status);
  answers.add(1, { ...tags, status: statuses.includes(status) ? status : 'other' });
}
