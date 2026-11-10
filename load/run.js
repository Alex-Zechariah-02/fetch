// k6 load run of the Fetch mix (mix.json) at a constant arrival rate, through
// the gateway or straight to the services with the identity headers the
// gateway would add. Tokens come from Fetch Accounts before timing starts, on
// its own address with the gateway's client certificate, so sign-in limits
// never shape the run. Start the Fetch host with demo up -role fetch -measure.
//
// Environment: MODE gateway|direct, RATE (requests/s), WARMUP and DURATION
// (k6 durations), GATEWAY (https origin), FETCH_IP, CERT and KEY (the
// gateway's client certificate), CUSTOMERS (1 to 999), SEED.
import http from 'k6/http';
import { Rate } from 'k6/metrics';

const mix = JSON.parse(open('./mix.json'));
const env = (name, fallback) => __ENV[name] || fallback;
const mode = env('MODE', 'gateway');
const rate = Number(env('RATE', '500'));
const customers = Number(env('CUSTOMERS', '999'));
const fetchIP = env('FETCH_IP', '127.0.0.3');
const gateway = env('GATEWAY', 'https://localhost:9480');
const seed = Number(env('SEED', '20261111'));
const ports = { inventory: 9501, orders: 9502, accounts: 9505 };
const password = 'FetchDemo2026!';
const expected = new Rate('expected');

// Each class gets its own latency series in the summary.
const thresholds = {};
for (const kind of mix.kinds) {
  thresholds[`http_req_duration{class:${kind.class},scenario:measured}`] = ['max>=0'];
  thresholds[`expected{class:${kind.class},scenario:measured}`] = ['rate>=0'];
  thresholds[`expected{class:${kind.class},expect:${kind.expect},scenario:measured}`] = ['rate>=0'];
}
thresholds['http_req_duration{scenario:measured}'] = ['max>=0'];
thresholds['expected{scenario:measured}'] = ['rate>=0'];

const scenario = (duration, start) => ({
  executor: 'constant-arrival-rate', rate, timeUnit: '1s', duration, startTime: start,
  preAllocatedVUs: Math.max(50, rate / 5), maxVUs: Math.max(200, rate), exec: 'request',
});
export const options = {
  scenarios: { warmup: scenario(env('WARMUP', '60s'), '0s'), measured: scenario(env('DURATION', '300s'), env('WARMUP', '60s')) },
  thresholds,
  insecureSkipTLSVerify: true,
  tlsAuth: [{ domains: [fetchIP], cert: open(env('CERT', '/certs/client.pem')), key: open(env('KEY', '/certs/client-key.pem')) }],
  setupTimeout: '900s',
  discardResponseBodies: true,
  summaryTrendStats: ['med', 'p(95)', 'p(99)', 'avg', 'min', 'max'],
};

function service(path) {
  return `https://${fetchIP}:${ports[path.split('/')[1]]}`;
}

// signIn returns the account's token and roles from Fetch Accounts directly.
function signIn(email) {
  const response = http.post(`${service('/accounts')}/accounts/login`, JSON.stringify({ email, password }), {
    headers: { 'Content-Type': 'application/json' }, responseType: 'text',
  });
  if (response.status !== 200) {
    throw new Error(`sign-in ${email}: ${response.status}`);
  }
  const reply = response.json();
  return { id: reply.user.id, token: reply.token, roles: reply.user.roles.join(','), merchant: reply.user.merchant };
}

// The merchants whose stock is read: MER-005 is merchant5@fetch.test.
const merchantNumbers = Object.keys(mix.merchant_items).map((id) => Number(id.slice(-3)));

export function setup() {
  const pad = (n) => String(n).padStart(4, '0');
  const ids = (prefix, count) => Array.from({ length: count }, (_, i) => prefix(i + 1));
  if (mode === 'direct') {
    const customer = (id) => ({ id, roles: 'CUSTOMER' });
    return {
      customers: ids((n) => customer(`load-${pad(n)}`), customers),
      merchants: merchantNumbers.map((n) => ({ id: `merchant-00${n}`, roles: 'MERCHANT', merchant: `MER-00${n}` })),
      limited: customer('load-1000'),
    };
  }
  return {
    customers: ids((n) => signIn(`load${pad(n)}@fetch.test`), customers),
    merchants: merchantNumbers.map((n) => signIn(`merchant${n}@fetch.test`)),
    limited: signIn('load1000@fetch.test'),
  };
}

// random is a per-VU mulberry32 stream, so a run's request sequence repeats.
let state = 0;
function random() {
  if (state === 0) {
    state = (seed ^ (__VU * 0x9e3779b9)) >>> 0 || 1;
  }
  state = (state + 0x6d2b79f5) >>> 0;
  let t = state;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const total = mix.kinds.reduce((sum, kind) => sum + kind.share, 0);
function pick() {
  let point = random() * total;
  for (const kind of mix.kinds) {
    point -= kind.share;
    if (point < 0) {
      return kind;
    }
  }
  return mix.kinds[mix.kinds.length - 1];
}

function caller(data, as) {
  switch (as) {
    case 'customer': return data.customers[Math.floor(random() * data.customers.length)];
    case 'merchant': return data.merchants[Math.floor(random() * data.merchants.length)];
    case 'limited': return data.limited;
    default: return null;
  }
}

export function request(data) {
  const kind = pick();
  const who = caller(data, kind.as);
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
  const origin = mode === 'direct' ? service(path) : gateway;
  const tags = { class: kind.class, expect: String(kind.expect) };
  const response = http.request(kind.method, origin + path, body, { headers, tags });
  expected.add(response.status === kind.expect, tags);
}
