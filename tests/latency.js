import http from "k6/http";
import { sleep } from "k6";
import { Trend } from "k6/metrics";
import encoding from "k6/encoding";

export const options = {
  vus: 1,
  iterations: 3,
  noConnectionReuse: false,
};

const latency = {
  quad9_wire_post: new Trend("quad9_wire_post"),
  quad9_wire_get: new Trend("quad9_wire_get"),

  cloudflare_wire_post: new Trend("cloudflare_wire_post"),
  cloudflare_wire_get: new Trend("cloudflare_wire_get"),

  nextdns_wire_post: new Trend("nextdns_wire_post"),
  nextdns_wire_get: new Trend("nextdns_wire_get"),

  worker_all_wire_post: new Trend("worker_all_wire_post"),
  worker_all_wire_get: new Trend("worker_all_wire_get"),
  worker_all_json_get: new Trend("worker_all_json_get"),
  worker_all_wire_blocked_get: new Trend("worker_all_wire_blocked_get"),
  worker_all_wire_blocked_post: new Trend("worker_all_wire_blocked_post"),

  worker_cloudflare_wire_post: new Trend("worker_cloudflare_wire_post"),
  worker_cloudflare_wire_get: new Trend("worker_cloudflare_wire_get"),
  worker_cloudflare_json_get: new Trend("worker_cloudflare_json_get"),
  worker_cloudflare_wire_blocked_get: new Trend("worker_cloudflare_wire_blocked_get"),
  worker_cloudflare_wire_blocked_post: new Trend("worker_cloudflare_wire_blocked_post"),

  worker_quad9_wire_post: new Trend("worker_quad9_wire_post"),
  worker_quad9_wire_get: new Trend("worker_quad9_wire_get"),
  worker_quad9_wire_blocked_get: new Trend("worker_quad9_wire_blocked_get"),
  worker_quad9_wire_blocked_post: new Trend("worker_quad9_wire_blocked_post"),

  worker_nextdns_wire_post: new Trend("worker_nextdns_wire_post"),
  worker_nextdns_wire_get: new Trend("worker_nextdns_wire_get"),

  worker_nextdns_wire_blocked_get: new Trend("worker_nextdns_wire_blocked_get"),
  worker_nextdns_wire_blocked_post: new Trend("worker_nextdns_wire_blocked_post"),
};

const directEndpoints = {
  quad9: "https://dns.quad9.net/dns-query",
  cloudflare: "https://security.cloudflare-dns.com/dns-query",
  nextdns: `https://dns.nextdns.io/${__ENV.NEXTDNS_ID}`,
};

const base = __ENV.DOH_BASE_URL;
const workerEndpoints = {
  worker_all: `${base}/doh-test`,
  worker_cloudflare: `${base}/doh-test-cloudflare`,
  worker_quad9: `${base}/doh-test-quad9`,
  worker_nextdns: `${base}/doh-test-nextdns`,
};

function buildWireQuery(name) {
  const labels = name.split(".");
  const parts = [];

  for (const label of labels) {
    parts.push(label.length);
    for (let i = 0; i < label.length; i++) {
      parts.push(label.charCodeAt(i));
    }
  }

  parts.push(0);

  return new Uint8Array([
    0x12, 0x34, // transaction ID
    0x01, 0x00, // flags: RD set
    0x00, 0x01, // QDCOUNT = 1
    0x00, 0x00, // ANCOUNT = 0
    0x00, 0x00, // NSCOUNT = 0
    0x00, 0x00, // ARCOUNT = 0
    ...parts,
    0x00, 0x01, // QTYPE  = A
    0x00, 0x01, // QCLASS = IN
  ]);
}

function toBase64url(bytes) {
  return encoding.b64encode(bytes, "rawurl");
}

function shuffle(array) {
  return array.sort(() => Math.random() - 0.5);
}

function randomDomain() {
  return `latency-${Math.random().toString(36).slice(2)}.doh-test.trevorlauder.dev`;
}

function testWorker(prefix, url, wireBytes, { jsonGet = true } = {}) {
  const warmupBytes = buildWireQuery("warmup.invalid");
  http.get(`${url}?dns=${toBase64url(warmupBytes)}`, {
    headers: { "Accept": "application/dns-message" },
  });

  const postRes = http.post(url, wireBytes.buffer, {
    headers: {
      "Content-Type": "application/dns-message",
      "Accept": "application/dns-message",
    },
  });

  latency[`${prefix}_wire_post`].add(postRes.timings.duration);

  const getWireBytes = buildWireQuery(randomDomain());

  const getWireRes = http.get(`${url}?dns=${toBase64url(getWireBytes)}`, {
    headers: { "Accept": "application/dns-message" },
  });

  latency[`${prefix}_wire_get`].add(getWireRes.timings.duration);

  const blockedBytes = buildWireQuery("www.00.business");

  const blockedGetRes = http.get(`${url}?dns=${toBase64url(blockedBytes)}`, {
    headers: { "Accept": "application/dns-message" },
  });

  latency[`${prefix}_wire_blocked_get`].add(blockedGetRes.timings.duration);

  const blockedPostRes = http.post(url, blockedBytes.buffer, {
    headers: {
      "Content-Type": "application/dns-message",
      "Accept": "application/dns-message",
    },
  });

  latency[`${prefix}_wire_blocked_post`].add(blockedPostRes.timings.duration);

  if (jsonGet) {
    const getJsonRes = http.get(`${url}?name=${randomDomain()}&type=A`, {
      headers: { "Accept": "application/dns-json" },
    });

    latency[`${prefix}_json_get`].add(getJsonRes.timings.duration);
  }
}

export default function () {
  const wireBytes = buildWireQuery(randomDomain());

  const directEntries = shuffle(Object.entries(directEndpoints));

  for (const [name, url] of directEntries) {
    const postRes = http.post(url, wireBytes.buffer, {
      headers: {
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
      },
    });

    latency[`${name}_wire_post`].add(postRes.timings.duration);

    const getBytes = buildWireQuery(randomDomain());

    const getRes = http.get(`${url}?dns=${toBase64url(getBytes)}`, {
      headers: { "Accept": "application/dns-message" },
    });

    latency[`${name}_wire_get`].add(getRes.timings.duration);
  }

  const noJsonGet = new Set(["worker_quad9", "worker_nextdns"]);
  const workerEntries = shuffle(Object.entries(workerEndpoints));

  for (const [prefix, url] of workerEntries) {
    testWorker(prefix, url, wireBytes, { jsonGet: !noJsonGet.has(prefix) });
  }

  sleep(2);
}
