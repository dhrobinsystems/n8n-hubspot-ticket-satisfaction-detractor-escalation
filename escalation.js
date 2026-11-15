'use strict';
/**
 * escalation.js — n8n-hubspot-ticket-satisfaction-detractor-escalation
 * License: MIT © 2026 dhRobin Systems · Provided as-is, see the disclaimer.
 *
 * Receives signed CSAT / NPS / NES survey webhooks, isolates detractors, re-opens and
 * escalates the related HubSpot ticket, appends an internal audit note, and alerts the
 * ticket owner / account manager / executives via Slack Block Kit and (optionally) PagerDuty.
 *
 * HOW IT RUNS
 * - In n8n: each Code node in workflow.json contains this whole file, preceded by one
 *   line such as `const SYNDICATOR_STAGE = 'plan';`. That line selects what the node does
 *   (see runStage). If you edit this file, paste it into every Code node again and keep
 *   each node's first line.
 * - In Node.js: `require('./escalation.js')` exports the pure functions. Nothing runs on require.
 *
 * SAFETY
 * - Every webhook request must carry a valid HMAC-SHA256 signature (with replay window).
 * - DRY_RUN=true (default): plans the ticket changes, note and alerts, and changes/sends nothing.
 * - SANDBOX_MODE=true (default): HubSpot must report a SANDBOX or DEVELOPER_TEST portal.
 * - Priority is never lowered; old closed tickets are not re-opened (REOPEN_MAX_AGE_DAYS).
 * - Secrets (HubSpot token, webhook secrets, Slack URLs, PagerDuty routing key) stay in $env and
 *   never enter item data. Every error passes through maskSecrets()/maskError().
 */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const SECRET_KEYS = ['HUBSPOT_ACCESS_TOKEN', 'WEBHOOK_SECRET', 'WEBHOOK_SECRET_PREVIOUS', 'SLACK_WEBHOOK_URLS', 'PAGERDUTY_ROUTING_KEY', 'ALERT_WEBHOOK_URL'];
const CONFIG_KEYS = SECRET_KEYS.concat([
  'DRY_RUN', 'SANDBOX_MODE', 'HUBSPOT_API_BASE',
  'SIGNATURE_HEADER', 'SIGNATURE_TIMESTAMP_HEADER', 'SIGNATURE_PAYLOAD_FORMAT', 'SIGNATURE_TOLERANCE_SECONDS',
  'MAX_RESPONSES_PER_REQUEST', 'DEDUPE_HOURS',
  'CSAT_SCALE_MAX', 'CSAT_DETRACTOR_THRESHOLD', 'CSAT_CRITICAL_THRESHOLD',
  'NPS_DETRACTOR_MAX', 'NPS_CRITICAL_MAX', 'NES_DETRACTOR_THRESHOLD', 'NES_CRITICAL_THRESHOLD', 'CRITICAL_KEYWORDS',
  'LOOKUP_WINDOW_DAYS', 'REOPEN_CLOSED_TICKETS', 'REOPEN_MAX_AGE_DAYS', 'REOPEN_STAGE_MAP_JSON', 'REOPEN_STAGE_LABEL_REGEX', 'CLOSED_STAGE_IDS',
  'ESCALATION_PRIORITY', 'CRITICAL_PRIORITY', 'ACCOUNT_MANAGER_PROPERTY', 'NOTE_FEEDBACK_MAX_CHARS',
  'ALERT_DESTINATIONS', 'PAGERDUTY_MIN_SEVERITY', 'SLACK_USER_MAP_JSON', 'EXEC_SLACK_MENTIONS', 'SHOW_CUSTOMER_EMAIL',
]);
const ALLOWED_ACCOUNT_TYPES = ['SANDBOX', 'DEVELOPER_TEST'];
const PRIORITIES = ['LOW', 'MEDIUM', 'HIGH', 'URGENT'];
const SURVEY_ALIASES = {
  CSAT: 'CSAT', CUSTOMER_SATISFACTION: 'CSAT', SATISFACTION: 'CSAT',
  NPS: 'NPS', NET_PROMOTER: 'NPS', NET_PROMOTER_SCORE: 'NPS',
  NES: 'NES', NET_EMOTIONAL_SCORE: 'NES', NET_EASE_SCORE: 'NES', EMOTION: 'NES',
};
const DAY = 86400000;

function parseBool(value, fallback) {
  if (value === undefined || value === null) return fallback;
  const v = String(value).trim().toLowerCase();
  if (['true', '1', 'yes', 'on'].includes(v)) return true;
  if (['false', '0', 'no', 'off'].includes(v)) return false;
  return fallback;
}

/** Placeholders such as YOUR_WEBHOOK_SECRET count as "not set". */
function cleanValue(value) {
  if (value === undefined || value === null) return '';
  const s = String(value).trim();
  return /^YOUR_[A-Z0-9_]+$/.test(s) ? '' : s;
}

function num(value, fallback) {
  const s = cleanValue(value);
  if (s === '') return fallback;
  const n = Number(s);
  return Number.isFinite(n) ? n : NaN;
}

function listOf(value, fallback) {
  const s = cleanValue(value);
  return s ? s.split(',').map((x) => x.trim()).filter(Boolean) : fallback.slice();
}

function jsonObject(raw, name, errors) {
  const s = cleanValue(raw);
  if (!s) return {};
  try {
    const o = JSON.parse(s);
    if (o && typeof o === 'object' && !Array.isArray(o)) return o;
  } catch (e) { /* fall through */ }
  errors.push(name + ' must be a JSON object');
  return {};
}

/** Slack webhook URLs (comma-separated). Only their count leaves this function. */
function slackWebhookUrls(value) {
  return cleanValue(value).split(',').map((u) => u.trim()).filter((u) => u && !/^YOUR_/.test(u));
}

/**
 * Resolve settings from an env-like object. `settings` holds no secrets (presence flags and a
 * channel count only), so it is safe to carry in n8n item data.
 */
function resolveConfig(env) {
  const e = env || {};
  const errors = [];
  const s = {
    dryRun: parseBool(e.DRY_RUN, true),
    sandboxMode: parseBool(e.SANDBOX_MODE, true),
    hubspotApiBase: String(cleanValue(e.HUBSPOT_API_BASE) || 'https://api.hubapi.com').replace(/\/+$/, ''),
    signatureHeader: (cleanValue(e.SIGNATURE_HEADER) || 'x-signature-256').toLowerCase(),
    timestampHeader: (cleanValue(e.SIGNATURE_TIMESTAMP_HEADER) || 'x-signature-timestamp').toLowerCase(),
    signaturePayloadFormat: (cleanValue(e.SIGNATURE_PAYLOAD_FORMAT) || 'timestamp.body').toLowerCase(),
    signatureToleranceSeconds: num(e.SIGNATURE_TOLERANCE_SECONDS, 300),
    maxResponsesPerRequest: num(e.MAX_RESPONSES_PER_REQUEST, 25),
    dedupeHours: num(e.DEDUPE_HOURS, 72),
    csat: { scaleMax: num(e.CSAT_SCALE_MAX, 5), detractorBelow: num(e.CSAT_DETRACTOR_THRESHOLD, 3), criticalAtOrBelow: num(e.CSAT_CRITICAL_THRESHOLD, 1) },
    nps: { detractorMax: num(e.NPS_DETRACTOR_MAX, 6), criticalMax: num(e.NPS_CRITICAL_MAX, 3) },
    nes: { detractorBelow: num(e.NES_DETRACTOR_THRESHOLD, 0), criticalAtOrBelow: num(e.NES_CRITICAL_THRESHOLD, -50) },
    criticalKeywords: listOf(e.CRITICAL_KEYWORDS, ['cancel', 'churn', 'refund', 'lawyer', 'legal action', 'terminate']).map((k) => k.toLowerCase()),
    lookupWindowDays: num(e.LOOKUP_WINDOW_DAYS, 90),
    reopenClosedTickets: parseBool(e.REOPEN_CLOSED_TICKETS, true),
    reopenMaxAgeDays: num(e.REOPEN_MAX_AGE_DAYS, 30),
    reopenStageLabelRegex: cleanValue(e.REOPEN_STAGE_LABEL_REGEX) || 'waiting on us|waiting on support|in progress|open',
    closedStageIds: listOf(e.CLOSED_STAGE_IDS, []),
    escalationPriority: (cleanValue(e.ESCALATION_PRIORITY) || 'HIGH').toUpperCase(),
    criticalPriority: (cleanValue(e.CRITICAL_PRIORITY) || 'HIGH').toUpperCase(),
    accountManagerProperty: cleanValue(e.ACCOUNT_MANAGER_PROPERTY),
    noteFeedbackMaxChars: num(e.NOTE_FEEDBACK_MAX_CHARS, 3000),
    alertDestinations: listOf(e.ALERT_DESTINATIONS, ['slack']).map((d) => d.toLowerCase()),
    pagerdutyMinSeverity: (cleanValue(e.PAGERDUTY_MIN_SEVERITY) || 'critical').toLowerCase(),
    execSlackMentions: listOf(e.EXEC_SLACK_MENTIONS, []),
    showCustomerEmail: parseBool(e.SHOW_CUSTOMER_EMAIL, false),
    slackChannelCount: slackWebhookUrls(e.SLACK_WEBHOOK_URLS).length,
    present: {
      hubspotAccessToken: cleanValue(e.HUBSPOT_ACCESS_TOKEN) !== '',
      webhookSecret: cleanValue(e.WEBHOOK_SECRET) !== '',
      webhookSecretPrevious: cleanValue(e.WEBHOOK_SECRET_PREVIOUS) !== '',
      pagerdutyRoutingKey: cleanValue(e.PAGERDUTY_ROUTING_KEY) !== '',
      alertWebhookUrl: cleanValue(e.ALERT_WEBHOOK_URL) !== '',
    },
  };
  s.reopenStageMap = jsonObject(e.REOPEN_STAGE_MAP_JSON, 'REOPEN_STAGE_MAP_JSON', errors);
  const userMap = jsonObject(e.SLACK_USER_MAP_JSON, 'SLACK_USER_MAP_JSON', errors);
  s.slackUserMap = {};
  for (const [k, v] of Object.entries(userMap)) {
    if (!/^[UW][A-Z0-9]{2,20}$/.test(String(v))) errors.push('SLACK_USER_MAP_JSON["' + k + '"] must be a Slack user ID such as U0123ABCD');
    else s.slackUserMap[String(k).toLowerCase()] = String(v);
  }

  if (!s.present.hubspotAccessToken) errors.push('HUBSPOT_ACCESS_TOKEN is not set (placeholders count as unset)');
  if (!s.present.webhookSecret) errors.push('WEBHOOK_SECRET is not set; every request must be HMAC-signed');
  else if (cleanValue(e.WEBHOOK_SECRET).length < 16) errors.push('WEBHOOK_SECRET must be at least 16 characters');
  if (!/^https:\/\//i.test(s.hubspotApiBase)) errors.push('HUBSPOT_API_BASE must use https://');
  if (!/^[a-z0-9-]{1,64}$/.test(s.signatureHeader) || !/^[a-z0-9-]{1,64}$/.test(s.timestampHeader)) errors.push('SIGNATURE_HEADER and SIGNATURE_TIMESTAMP_HEADER must be plain header names');
  if (!['timestamp.body', 'body'].includes(s.signaturePayloadFormat)) errors.push('SIGNATURE_PAYLOAD_FORMAT must be timestamp.body or body');
  if (!(Number.isInteger(s.signatureToleranceSeconds) && s.signatureToleranceSeconds >= 30 && s.signatureToleranceSeconds <= 3600)) errors.push('SIGNATURE_TOLERANCE_SECONDS must be an integer from 30 to 3600');
  if (!(Number.isInteger(s.maxResponsesPerRequest) && s.maxResponsesPerRequest >= 1 && s.maxResponsesPerRequest <= 100)) errors.push('MAX_RESPONSES_PER_REQUEST must be an integer from 1 to 100');
  if (!(s.dedupeHours >= 0 && s.dedupeHours <= 720)) errors.push('DEDUPE_HOURS must be 0-720');
  if (!(s.csat.scaleMax >= 2 && s.csat.scaleMax <= 10)) errors.push('CSAT_SCALE_MAX must be 2-10');
  if (!(s.csat.detractorBelow > 0 && s.csat.detractorBelow <= s.csat.scaleMax)) errors.push('CSAT_DETRACTOR_THRESHOLD must be > 0 and <= CSAT_SCALE_MAX');
  if (!(s.csat.criticalAtOrBelow >= 0 && s.csat.criticalAtOrBelow < s.csat.detractorBelow)) errors.push('CSAT_CRITICAL_THRESHOLD must be >= 0 and below CSAT_DETRACTOR_THRESHOLD');
  if (!(s.nps.detractorMax >= 0 && s.nps.detractorMax <= 10 && s.nps.criticalMax >= 0 && s.nps.criticalMax <= s.nps.detractorMax)) errors.push('NPS_DETRACTOR_MAX / NPS_CRITICAL_MAX must be 0-10 with critical <= detractor');
  if (!(s.nes.detractorBelow >= -100 && s.nes.detractorBelow <= 100 && s.nes.criticalAtOrBelow >= -100 && s.nes.criticalAtOrBelow < s.nes.detractorBelow)) errors.push('NES thresholds must be -100..100 with critical below detractor');
  if (!(s.lookupWindowDays >= 1 && s.lookupWindowDays <= 730)) errors.push('LOOKUP_WINDOW_DAYS must be 1-730');
  if (!(s.reopenMaxAgeDays >= 0 && s.reopenMaxAgeDays <= 365)) errors.push('REOPEN_MAX_AGE_DAYS must be 0-365');
  try { new RegExp(s.reopenStageLabelRegex, 'i'); } catch (err) { errors.push('REOPEN_STAGE_LABEL_REGEX is not a valid regular expression'); }
  for (const [p, st] of Object.entries(s.reopenStageMap)) if (!/^[A-Za-z0-9_-]{1,40}$/.test(p) || !/^[A-Za-z0-9_-]{1,40}$/.test(String(st))) errors.push('REOPEN_STAGE_MAP_JSON must map pipeline IDs to stage IDs');
  if (s.closedStageIds.some((x) => !/^[A-Za-z0-9_-]{1,40}$/.test(x))) errors.push('CLOSED_STAGE_IDS must be comma-separated stage IDs');
  if (!PRIORITIES.includes(s.escalationPriority) || !PRIORITIES.includes(s.criticalPriority)) errors.push('ESCALATION_PRIORITY / CRITICAL_PRIORITY must be one of ' + PRIORITIES.join(', '));
  if (s.accountManagerProperty && !/^[a-z0-9_]{1,100}$/.test(s.accountManagerProperty)) errors.push('ACCOUNT_MANAGER_PROPERTY must be an internal property name');
  if (!(Number.isInteger(s.noteFeedbackMaxChars) && s.noteFeedbackMaxChars >= 100 && s.noteFeedbackMaxChars <= 20000)) errors.push('NOTE_FEEDBACK_MAX_CHARS must be an integer from 100 to 20000');
  if (!s.alertDestinations.length || s.alertDestinations.some((d) => !['slack', 'pagerduty'].includes(d))) errors.push('ALERT_DESTINATIONS must be slack, pagerduty or slack,pagerduty');
  if (!['critical', 'high'].includes(s.pagerdutyMinSeverity)) errors.push('PAGERDUTY_MIN_SEVERITY must be critical or high');
  if (s.execSlackMentions.some((m) => !/^[UWS][A-Z0-9]{2,20}$/.test(m))) errors.push('EXEC_SLACK_MENTIONS must be Slack user (U…) or user-group (S…) IDs');
  if (slackWebhookUrls(e.SLACK_WEBHOOK_URLS).some((u) => !/^https:\/\//i.test(u))) errors.push('Every SLACK_WEBHOOK_URLS entry must use https://');
  if (s.slackChannelCount > 10) errors.push('SLACK_WEBHOOK_URLS supports at most 10 channels');
  if (!s.dryRun) {
    if (s.alertDestinations.includes('slack') && s.slackChannelCount === 0) errors.push('SLACK_WEBHOOK_URLS is required when ALERT_DESTINATIONS includes slack and DRY_RUN=false');
    if (s.alertDestinations.includes('pagerduty') && !s.present.pagerdutyRoutingKey) errors.push('PAGERDUTY_ROUTING_KEY is required when ALERT_DESTINATIONS includes pagerduty and DRY_RUN=false');
  }
  return { settings: s, errors };
}

function assertSandbox(accountInfo, sandboxMode) {
  const type = String((accountInfo && accountInfo.accountType) || '').toUpperCase();
  if (!sandboxMode) return { ok: true, enforced: false, accountType: type || 'UNKNOWN' };
  if (ALLOWED_ACCOUNT_TYPES.includes(type)) return { ok: true, enforced: true, accountType: type };
  throw new Error('Sandbox gate blocked this run: SANDBOX_MODE=true but the HubSpot portal reports accountType "' + (type || 'UNKNOWN') +
    '". Allowed: ' + ALLOWED_ACCOUNT_TYPES.join(', ') + '. Nothing was changed or sent.');
}

// ---------------------------------------------------------------------------
// Constant-time compare + pure-JS SHA-256 / HMAC-SHA256 (no crypto module needed)
// ---------------------------------------------------------------------------

function constantTimeEqual(a, b) {
  const x = String(a || '');
  const y = String(b || '');
  if (!x || x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}

// ---------------------------------------------------------------------------
// Pure-JS hashing (SHA-256 / HMAC-SHA256 / SHA-1 / HMAC-SHA1) — no crypto module needed
// ---------------------------------------------------------------------------

const SHA256_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/** UTF-8 encode a string into a Uint8Array (handles surrogate pairs). */
function utf8Bytes(str) {
  const s = String(str);
  const out = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
        i++;
      }
    }
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 0x3f), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
  }
  return Uint8Array.from(out);
}

function toBytes(data) {
  if (typeof data === 'string') return utf8Bytes(data);
  if (data instanceof Uint8Array) return data;
  return Uint8Array.from(data || []);
}

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

/** SHA-256 digest (32-byte Uint8Array) of a string (UTF-8) or byte array. */
function sha256Bytes(data) {
  const bytes = toBytes(data);
  const len = bytes.length;
  const total = ((len + 9 + 63) >> 6) << 6;
  const m = new Uint8Array(total);
  m.set(bytes);
  m[len] = 0x80;
  const hi = Math.floor(len / 0x20000000);
  const lo = (len << 3) >>> 0;
  m[total - 8] = hi >>> 24; m[total - 7] = (hi >>> 16) & 0xff; m[total - 6] = (hi >>> 8) & 0xff; m[total - 5] = hi & 0xff;
  m[total - 4] = lo >>> 24; m[total - 3] = (lo >>> 16) & 0xff; m[total - 2] = (lo >>> 8) & 0xff; m[total - 1] = lo & 0xff;

  const H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const W = new Array(64);
  for (let off = 0; off < total; off += 64) {
    for (let t = 0; t < 16; t++) {
      const j = off + t * 4;
      W[t] = ((m[j] << 24) | (m[j + 1] << 16) | (m[j + 2] << 8) | m[j + 3]) | 0;
    }
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
      const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
    }
    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA256_K[t] + W[t]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    out[i * 4] = H[i] >>> 24; out[i * 4 + 1] = (H[i] >>> 16) & 0xff; out[i * 4 + 2] = (H[i] >>> 8) & 0xff; out[i * 4 + 3] = H[i] & 0xff;
  }
  return out;
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

/** HMAC-SHA256 (RFC 2104). Key and message may be strings (UTF-8) or byte arrays. */
function hmacSha256(key, message) {
  let k = toBytes(key);
  if (k.length > 64) k = sha256Bytes(k);
  const block = new Uint8Array(64);
  block.set(k);
  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) { ipad[i] = block[i] ^ 0x36; opad[i] = block[i] ^ 0x5c; }
  return sha256Bytes(concatBytes(opad, sha256Bytes(concatBytes(ipad, toBytes(message)))));
}

function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
  return s;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function bytesToBase64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const n = (a << 16) | (b << 8) | c;
    s += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] +
      (i + 1 < bytes.length ? B64[(n >> 6) & 63] : '=') +
      (i + 2 < bytes.length ? B64[n & 63] : '=');
  }
  return s;
}

function base64UrlEncode(data) {
  return bytesToBase64(toBytes(data)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function sha256Hex(data) {
  return bytesToHex(sha256Bytes(data));
}

function sha256Base64(data) {
  return bytesToBase64(sha256Bytes(data));
}
function base64UrlDecodeToString(s) {
  const b64 = String(s).replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  const bin = [];
  const str = b64 + pad;
  for (let i = 0; i < str.length; i += 4) {
    const n = (B64.indexOf(str[i]) << 18) | (B64.indexOf(str[i + 1]) << 12) | ((B64.indexOf(str[i + 2]) & 63) << 6) | (B64.indexOf(str[i + 3]) & 63);
    bin.push((n >> 16) & 255);
    if (str[i + 2] !== '=') bin.push((n >> 8) & 255);
    if (str[i + 3] !== '=') bin.push(n & 255);
  }
  // UTF-8 decode
  let out = '';
  for (let i = 0; i < bin.length; i++) {
    const c = bin[i];
    if (c < 0x80) out += String.fromCharCode(c);
    else if (c < 0xe0) out += String.fromCharCode(((c & 0x1f) << 6) | (bin[++i] & 0x3f));
    else if (c < 0xf0) out += String.fromCharCode(((c & 0x0f) << 12) | ((bin[++i] & 0x3f) << 6) | (bin[++i] & 0x3f));
    else {
      const cp = ((c & 0x07) << 18) | ((bin[++i] & 0x3f) << 12) | ((bin[++i] & 0x3f) << 6) | (bin[++i] & 0x3f);
      out += String.fromCodePoint(cp);
    }
  }
  return out;
}


// ---------------------------------------------------------------------------
// HMAC-SHA256 webhook signature verification
// ---------------------------------------------------------------------------

const MAX_BODY_BYTES = 262144; // 256 KB

function lowerHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) out[String(k).toLowerCase()] = Array.isArray(v) ? v.join(',') : String(v);
  return out;
}

/** Hex HMAC-SHA256 over "<timestamp>.<rawBody>" (default) or the raw body alone. */
function computeSignature(secret, rawBody, timestamp, format) {
  const message = format === 'body' ? String(rawBody) : String(timestamp) + '.' + String(rawBody);
  return bytesToHex(hmacSha256(secret, message));
}

/** Accepts "sha256=<hex>", "v1=<hex>", bare hex or base64; several values may be comma/space separated. */
function signatureCandidates(headerValue) {
  return String(headerValue || '').split(/[\s,]+/).map((v) => v.replace(/^(sha256|v1|v0)=/i, '').trim()).filter(Boolean);
}

/**
 * Verify a signed request. Returns { ok, reason }. Reasons are generic on purpose
 * (they are logged and returned to callers without revealing expected values).
 */
function verifySignature(input) {
  const { rawBody, headers, secrets, settings: s, nowMs } = input;
  if (typeof rawBody !== 'string') return { ok: false, reason: 'raw body unavailable (enable the Webhook node "Raw Body" option)' };
  if (rawBody.length > MAX_BODY_BYTES) return { ok: false, reason: 'body too large' };
  const h = lowerHeaders(headers);
  const candidates = signatureCandidates(h[s.signatureHeader]);
  if (!candidates.length) return { ok: false, reason: 'missing signature header' };
  let ts = '';
  if (s.signaturePayloadFormat === 'timestamp.body') {
    ts = String(h[s.timestampHeader] || '').trim();
    if (!/^\d{9,13}$/.test(ts)) return { ok: false, reason: 'missing or malformed timestamp header' };
    const tsMs = ts.length > 11 ? Number(ts) : Number(ts) * 1000;
    if (Math.abs((nowMs || Date.now()) - tsMs) > s.signatureToleranceSeconds * 1000) return { ok: false, reason: 'timestamp outside tolerance (possible replay)' };
  }
  const usable = (secrets || []).filter((x) => typeof x === 'string' && x.length >= 16);
  if (!usable.length) return { ok: false, reason: 'no webhook secret configured' };
  for (const secret of usable) {
    const message = s.signaturePayloadFormat === 'body' ? rawBody : ts + '.' + rawBody;
    const mac = hmacSha256(secret, message);
    const hex = bytesToHex(mac);
    const b64 = bytesToBase64(mac);
    for (const c of candidates) {
      if (constantTimeEqual(c.toLowerCase(), hex) || constantTimeEqual(c, b64)) return { ok: true, reason: null };
    }
  }
  return { ok: false, reason: 'signature mismatch' };
}

// ---------------------------------------------------------------------------
// Survey payload parsing and detractor evaluation
// ---------------------------------------------------------------------------

function extractResponses(body) {
  if (Array.isArray(body)) return body;
  if (body && Array.isArray(body.responses)) return body.responses;
  if (body && typeof body === 'object') return [body];
  return [];
}

function pick(obj, paths) {
  for (const p of paths) {
    let v = obj;
    for (const k of p.split('.')) v = v === undefined || v === null ? undefined : v[k];
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return undefined;
}

function isValidEmail(v) {
  return typeof v === 'string' && v.length <= 254 && /^[^\s@<>()",;]+@[^\s@<>()",;]+\.[A-Za-z]{2,}$/.test(v);
}

function maskEmail(v) {
  if (!isValidEmail(v)) return null;
  const [local, domain] = v.split('@');
  return local[0] + '***@' + domain;
}

function cleanText(v, max) {
  if (v === undefined || v === null) return '';
  // Strip control characters except newline/tab, collapse runaway whitespace.
  const s = String(v).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').replace(/\r\n?/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

/** Normalise one survey response. Returns { ok: true, response } or { ok: false, reason }. */
function normalizeResponse(raw, s) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { ok: false, reason: 'response is not an object' };
  const typeRaw = String(pick(raw, ['survey_type', 'surveyType', 'type', 'hs_survey_type', 'survey.type']) || '').trim().toUpperCase().replace(/[\s-]+/g, '_');
  const surveyType = SURVEY_ALIASES[typeRaw];
  if (!surveyType) return { ok: false, reason: 'unsupported survey_type' };
  const scoreRaw = pick(raw, ['score', 'rating', 'value', 'hs_response_value', 'answer.score']);
  const score = scoreRaw === undefined ? null : Number(scoreRaw);
  const sentiment = String(pick(raw, ['sentiment', 'hs_sentiment']) || '').trim().toLowerCase() || null;
  if (score === null && !(surveyType === 'NES' && sentiment)) return { ok: false, reason: 'missing score' };
  if (score !== null && !Number.isFinite(score)) return { ok: false, reason: 'score is not a number' };
  const ticketId = String(pick(raw, ['ticket_id', 'ticketId', 'hs_ticket_id', 'ticket.id']) || '').trim();
  const contactId = String(pick(raw, ['contact_id', 'contactId', 'hs_contact_id', 'contact.id']) || '').trim();
  if (ticketId && !/^\d{1,20}$/.test(ticketId)) return { ok: false, reason: 'ticket_id must be a numeric HubSpot ID' };
  if (contactId && !/^\d{1,20}$/.test(contactId)) return { ok: false, reason: 'contact_id must be a numeric HubSpot ID' };
  if (!ticketId && !contactId) return { ok: false, reason: 'ticket_id or contact_id is required' };
  let responseId = String(pick(raw, ['response_id', 'responseId', 'submission_id', 'id', 'hs_object_id']) || '').trim();
  if (!responseId) responseId = 'auto-' + sha256Hex(JSON.stringify(raw)).slice(0, 20);
  if (!/^[A-Za-z0-9_.:-]{1,100}$/.test(responseId)) return { ok: false, reason: 'response_id contains unsupported characters' };
  const scaleRaw = pick(raw, ['scale_max', 'scaleMax', 'max_score', 'scale']);
  const scaleMax = scaleRaw === undefined ? null : Number(scaleRaw);
  if (scaleMax !== null && !(scaleMax >= 1 && scaleMax <= 100)) return { ok: false, reason: 'scale_max must be 1-100' };
  const email = String(pick(raw, ['customer_email', 'email', 'contact_email', 'contact.email']) || '').trim();
  const submittedRaw = pick(raw, ['submitted_at', 'submittedAt', 'timestamp', 'hs_submission_timestamp', 'created_at']);
  let submittedAt = null;
  if (submittedRaw !== undefined) {
    const n = Number(submittedRaw);
    const ms = Number.isFinite(n) ? (n > 1e11 ? n : n * 1000) : Date.parse(String(submittedRaw));
    if (Number.isFinite(ms)) submittedAt = new Date(ms).toISOString();
  }
  const response = {
    responseId, surveyType, score, scaleMax, sentiment, ticketId: ticketId || null, contactId: contactId || null,
    feedback: cleanText(pick(raw, ['feedback', 'comment', 'comments', 'hs_content', 'answer.text', 'text']), 5000),
    customerName: cleanText(pick(raw, ['customer_name', 'company_name', 'customer.name', 'company.name']), 120) || null,
    customerEmailMasked: isValidEmail(email) ? maskEmail(email) : null,
    submittedAt,
  };
  if (s && s.showCustomerEmail && isValidEmail(email)) response.customerEmail = email;
  return { ok: true, response };
}

function round2(n) {
  return Math.round(n * 100) / 100;
}

/** Decide whether a response is a detractor and how severe it is. */
function classifyResponse(r, s) {
  const text = (r.feedback || '').toLowerCase();
  const keyword = s.criticalKeywords.find((k) => k && text.includes(k)) || null;
  let isDetractor = false;
  let critical = false;
  let normalizedScore = r.score;
  let display;
  if (r.surveyType === 'CSAT') {
    const max = r.scaleMax || s.csat.scaleMax;
    if (r.score < 0 || r.score > max) return { valid: false, reason: 'CSAT score outside 0-' + max };
    normalizedScore = r.scaleMax && r.scaleMax !== s.csat.scaleMax ? round2((r.score / r.scaleMax) * s.csat.scaleMax) : r.score;
    isDetractor = normalizedScore < s.csat.detractorBelow;
    critical = normalizedScore <= s.csat.criticalAtOrBelow;
    display = 'CSAT ' + r.score + '/' + max;
  } else if (r.surveyType === 'NPS') {
    if (r.score < 0 || r.score > 10) return { valid: false, reason: 'NPS score outside 0-10' };
    isDetractor = r.score <= s.nps.detractorMax;
    critical = r.score <= s.nps.criticalMax;
    display = 'NPS ' + r.score + '/10';
  } else {
    // NES: -100..100 (or -1..1, scaled to -100..100). A "negative" sentiment counts as a detractor.
    if (r.score !== null) {
      normalizedScore = Math.abs(r.score) <= 1 && r.scaleMax !== 100 ? round2(r.score * 100) : r.score;
      if (normalizedScore < -100 || normalizedScore > 100) return { valid: false, reason: 'NES score outside -100..100' };
      isDetractor = normalizedScore < s.nes.detractorBelow;
      critical = normalizedScore <= s.nes.criticalAtOrBelow;
      display = 'NES ' + (normalizedScore > 0 ? '+' : '') + normalizedScore;
    } else {
      isDetractor = r.sentiment === 'negative' || r.sentiment === 'very_negative';
      critical = r.sentiment === 'very_negative';
      display = 'NES ' + r.sentiment;
    }
  }
  if (isDetractor && keyword) critical = true;
  return { valid: true, isDetractor, severity: isDetractor ? (critical ? 'critical' : 'high') : null, normalizedScore, display, keyword: isDetractor ? keyword : null };
}

/** Track processed response IDs to ignore re-deliveries. Mutates and returns `store`. */
function dedupe(responses, store, s, nowMs) {
  const seen = (store.seen = store.seen || {});
  const cutoff = nowMs - s.dedupeHours * 3600000;
  for (const [k, t] of Object.entries(seen)) if (t < cutoff) delete seen[k];
  const fresh = [];
  const duplicates = [];
  for (const r of responses) {
    if (s.dedupeHours > 0 && seen[r.response.responseId]) duplicates.push(r.response.responseId);
    else fresh.push(r);
  }
  return { fresh, duplicates, markSeen: () => { for (const r of fresh) seen[r.response.responseId] = nowMs; } };
}

/** Parse a verified body and split it into detractors / promoters / rejects. */
function evaluateBody(body, s) {
  const list = extractResponses(body);
  const out = { detractors: [], notDetractors: 0, rejected: [] };
  if (!list.length) out.rejected.push({ index: 0, reason: 'no survey responses in body' });
  if (list.length > s.maxResponsesPerRequest) {
    out.rejected.push({ index: s.maxResponsesPerRequest, reason: (list.length - s.maxResponsesPerRequest) + ' responses over MAX_RESPONSES_PER_REQUEST ignored' });
  }
  list.slice(0, s.maxResponsesPerRequest).forEach((raw, index) => {
    const n = normalizeResponse(raw, s);
    if (!n.ok) { out.rejected.push({ index, reason: n.reason }); return; }
    const c = classifyResponse(n.response, s);
    if (!c.valid) { out.rejected.push({ index, reason: c.reason }); return; }
    if (c.isDetractor) out.detractors.push({ response: n.response, classification: c });
    else out.notDetractors++;
  });
  return out;
}

// ---------------------------------------------------------------------------
// HubSpot lookups and update payloads
// ---------------------------------------------------------------------------

const TICKET_PROPERTIES = ['subject', 'hs_pipeline', 'hs_pipeline_stage', 'hs_ticket_priority', 'hubspot_owner_id', 'closed_date', 'hs_lastmodifieddate', 'createdate'];

function ticketSearchBody(r, s, nowMs) {
  const properties = TICKET_PROPERTIES.concat(s.accountManagerProperty ? [s.accountManagerProperty] : []);
  if (r.ticketId) {
    return { filterGroups: [{ filters: [{ propertyName: 'hs_object_id', operator: 'EQ', value: r.ticketId }] }], properties, limit: 1 };
  }
  return {
    filterGroups: [{ filters: [
      { propertyName: 'associations.contact', operator: 'EQ', value: r.contactId },
      { propertyName: 'hs_lastmodifieddate', operator: 'GTE', value: String(nowMs - s.lookupWindowDays * DAY) },
    ] }],
    sorts: [{ propertyName: 'hs_lastmodifieddate', direction: 'DESCENDING' }],
    properties,
    limit: 5,
  };
}

/** Index ticket pipelines: { pipelineId: { label, stages: [{ id, label, displayOrder, closed }] } }. */
function indexPipelines(resp, s) {
  const out = {};
  for (const p of (resp && resp.results) || []) {
    if (!p || p.archived) continue;
    out[String(p.id)] = {
      label: p.label || 'Pipeline ' + p.id,
      stages: (p.stages || []).filter((st) => st && !st.archived).map((st) => {
        const m = st.metadata || {};
        return { id: String(st.id), label: st.label || String(st.id), displayOrder: Number(st.displayOrder) || 0,
          closed: String(m.ticketState || '').toUpperCase() === 'CLOSED' || String(m.isClosed) === 'true' || (s && s.closedStageIds.includes(String(st.id))) };
      }).sort((a, b) => a.displayOrder - b.displayOrder),
    };
  }
  return out;
}

function indexOwners(owners) {
  const out = {};
  for (const o of owners || []) {
    if (!o || o.id === undefined) continue;
    out[String(o.id)] = { id: String(o.id), firstName: o.firstName || '', lastName: o.lastName || '', email: o.email || null, archived: o.archived === true };
  }
  return out;
}

/** Stage to re-open into: REOPEN_STAGE_MAP_JSON, else first open stage matching the label regex, else first open stage. */
function resolveReopenStage(pipelineId, pipeline, s) {
  const stages = (pipeline && pipeline.stages) || [];
  const mapped = s.reopenStageMap[String(pipelineId)];
  if (mapped) return stages.find((st) => st.id === String(mapped)) || { id: String(mapped), label: 'stage ' + mapped, closed: false };
  const open = stages.filter((st) => !st.closed);
  const re = new RegExp(s.reopenStageLabelRegex, 'i');
  return open.find((st) => re.test(st.label)) || open[0] || null;
}

function higherPriority(current, target) {
  const ci = PRIORITIES.indexOf(String(current || '').toUpperCase());
  const ti = PRIORITIES.indexOf(target);
  return ci > ti ? PRIORITIES[ci] : target;
}

function ownerName(o) {
  if (!o) return null;
  const n = (o.firstName + ' ' + o.lastName).trim();
  return n || 'Owner ' + o.id;
}

function slackIdFor(owner, s) {
  if (!owner) return null;
  return s.slackUserMap[owner.id] || (owner.email ? s.slackUserMap[String(owner.email).toLowerCase()] : null) || null;
}

function hubspotRecordUrl(portal, objectTypeId, id) {
  if (!portal || !portal.portalId || !id) return null;
  const domain = /^[a-z0-9.-]+\.hubspot\.com$/i.test(String(portal.uiDomain || '')) ? portal.uiDomain : 'app.hubspot.com';
  return 'https://' + domain + '/contacts/' + encodeURIComponent(String(portal.portalId)) + '/record/' + objectTypeId + '/' + encodeURIComponent(String(id));
}

function escHtml(v) {
  return String(v === undefined || v === null ? '' : v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function buildNoteHtml(plan, r, s) {
  const feedback = cleanText(r.feedback, s.noteFeedbackMaxChars);
  return [
    '<p><strong>⚠️ Detractor survey escalation (automated)</strong></p>',
    '<p><strong>Survey:</strong> ' + escHtml(plan.display) + ' · <strong>Severity:</strong> ' + escHtml(plan.severity) +
      (plan.keyword ? ' · <strong>Keyword:</strong> ' + escHtml(plan.keyword) : '') + '<br>' +
      '<strong>Response ID:</strong> ' + escHtml(r.responseId) + (r.submittedAt ? ' · <strong>Submitted:</strong> ' + escHtml(r.submittedAt) : '') + '</p>',
    '<p><strong>Customer feedback:</strong></p>',
    '<blockquote>' + (feedback ? escHtml(feedback).replace(/\n/g, '<br>') : '<em>No written feedback.</em>') + '</blockquote>',
    '<p><strong>Automated actions:</strong></p>',
    '<ul>' + plan.actions.concat(plan.warnings.map((w) => 'Note: ' + w)).map((a) => '<li>' + escHtml(a) + '</li>').join('') + '</ul>',
    '<p><em>Added by n8n-hubspot-ticket-satisfaction-detractor-escalation. Review before replying to the customer.</em></p>',
  ].join('');
}

/** Pick the best ticket from search results (exact ID first, else most recently modified). */
function chooseTicket(searchResponse, r) {
  const results = ((searchResponse && searchResponse.results) || []).filter((t) => t && t.id);
  if (!results.length) return null;
  if (r.ticketId) return results.find((t) => String(t.id) === r.ticketId) || null;
  return results[0];
}

/**
 * Build the full escalation plan for one detractor.
 * input: { response, classification, ticket (HubSpot object or null), owners (index), pipelines (index), portal, nowMs }
 */
function planEscalation(input, s) {
  const r = input.response;
  const c = input.classification;
  const nowMs = input.nowMs || Date.now();
  const plan = {
    responseId: r.responseId, surveyType: r.surveyType, display: c.display, severity: c.severity, keyword: c.keyword,
    ticketFound: false, ticketId: null, ticketSubject: null, ticketUrl: null, contactUrl: hubspotRecordUrl(input.portal, '0-1', r.contactId),
    pipelineLabel: null, statusBefore: null, statusAfter: null, priorityBefore: null, priorityAfter: null,
    owner: null, accountManager: null, actions: [], warnings: [], ticketUpdate: null, note: null,
  };
  const t = input.ticket;
  if (!t) {
    plan.warnings.push(r.ticketId ? 'Ticket ' + r.ticketId + ' was not found in HubSpot' : 'No ticket for contact ' + r.contactId + ' was modified in the last ' + s.lookupWindowDays + ' days');
  } else {
    const p = t.properties || {};
    plan.ticketFound = true;
    plan.ticketId = String(t.id);
    plan.ticketSubject = cleanText(p.subject, 150) || 'Ticket ' + t.id;
    plan.ticketUrl = hubspotRecordUrl(input.portal, '0-5', t.id);
    const pipeline = (input.pipelines || {})[String(p.hs_pipeline)] || null;
    plan.pipelineLabel = pipeline ? pipeline.label : null;
    const stage = pipeline ? pipeline.stages.find((st) => st.id === String(p.hs_pipeline_stage)) : null;
    const isClosed = stage ? stage.closed : s.closedStageIds.includes(String(p.hs_pipeline_stage));
    plan.statusBefore = stage ? stage.label : String(p.hs_pipeline_stage || 'unknown');
    plan.statusAfter = plan.statusBefore;
    const props = {};
    if (isClosed) {
      const closedMs = Date.parse(p.closed_date || '');
      const ageDays = Number.isFinite(closedMs) ? Math.floor((nowMs - closedMs) / DAY) : null;
      if (!s.reopenClosedTickets) plan.warnings.push('Ticket is closed and was not re-opened (REOPEN_CLOSED_TICKETS=false)');
      else if (ageDays !== null && ageDays > s.reopenMaxAgeDays) plan.warnings.push('Ticket closed ' + ageDays + ' days ago (> REOPEN_MAX_AGE_DAYS=' + s.reopenMaxAgeDays + '); not re-opened');
      else {
        const target = resolveReopenStage(p.hs_pipeline, pipeline, s);
        if (!target) plan.warnings.push('No open stage found in the ticket pipeline; set REOPEN_STAGE_MAP_JSON');
        else {
          props.hs_pipeline_stage = target.id;
          plan.statusAfter = target.label;
          plan.actions.push('Status: ' + plan.statusBefore + ' → ' + target.label + ' (re-opened)');
        }
      }
    } else {
      plan.actions.push('Status unchanged (ticket already open: ' + plan.statusBefore + ')');
    }
    const targetPriority = c.severity === 'critical' ? s.criticalPriority : s.escalationPriority;
    plan.priorityBefore = String(p.hs_ticket_priority || '').toUpperCase() || 'NONE';
    plan.priorityAfter = higherPriority(p.hs_ticket_priority, targetPriority);
    props.hs_ticket_priority = plan.priorityAfter;
    plan.actions.push(plan.priorityAfter === plan.priorityBefore ? 'Priority unchanged (' + plan.priorityAfter + ', never lowered)' : 'Priority: ' + plan.priorityBefore + ' → ' + plan.priorityAfter);
    plan.actions.push('Internal note added with survey feedback');
    plan.ticketUpdate = { properties: props };
    const owners = input.owners || {};
    plan.owner = p.hubspot_owner_id ? owners[String(p.hubspot_owner_id)] || { id: String(p.hubspot_owner_id), firstName: '', lastName: '', email: null } : null;
    if (s.accountManagerProperty && p[s.accountManagerProperty]) {
      const amId = String(p[s.accountManagerProperty]);
      plan.accountManager = owners[amId] || { id: amId, firstName: '', lastName: '', email: null };
    }
    if (!plan.owner) plan.warnings.push('Ticket has no owner');
  }
  if (plan.ticketFound) {
    plan.note = {
      properties: { hs_timestamp: new Date(nowMs).toISOString(), hs_note_body: buildNoteHtml(plan, r, s) },
      associations: [{ to: { id: plan.ticketId }, types: [{ associationCategory: 'HUBSPOT_DEFINED', associationTypeId: 228 }] }],
    };
  }
  plan.slackPayload = buildSlackPayload(plan, r, s);
  plan.pagerdutyEvent = buildPagerDutyEvent(plan, r, s, nowMs);
  plan.destinations = alertDestinations(plan, s);
  // Owners carry emails; keep only display data in the plan.
  plan.ownerName = ownerName(plan.owner);
  plan.accountManagerName = ownerName(plan.accountManager);
  delete plan.owner;
  delete plan.accountManager;
  return plan;
}

function alertDestinations(plan, s) {
  const out = [];
  if (s.alertDestinations.includes('slack')) out.push('slack');
  if (s.alertDestinations.includes('pagerduty') && (s.pagerdutyMinSeverity === 'high' || plan.severity === 'critical')) out.push('pagerduty');
  return out;
}

// ---------------------------------------------------------------------------
// Slack Block Kit + PagerDuty Events API v2
// ---------------------------------------------------------------------------

function esc(text) {
  return String(text === undefined || text === null ? '' : text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function slackLink(url, label) {
  return url && /^https:\/\/[^\s|<>]+$/.test(url) ? '<' + url + '|' + esc(label).replace(/\|/g, '¦') + '>' : esc(label);
}

function mention(id) {
  return /^S/.test(id) ? '<!subteam^' + id + '>' : '<@' + id + '>';
}

function personLine(owner, s) {
  if (!owner) return '_unassigned_';
  const id = slackIdFor(owner, s);
  return id ? mention(id) : esc(ownerName(owner));
}

function customerLabel(r) {
  const name = r.customerName ? esc(r.customerName) : 'Unknown customer';
  const email = r.customerEmail ? esc(r.customerEmail) : r.customerEmailMasked ? esc(r.customerEmailMasked) : null;
  return name + (email ? ' (' + email + ')' : '');
}

/** Slack incoming-webhook payload (<= 50 blocks, <= 3000 chars per text, header <= 150). */
function buildSlackPayload(plan, r, s) {
  const icon = plan.severity === 'critical' ? '🚨' : '⚠️';
  const title = (s.dryRun ? '[DRY RUN] ' : '') + icon + ' Detractor escalation · ' + plan.display;
  const ticketLine = plan.ticketFound ? slackLink(plan.ticketUrl, '#' + plan.ticketId + ' ' + plan.ticketSubject) : '_No matching ticket found_';
  const mentions = [];
  const ownerId = slackIdFor(plan.owner, s);
  const amId = slackIdFor(plan.accountManager, s);
  if (ownerId) mentions.push(mention(ownerId));
  if (amId && amId !== ownerId) mentions.push(mention(amId));
  if (plan.severity === 'critical') for (const m of s.execSlackMentions) if (!mentions.includes(mention(m))) mentions.push(mention(m));
  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: title.slice(0, 150), emoji: true } },
    { type: 'section', text: { type: 'mrkdwn', text: ('*Customer:* ' + customerLabel(r) + '\n*Ticket:* ' + ticketLine + (plan.pipelineLabel ? ' · ' + esc(plan.pipelineLabel) : '')).slice(0, 2900) } },
    {
      type: 'section',
      fields: [
        { type: 'mrkdwn', text: '*Score*\n' + esc(plan.display) },
        { type: 'mrkdwn', text: '*Severity*\n' + (plan.severity === 'critical' ? '🔴 Critical' : '🟠 High') + (plan.keyword ? ' (“' + esc(plan.keyword) + '”)' : '') },
        { type: 'mrkdwn', text: '*Ticket owner*\n' + personLine(plan.owner, s) },
        { type: 'mrkdwn', text: '*Account manager*\n' + (plan.accountManager ? personLine(plan.accountManager, s) : '_not set_') },
        { type: 'mrkdwn', text: '*Status*\n' + (plan.ticketFound ? esc(plan.statusBefore) + (plan.statusAfter !== plan.statusBefore ? ' → *' + esc(plan.statusAfter) + '*' : '') : '—') },
        { type: 'mrkdwn', text: '*Priority*\n' + (plan.ticketFound ? esc(plan.priorityBefore) + (plan.priorityAfter !== plan.priorityBefore ? ' → *' + esc(plan.priorityAfter) + '*' : '') : '—') },
      ],
    },
  ];
  const feedback = cleanText(r.feedback, 1500);
  blocks.push({ type: 'section', text: { type: 'mrkdwn', text: feedback ? '*Feedback*\n' + esc(feedback).split('\n').map((l) => '> ' + l).join('\n') : '*Feedback*\n_No written feedback._' } });
  if (plan.warnings.length) blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: plan.warnings.map((w) => ':warning: ' + esc(w)).join('\n').slice(0, 2900) }] });
  const buttons = [];
  if (plan.ticketUrl) buttons.push({ type: 'button', text: { type: 'plain_text', text: 'Open ticket in HubSpot', emoji: true }, url: plan.ticketUrl, style: 'danger' });
  if (plan.contactUrl) buttons.push({ type: 'button', text: { type: 'plain_text', text: 'View contact', emoji: true }, url: plan.contactUrl });
  if (buttons.length) blocks.push({ type: 'actions', elements: buttons });
  if (mentions.length) blocks.push({ type: 'section', text: { type: 'mrkdwn', text: 'cc ' + mentions.join(' ') } });
  blocks.push({ type: 'context', elements: [{ type: 'mrkdwn', text: esc(r.surveyType) + ' response `' + esc(r.responseId) + '`' + (r.submittedAt ? ' · submitted ' + esc(r.submittedAt) : '') + ' · ' + (s.dryRun ? 'dry run: no HubSpot changes made' : 'HubSpot ticket updated and note added') }] });
  const fallback = esc(title + ': ' + (r.customerName || 'customer') + (plan.ticketId ? ' · ticket #' + plan.ticketId : ''));
  return { text: fallback, blocks: blocks.slice(0, 50), unfurl_links: false, unfurl_media: false };
}

/** PagerDuty Events API v2 body WITHOUT routing_key (the HTTP node adds it from $env). */
function buildPagerDutyEvent(plan, r, s, nowMs) {
  const summary = (s.dryRun ? '[DRY RUN] ' : '') + 'Detractor ' + plan.display + (plan.ticketId ? ' on ticket #' + plan.ticketId : '') + (r.customerName ? ' (' + r.customerName + ')' : '');
  const event = {
    event_action: 'trigger',
    dedup_key: ('detractor-' + (plan.ticketId || 'noticket') + '-' + r.responseId).slice(0, 255),
    payload: {
      summary: summary.slice(0, 1024),
      source: 'n8n-hubspot-detractor-escalation',
      severity: plan.severity === 'critical' ? 'critical' : 'error',
      timestamp: new Date(nowMs).toISOString(),
      component: 'customer-satisfaction',
      group: plan.pipelineLabel || 'hubspot-tickets',
      class: r.surveyType,
      custom_details: {
        score: plan.display, severity: plan.severity, keyword: plan.keyword, ticket_id: plan.ticketId, ticket_subject: plan.ticketSubject,
        ticket_owner: ownerName(plan.owner), account_manager: ownerName(plan.accountManager), status: plan.statusBefore + ' → ' + plan.statusAfter,
        priority: plan.priorityBefore + ' → ' + plan.priorityAfter, feedback: cleanText(r.feedback, 1000), actions: plan.actions, warnings: plan.warnings, response_id: r.responseId,
      },
    },
    client: 'HubSpot detractor escalation (n8n)',
  };
  if (plan.ticketUrl) { event.client_url = plan.ticketUrl; event.links = [{ href: plan.ticketUrl, text: 'Open ticket in HubSpot' }]; }
  return event;
}

// ---------------------------------------------------------------------------
// Masked logging
// ---------------------------------------------------------------------------

const SECRET_PATTERNS = [
  [/(Bearer|Basic)\s+[A-Za-z0-9._~+\/=:-]+/gi, '$1 ***'],
  [/\bpat-[a-z0-9]{2,4}-[A-Za-z0-9-]{8,}/gi, 'pat-***'],
  [/https:\/\/hooks\.slack\.com\/[^\s"'<>]+/gi, 'https://hooks.slack.com/***'],
  [/\bxox[abposr]-[A-Za-z0-9-]{10,}/g, 'xox*-***'],
  [/("?routing_key"?\s*[:=]\s*"?)[A-Za-z0-9]{8,}/gi, '$1***'],
  [/\b(sha256|v1)=[A-Fa-f0-9]{32,}/g, '$1=***'],
  [/([?&](?:token|hapikey|api_key|access_token|secret|signature)=)[^&\s"']+/gi, '$1***'],
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '***@***'],
  [/\+\d{8,15}\b/g, '***phone***'],
  [/\(?\d{2,4}\)?[\s.-]\d{3,4}[\s.-]\d{3,4}\b/g, '***phone***'],
];

function maskSecrets(text, secretValues) {
  let out = text === undefined || text === null ? '' : String(text);
  const values = (secretValues || []).filter((v) => typeof v === 'string' && v.length >= 6).sort((a, b) => b.length - a.length);
  for (const v of values) out = out.split(v).join('***');
  for (const [re, rep] of SECRET_PATTERNS) out = out.replace(re, rep);
  return out;
}

function maskError(errLike, secretValues) {
  let message;
  let status = null;
  if (errLike === undefined || errLike === null) message = 'Unknown error';
  else if (typeof errLike === 'string') message = errLike;
  else {
    status = errLike.httpCode || errLike.status || errLike.statusCode || null;
    message = errLike.message || errLike.description || '';
    if (!message) { try { message = JSON.stringify(errLike); } catch (_) { message = String(errLike); } }
  }
  let m = maskSecrets(message, secretValues);
  if (String(status) === '403' || /\b403\b/.test(m)) m += ' — hint: tickets need crm.objects.tickets.read + crm.objects.tickets.write (or the legacy "tickets" scope), owners need crm.objects.owners.read.';
  if (String(status) === '429' || /\b429\b/.test(m)) m += ' — hint: rate limited; the workflow already retries and paces requests.';
  if (/routing key|events\.pagerduty/i.test(m)) m += ' — hint: PAGERDUTY_ROUTING_KEY must be an Events API v2 integration key.';
  return { status: status === null ? null : String(status), message: m.length > 1200 ? m.slice(0, 1199) + '…' : m };
}

// ---------------------------------------------------------------------------
// n8n stages
// ---------------------------------------------------------------------------

function readEnv(keys) {
  const env = {};
  for (const k of keys) {
    let v;
    try { v = $env[k]; } catch (e) {
      throw new Error('This workflow reads its configuration from environment variables. Set N8N_BLOCK_ENV_ACCESS_IN_NODE=false on the n8n instance.');
    }
    if (v !== undefined && v !== null) env[k] = String(v);
  }
  return env;
}

function loadConfig() {
  const env = readEnv(CONFIG_KEYS.concat(['SAMPLE_TICKET_ID']));
  const r = resolveConfig(env);
  if (r.errors.length) throw new Error('Configuration invalid: ' + r.errors.join('; '));
  return { env, settings: r.settings };
}

function allJson(nodeName) {
  try {
    const node = $(nodeName);
    if (node.isExecuted === false) return [];
    return node.all().map((i) => i.json);
  } catch (e) {
    return [];
  }
}

/** Raw request body for signature checks: Webhook "Raw Body" binary, else the manual sample. */
async function rawBodyFrom(item, index, ctx) {
  const j = item.json || {};
  const bin = item.binary && item.binary.data;
  if (bin) {
    if (ctx && ctx.helpers && typeof ctx.helpers.getBinaryDataBuffer === 'function') {
      try {
        const buf = await ctx.helpers.getBinaryDataBuffer(index, 'data');
        if (buf) return buf.toString('utf8');
      } catch (e) { /* fall back to inline data */ }
    }
    if (typeof bin.data === 'string' && bin.data && !bin.id) return base64UrlDecodeToString(bin.data);
  }
  if (j.sample === true && typeof j.rawBody === 'string') return j.rawBody;
  return null;
}

function staticStore() {
  try { return $getWorkflowStaticData('global'); } catch (e) { return {}; }
}

async function runStage(stage, ctx) {
  if (stage === 'sample') {
    const { env } = loadConfig();
    const ticketId = /^\d{1,20}$/.test(cleanValue(env.SAMPLE_TICKET_ID)) ? cleanValue(env.SAMPLE_TICKET_ID) : '1000000001';
    const body = { responses: [{
      response_id: 'resp_demo_' + Date.now(), survey_type: 'CSAT', score: 1, scale_max: 5, ticket_id: ticketId,
      customer_name: 'Example Customer Co.', customer_email: 'customer_1@example.com', submitted_at: new Date().toISOString(),
      feedback: 'Example feedback: the issue came back after the ticket was closed and nobody followed up. We are considering whether to cancel.',
    }] };
    const rawBody = JSON.stringify(body);
    const ts = String(Math.floor(Date.now() / 1000));
    const r = resolveConfig(env).settings;
    const sig = 'sha256=' + computeSignature(cleanValue(env.WEBHOOK_SECRET), rawBody, ts, r.signaturePayloadFormat);
    return [{ json: { sample: true, rawBody, headers: { [r.signatureHeader]: sig, [r.timestampHeader]: ts, 'content-type': 'application/json' } } }];
  }

  if (stage === 'gate') {
    const { env, settings } = loadConfig();
    const item = $input.first() || { json: {} };
    const nowMs = Date.now();
    const rawBody = await rawBodyFrom(item, 0, ctx);
    const v = verifySignature({ rawBody, headers: item.json.headers, secrets: [cleanValue(env.WEBHOOK_SECRET), cleanValue(env.WEBHOOK_SECRET_PREVIOUS)], settings, nowMs });
    const base = { config: settings, trigger: item.json.sample === true ? 'manual-sample' : 'webhook', receivedAt: new Date(nowMs).toISOString() };
    if (!v.ok) return [{ json: Object.assign(base, { verified: false, rejectReason: v.reason, detractorCount: 0, detractors: [] }) }];
    let body;
    try { body = JSON.parse(rawBody); } catch (e) {
      return [{ json: Object.assign(base, { verified: false, rejectReason: 'body is not valid JSON', detractorCount: 0, detractors: [] }) }];
    }
    const ev = evaluateBody(body, settings);
    const store = staticStore();
    const d = dedupe(ev.detractors, store, settings, nowMs);
    if (!settings.dryRun) d.markSeen();
    return [{ json: Object.assign(base, {
      verified: true, detractors: d.fresh, detractorCount: d.fresh.length, duplicates: d.duplicates,
      notDetractorCount: ev.notDetractors, rejected: ev.rejected,
    }) }];
  }

  if (stage === 'lookups') {
    const gate = $('Verify Signature & Evaluate').first().json;
    const account = allJson('HubSpot: Account Info')[0] || {};
    assertSandbox(account, gate.config.sandboxMode);
    const nowMs = Date.now();
    return gate.detractors.map((d, i) => ({ json: { detractorIndex: i, searchBody: ticketSearchBody(d.response, gate.config, nowMs) } }));
  }

  if (stage === 'plan') {
    const gate = $('Verify Signature & Evaluate').first().json;
    const s = gate.config;
    const account = allJson('HubSpot: Account Info')[0] || {};
    const portal = { portalId: account.portalId, uiDomain: account.uiDomain };
    const owners = indexOwners(allJson('HubSpot: List Owners').flatMap((p) => (p && p.results) || []));
    const pipelines = indexPipelines(allJson('HubSpot: Ticket Pipelines')[0], s);
    const lookups = allJson('Build Ticket Lookups');
    const nowMs = Date.now();
    // Pair each search result with its lookup via pairedItem (failed searches go to the error branch).
    return $input.all().map((it, i) => {
      const pi = Array.isArray(it.pairedItem) ? it.pairedItem[0] : it.pairedItem;
      const l = lookups[pi && Number.isInteger(pi.item) ? pi.item : i];
      const d = gate.detractors[l.detractorIndex];
      const ticket = chooseTicket(it.json, d.response);
      return { json: planEscalation({ response: d.response, classification: d.classification, ticket, owners, pipelines, portal, nowMs }, s), pairedItem: { item: i } };
    });
  }

  if (stage === 'crm-items') {
    return $('Plan Escalation').all().map((i) => i.json).filter((p) => p.ticketFound && p.ticketUpdate)
      .map((p) => ({ json: { responseId: p.responseId, ticketId: p.ticketId, ticketUpdate: p.ticketUpdate, note: p.note } }));
  }

  if (stage === 'alert-items') {
    const gate = $('Verify Signature & Evaluate').first().json;
    const s = gate.config;
    const out = [];
    for (const p of $('Plan Escalation').all().map((i) => i.json)) {
      if (p.destinations.includes('slack')) for (let c = 0; c < s.slackChannelCount; c++) out.push({ json: { destination: 'slack', channelIndex: c, responseId: p.responseId, slackPayload: p.slackPayload } });
      if (p.destinations.includes('pagerduty') && s.present.pagerdutyRoutingKey) out.push({ json: { destination: 'pagerduty', responseId: p.responseId, pagerdutyEvent: p.pagerdutyEvent } });
    }
    return out;
  }

  if (stage === 'logger') {
    const secrets = [];
    for (const k of SECRET_KEYS) {
      try { const v = cleanValue($env[k]); if (v) secrets.push(v, ...v.split(',').map((x) => x.trim())); } catch (e) { /* blocked */ }
    }
    let source = 'unknown node';
    try { source = $prevNode.name; } catch (e) { /* not available */ }
    return $input.all().map((item) => {
      const j = item.json || {};
      const masked = maskError(j.error !== undefined ? j.error : j, secrets);
      return { json: {
        node: source, status: masked.status, message: masked.message, at: new Date().toISOString(),
        alert: { text: 'Detractor escalation error at ' + source + (masked.status ? ' (HTTP ' + masked.status + ')' : '') + ': ' + masked.message },
      } };
    });
  }

  throw new Error('Unknown SYNDICATOR_STAGE: ' + stage);
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    CONFIG_KEYS, SECRET_KEYS, PRIORITIES,
    parseBool, cleanValue, slackWebhookUrls, resolveConfig, assertSandbox,
    constantTimeEqual, sha256Hex, hmacSha256, bytesToHex, computeSignature, signatureCandidates, verifySignature,
    extractResponses, normalizeResponse, classifyResponse, evaluateBody, dedupe, maskEmail,
    ticketSearchBody, indexPipelines, indexOwners, resolveReopenStage, higherPriority, chooseTicket, hubspotRecordUrl,
    buildNoteHtml, planEscalation, buildSlackPayload, buildPagerDutyEvent, esc, escHtml, maskSecrets, maskError, runStage,
  };
}

// n8n entry point: the Code node defines SYNDICATOR_STAGE on its first line.
if (typeof SYNDICATOR_STAGE !== 'undefined') {
  return runStage(SYNDICATOR_STAGE, this);
}
