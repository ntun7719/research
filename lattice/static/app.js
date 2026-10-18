function safeGetStorage(key) {
  try { return window.localStorage ? window.localStorage.getItem(key) : null; } catch (_) { return null; }
}
function safeSetStorage(key, val) {
  try { if (window.localStorage) window.localStorage.setItem(key, val); } catch (_) {}
}
const state = {
  csrf: "",
  authenticated: false,
  config: null,
  secrets: {},
  status: null,
  rules: [],
  feeds: [],
  devices: [],
  presets: [],
  queries: [],
  page: "dashboard",
  version: "",
  livePolling: true,
  timeWindow: 86400,
  chartMode: "volume",
  catalog: [],
  catalogFilter: "all",
  presetGroup: "all",
  activeDeviceIp: "",
  sseSource: null,
  liveRecent: [],
  snoozeTimer: null,
  snoozeRemaining: 0
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const QTYPE_NAMES = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  43: "DS",
  48: "DNSKEY",
  64: "SVCB",
  65: "HTTPS"
};

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function number(value) {
  return new Intl.NumberFormat().format(Number(value || 0));
}

function ago(ts) {
  if (!ts) return "Never";
  const seconds = Math.max(0, Math.round(Date.now() / 1000 - Number(ts)));
  if (seconds < 60) return seconds + "s ago";
  if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
  if (seconds < 86400) return Math.floor(seconds / 3600) + "h ago";
  return Math.floor(seconds / 86400) + "d ago";
}

function when(ts) {
  if (!ts) return "Not available";
  return new Date(Number(ts) * 1000).toLocaleString();
}

function deepCopy(value) {
  return JSON.parse(JSON.stringify(value));
}

function slug(value) {
  return String(value || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9_-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 40);
}

function toast(message, bad) {
  const node = $("#toast");
  if (!node) return;
  node.textContent = message;
  node.classList.toggle("bad", Boolean(bad));
  node.classList.remove("hidden");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => node.classList.add("hidden"), 4000);
}

function svgBar(pct, tone) {
  const clamped = Math.max(0, Math.min(100, Math.round(Number(pct || 0))));
  return (
    '<svg class="metric-bar" viewBox="0 0 100 6" preserveAspectRatio="none">' +
      '<rect class="metric-bar-bg" width="100" height="6" rx="3"></rect>' +
      '<rect class="metric-bar-fill ' + escapeHtml(tone || "good") + '" width="' + clamped + '" height="6" rx="3"></rect>' +
    "</svg>"
  );
}

async function api(path, options) {
  const opts = Object.assign({ method: "GET", headers: {} }, options || {});
  if (opts.body && typeof opts.body !== "string") {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }
  if (opts.method !== "GET" && opts.method !== "HEAD" && state.csrf) {
    opts.headers["X-CSRF-Token"] = state.csrf;
  }
  const response = await fetch(path, opts);
  let payload = {};
  try {
    payload = await response.json();
  } catch (_) {
    payload = {};
  }
  if (response.status === 401 && path !== "/api/login" && path !== "/api/setup") {
    state.authenticated = false;
    await bootstrap();
    throw new Error(payload.error || "Authentication required");
  }
  if (!response.ok) {
    throw new Error(payload.error || "Request failed");
  }
  return payload;
}

async function bootstrap() {
  const info = await api("/api/bootstrap");
  state.authenticated = Boolean(info.authenticated);
  state.csrf = info.csrf || "";
  state.version = info.version || "";
  if ($("#rail-version")) $("#rail-version").textContent = "Version " + state.version;
  if ($("#system-version")) $("#system-version").textContent = state.version || "unknown";

  if (!state.authenticated) {
    $("#shell").classList.add("hidden");
    $("#auth").classList.remove("hidden");
    $("#setup-code-wrap").classList.toggle("hidden", !info.setup_required);
    $("#auth-title").textContent = info.setup_required ? "Initialize Lattice DNS" : "Administrator Sign In";
    $("#auth-copy").textContent = info.setup_required
      ? "Enter your one-time setup code from the container logs and choose a strong administrator password."
      : "Enter your administrator password to manage DNS over TLS, policy rules, and upstreams.";
    $("#password").setAttribute("autocomplete", info.setup_required ? "new-password" : "current-password");
    $("#auth-form").dataset.setup = info.setup_required ? "1" : "0";
    return;
  }

  $("#auth").classList.add("hidden");
  $("#shell").classList.remove("hidden");
  await loadAll();
}

async function loadAll() {
  const results = await Promise.all([
    api("/api/status?window=" + state.timeWindow),
    api("/api/config"),
    api("/api/rules"),
    api("/api/feeds"),
    api("/api/devices"),
    api("/api/rules/presets"),
    api("/api/feeds/catalog").catch(() => ({ catalog: [] }))
  ]);
  state.status = results[0];
  state.config = results[1].config;
  state.secrets = results[1].secrets || {};
  state.rules = results[2] || [];
  state.feeds = results[3] || [];
  state.devices = results[4] || [];
  state.presets = results[5] || [];
  state.catalog = (results[6] && results[6].catalog) || [];
  renderAll();
}

async function refreshRulesAndPresets() {
  const [rules, presets, status] = await Promise.all([
    api("/api/rules"),
    api("/api/rules/presets"),
    api("/api/status?window=" + state.timeWindow)
  ]);
  state.rules = rules || [];
  state.presets = presets || [];
  state.status = status;
  renderRules();
  renderPresets();
  renderStatus();
}

async function refreshStatus() {
  if (!state.authenticated || state._refreshingStatus) return;
  state._refreshingStatus = true;
  try {
    state.status = await api("/api/status?window=" + state.timeWindow);
    renderStatus();
    renderPrivateStatus();
    if (state.page === "queries" && state.livePolling) {
      await loadQueries();
    }
  } catch (error) {
    toast(error.message, true);
  } finally {
    state._refreshingStatus = false;
  }
}

function renderAll() {
  renderStatus();
  renderRules();
  renderFeeds();
  renderCatalog();
  renderProtectionCategories();
  renderPresets();
  renderDnsForms();
  renderPrivateForm();
  renderPrivateStatus();
  renderSystemForm();
  fillProfiles();
  renderDevices();
  renderProfilesEditor();
}

function isResolverHealthy() {
  const s = state.status || {};
  return Boolean(s.resolver && s.resolver.running && s.dot && s.dot.running);
}

function friendlyFrpState(value) {
  const names = {
    online: "Connected",
    connecting: "Connecting",
    error: "Error",
    stopped: "Stopped",
    disabled: "Disabled"
  };
  return names[value] || "Unknown";
}

function friendlyAction(action) {
  const names = {
    allowed: "Allowed",
    blocked: "Blocked",
    rewritten: "Rewritten",
    refused: "Refused",
    error: "Error",
    deny: "Block",
    allow: "Allow",
    rewrite: "Rewrite"
  };
  return names[action] || action;
}

function profileName(id) {
  if (!id || id === "*") return "All clients";
  const profile = ((state.config && state.config.profiles) || []).find(item => item.id === id);
  return profile ? profile.name : id;
}

function defaultProfile() {
  const list = (state.config && state.config.profiles) || [];
  return list.find(item => item.id === "default") || list[0];
}

function renderStatus() {
  const s = state.status;
  if (!s || !state.config) return;

  const dashboard = s.dashboard || {};
  const total = Number(dashboard.total || 0);
  const blocked = Number(dashboard.blocked || 0);
  const allowed = Number(dashboard.allowed != null ? dashboard.allowed : Math.max(0, total - blocked));
  const rewritten = Number(dashboard.rewritten || 0);
  const errors = Number(dashboard.errors || 0);
  const healthy = isResolverHealthy();
  const privateReady = healthy && Boolean(s.tls && s.tls.valid && !s.tls.self_signed);

  $("#queries-total").textContent = number(total);
  $("#blocked-rate").textContent = (total ? (blocked / total) * 100 : 0).toFixed(1) + "%";
  $("#blocked-count").textContent = number(blocked) + " blocked requests.";
  $("#mean-latency").textContent = Number(dashboard.latency || 0).toFixed(1) + " ms";
  $("#policy-size").textContent = number((s.policy || {}).indexed_domains || 0);

  if ($("#pill-allowed")) $("#pill-allowed").textContent = number(allowed);
  if ($("#pill-blocked")) $("#pill-blocked").textContent = number(blocked);
  if ($("#pill-rewritten")) $("#pill-rewritten").textContent = number(rewritten);
  if ($("#pill-errors")) $("#pill-errors").textContent = number(errors);

  const l1 = s.l1_cache || (s.dot && (s.dot.l1_cache || s.dot.cache)) || {};
  const hitRatePct = Number(l1.hit_rate != null ? l1.hit_rate : (l1.hit_rate_pct || 0)).toFixed(1) + "%";
  if ($("#pill-l1-hit")) $("#pill-l1-hit").textContent = hitRatePct;
  if ($("#l1-hit-rate")) $("#l1-hit-rate").textContent = hitRatePct;
  if ($("#l1-hit-detail")) {
    $("#l1-hit-detail").textContent = number(l1.hits || 0) + " hits / " + number(l1.misses || 0) + " misses";
  }
  if ($("#l1-active-entries")) $("#l1-active-entries").textContent = number(l1.active_entries || l1.entries || l1.size || 0);
  if ($("#l1-capacity-detail")) $("#l1-capacity-detail").textContent = "Max " + number(l1.max_entries || 8192) + " RRsets";
  if ($("#l1-stale-hits")) $("#l1-stale-hits").textContent = number(l1.stale_hits || 0);
  renderL1CacheEntries(l1.top_entries || []);

  const clients = dashboard.top_clients || [];
  const devCount = (state.devices && state.devices.length) || 0;
  if ($("#clients-total")) {
    $("#clients-total").textContent = number(Math.max(clients.length, devCount, total > 0 ? 1 : 0));
  }

  $("#dashboard-status").textContent = healthy ? "Running" : "Needs attention";
  $("#dashboard-status-dot").className = "status-dot " + (healthy ? "good" : "bad");
  $("#dashboard-status-help").textContent = healthy
    ? (privateReady ? "Resolver and Private DNS listener are ready." : "Resolver is running. Complete TLS setup for Android Private DNS.")
    : "One or more DNS services require attention.";

  const servicePill = $("#service-pill");
  if (servicePill) {
    servicePill.className = "badge " + (healthy ? "allowed" : "error");
    servicePill.innerHTML = '<span class="pulse-indicator"></span>' + (healthy ? "Operational" : "Degraded");
  }

  $("#system-dot").className = "status-dot " + (healthy ? "good" : "bad");
  $("#rail-state").textContent = healthy ? "DNS is running" : "DNS needs attention";
  $("#sidebar-hostname").textContent = state.config.hostname || "Private DNS not configured";

  const dotReady = Boolean(s.dot && s.dot.running && s.dot.certificate_ready);
  $("#dot-state").textContent = dotReady ? "Ready" : (s.dot && s.dot.running ? "Waiting for certificate" : "Offline");
  $("#dot-listener").className = "status-dot " + (dotReady ? "good" : "warn");

  const tls = s.tls || {};
  const days = Number(tls.days_left || 0);
  $("#tls-state").textContent = tls.valid ? days.toFixed(0) + " days left" : "Not installed";
  $("#dot-certificate").className = "status-dot " + (tls.valid ? "good" : "warn");

  if ($("#cert-days-left")) {
    $("#cert-days-left").textContent = tls.valid ? Math.round(days) + " days remaining" : "No active certificate";
  }
  const certRect = $("#cert-progress-rect");
  if (certRect) {
    const pct = tls.valid ? Math.max(4, Math.min(100, Math.round((days / 90) * 100))) : 0;
    certRect.setAttribute("width", String(pct));
    certRect.setAttribute("class", "metric-bar-fill " + (days > 25 ? "good" : days > 10 ? "warn" : "bad"));
  }

  const frp = s.frp || {};
  const frpEnabled = Boolean(state.config.frp && state.config.frp.enabled);
  $("#frp-state").textContent = frpEnabled ? friendlyFrpState(frp.state) : "Disabled";
  $("#dot-frp").className = "status-dot " + (!frpEnabled ? "neutral" : frp.state === "online" ? "good" : frp.state === "error" ? "bad" : "warn");
  $("#last-query").textContent = ago(s.dot && s.dot.last_query);

  const threat = s.threat || {};
  $("#nx-ratio").textContent = (Number(threat.nxdomain_ratio || 0) * 100).toFixed(1) + "%";
  $("#unique-domains").textContent = number(threat.unique_domains);
  $("#hour-queries").textContent = number(threat.queries);

  if ($("#p50-latency")) $("#p50-latency").textContent = "P50: " + Number(dashboard.p50_latency || 0).toFixed(1) + " ms";
  if ($("#p95-latency")) $("#p95-latency").textContent = "P95: " + Number(dashboard.p95_latency || 0).toFixed(1) + " ms";
  if ($("#p99-latency")) $("#p99-latency").textContent = "P99: " + Number(dashboard.p99_latency || 0).toFixed(1) + " ms";

  const dotMetrics = (s.dot && s.dot.metrics) || {};
  const dotQ = Number(dotMetrics.dot_queries || 0);
  const dohQ = Number(dotMetrics.doh_queries || 0);
  if ($("#proto-dot-count")) $("#proto-dot-count").textContent = "DoT :853 — " + number(dotQ);
  if ($("#proto-doh-count")) $("#proto-doh-count").textContent = "DoH :443 — " + number(dohQ);

  const tlsPool = (s.dot && s.dot.tls_pool) || {};
  if ($("#pool-hits-count")) $("#pool-hits-count").textContent = "Pool Hits: " + number(tlsPool.pool_hits || 0);
  if ($("#prefetch-count")) $("#prefetch-count").textContent = "Prefetches: " + number(l1.prefetches || 0);
  if ($("#sec-blocks-count")) $("#sec-blocks-count").textContent = number(dashboard.security_blocks_window || 0) + " security/focus blocks";

  if (Array.isArray(dashboard.recent_live) && dashboard.recent_live.length) {
    state.liveRecent = dashboard.recent_live.slice(0, 8);
  }

  renderChart(dashboard.series || []);
  renderHealth(s.upstreams || []);
  renderSetupGuide();
  renderTopDomains(dashboard);
  renderTopology(s, state.config);
  renderDGA(threat);
  updateSnoozeUI(s.pause_blocking);
  renderSchedule(s.schedule, s.schedule_active);
  const sysInfo = s.system_info || {};
  if ($("#sys-db-size")) {
    $("#sys-db-size").textContent = (sysInfo.db_size_mb >= 1)
      ? Number(sysInfo.db_size_mb).toFixed(2) + " MB"
      : Number(sysInfo.db_size_kb || 0).toFixed(1) + " KB";
  }
  if ($("#sys-queries-count")) $("#sys-queries-count").textContent = number(sysInfo.total_queries_stored || 0);
  if ($("#sys-feed-domains-count")) $("#sys-feed-domains-count").textContent = number(sysInfo.total_feed_domains || 0);
  if ($("#sys-devices-count")) $("#sys-devices-count").textContent = number(sysInfo.total_devices || 0);

  renderSecurityShields(s.security_shields || state.config);
  renderLivePulse(state.liveRecent);
  ensureSSEStream();
}

function updateSnoozeUI(status) {
  const snoozeWrap = $("#snooze-indicator-wrap");
  const snoozeText = $("#snooze-timer-label");
  if (!snoozeWrap || !snoozeText) return;

  if (status && status.paused && status.remaining > 0) {
    state.snoozeRemaining = status.remaining;
    snoozeWrap.classList.remove("hidden");
    const formatSnooze = (rem) => {
      const m = Math.floor(rem / 60);
      const sec = rem % 60;
      return "Blocking Paused (" + String(m).padStart(2, "0") + ":" + String(sec).padStart(2, "0") + ") — Click to Resume";
    };
    snoozeText.textContent = formatSnooze(state.snoozeRemaining);

    if (!state.snoozeTimer) {
      state.snoozeTimer = setInterval(() => {
        if (state.snoozeRemaining <= 0) {
          clearInterval(state.snoozeTimer);
          state.snoozeTimer = null;
          snoozeWrap.classList.add("hidden");
          refreshStatus();
          return;
        }
        state.snoozeRemaining -= 1;
        snoozeText.textContent = formatSnooze(state.snoozeRemaining);
      }, 1000);
    }
  } else {
    if (state.snoozeTimer) {
      clearInterval(state.snoozeTimer);
      state.snoozeTimer = null;
    }
    snoozeWrap.classList.add("hidden");
  }
}

function renderTopology(status, config) {
  const hostLabel = $("#topo-hostname-label");
  if (hostLabel) {
    hostLabel.textContent = config.hostname ? config.hostname : "Android DoT / HTTPS DoH";
  }

  const frpLabel = $("#topo-frp-state");
  if (frpLabel) {
    if (!config.frp || !config.frp.enabled) {
      frpLabel.textContent = "Direct TCP 853 Listener";
    } else {
      frpLabel.textContent = status.frp && status.frp.state === "online" ? "FRP Bridge Online" : "FRP Tunnel " + friendlyFrpState(status.frp && status.frp.state);
    }
  }

  const policyLabel = $("#topo-policy-status");
  if (policyLabel) {
    const rulesCount = (state.rules || []).length;
    const defProf = defaultProfile() || { categories: [] };
    const catCount = Array.isArray(defProf.categories) ? defProf.categories.length : 0;
    policyLabel.textContent = rulesCount + " rules • " + catCount + " active categories";
  }

  const upstreamLabel = $("#topo-upstream-status");
  if (upstreamLabel) {
    const upRows = status.upstreams || [];
    const healthyCount = upRows.filter(u => Number(u.healthy) === 1).length;
    const enabledCount = (config.upstreams || []).filter(u => u.enabled).length;
    upstreamLabel.textContent = healthyCount > 0
      ? healthyCount + "/" + enabledCount + " DoT Upstreams Online"
      : enabledCount + " DoT Upstreams Configured";
  }
}

function renderTopDomains(dashboard) {
  const allowedNode = $("#top-allowed-list");
  const blockedNode = $("#top-blocked-list");
  const allowed = dashboard.top_allowed || [];
  const blocked = dashboard.top_blocked || [];

  if (allowedNode) {
    if (!allowed.length) {
      allowedNode.innerHTML = '<div class="empty-state">No allowed domain queries recorded yet.</div>';
    } else {
      const maxCount = Math.max(1, ...allowed.map(x => Number(x.count || 0)));
      allowedNode.innerHTML = allowed.map(item => {
        const pct = Math.round((Number(item.count || 0) / maxCount) * 100);
        return (
          '<div class="ranked-row">' +
            '<div class="ranked-info">' +
              '<div class="ranked-domain-line">' +
                '<span class="ranked-domain" title="' + escapeHtml(item.domain) + '">' + escapeHtml(item.domain) + "</span>" +
                '<span class="ranked-count">' + number(item.count) + "</span>" +
              "</div>" +
              svgBar(pct, "allowed") +
            "</div>" +
            '<button type="button" class="btn-mini-action" data-action="quick-block" data-domain="' + escapeHtml(item.domain) + '">Block</button>' +
          "</div>"
        );
      }).join("");
    }
  }

  if (blockedNode) {
    if (!blocked.length) {
      blockedNode.innerHTML = '<div class="empty-state">No blocked domains recorded in this window.</div>';
    } else {
      const maxCount = Math.max(1, ...blocked.map(x => Number(x.count || 0)));
      blockedNode.innerHTML = blocked.map(item => {
        const pct = Math.round((Number(item.count || 0) / maxCount) * 100);
        return (
          '<div class="ranked-row">' +
            '<div class="ranked-info">' +
              '<div class="ranked-domain-line">' +
                '<span class="ranked-domain" title="' + escapeHtml(item.domain) + '">' + escapeHtml(item.domain) + "</span>" +
                '<span class="ranked-count">' + number(item.count) + "</span>" +
              "</div>" +
              svgBar(pct, "blocked") +
            "</div>" +
            '<button type="button" class="btn-mini-action" data-action="quick-allow" data-domain="' + escapeHtml(item.domain) + '">Allow</button>' +
          "</div>"
        );
      }).join("");
    }
  }

  const clientsNode = $("#top-clients-list");
  const qtypesNode = $("#qtype-breakdown-list");
  const topClients = dashboard.top_clients || [];
  const qtypes = dashboard.qtypes || [];

  if (clientsNode) {
    if (!topClients.length) {
      clientsNode.innerHTML = '<div class="empty-state">No client endpoint telemetry recorded yet.</div>';
    } else {
      const maxClient = Math.max(1, ...topClients.map(x => Number(x.count || 0)));
      clientsNode.innerHTML = topClients.map(item => {
        const cnt = Number(item.count || 0);
        const blk = Number(item.blocked || 0);
        const pct = Math.round((cnt / maxClient) * 100);
        const blkPct = cnt ? Math.round((blk / cnt) * 100) : 0;
        const label = item.name ? item.name + " (" + item.client + ")" : item.client;
        return (
          '<div class="ranked-row">' +
            '<div class="ranked-info">' +
              '<div class="ranked-domain-line">' +
                '<span class="ranked-domain" title="' + escapeHtml(label) + '">' + escapeHtml(label) + "</span>" +
                '<span class="ranked-count">' + number(cnt) + " (" + blkPct + "% blocked)</span>" +
              "</div>" +
              svgBar(pct, "good") +
            "</div>" +
            '<button type="button" class="btn-mini-action dev-insights-btn" data-ip="' + escapeHtml(item.client) + '">Insights</button>' +
          "</div>"
        );
      }).join("");
    }
  }

  if (qtypesNode) {
    if (!qtypes.length) {
      qtypesNode.innerHTML = '<div class="empty-state">No query type distribution recorded yet.</div>';
    } else {
      const totalQ = Math.max(1, qtypes.reduce((acc, x) => acc + Number(x.count || 0), 0));
      qtypesNode.innerHTML = qtypes.map(item => {
        const cnt = Number(item.count || 0);
        const share = ((cnt / totalQ) * 100).toFixed(1);
        const pct = Math.max(4, Math.round((cnt / totalQ) * 100));
        const tname = QTYPE_NAMES[item.qtype] || ("TYPE" + item.qtype);
        return (
          '<div class="ranked-row">' +
            '<div class="ranked-info">' +
              '<div class="ranked-domain-line">' +
                '<span class="ranked-domain"><span class="code-pill">' + escapeHtml(tname) + "</span></span>" +
                '<span class="ranked-count">' + number(cnt) + " (" + share + "%)</span>" +
              "</div>" +
              svgBar(pct, "purple") +
            "</div>" +
          "</div>"
        );
      }).join("");
    }
  }
}

function renderDGA(threat) {
  const card = $("#dga-card");
  const body = $("#dga-body");
  if (!card || !body) return;
  const dga = (threat && threat.dga_suspicious) || [];
  if (!dga.length) {
    card.classList.add("hidden");
    body.innerHTML = "";
    return;
  }
  card.classList.remove("hidden");
  body.innerHTML = dga.map(item =>
    '<div class="list-row">' +
      '<div class="list-row-main">' +
        '<span class="code-pill">' + escapeHtml(item.domain) + "</span>" +
        '<span class="badge warn">H=' + Number(item.entropy).toFixed(2) + "</span>" +
      "</div>" +
      '<button type="button" class="btn-mini-action" data-action="quick-block" data-domain="' + escapeHtml(item.domain) + '">Block</button>' +
    "</div>"
  ).join("");
}

function renderSetupGuide() {
  const s = state.status || {};
  const cfg = state.config || {};
  const hostnameDone = Boolean(cfg.hostname);
  const certDone = Boolean(s.tls && s.tls.valid && !s.tls.self_signed && s.tls.hostname_matches !== false);
  const listenerDone = Boolean(s.dot && s.dot.running && s.dot.certificate_ready);
  const allDone = hostnameDone && certDone && listenerDone;
  $("#setup-guide").classList.toggle("hidden", allDone);

  const steps = [
    {
      done: hostnameDone,
      title: "Configure your Private DNS hostname",
      help: hostnameDone ? cfg.hostname : "Example: dns.example.com",
      target: "private"
    },
    {
      done: certDone,
      title: "Activate a matching TLS certificate",
      help: certDone ? "Certificate is valid and active" : "Issue via Cloudflare DNS-01 or upload PEM",
      target: "private"
    },
    {
      done: listenerDone,
      title: "Expose TCP port 853 or HTTPS DoH",
      help: listenerDone ? "DoT & DoH listeners are ready" : "Direct port 853, FRP PROXY bridge, or Railway 443 DoH",
      target: "private"
    }
  ];

  $("#setup-steps").innerHTML = steps.map((step, index) =>
    '<div class="setup-step ' + (step.done ? "done" : "") + '">' +
      '<span class="setup-check">' + (step.done ? "✓" : index + 1) + "</span>" +
      "<div><strong>" + escapeHtml(step.title) + "</strong><small>" + escapeHtml(step.help) + "</small></div>" +
      (step.done ? "" : '<button type="button" class="text-button setup-go" data-target="' + step.target + '">Configure →</button>') +
    "</div>"
  ).join("");

  $$(".setup-go").forEach(button => button.addEventListener("click", () => switchPage(button.dataset.target)));
}

function buildSmoothPath(pts) {
  if (!pts.length) return "";
  if (pts.length === 1) return "M " + pts[0].x + " " + pts[0].y;
  let d = "M " + pts[0].x + " " + pts[0].y;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i];
    const p1 = pts[i + 1];
    const cx = Number(((p0.x + p1.x) / 2).toFixed(1));
    d += " C " + cx + " " + p0.y + ", " + cx + " " + p1.y + ", " + p1.x + " " + p1.y;
  }
  return d;
}

function renderChart(series) {
  const svg = $("#traffic-chart");
  if (!svg) return;
  if (!series.length) {
    svg.innerHTML = '<text x="500" y="125" text-anchor="middle" fill="currentColor" opacity="0.45" font-size="13">No query telemetry recorded in this window yet</text>';
    return;
  }
  const width = 1000;
  const height = 250;
  const padTop = 20;
  const padBottom = 30;
  const padLeft = 44;
  const padRight = 18;
  const chartWidth = width - padLeft - padRight;
  const chartHeight = height - padTop - padBottom;
  const mode = state.chartMode || "volume";
  const mappedSeries = series.map(item => {
    const tot = Number(item.total || 0);
    const blk = Number(item.blocked || 0);
    const alw = Math.max(0, tot - blk);
    const rate = tot > 0 ? Number(((blk / tot) * 100).toFixed(1)) : 0;
    return {
      bucket: item.bucket,
      total: tot,
      blocked: blk,
      allowed: alw,
      primary: mode === "block_rate" ? rate : (mode === "split" ? alw : tot),
      secondary: mode === "block_rate" ? 0 : blk
    };
  });

  const max = mode === "block_rate"
    ? 100
    : Math.max(4, ...mappedSeries.map(item => Math.max(item.primary, item.secondary)));

  const legendEl = $("#chart-legend");
  if (legendEl) {
    if (mode === "block_rate") {
      legendEl.innerHTML = '<span><i class="legend-dot blocked"></i>Block Ratio (%)</span>';
    } else if (mode === "split") {
      legendEl.innerHTML = '<span><i class="legend-dot total"></i>Allowed Queries</span><span><i class="legend-dot blocked"></i>Blocked Threats</span>';
    } else {
      legendEl.innerHTML = '<span><i class="legend-dot total"></i>Total Queries</span><span><i class="legend-dot blocked"></i>Blocked Threats</span>';
    }
  }

  // Update Chart Summary Bar
  let peakBucket = mappedSeries[0] || { bucket: 0, total: 0 };
  let sumTotal = 0;
  mappedSeries.forEach(b => {
    sumTotal += b.total;
    if (b.total >= peakBucket.total) peakBucket = b;
  });
  if ($("#chart-peak-label")) {
    if (peakBucket && peakBucket.bucket && peakBucket.total > 0) {
      const pd = new Date(Number(peakBucket.bucket) * 1000);
      const pt = String(pd.getHours()).padStart(2, "0") + ":" + String(pd.getMinutes()).padStart(2, "0");
      $("#chart-peak-label").textContent = pt + " (" + number(peakBucket.total) + " q)";
    } else {
      $("#chart-peak-label").textContent = "—";
    }
  }
  if ($("#chart-avg-label")) {
    const avg = mappedSeries.length ? Math.round(sumTotal / mappedSeries.length) : 0;
    $("#chart-avg-label").textContent = number(avg) + " queries";
  }
  if ($("#chart-cache-label")) {
    const dash = (state.status && state.status.dashboard) || {};
    const l1 = (state.status && state.status.l1_cache) || {};
    $("#chart-cache-label").textContent = number(dash.cache_hits_window || l1.hits || 0);
  }

  const getCoord = (val, idx) => {
    const x = mappedSeries.length === 1 ? padLeft + chartWidth / 2 : padLeft + (idx * chartWidth) / (mappedSeries.length - 1);
    const y = height - padBottom - (Number(val || 0) / max) * chartHeight;
    return { x: Number(x.toFixed(1)), y: Number(y.toFixed(1)), val: Number(val || 0) };
  };

  let grid = "";
  for (let i = 0; i <= 4; i++) {
    const y = padTop + (chartHeight / 4) * i;
    const scaleVal = Math.round(max * (1 - i / 4)) + (mode === "block_rate" ? "%" : "");
    grid += '<line class="chart-grid" x1="' + padLeft + '" x2="' + (width - padRight) + '" y1="' + y.toFixed(1) + '" y2="' + y.toFixed(1) + '"></line>';
    if (i === 0 || i === 2 || i === 4) {
      grid += '<text class="chart-axis-label" x="' + (padLeft - 8) + '" y="' + (y + 3.5).toFixed(1) + '" text-anchor="end">' + scaleVal + '</text>';
    }
  }

  let totalPoints = mappedSeries.map((s, i) => getCoord(s.primary, i));
  let blockedPoints = mappedSeries.map((s, i) => getCoord(s.secondary, i));
  if (series.length === 1) {
    totalPoints = [{ x: padLeft, y: totalPoints[0].y, val: totalPoints[0].val }, { x: width - padRight, y: totalPoints[0].y, val: totalPoints[0].val }];
    blockedPoints = [{ x: padLeft, y: blockedPoints[0].y, val: blockedPoints[0].val }, { x: width - padRight, y: blockedPoints[0].y, val: blockedPoints[0].val }];
  }

  const bottomY = height - padBottom;
  const firstX = totalPoints[0].x;
  const lastX = totalPoints[totalPoints.length - 1].x;

  const totalLinePath = buildSmoothPath(totalPoints);
  const blockedLinePath = buildSmoothPath(blockedPoints);
  const totalAreaPath = totalLinePath + " L " + lastX + " " + bottomY + " L " + firstX + " " + bottomY + " Z";
  const blockedAreaPath = blockedLinePath + " L " + lastX + " " + bottomY + " L " + firstX + " " + bottomY + " Z";

  let xAxisLabels = "";
  const labelStep = Math.max(1, Math.floor((series.length - 1) / 4));
  for (let i = 0; i < series.length; i += labelStep) {
    const pt = totalPoints[i];
    const bTs = Number(series[i].bucket || 0);
    if (pt && bTs > 0) {
      const d = new Date(bTs * 1000);
      const tStr = String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
      xAxisLabels += '<text class="chart-axis-label" x="' + pt.x + '" y="' + (height - 8) + '" text-anchor="middle">' + tStr + '</text>';
    }
  }

  const dots = totalPoints
    .map((p, idx) => (p.val > 0 || idx === totalPoints.length - 1 ? '<circle class="chart-dot-total" cx="' + p.x + '" cy="' + p.y + '" r="3.5"/>' : ""))
    .join("") +
    blockedPoints
    .map((p, idx) => (p.val > 0 || idx === blockedPoints.length - 1 ? '<circle class="chart-dot-blocked" cx="' + p.x + '" cy="' + p.y + '" r="3"/>' : ""))
    .join("");

  svg.innerHTML =
    "<defs>" +
      '<linearGradient id="grad-total" x1="0%" y1="0%" x2="0%" y2="100%">' +
        '<stop offset="0%" stop-color="var(--primary)" stop-opacity="0.34"/>' +
        '<stop offset="100%" stop-color="var(--primary)" stop-opacity="0.0"/>' +
      "</linearGradient>" +
      '<linearGradient id="grad-blocked" x1="0%" y1="0%" x2="0%" y2="100%">' +
        '<stop offset="0%" stop-color="var(--red)" stop-opacity="0.38"/>' +
        '<stop offset="100%" stop-color="var(--red)" stop-opacity="0.0"/>' +
      "</linearGradient>" +
    "</defs>" +
    grid +
    xAxisLabels +
    '<path class="chart-area-total" d="' + totalAreaPath + '"></path>' +
    '<path class="chart-area-blocked" d="' + blockedAreaPath + '"></path>' +
    '<path class="chart-line-total" d="' + totalLinePath + '"></path>' +
    '<path class="chart-line-blocked" d="' + blockedLinePath + '"></path>' +
    dots +
    '<line id="chart-crosshair" class="chart-crosshair hidden" x1="0" x2="0" y1="' + padTop + '" y2="' + bottomY + '"></line>' +
    '<circle id="chart-halo-total" class="chart-halo-total hidden" cx="0" cy="0" r="6"></circle>' +
    '<circle id="chart-halo-blocked" class="chart-halo-blocked hidden" cx="0" cy="0" r="5.5"></circle>';

  const handleScrub = (clientX) => {
    const rect = svg.getBoundingClientRect();
    if (!rect.width) return;
    const relX = ((clientX - rect.left) / rect.width) * width;
    let bestIdx = 0;
    let bestDist = Infinity;
    totalPoints.forEach((pt, idx) => {
      const dist = Math.abs(pt.x - relX);
      if (dist < bestDist) {
        bestDist = dist;
        bestIdx = idx;
      }
    });
    const tPt = totalPoints[bestIdx];
    const bPt = blockedPoints[bestIdx];
    const bucketObj = series[bestIdx] || series[0];
    const cross = $("#chart-crosshair");
    const hTot = $("#chart-halo-total");
    const hBlk = $("#chart-halo-blocked");
    const readout = $("#chart-hover-readout");
    if (cross && tPt) {
      cross.setAttribute("x1", String(tPt.x));
      cross.setAttribute("x2", String(tPt.x));
      cross.classList.remove("hidden");
    }
    if (hTot && tPt) {
      hTot.setAttribute("cx", String(tPt.x));
      hTot.setAttribute("cy", String(tPt.y));
      hTot.classList.remove("hidden");
    }
    if (hBlk && bPt) {
      hBlk.setAttribute("cx", String(bPt.x));
      hBlk.setAttribute("cy", String(bPt.y));
      hBlk.classList.remove("hidden");
    }
    if (readout && bucketObj) {
      const d = new Date(Number(bucketObj.bucket || 0) * 1000);
      const tLabel = String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
      const totVal = Number(bucketObj.total || 0);
      const blkVal = Number(bucketObj.blocked || 0);
      const pct = totVal ? ((blkVal / totVal) * 100).toFixed(0) : "0";
      readout.textContent = tLabel + " • " + number(totVal) + " queries • " + number(blkVal) + " blocked (" + pct + "%)";
      readout.classList.remove("hidden");
    }
  };

  svg.onmousemove = (e) => handleScrub(e.clientX);
  svg.ontouchmove = (e) => {
    if (e.touches && e.touches[0]) handleScrub(e.touches[0].clientX);
  };
  svg.onmouseleave = () => {
    $("#chart-crosshair")?.classList.add("hidden");
    $("#chart-halo-total")?.classList.add("hidden");
    $("#chart-halo-blocked")?.classList.add("hidden");
    $("#chart-hover-readout")?.classList.add("hidden");
  };
}

function renderSchedule(sched, isActive) {
  if (!sched) return;
  const badge = $("#schedule-status-badge");
  const enabledInput = $("#sched-enabled");
  const startInput = $("#sched-start");
  const endInput = $("#sched-end");
  const profSelect = $("#sched-profile");
  if (enabledInput && document.activeElement !== enabledInput) {
    enabledInput.checked = Boolean(sched.enabled);
  }
  if (startInput && document.activeElement !== startInput) {
    startInput.value = sched.start || "22:00";
  }
  if (endInput && document.activeElement !== endInput) {
    endInput.value = sched.end || "07:00";
  }
  if (profSelect && document.activeElement !== profSelect) {
    profSelect.value = sched.profile || "*";
  }
  const activeDays = new Set(Array.isArray(sched.days) ? sched.days : ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]);
  $$("#sched-days-pills .day-pill").forEach(btn => {
    btn.classList.toggle("active", activeDays.has(btn.dataset.day));
  });

  const statusText = !sched.enabled
    ? "Standby"
    : (isActive ? "Active Window (" + sched.start + "–" + sched.end + ")" : "Armed (" + sched.start + "–" + sched.end + ")");
  const statusClass = !sched.enabled ? "badge info" : (isActive ? "badge blocked" : "badge allowed");

  if (badge) {
    badge.className = statusClass;
    badge.textContent = statusText;
  }
  if ($("#dash-schedule-pill")) {
    $("#dash-schedule-pill").className = statusClass;
    $("#dash-schedule-pill").textContent = statusText;
  }
  if ($("#dash-schedule-summary")) {
    const daysLabel = activeDays.size === 7 ? "Every day" : Array.from(activeDays).map(d => d.toUpperCase()).join(", ");
    const profLabel = profileName(sched.profile || "*");
    $("#dash-schedule-summary").textContent = sched.enabled
      ? (sched.mode || "curfew").toUpperCase() + " • " + sched.start + "–" + sched.end + " • " + daysLabel + " • " + profLabel
      : "Standby — Click Configure to set Bedtime Curfew or Deep Work hours";
  }
}

function renderSecurityShields(shields) {
  if (!shields) return;
  const keys = ["dnssec", "rebinding_protection", "block_doh_canary", "safesearch", "block_risky_tlds", "block_punycode"];
  let activeCount = 0;
  keys.forEach(k => {
    const on = k === "rebinding_protection" || k === "block_doh_canary" || k === "dnssec"
      ? shields[k] !== false
      : Boolean(shields[k]);
    if (on) activeCount += 1;
    const tile = $('#dash-shields-grid .shield-tile[data-shield="' + k + '"]');
    if (tile) {
      tile.classList.toggle("active", on);
      const pill = tile.querySelector(".shield-pill");
      if (pill) pill.textContent = on ? "ON" : "OFF";
    }
  });
  if ($("#active-shields-badge")) {
    $("#active-shields-badge").textContent = activeCount + "/6 Shields";
    $("#active-shields-badge").className = "badge " + (activeCount >= 3 ? "info" : "warn");
  }
  const secScore = (state.status && state.status.security_score) || null;
  if ($("#security-score-badge") && secScore) {
    $("#security-score-badge").textContent = "Grade " + (secScore.grade || "A") + " • " + (secScore.score || 90) + "/100";
    $("#security-score-badge").className = "badge " + ((secScore.score || 0) >= 85 ? "allowed" : "warn");
    $("#security-score-badge").title = (secScore.breakdown || []).join(" | ");
  }
}

function renderLivePulse(items) {
  const container = $("#dash-live-list");
  if (!container) return;
  if (!items || !items.length) {
    container.innerHTML = '<div class="empty-state">No recent DNS queries recorded yet.</div>';
    return;
  }
  container.innerHTML = items.slice(0, 7).map(q => {
    const qtypeLabel = QTYPE_NAMES[q.qtype] || ("TYPE" + q.qtype);
    const isBlocked = q.action === "blocked" || q.action === "refused";
    const badgeTone = q.action === "allowed" ? "allowed" : (q.action === "rewritten" ? "info" : "blocked");
    const clientLabel = q.device_name ? (q.device_name + " (" + q.client + ")") : q.client;
    const quickAction = isBlocked ? "quick-allow" : "quick-block";
    const quickLabel = isBlocked ? "Allow" : "Block";
    return (
      '<div class="live-pulse-row">' +
        '<div class="live-pulse-main">' +
          '<div class="live-pulse-domain-line">' +
            '<span class="badge ' + badgeTone + '">' + escapeHtml(friendlyAction(q.action)) + '</span>' +
            '<span class="live-pulse-domain" title="' + escapeHtml(q.domain) + '">' + escapeHtml(q.domain || ".") + '</span>' +
          '</div>' +
          '<div class="live-pulse-meta">' +
            '<span class="code-pill">' + escapeHtml(qtypeLabel) + '</span>' +
            '<span>' + escapeHtml(clientLabel || "127.0.0.1") + '</span>' +
            '<span>• ' + Number(q.latency || 0).toFixed(1) + ' ms</span>' +
            (q.detail ? '<span>• ' + escapeHtml(q.detail) + '</span>' : "") +
          '</div>' +
        '</div>' +
        '<button type="button" class="btn-mini-action" data-action="' + quickAction + '" data-domain="' + escapeHtml(q.domain) + '">' + quickLabel + '</button>' +
      '</div>'
    );
  }).join("");
}

function ensureSSEStream() {
  if (!state.authenticated || !state.livePolling) return;
  if (state.sseTimer) return;
  state.sseTimer = setTimeout(async () => {
    state.sseTimer = null;
    if (!state.authenticated || !state.livePolling) return;
    try {
      const res = await api("/api/events?since=" + Number(state.lastEventSeq || 0));
      if (res && res.seq != null) state.lastEventSeq = res.seq;
      const evs = (res && res.events) || [];
      if (evs.length) {
        const reversed = evs.slice().reverse();
        const seen = new Set();
        const combined = reversed.concat(state.liveRecent || []).filter(item => {
          const key = (item.seq || item.id || "") + ":" + item.ts + ":" + item.domain;
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        });
        state.liveRecent = combined.slice(0, 8);
        renderLivePulse(state.liveRecent);
      }
    } catch (_) {}
  }, 2500);
}

function renderL1CacheEntries(entries) {
  const body = $("#l1-entries-body");
  if (!body) return;
  if (!entries || !entries.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty-state">No cached RRsets in L1 memory yet.</td></tr>';
    return;
  }
  body.innerHTML = entries.slice(0, 12).map(item =>
    "<tr>" +
      '<td class="domain">' + escapeHtml(item.domain) + "</td>" +
      '<td><span class="code-pill">' + escapeHtml(item.type || "A") + "</span></td>" +
      "<td><small>" + escapeHtml(item.summary || "NOERROR") + "</small></td>" +
      '<td><span class="latency-pill">' + number(item.ttl_remaining || 0) + "s</span></td>" +
      "<td><strong>" + number(item.hits || 0) + "</strong></td>" +
      '<td class="cell-right"><button type="button" class="btn-mini-action evict-l1-btn" data-domain="' + escapeHtml(item.domain) + '">Evict</button></td>' +
    "</tr>"
  ).join("");

  $$(".evict-l1-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const dom = btn.dataset.domain;
      try {
        await api("/api/cache/evict", { method: "POST", body: { domain: dom } });
        toast("Evicted " + dom + " from L1 cache");
        await refreshStatus();
      } catch (err) {
        toast(err.message, true);
      }
    });
  });
}

async function loadQrCode(target) {
  const wrap = $("#qr-svg-container");
  const cap = $("#qr-caption-label");
  if (!wrap) return;
  try {
    const res = await api("/api/qr?target=" + encodeURIComponent(target || "doh"));
    if (res && res.svg) {
      wrap.innerHTML = res.svg;
    }
    if (cap && res && res.label) {
      cap.textContent = res.label;
    }
  } catch (_) {
    wrap.innerHTML = '<span class="muted">QR ready after login</span>';
  }
}

function renderHealth(rows) {
  const names = new Map(((state.config && state.config.upstreams) || []).map(item => [item.id, item.name]));
  const container = $("#upstream-health");
  if (!container) return;
  if (!rows.length) {
    container.innerHTML = '<div class="empty-state">Upstream TLS probes are initializing...</div>';
    return;
  }
  container.innerHTML = rows.map(row => {
    const good = Number(row.healthy) === 1;
    const lat = Number(row.latency || 0);
    const message = good ? lat.toFixed(1) + " ms" : (row.error || "Unreachable");
    return (
      '<div class="list-row">' +
        '<div class="list-row-main">' +
          '<i class="status-dot ' + (good ? "good" : "bad") + '"></i>' +
          '<div class="list-row-copy">' +
            "<strong>" + escapeHtml(names.get(row.upstream) || row.upstream) + "</strong>" +
            "<small>" + escapeHtml(good ? "Certificate-verified DoT active" : "TLS probe failed") + "</small>" +
          "</div>" +
        "</div>" +
        '<div class="list-row-meta">' +
          '<span class="latency-pill ' + (!good || lat > 85 ? "slow" : "") + '">' + escapeHtml(message) + "</span>" +
        "</div>" +
      "</div>"
    );
  }).join("");
}

function fillProfiles() {
  const profiles = (state.config && state.config.profiles) || [];
  const options = ['<option value="*">All clients (*)</option>'].concat(
    profiles.map(p => '<option value="' + escapeHtml(p.id) + '">' + escapeHtml(p.name) + "</option>")
  ).join("");
  if ($("#rule-profile")) $("#rule-profile").innerHTML = options;
  if ($("#bulk-rules-profile")) $("#bulk-rules-profile").innerHTML = options;
  if ($("#sched-profile")) {
    const prev = (state.status && state.status.schedule && state.status.schedule.profile) || $("#sched-profile").value || "*";
    $("#sched-profile").innerHTML = options;
    $("#sched-profile").value = prev;
  }
}

async function loadQueries() {
  const q = ($("#query-search") ? $("#query-search").value : "").trim().toLowerCase();
  const filter = $("#query-filter") ? $("#query-filter").value : "all";
  const qtype = $("#query-qtype-filter") ? $("#query-qtype-filter").value : "0";
  const rcode = $("#query-rcode-filter") ? $("#query-rcode-filter").value : "all";
  let url = "/api/queries?limit=300";
  if (q) url += "&q=" + encodeURIComponent(q);
  if (filter && filter !== "all") url += "&action=" + encodeURIComponent(filter);
  if (qtype && qtype !== "0") url += "&qtype=" + encodeURIComponent(qtype);
  if (rcode && rcode !== "all") url += "&rcode=" + encodeURIComponent(rcode);

  state.queries = await api(url);
  renderQueries();
}

function renderQueries() {
  const search = ($("#query-search") ? $("#query-search").value : "").trim().toLowerCase();
  const filter = $("#query-filter") ? $("#query-filter").value : "all";
  const qtypeFilter = $("#query-qtype-filter") ? Number($("#query-qtype-filter").value) : 0;
  const rcodeFilter = $("#query-rcode-filter") ? $("#query-rcode-filter").value : "all";

  const rows = (state.queries || []).filter(row => {
    if (rcodeFilter !== "all" && Number(row.rcode) !== Number(rcodeFilter)) return false;
    if (
      search &&
      !String(row.domain || "").toLowerCase().includes(search) &&
      !String(row.client || "").toLowerCase().includes(search) &&
      !String(row.device_name || "").toLowerCase().includes(search)
    ) {
      return false;
    }
    if (filter !== "all" && row.action !== filter) return false;
    if (qtypeFilter !== 0 && Number(row.qtype) !== qtypeFilter) return false;
    return true;
  });

  const body = $("#query-body");
  const empty = $("#query-empty");
  if (!body || !empty) return;

  if (!rows.length) {
    body.innerHTML = "";
    empty.classList.remove("hidden");
    return;
  }

  empty.classList.add("hidden");
  body.innerHTML = rows.map((row, index) => {
    const typeLabel = QTYPE_NAMES[row.qtype] || row.qtype;
    const isBlocked = row.action === "blocked";
    const clientLabel = row.device_name ? row.device_name + " (" + row.client + ")" : row.client;
    const actionBtn = isBlocked
      ? '<button type="button" class="btn-mini-action" data-action="quick-allow" data-domain="' + escapeHtml(row.domain) + '">Allow</button>'
      : '<button type="button" class="btn-mini-action" data-action="quick-block" data-domain="' + escapeHtml(row.domain) + '">Block</button>';

    return (
      '<tr class="clickable-row" data-query-index="' + index + '">' +
        "<td>" + escapeHtml(new Date(row.ts * 1000).toLocaleTimeString()) + "</td>" +
        '<td class="domain" title="' + escapeHtml(row.domain) + '">' + escapeHtml(row.domain) + "</td>" +
        '<td><span class="code-pill">' + escapeHtml(typeLabel) + "</span></td>" +
        '<td><span class="badge ' + escapeHtml(row.action) + '">' + escapeHtml(friendlyAction(row.action)) + "</span></td>" +
        "<td><small>" + escapeHtml(clientLabel) + " • " + escapeHtml(profileName(row.profile)) + "</small></td>" +
        '<td><span class="latency-pill">' + Number(row.latency || 0).toFixed(1) + " ms</span></td>" +
        '<td class="cell-right">' + actionBtn + "</td>" +
      "</tr>"
    );
  }).join("");

  $$("#query-body tr.clickable-row").forEach(rowEl => {
    rowEl.addEventListener("click", (e) => {
      if (e.target.closest("button")) return;
      const idx = Number(rowEl.dataset.queryIndex);
      openQueryDrawer(rows[idx]);
    });
  });
}

function openQueryDrawer(query) {
  if (!query) return;
  const drawer = $("#query-drawer");
  const scrim = $("#drawer-scrim");
  if (!drawer || !scrim) return;

  const typeLabel = QTYPE_NAMES[query.qtype] || query.qtype;
  const isBlocked = query.action === "blocked";

  $("#drawer-domain").textContent = query.domain;
  const badge = $("#drawer-verdict-badge");
  badge.textContent = friendlyAction(query.action);
  badge.className = "badge " + query.action;

  $("#drawer-time").textContent = new Date(query.ts * 1000).toLocaleString() + " (" + ago(query.ts) + ")";
  $("#drawer-client").textContent = query.device_name ? query.device_name + " (" + query.client + ")" : query.client;
  $("#drawer-qtype").textContent = typeLabel + " (Type " + query.qtype + ")";
  $("#drawer-rcode").textContent = query.rcode === 0 ? "0 (NOERROR)" : query.rcode === 3 ? "3 (NXDOMAIN)" : query.rcode === 5 ? "5 (REFUSED)" : String(query.rcode);
  $("#drawer-latency").textContent = Number(query.latency || 0).toFixed(2) + " ms";

  $("#drawer-profile").textContent = profileName(query.profile);
  $("#drawer-verdict").textContent = friendlyAction(query.action);
  $("#drawer-source").textContent = query.detail || (isBlocked ? "Category Blocklist" : "Recursive Forwarder");

  const flagAd = $("#flag-ad");
  if (flagAd) flagAd.classList.toggle("active", query.rcode === 0 && Boolean(state.config && state.config.dnssec));

  const actBtn = $("#drawer-action-btn");
  if (actBtn) {
    actBtn.textContent = isBlocked ? "Allow / Whitelist Domain" : "Block / Deny Domain";
    actBtn.dataset.action = isBlocked ? "quick-allow" : "quick-block";
    actBtn.dataset.domain = query.domain;
  }

  const testBtn = $("#drawer-test-btn");
  if (testBtn) {
    testBtn.onclick = () => {
      closeQueryDrawer();
      switchPage("system");
      $("#diag-name").value = query.domain;
      $("#diag-type").value = String(query.qtype || 1);
      $("#diagnostic-form").dispatchEvent(new Event("submit"));
    };
  }

  drawer.classList.remove("hidden");
  scrim.classList.remove("hidden");
}

function closeQueryDrawer() {
  const drawer = $("#query-drawer");
  const scrim = $("#drawer-scrim");
  if (drawer) drawer.classList.add("hidden");
  if (scrim) scrim.classList.add("hidden");
}

function renderProtectionCategories() {
  if (!state.config || !state.config.profiles || !state.config.profiles.length) return;
  const profile = defaultProfile();
  const currentList = Array.isArray(profile.categories)
    ? profile.categories
    : Object.keys(profile.categories || {}).filter(k => profile.categories[k]);
  const selected = new Set(currentList);

  const presets = [
    ["ads", "Ads & Ad Networks", "Advertising banners, popups, and ad delivery CDNs"],
    ["tracking", "Trackers & Telemetry", "Behavioral analytics, fingerprinting, and beacons"],
    ["malware", "Malware & Phishing", "Command-and-control hosts, ransomware, and phishing"],
    ["adult", "Adult Content", "Explicit adult domains when adult lists are enabled"],
    ["social", "Social Networks", "Social media platforms when social lists are enabled"],
    ["custom", "Custom Category", "User-curated feeds assigned to the custom category"]
  ];
  const known = new Set(presets.map(item => item[0]));
  const extra = Array.from(selected)
    .filter(c => !known.has(c))
    .map(c => [c, c, "Custom category configured in profile"]);

  $("#category-grid").innerHTML = presets.concat(extra).map(item =>
    '<label class="category-card">' +
      '<div class="cat-copy"><strong>' + escapeHtml(item[1]) + "</strong><small>" + escapeHtml(item[2]) + "</small></div>" +
      '<input type="checkbox" class="switch-input category-toggle" value="' + escapeHtml(item[0]) + '" data-cat="' + escapeHtml(item[0]) + '" ' + (selected.has(item[0]) ? "checked" : "") + ">" +
    "</label>"
  ).join("");
}

function renderCatalog() {
  const grid = $("#catalog-grid");
  if (!grid) return;
  const catalog = state.catalog || [];
  const installedCount = catalog.filter(c => c.installed).length;
  if ($("#catalog-installed-badge")) {
    $("#catalog-installed-badge").textContent = installedCount + "/" + (catalog.length || 18) + " Installed";
    $("#catalog-installed-badge").className = "badge " + (installedCount > 0 ? "allowed" : "info");
  }
  const catFilter = state.catalogFilter || "all";
  const filtered = catalog.filter(item => {
    if (catFilter === "all") return true;
    if (catFilter === "family_social") return item.category === "adult" || item.category === "social" || item.category === "custom";
    return item.category === catFilter;
  });
  if (!filtered.length) {
    grid.innerHTML = '<div class="empty-state">No blocklists match this category filter.</div>';
    return;
  }
  grid.innerHTML = filtered.map(item => {
    const inst = Boolean(item.installed);
    const catTone = item.category === "malware" ? "blocked" : (item.category === "tracking" ? "warn" : "info");
    return (
      '<div class="catalog-card ' + (inst ? "installed" : "") + '">' +
        '<div class="catalog-card-top">' +
          '<div class="catalog-title-row">' +
            "<strong>" + escapeHtml(item.name) + "</strong>" +
            '<span class="badge ' + (inst ? "allowed" : catTone) + '">' + (inst ? "Installed" : escapeHtml(item.category)) + "</span>" +
          "</div>" +
          '<div class="catalog-badges">' +
            '<span class="code-pill">' + escapeHtml(item.scale || "") + "</span>" +
            '<span class="code-pill">' + escapeHtml(item.format || "domains") + "</span>" +
          "</div>" +
          '<p class="catalog-desc">' + escapeHtml(item.description || "") + "</p>" +
        "</div>" +
        '<div class="catalog-card-foot">' +
          '<small class="muted">' + (inst && item.domain_count ? number(item.domain_count) + " active domains" : "Verified HTTPS feed") + "</small>" +
          (inst
            ? '<button type="button" class="btn-mini-action catalog-remove-btn" data-feed-id="' + item.feed_id + '" data-name="' + escapeHtml(item.name) + '">Remove</button>'
            : '<button type="button" class="button primary catalog-install-btn" data-id="' + escapeHtml(item.id) + '">+ Enable List</button>') +
        "</div>" +
      "</div>"
    );
  }).join("");

  $$(".catalog-install-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const cid = btn.dataset.id;
      try {
        btn.disabled = true;
        btn.textContent = "Adding...";
        const res = await api("/api/feeds/catalog", { method: "POST", body: { feed_id: cid } });
        state.catalog = res.catalog || state.catalog;
        state.feeds = res.feeds || (await api("/api/feeds"));
        renderCatalog();
        renderFeeds();
        toast("Blocklist added and syncing in background");
      } catch (err) {
        toast(err.message, true);
        btn.disabled = false;
        btn.textContent = "+ Enable List";
      }
    });
  });

  $$(".catalog-remove-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const fid = btn.dataset.feedId;
      if (!fid) return;
      try {
        btn.disabled = true;
        await api("/api/feeds/" + fid, { method: "DELETE" });
        const [feeds, catRes, status] = await Promise.all([
          api("/api/feeds"),
          api("/api/feeds/catalog"),
          api("/api/status?window=" + state.timeWindow)
        ]);
        state.feeds = feeds || [];
        state.catalog = (catRes && catRes.catalog) || [];
        state.status = status;
        renderCatalog();
        renderFeeds();
        renderStatus();
        toast("Removed " + (btn.dataset.name || "blocklist"));
      } catch (err) {
        toast(err.message, true);
        btn.disabled = false;
      }
    });
  });
}

async function openDeviceInsights(ip) {
  if (!ip) return;
  state.activeDeviceIp = ip;
  const modal = $("#device-insights-modal");
  const scrim = $("#device-insights-scrim");
  if (!modal || !scrim) return;
  modal.classList.remove("hidden");
  scrim.classList.remove("hidden");
  $("#dev-insights-badge").textContent = ip;
  $("#dev-insights-title").textContent = "Loading Device Telemetry...";
  try {
    const data = await api("/api/devices/insights?ip=" + encodeURIComponent(ip) + "&window=" + state.timeWindow);
    $("#dev-insights-title").textContent = data.name ? (data.name + " Telemetry") : ("Client " + ip);
    $("#dev-kpi-total").textContent = number(data.total || 0);
    $("#dev-kpi-blockrate").textContent = Number(data.block_rate_pct || 0).toFixed(1) + "%";
    $("#dev-kpi-latency").textContent = Number(data.avg_latency || 0).toFixed(1) + " ms";
    $("#dev-kpi-profile").textContent = profileName(data.profile || "*");
    const curMode = data.mode || "normal";
    $$(".dev-mode-action-btn").forEach(b => b.classList.toggle("active", b.dataset.mode === curMode));
    if ($("#dev-mode-status-text")) {
      $("#dev-mode-status-text").textContent = curMode === "bypass"
        ? "Bypass Active — Policy filtering temporarily disabled for this device"
        : (curMode === "quarantine"
            ? "Quarantine Active — All non-essential DNS lookups blocked for this device"
            : "Standard Policy — Following assigned profile rules");
    }

    const renderMiniList = (el, rows, actionType) => {
      if (!el) return;
      if (!rows || !rows.length) {
        el.innerHTML = '<div class="empty-state">No domains recorded in this window.</div>';
        return;
      }
      el.innerHTML = rows.map(r =>
        '<div class="live-pulse-row">' +
          '<div class="live-pulse-main">' +
            '<span class="live-pulse-domain">' + escapeHtml(r.domain) + '</span>' +
            '<small class="muted">' + number(r.count) + ' lookups</small>' +
          '</div>' +
          '<button type="button" class="btn-mini-action" data-action="' + (actionType === "allow" ? "quick-block" : "quick-allow") + '" data-domain="' + escapeHtml(r.domain) + '">' + (actionType === "allow" ? "Block" : "Allow") + '</button>' +
        '</div>'
      ).join("");
    };
    renderMiniList($("#dev-top-allowed"), data.top_allowed || [], "allow");
    renderMiniList($("#dev-top-blocked"), data.top_blocked || [], "block");
  } catch (err) {
    toast(err.message, true);
  }
}

function closeDeviceInsights() {
  $("#device-insights-modal")?.classList.add("hidden");
  $("#device-insights-scrim")?.classList.add("hidden");
}

function renderPresets() {
  const grid = $("#presets-grid");
  if (!grid) return;
  const allPresets = state.presets || [];
  const blockedTotal = allPresets.filter(p => p.blocked).length;
  if ($("#presets-active-badge")) {
    $("#presets-active-badge").textContent = blockedTotal + "/" + (allPresets.length || 20) + " Blocked";
    $("#presets-active-badge").className = "badge " + (blockedTotal > 0 ? "blocked" : "info");
  }
  const grp = state.presetGroup || "all";
  const presets = allPresets.filter(p => grp === "all" || (p.group || "social") === grp);
  if (!presets.length) {
    grid.innerHTML = '<div class="empty-state">No service presets in this category.</div>';
    return;
  }
  grid.innerHTML = presets.map(p => {
    const isBlocked = Boolean(p.blocked);
    const statusClass = isBlocked ? "blocked" : p.partial ? "warn" : "";
    const badgeText = isBlocked ? "Blocked" : p.partial ? "Partial" : "Permitted";
    const badgeClass = isBlocked ? "blocked" : p.partial ? "warn" : "allowed";
    const btnText = isBlocked ? "Unblock Service" : "Block Service";
    const btnClass = isBlocked ? "button secondary" : "button primary";
    return (
      '<div class="preset-card ' + statusClass + '">' +
        "<div>" +
          '<div class="preset-card-header">' +
            "<strong>" + escapeHtml(p.name) + "</strong>" +
            '<span class="badge ' + badgeClass + '">' + badgeText + "</span>" +
          "</div>" +
          "<p>" + escapeHtml(p.description) + "</p>" +
        "</div>" +
        '<button type="button" class="' + btnClass + ' preset-toggle-btn" data-preset="' + escapeHtml(p.id) + '" data-enable="' + (!isBlocked) + '">' +
          btnText +
        "</button>" +
      "</div>"
    );
  }).join("");

  $$(".preset-toggle-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.preset;
      const enable = btn.dataset.enable === "true";
      try {
        btn.disabled = true;
        btn.textContent = "Applying...";
        await api("/api/rules/presets/toggle", {
          method: "POST",
          body: { preset: id, enabled: enable }
        });
        toast(enable ? "Preset blocked" : "Preset unblocked");
        await refreshRulesAndPresets();
      } catch (err) {
        toast(err.message, true);
      } finally {
        btn.disabled = false;
      }
    });
  });
}

function renderRules() {
  const search = ($("#rule-search") ? $("#rule-search").value : "").trim().toLowerCase();
  const rules = (state.rules || []).filter(rule => {
    if (search && !String(rule.pattern || "").toLowerCase().includes(search)) return false;
    return true;
  });

  const body = $("#rule-body");
  if (!body) return;

  body.innerHTML = rules.length
    ? rules.map(rule => {
        const badgeClass = rule.action === "deny" ? "blocked" : rule.action === "allow" ? "allowed" : "rewritten";
        const badgeLabel = rule.action === "deny" ? "Block" : rule.action === "allow" ? "Allow" : "Rewrite → " + (rule.value || "");
        let scopeText = "Exact hostname only";
        if (rule.kind === "suffix") {
          scopeText = "Domain & subdomains (*." + escapeHtml(rule.pattern) + ")";
        } else if (rule.kind === "regex") {
          scopeText = '<span class="badge info">Regex (re)</span> <code>' + escapeHtml(rule.pattern) + "</code>";
        }
        let expiryPill = "";
        if (rule.expires_at && Number(rule.expires_at) > 0) {
          const rem = Math.max(0, Math.round(Number(rule.expires_at) - Date.now() / 1000));
          expiryPill = rem > 0
            ? ' <span class="badge warn">TTL ' + Math.ceil(rem / 60) + "m</span>"
            : ' <span class="badge error">Expired</span>';
        }
        return (
          "<tr>" +
            '<td class="domain">' + escapeHtml(rule.pattern) + expiryPill + "</td>" +
            "<td>" + scopeText + "</td>" +
            '<td><span class="badge ' + badgeClass + '">' + escapeHtml(badgeLabel) + "</span></td>" +
            '<td><span class="code-pill">' + escapeHtml(profileName(rule.profile)) + "</span></td>" +
            '<td class="cell-right"><button type="button" class="btn-mini-action delete-rule" data-id="' + rule.id + '">Delete</button></td>' +
          "</tr>"
        );
      }).join("")
    : '<tr><td colspan="5" class="empty-state">No custom rules configured yet.</td></tr>';

  $$(".delete-rule").forEach(button => {
    button.addEventListener("click", async () => {
      try {
        await api("/api/rules/" + button.dataset.id, { method: "DELETE" });
        toast("Custom rule deleted");
        await refreshRulesAndPresets();
      } catch (error) {
        toast(error.message, true);
      }
    });
  });
}

function renderFeeds() {
  const container = $("#feed-list");
  if (!container) return;
  container.innerHTML = (state.feeds || []).length
    ? state.feeds.map(feed => {
        const status = feed.error ? "error" : feed.refreshed ? "ready" : "pending";
        const statusText = feed.error ? "Sync Error" : feed.refreshed ? "Synced " + ago(feed.refreshed) : "Pending Sync";
        return (
          '<div class="list-row">' +
            '<div class="list-row-main">' +
              '<i class="status-dot ' + (feed.error ? "bad" : feed.enabled ? "good" : "neutral") + '"></i>' +
              '<div class="list-row-copy">' +
                "<strong>" + escapeHtml(feed.name) + "</strong>" +
                "<small><span class=\"badge info\">" + escapeHtml(feed.category) + "</span> • <strong>" + number(feed.domain_count) + "</strong> domains</small>" +
                '<small class="feed-url-line">' + escapeHtml(feed.url) + (feed.error ? ' <span class="text-red">(' + escapeHtml(feed.error) + ")</span>" : "") + "</small>" +
              "</div>" +
            "</div>" +
            '<div class="list-row-meta">' +
              '<span class="badge ' + status + '">' + escapeHtml(statusText) + "</span>" +
              '<button type="button" class="btn-mini-action feed-refresh" data-id="' + feed.id + '">Update</button>' +
              '<button type="button" class="btn-mini-action feed-toggle" data-id="' + feed.id + '" data-enabled="' + (feed.enabled ? "1" : "0") + '">' + (feed.enabled ? "Disable" : "Enable") + "</button>" +
              '<button type="button" class="btn-mini-action feed-delete" data-id="' + feed.id + '">Delete</button>' +
            "</div>" +
          "</div>"
        );
      }).join("")
    : '<div class="empty-state">No subscription blocklists added yet. Click "1-Click Recommended Bundle" or add a feed below.</div>';

  $$(".feed-refresh").forEach(button => {
    button.addEventListener("click", () => refreshFeed(Number(button.dataset.id)));
  });
  $$(".feed-toggle").forEach(button => {
    button.addEventListener("click", async () => {
      try {
        const enabled = button.dataset.enabled !== "1";
        await api("/api/feeds/" + button.dataset.id + "/enabled", { method: "PUT", body: { enabled } });
        state.feeds = await api("/api/feeds");
        state.status = await api("/api/status?window=" + state.timeWindow);
        renderFeeds();
        renderStatus();
        toast(enabled ? "Blocklist enabled" : "Blocklist disabled");
      } catch (error) {
        toast(error.message, true);
      }
    });
  });
  $$(".feed-delete").forEach(button => {
    button.addEventListener("click", async () => {
      try {
        await api("/api/feeds/" + button.dataset.id, { method: "DELETE" });
        state.feeds = await api("/api/feeds");
        state.status = await api("/api/status?window=" + state.timeWindow);
        renderFeeds();
        renderStatus();
        toast("Blocklist removed");
      } catch (error) {
        toast(error.message, true);
      }
    });
  });
}

async function refreshFeed(id) {
  try {
    await api("/api/feeds/refresh", { method: "POST", body: id ? { id } : {} });
    toast(id ? "Blocklist sync started" : "Updating all enabled blocklists...");
    setTimeout(async () => {
      try {
        state.feeds = await api("/api/feeds");
        state.status = await api("/api/status?window=" + state.timeWindow);
        renderFeeds();
        renderStatus();
      } catch (_) {}
    }, 2200);
  } catch (error) {
    toast(error.message, true);
  }
}

function renderDevices() {
  const body = $("#devices-body");
  if (!body) return;
  if (!state.devices.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty-state">No client devices observed yet. Devices appear automatically as they query Lattice DNS.</td></tr>';
    return;
  }
  const profiles = (state.config && state.config.profiles) || [];
  body.innerHTML = state.devices.map((dev, idx) => {
    const profOptions = ['<option value="*" ' + (dev.profile === "*" ? "selected" : "") + ">Default Policy (*)</option>"]
      .concat(profiles.map(p => '<option value="' + escapeHtml(p.id) + '" ' + (dev.profile === p.id ? "selected" : "") + ">" + escapeHtml(p.name) + "</option>"))
      .join("");

    return (
      '<tr data-dev-row="' + idx + '">' +
        '<td><span class="code-pill">' + escapeHtml(dev.ip) + "</span>" +
          ((/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(dev.ip) || /^10\.(8|66|0)\./.test(dev.ip)) ? ' <span class="badge info">VPN</span>' : "") +
          (dev.mode === "bypass" ? ' <span class="badge warn">Bypass</span>' : (dev.mode === "quarantine" ? ' <span class="badge blocked">Quarantine</span>' : "")) +
        "</td>" +
        '<td><input class="dev-name" data-ip="' + escapeHtml(dev.ip) + '" value="' + escapeHtml(dev.name || "") + '" placeholder="e.g. Living Room TV"></td>' +
        '<td><select class="dev-icon" data-ip="' + escapeHtml(dev.ip) + '">' +
          '<option value="phone" ' + (dev.icon === "phone" ? "selected" : "") + ">Phone</option>" +
          '<option value="laptop" ' + (dev.icon === "laptop" ? "selected" : "") + ">Laptop</option>" +
          '<option value="tv" ' + (dev.icon === "tv" ? "selected" : "") + ">TV / Media</option>" +
          '<option value="server" ' + (dev.icon === "server" ? "selected" : "") + ">Server</option>" +
          '<option value="iot" ' + (dev.icon === "iot" ? "selected" : "") + ">IoT Device</option>" +
        "</select></td>" +
        '<td><select class="dev-profile" data-ip="' + escapeHtml(dev.ip) + '">' + profOptions + "</select></td>" +
        "<td><strong>" + number(dev.query_count) + "</strong></td>" +
        "<td>" + ago(dev.last_seen) + "</td>" +
        '<td class="cell-right">' +
          '<div class="button-row">' +
            '<button type="button" class="btn-mini-action dev-insights-btn" data-ip="' + escapeHtml(dev.ip) + '">Insights</button>' +
            '<button type="button" class="btn-mini-action logs-dev-btn" data-ip="' + escapeHtml(dev.ip) + '">Logs</button>' +
            '<button type="button" class="btn-mini-action save-dev-btn" data-ip="' + escapeHtml(dev.ip) + '">Save</button>' +
            '<button type="button" class="btn-mini-action del-dev-btn" data-ip="' + escapeHtml(dev.ip) + '">×</button>' +
          "</div>" +
        "</td>" +
      "</tr>"
    );
  }).join("");

  $$(".logs-dev-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const ip = btn.dataset.ip;
      switchPage("queries");
      if ($("#query-search")) {
        $("#query-search").value = ip;
        loadQueries().catch(() => {});
      }
    });
  });

  $$(".save-dev-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const ip = btn.dataset.ip;
      const row = btn.closest("tr");
      const name = row.querySelector(".dev-name").value.trim();
      const icon = row.querySelector(".dev-icon").value;
      const profile = row.querySelector(".dev-profile").value;
      try {
        await api("/api/devices", { method: "POST", body: { ip, name, icon, profile } });
        toast("Device saved");
        state.devices = await api("/api/devices");
        renderDevices();
      } catch (err) {
        toast(err.message, true);
      }
    });
  });

  $$(".del-dev-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const ip = btn.dataset.ip;
      try {
        await api("/api/devices/" + encodeURIComponent(ip), { method: "DELETE" });
        toast("Device entry removed");
        state.devices = await api("/api/devices");
        renderDevices();
      } catch (err) {
        toast(err.message, true);
      }
    });
  });
}

function renderProfilesEditor() {
  const container = $("#profiles-editor");
  if (!container || !state.config) return;
  const profiles = state.config.profiles || [];
  container.innerHTML = profiles.map((prof, idx) =>
    '<div class="editor-row" data-profile-index="' + idx + '">' +
      '<div class="editor-grid-profile">' +
        '<label class="editor-label"><span>Profile Name</span><input data-field="name" value="' + escapeHtml(prof.name) + '"></label>' +
        '<label class="editor-label"><span>CIDR Subnets (comma-sep)</span><input data-field="networks" value="' + escapeHtml((prof.networks || []).join(", ")) + '"></label>' +
        '<label class="editor-label"><span>Blocked Categories</span><input data-field="categories" value="' + escapeHtml((prof.categories || []).join(", ")) + '" placeholder="ads, tracking, malware"></label>' +
        '<label class="editor-label"><span>Rate Limit/s</span><input data-field="rate_limit" type="number" min="1" max="10000" value="' + (prof.rate_limit || 300) + '"></label>' +
        '<label class="check-row"><input data-field="logging" type="checkbox" ' + (prof.logging !== false ? "checked" : "") + "><span><strong>Log</strong></span></label>" +
        '<button type="button" class="button secondary remove-profile" data-index="' + idx + '">Remove</button>' +
      "</div>" +
    "</div>"
  ).join("");

  $$(".remove-profile").forEach(btn => {
    btn.addEventListener("click", () => {
      if (state.config.profiles.length <= 1) {
        toast("At least one client profile is required", true);
        return;
      }
      state.config.profiles.splice(Number(btn.dataset.index), 1);
      renderProfilesEditor();
    });
  });
}

function renderDnsForms() {
  const cfg = state.config;
  if (!cfg) return;
  $("#dnssec-toggle").checked = Boolean(cfg.dnssec);
  if ($("#safesearch-toggle")) $("#safesearch-toggle").checked = Boolean(cfg.safesearch);
  if ($("#rebind-toggle")) $("#rebind-toggle").checked = cfg.rebinding_protection !== false;
  if ($("#doh-canary-toggle")) $("#doh-canary-toggle").checked = cfg.block_doh_canary !== false;
  if ($("#risky-tld-toggle")) $("#risky-tld-toggle").checked = Boolean(cfg.block_risky_tlds);
  if ($("#punycode-toggle")) $("#punycode-toggle").checked = Boolean(cfg.block_punycode);
  if ($("#doh-enabled-toggle")) $("#doh-enabled-toggle").checked = cfg.doh_enabled !== false;
  $("#prefetch-toggle").checked = Boolean(cfg.cache && cfg.cache.prefetch);
  $("#stale-toggle").checked = Boolean(cfg.cache && cfg.cache.serve_expired);
  $("#block-response").value = cfg.block_response || "nxdomain";
  if ($("#block-custom-ip")) $("#block-custom-ip").value = cfg.block_custom_ip || "";
  if ($("#block-ttl")) $("#block-ttl").value = cfg.block_ttl || 30;
  renderUpstreamEditor();
  renderLocalRecordsEditor();
  renderRouteEditor();
}

function renderUpstreamEditor() {
  const items = (state.config && state.config.upstreams) || [];
  $("#upstream-editor").innerHTML = items.length
    ? items.map((item, index) =>
        '<div class="editor-row" data-upstream-index="' + index + '">' +
          '<div class="editor-grid-upstream">' +
            '<label class="editor-label"><span>Resolver Name</span><input data-field="name" value="' + escapeHtml(item.name) + '"></label>' +
            '<label class="editor-label"><span>IPv4 / IPv6 Address</span><input data-field="address" value="' + escapeHtml(item.address) + '"></label>' +
            '<label class="editor-label"><span>Port</span><input data-field="port" type="number" min="1" max="65535" value="' + (item.port || 853) + '"></label>' +
            '<label class="editor-label"><span>TLS SNI Hostname</span><input data-field="sni" value="' + escapeHtml(item.sni || item.tls_hostname || "") + '"></label>' +
            '<label class="check-row"><input data-field="enabled" type="checkbox" ' + (item.enabled !== false ? "checked" : "") + "><span><strong>Enabled</strong></span></label>" +
            '<button type="button" class="button secondary remove-upstream" data-index="' + index + '">Remove</button>' +
          "</div>" +
        "</div>"
      ).join("")
    : '<div class="empty-state">No upstream DNS resolvers configured.</div>';

  $$(".remove-upstream").forEach(button => {
    button.addEventListener("click", () => {
      if (state.config.upstreams.length <= 1) {
        toast("At least one upstream DNS server is required", true);
        return;
      }
      state.config.upstreams.splice(Number(button.dataset.index), 1);
      const ids = new Set(state.config.upstreams.map(item => item.id));
      state.config.routes = (state.config.routes || [])
        .map(route => Object.assign({}, route, { upstreams: (route.upstreams || []).filter(id => ids.has(id)) }))
        .filter(route => route.upstreams.length > 0);
      renderUpstreamEditor();
      renderRouteEditor();
    });
  });
}

function collectUpstreams() {
  const used = new Set();
  return $$("#upstream-editor [data-upstream-index]").map((row, index) => {
    const previous = (state.config.upstreams || [])[index] || {};
    const nameVal = row.querySelector('[data-field="name"]').value.trim();
    let id = previous.id || slug(nameVal) || "upstream";
    let candidate = id;
    let suffix = 2;
    while (used.has(candidate)) {
      candidate = id + "_" + suffix++;
    }
    id = candidate;
    used.add(id);
    return {
      id,
      name: nameVal,
      address: row.querySelector('[data-field="address"]').value.trim(),
      port: Number(row.querySelector('[data-field="port"]').value || 853),
      sni: row.querySelector('[data-field="sni"]').value.trim(),
      enabled: row.querySelector('[data-field="enabled"]').checked
    };
  });
}

function renderLocalRecordsEditor() {
  const container = $("#local-records-editor");
  if (!container) return;
  const records = (state.config && state.config.local_records) || [];
  if (!records.length) {
    container.innerHTML = '<div class="empty-state">No local LAN records configured. Click "+ Add Local Record" to define split-horizon hosts.</div>';
    return;
  }
  container.innerHTML = records.map((rec, index) =>
    '<div class="editor-row" data-local-index="' + index + '">' +
      '<div class="editor-grid-local">' +
        '<label class="editor-label"><span>Hostname</span><input class="local-rec-name" value="' + escapeHtml(rec.name) + '" placeholder="nas.lan"></label>' +
        '<label class="editor-label"><span>Type</span><select class="local-rec-type">' +
          '<option value="A" ' + (rec.type === "A" ? "selected" : "") + ">A</option>" +
          '<option value="AAAA" ' + (rec.type === "AAAA" ? "selected" : "") + ">AAAA</option>" +
          '<option value="CNAME" ' + (rec.type === "CNAME" ? "selected" : "") + ">CNAME</option>" +
          '<option value="TXT" ' + (rec.type === "TXT" ? "selected" : "") + ">TXT</option>" +
        "</select></label>" +
        '<label class="editor-label"><span>Target IP / Value</span><input class="local-rec-val" value="' + escapeHtml(rec.value) + '" placeholder="192.168.1.100"></label>' +
        '<label class="editor-label"><span>TTL (s)</span><input class="local-rec-ttl" type="number" min="1" max="86400" value="' + (rec.ttl || 300) + '"></label>' +
        '<button type="button" class="button secondary delete-local-rec" data-index="' + index + '">Remove</button>' +
      "</div>" +
    "</div>"
  ).join("");

  $$(".delete-local-rec").forEach(btn => {
    btn.addEventListener("click", () => {
      state.config.local_records.splice(Number(btn.dataset.index), 1);
      renderLocalRecordsEditor();
    });
  });
}

function collectLocalRecords() {
  const records = [];
  $$("#local-records-editor [data-local-index]").forEach(row => {
    const name = row.querySelector(".local-rec-name").value.trim();
    const type = row.querySelector(".local-rec-type").value;
    const value = row.querySelector(".local-rec-val").value.trim();
    const ttl = Number(row.querySelector(".local-rec-ttl").value || 300);
    if (name && value) {
      records.push({ name, type, value, ttl });
    }
  });
  return records;
}

function renderRouteEditor() {
  const editor = $("#route-editor");
  if (!editor || !state.config) return;
  const routes = state.config.routes || [];
  const enabled = (state.config.upstreams || []).filter(item => item.enabled !== false);
  if (!routes.length) {
    editor.innerHTML = '<div class="empty-state">No custom domain suffix routes. All queries use the default upstream pool.</div>';
    return;
  }
  editor.innerHTML = routes.map((route, index) => {
    const checks = enabled.map(upstream =>
      '<label class="check-row"><input type="checkbox" class="route-upstream" data-id="' + escapeHtml(upstream.id) + '" ' + ((route.upstreams || []).includes(upstream.id) ? "checked" : "") + "><span><strong>" + escapeHtml(upstream.name) + "</strong></span></label>"
    ).join("");
    return (
      '<div class="editor-row" data-route-index="' + index + '">' +
        '<div class="editor-grid-route">' +
          '<label class="editor-label"><span>Domain Suffix</span><input class="route-suffix" value="' + escapeHtml(route.suffix) + '" placeholder="corp.example.com"></label>' +
          '<div class="editor-label"><span>Target Upstreams</span><div class="button-row">' + checks + "</div></div>" +
          '<button type="button" class="button secondary remove-route" data-index="' + index + '">Remove</button>' +
        "</div>" +
      "</div>"
    );
  }).join("");

  $$(".remove-route").forEach(btn => {
    btn.addEventListener("click", () => {
      state.config.routes.splice(Number(btn.dataset.index), 1);
      renderRouteEditor();
    });
  });
}

function collectRoutes() {
  return $$("#route-editor [data-route-index]").map(row => ({
    suffix: row.querySelector(".route-suffix").value.trim(),
    upstreams: Array.from(row.querySelectorAll(".route-upstream:checked")).map(input => input.dataset.id)
  })).filter(r => r.suffix && r.upstreams.length > 0);
}

function renderPrivateForm() {
  const cfg = state.config;
  if (!cfg) return;
  $("#private-hostname").value = cfg.hostname || "";
  $("#private-email").value = cfg.email || "";
  $("#private-target").value = cfg.public_target || "";
  $("#cloudflare-token").value = "";
  $("#cloudflare-token-state").textContent = state.secrets.cloudflare
    ? "Encrypted Cloudflare token is saved. Leave blank to keep it."
    : "No Cloudflare API token saved yet.";

  const frp = cfg.frp || {};
  $("#frp-enabled").checked = Boolean(frp.enabled);
  $("#frp-server").value = frp.server || "";
  $("#frp-port").value = frp.port || 7000;
  $("#frp-auth").value = frp.auth || "none";
  $("#frp-token").value = "";
  toggleFrpFields();

  const hostText = cfg.hostname || window.location.hostname || "dns.example.com";
  if ($("#instruction-hostname")) $("#instruction-hostname").textContent = hostText;
  if ($("#instruction-doh")) $("#instruction-doh").textContent = "https://" + hostText + "/dns-query";
  if ($("#instruction-railway-doh")) $("#instruction-railway-doh").textContent = "https://" + hostText + "/dns-query";
  if ($("#instruction-curl")) $("#instruction-curl").textContent = 'curl -s "https://' + hostText + '/dns-query?name=example.com&type=A"';
  if ($("#instruction-router")) $("#instruction-router").textContent = "[Resolve]\nDNS=1.1.1.1#" + hostText + "\nDNSOverTLS=yes";
}

function toggleFrpFields() {
  const enabled = $("#frp-enabled").checked;
  $("#frp-fields").classList.toggle("hidden", !enabled);
  $("#frp-token-wrap").classList.toggle("hidden", !enabled || $("#frp-auth").value !== "token");
}

function detailLine(label, value) {
  return '<div class="detail-line"><span>' + escapeHtml(label) + "</span><strong>" + escapeHtml(value) + "</strong></div>";
}

function renderPrivateStatus() {
  const s = state.status;
  if (!s || !state.config) return;

  const cert = s.tls || {};
  const certCard = $("#certificate-card");
  if (certCard) {
    certCard.innerHTML =
      detailLine("Certificate State", cert.valid ? "Valid & Active" : (cert.error || "Not installed")) +
      detailLine("Covered Hostname (SAN)", cert.hostname || state.config.hostname || "Not configured") +
      detailLine("Expiration Date", cert.expires ? when(cert.expires) : "Not available") +
      detailLine("Issuer CA", cert.issuer || "Not available");
  }

  const frp = s.frp || {};
  const frpCard = $("#frp-card");
  if (frpCard) {
    frpCard.innerHTML =
      detailLine("Tunnel Status", state.config.frp.enabled ? friendlyFrpState(frp.state) : "Disabled") +
      detailLine("Supervisor Process", frp.running ? "Running" : "Stopped") +
      detailLine("Last Error", frp.error || "None");
  }
  const logView = $("#frp-log");
  if (logView) {
    logView.textContent = frp.logs && frp.logs.length ? frp.logs.join("\n") : "No tunnel activity yet.";
  }
}

function renderSystemForm() {
  const cfg = state.config;
  if (!cfg) return;
  $("#privacy-mode").value = cfg.privacy.mode || "balanced";
  $("#retention-days").value = cfg.privacy.retention_days || 7;
  $("#rrset-cache").value = cfg.cache.rrset_mb || 96;
  $("#message-cache").value = cfg.cache.message_mb || 48;
  $("#config-editor").value = JSON.stringify(cfg, null, 2);
}

async function loadVpnDoctor() {
  const grid = $("#vpn-doctor-grid");
  const badge = $("#vpn-doctor-badge");
  if (!grid) return;
  try {
    const res = await api("/api/diagnostics/vpn");
    if (badge) {
      badge.className = "badge " + (res.ready ? "allowed" : "warn");
      badge.textContent = res.ready
        ? "VPN Continuity Ready (" + res.passed + "/" + res.total + " Active)"
        : res.passed + "/" + res.total + " Active";
    }
    grid.innerHTML = (res.checks || []).map(c =>
      `<div class="doctor-item ${c.ok ? "ok" : "warn"}">` +
        `<div class="doctor-item-head">` +
          `<span class="doctor-item-title">${escapeHtml(c.title)}</span>` +
          `<span class="badge ${c.ok ? "allowed" : "warn"}">${c.ok ? "ACTIVE" : "ACTION"}</span>` +
        `</div>` +
        `<div class="doctor-item-detail">${escapeHtml(c.detail || "")}</div>` +
      `</div>`
    ).join("");
  } catch (err) {
    grid.innerHTML = `<div class="empty-state">${escapeHtml(err.message)}</div>`;
  }
}

async function loadAndroidDoctor() {
  const grid = $("#android-doctor-grid");
  const badge = $("#android-doctor-badge");
  if (!grid) return;
  try {
    const res = await api("/api/diagnostics/android");
    if (badge) {
      badge.className = "badge " + (res.ready ? "allowed" : "warn");
      badge.textContent = res.ready
        ? "Android Ready (" + res.passed + "/" + res.total + " Checks Passed)"
        : res.passed + "/" + res.total + " Checks Passed";
    }
    grid.innerHTML = (res.checks || []).map(c =>
      `<div class="doctor-item ${c.ok ? "ok" : "warn"}">` +
        `<div class="doctor-item-head">` +
          `<span class="doctor-item-title">${escapeHtml(c.title)}</span>` +
          `<span class="badge ${c.ok ? "allowed" : "warn"}">${c.ok ? "PASS" : "ACTION"}</span>` +
        `</div>` +
        `<div class="doctor-item-detail">${escapeHtml(c.detail || "")}</div>` +
      `</div>`
    ).join("");
  } catch (err) {
    grid.innerHTML = `<div class="empty-state">${escapeHtml(err.message)}</div>`;
  }
}

async function loadAudit() {
  const body = $("#audit-body");
  if (!body) return;
  try {
    const rows = await api("/api/audit");
    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="3" class="empty-state">No audit events recorded yet.</td></tr>';
      return;
    }
    body.innerHTML = rows.map(r =>
      "<tr>" +
        '<td><span class="code-pill">' + escapeHtml(new Date(r.ts * 1000).toLocaleString()) + "</span></td>" +
        '<td><span class="badge info">' + escapeHtml(r.event || r.action || "Event") + "</span></td>" +
        "<td>" + escapeHtml(r.detail || "—") + "</td>" +
      "</tr>"
    ).join("");
  } catch (err) {
    body.innerHTML = '<tr><td colspan="3" class="empty-state">' + escapeHtml(err.message) + "</td></tr>";
  }
}

async function saveConfig(config, secrets, message) {
  const result = await api("/api/config", {
    method: "PUT",
    body: { config, secrets: secrets || {} }
  });
  state.config = result.config;
  await loadAll();
  toast(message || "Configuration saved and applied");
}

function switchPage(target) {
  state.page = target;
  $$(".page").forEach(page => page.classList.toggle("active", page.id === "page-" + target));
  $$(".nav-item, .mob-nav-btn").forEach(item => item.classList.toggle("active", item.dataset.page === target));

  const titles = {
    dashboard: ["Dashboard", "Real-time encrypted DNS telemetry, policy enforcement, and upstream health."],
    queries: ["Query Log", "Inspect live DNS lookups, filter decisions, and packet forensics."],
    blocking: ["Blocking", "Configure protection categories, remote blocklists, custom rules, and client profiles."],
    dns: ["DNS Settings", "Manage encrypted DoT upstreams, L1 wire caching, local LAN records, and Unbound resolver behavior."],
    private: ["Private DNS", "Set up Android Private DNS, Railway DoH, TLS certificates, Cloudflare DNS sync, and FRP transport."],
    system: ["System", "Privacy controls, cache sizing, resolution diagnostics, Prometheus metrics, backups, and security audit logs."]
  };

  const info = titles[target] || [target, ""];
  $("#page-title").textContent = info[0];
  $("#page-description").textContent = info[1];

  closeMobileNav();
  closeQueryDrawer();

  if (target === "queries") loadQueries().catch(err => toast(err.message, true));
  if (target === "private") { loadAndroidDoctor(); loadVpnDoctor(); loadQrCode("doh"); }
  if (target === "system") loadAudit();
}

function openMobileNav() {
  $("#sidebar").classList.add("open");
  $("#nav-scrim").classList.remove("hidden");
}

function closeMobileNav() {
  $("#sidebar").classList.remove("open");
  $("#nav-scrim").classList.add("hidden");
}

function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  safeSetStorage("lattice_theme", theme);
}

/* ==================== ONE-TIME EVENT BINDINGS ==================== */

function bindEvents() {
  const savedTheme = safeGetStorage("lattice_theme") || "dark";
  setTheme(savedTheme === "light" ? "light" : "dark");

  $("#theme-toggle")?.addEventListener("click", () => {
    const current = document.documentElement.dataset.theme || "dark";
    setTheme(current === "dark" ? "light" : "dark");
  });

  $$(".nav-item, .mob-nav-btn").forEach(button => {
    button.addEventListener("click", () => switchPage(button.dataset.page));
  });

  $$(".jump-page").forEach(button => {
    button.addEventListener("click", () => switchPage(button.dataset.target));
  });

  $("#open-nav")?.addEventListener("click", openMobileNav);
  $("#close-nav")?.addEventListener("click", closeMobileNav);
  $("#nav-scrim")?.addEventListener("click", closeMobileNav);
  $("#drawer-close")?.addEventListener("click", closeQueryDrawer);
  $("#drawer-scrim")?.addEventListener("click", closeQueryDrawer);

  // Snooze / Pause Blocking Controls
  const snoozeBtn = $("#snooze-btn");
  const snoozeMenu = $("#snooze-menu");
  if (snoozeBtn && snoozeMenu) {
    snoozeBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      snoozeMenu.classList.toggle("hidden");
    });
    document.addEventListener("click", () => snoozeMenu.classList.add("hidden"));
    $$(".dropdown-item").forEach(item => {
      item.addEventListener("click", async () => {
        const seconds = Number(item.dataset.duration || 0);
        try {
          const res = await api("/api/blocking/pause", { method: "POST", body: { seconds } });
          updateSnoozeUI(res);
          toast(seconds > 0 ? "Blocking paused for " + Math.round(seconds / 60) + "m" : "Policy blocking resumed");
          await refreshStatus();
        } catch (err) {
          toast(err.message, true);
        }
      });
    });
  }

  $("#snooze-active-btn")?.addEventListener("click", async () => {
    try {
      const res = await api("/api/blocking/pause", { method: "POST", body: { seconds: 0 } });
      updateSnoozeUI(res);
      toast("Policy blocking resumed");
      await refreshStatus();
    } catch (err) {
      toast(err.message, true);
    }
  });

  // Time Range Selector
  $$(".time-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      $$(".time-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      state.timeWindow = Number(btn.dataset.window || 86400);
      await refreshStatus();
    });
  });

  // Global Refresh
  $("#refresh")?.addEventListener("click", async () => {
    try {
      await loadAll();
      if (state.page === "queries") await loadQueries();
      if (state.page === "system") await loadAudit();
      toast("Telemetry refreshed");
    } catch (err) {
      toast(err.message, true);
    }
  });

  // Authentication
  $("#auth-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    $("#auth-error").textContent = "";
    const isSetup = $("#auth-form").dataset.setup === "1";
    try {
      const payload = isSetup
        ? { code: $("#setup-code").value.trim(), password: $("#password").value }
        : { password: $("#password").value };
      const result = await api(isSetup ? "/api/setup" : "/api/login", { method: "POST", body: payload });
      state.authenticated = true;
      state.csrf = result.csrf || "";
      $("#password").value = "";
      await bootstrap();
    } catch (error) {
      $("#auth-error").textContent = error.message;
    }
  });

  $("#logout")?.addEventListener("click", async () => {
    try {
      await api("/api/logout", { method: "POST", body: {} });
    } catch (_) {}
    state.authenticated = false;
    state.csrf = "";
    await bootstrap();
  });

  // Delegated Quick Allow / Quick Block
  document.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-action='quick-block'], [data-action='quick-allow']");
    if (!btn) return;
    const domain = btn.dataset.domain;
    const isBlock = btn.dataset.action === "quick-block";
    if (!domain) return;
    try {
      btn.disabled = true;
      await api("/api/rules", {
        method: "POST",
        body: {
          pattern: domain,
          kind: "exact",
          action: isBlock ? "deny" : "allow",
          profile: "*",
          value: ""
        }
      });
      toast((isBlock ? "Blocked " : "Allowed ") + domain);
      await refreshRulesAndPresets();
      if (state.page === "queries") await loadQueries();
      closeQueryDrawer();
    } catch (err) {
      toast(err.message, true);
    } finally {
      btn.disabled = false;
    }
  });

  // Query Log Controls
  $("#traffic-refresh")?.addEventListener("click", () => loadQueries().catch(e => toast(e.message, true)));
  $("#query-search")?.addEventListener("input", () => {
    clearTimeout(loadQueries.timer);
    loadQueries.timer = setTimeout(() => loadQueries().catch(() => {}), 200);
  });
  $("#query-filter")?.addEventListener("change", () => loadQueries().catch(() => {}));
  $("#query-qtype-filter")?.addEventListener("change", () => loadQueries().catch(() => {}));
  $("#query-rcode-filter")?.addEventListener("change", () => loadQueries().catch(() => {}));

  $("#query-live-toggle")?.addEventListener("click", () => {
    state.livePolling = !state.livePolling;
    const btn = $("#query-live-toggle");
    btn.className = "badge clickable " + (state.livePolling ? "allowed" : "warn");
    $("#live-toggle-text").textContent = state.livePolling ? "Live Stream (3s)" : "Stream Paused";
    toast(state.livePolling ? "Live query polling resumed" : "Live query polling paused");
  });

  $("#export-csv-btn")?.addEventListener("click", () => {
    const q = encodeURIComponent(($("#query-search") ? $("#query-search").value : "").trim());
    const action = encodeURIComponent($("#query-filter") ? $("#query-filter").value : "all");
    const qtype = encodeURIComponent($("#query-qtype-filter") ? $("#query-qtype-filter").value : "0");
    window.location.href = "/api/queries/export?q=" + q + "&action=" + action + "&qtype=" + qtype + "&limit=5000";
    toast("Downloading query log CSV...");
  });

  $("#clear-queries-btn")?.addEventListener("click", async () => {
    try {
      await api("/api/queries/clear", { method: "POST", body: {} });
      toast("Query journal cleared");
      await loadQueries();
      await refreshStatus();
    } catch (err) {
      toast(err.message, true);
    }
  });

  // Blocking Sub-navigation
  $$(".subnav-item").forEach(button => {
    button.addEventListener("click", () => {
      $$(".subnav-item").forEach(item => item.classList.toggle("active", item === button));
      const tab = button.dataset.blockTab;
      $("#blocking-lists").classList.toggle("active", tab === "lists");
      $("#blocking-rules").classList.toggle("active", tab === "rules");
      $("#blocking-devices").classList.toggle("active", tab === "devices");
    });
  });

  $("#rule-search")?.addEventListener("input", renderRules);

  $("#save-protection")?.addEventListener("click", async () => {
    try {
      const profile = defaultProfile();
      if (!profile) throw new Error("No client profile is configured");
      const cfg = deepCopy(state.config);
      const target = cfg.profiles.find(item => item.id === profile.id) || cfg.profiles[0];
      target.categories = $$("#category-grid .category-toggle:checked").map(input => input.value).sort();
      await saveConfig(cfg, {}, "Protection categories saved");
    } catch (error) {
      toast(error.message, true);
    }
  });

  // 1-Click Recommended 4-Feed Security Bundle
  $("#install-bundle-btn")?.addEventListener("click", async () => {
    const btn = $("#install-bundle-btn");
    try {
      if (btn) {
        btn.disabled = true;
        btn.textContent = "Installing 4 Feeds...";
      }
      const res = await api("/api/feeds/bundle", { method: "POST", body: {} });
      state.feeds = res.feeds || (await api("/api/feeds"));
      renderFeeds();
      toast("Installed " + (res.installed || 0) + " curated feeds (" + (res.total_bundle || 4) + " active) — syncing in background");
      setTimeout(async () => {
        try {
          state.feeds = await api("/api/feeds");
          state.status = await api("/api/status?window=" + state.timeWindow);
          renderFeeds();
          renderStatus();
        } catch (_) {}
      }, 2500);
    } catch (error) {
      toast(error.message, true);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "1-Click Recommended Bundle (4 Lists)";
      }
    }
  });

  // Delegated Device Telemetry Insights button
  document.addEventListener("click", (e) => {
    const insBtn = e.target.closest(".dev-insights-btn");
    if (insBtn && insBtn.dataset.ip) {
      openDeviceInsights(insBtn.dataset.ip);
    }
  });
  $$(".dev-mode-action-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const ip = state.activeDeviceIp;
      if (!ip) return;
      const mode = btn.dataset.mode || "normal";
      const seconds = Number(btn.dataset.sec || 0);
      try {
        await api("/api/devices/mode", { method: "POST", body: { ip, mode, seconds } });
        toast("Device " + ip + " set to " + mode.toUpperCase() + " mode");
        await openDeviceInsights(ip);
        state.devices = await api("/api/devices");
        renderDevices();
      } catch (err) {
        toast(err.message, true);
      }
    });
  });

  $("#test-rule-btn")?.addEventListener("click", async () => {
    const pat = ($("#rule-pattern")?.value || "").trim();
    const box = $("#rule-test-result");
    if (!box) return;
    if (!pat) {
      toast("Enter a domain or regex pattern first", true);
      return;
    }
    let kind = $("#rule-kind")?.value || "suffix";
    if (kind !== "regex" && $("#rule-subdomains") && !$("#rule-subdomains").checked) {
      kind = "exact";
    }
    box.classList.remove("hidden");
    try {
      const res = await api("/api/rules/test", { method: "POST", body: { pattern: pat, kind, sample: pat.replace(/^\^|\$$/g, "") } });
      const hits = res.matched_recent_domains || [];
      box.innerHTML =
        `<div class="detail-line"><span>Pattern Valid (${escapeHtml(res.kind)})</span><strong>${hits.length} recent query matches</strong></div>` +
        (hits.length
          ? `<small class="muted">Matched in log: ${escapeHtml(hits.slice(0, 6).join(", "))}</small>`
          : `<small class="muted">Syntax valid — ready to save rule.</small>`);
    } catch (err) {
      box.innerHTML = `<span class="text-red">${escapeHtml(err.message)}</span>`;
    }
  });

  $$(".template-profile-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      state.config.profiles = state.config.profiles || [];
      const pid = btn.dataset.id;
      if (state.config.profiles.some(p => p.id === pid)) {
        toast(btn.dataset.name + " is already in your profile list");
        return;
      }
      state.config.profiles.push({
        id: pid,
        name: btn.dataset.name,
        networks: [btn.dataset.net || "192.168.50.0/24"],
        categories: (btn.dataset.cats || "ads,tracking,malware").split(","),
        rate_limit: 300,
        logging: true
      });
      renderProfilesEditor();
      toast("Added " + btn.dataset.name + " — click Save Profiles to activate");
    });
  });

  $("#vacuum-db-btn")?.addEventListener("click", async () => {
    const btn = $("#vacuum-db-btn");
    try {
      if (btn) {
        btn.disabled = true;
        btn.textContent = "Optimizing...";
      }
      const res = await api("/api/system/vacuum", { method: "POST", body: {} });
      await refreshStatus();
      toast("SQLite WAL database checkpointed & optimized (" + Math.round((res.after_bytes || 0) / 1024) + " KB)");
    } catch (err) {
      toast(err.message, true);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Optimize & Checkpoint DB";
      }
    }
  });

  $("#run-batch-diag-btn")?.addEventListener("click", async () => {
    const box = $("#batch-diag-results");
    if (!box) return;
    const client = ($("#diag-client")?.value || "127.0.0.1").trim() || "127.0.0.1";
    const testDomains = [
      "connectivitycheck.gstatic.com",
      "use-application-dns.net",
      "www.google.com",
      "ads.doubleclick.net",
      "www.tiktok.com",
      "xn--80ak6aa92e.com",
      "quarterly-invoice.zip",
      "api.github.com"
    ];
    box.classList.remove("hidden");
    box.innerHTML = '<div class="empty-state">Running 8-domain security policy audit...</div>';
    try {
      const res = await api("/api/diagnose/batch", { method: "POST", body: { client, domains: testDomains } });
      const rows = res.results || [];
      box.innerHTML =
        '<table class="data-table"><thead><tr><th>Test Domain</th><th>Verdict</th><th>Matched Policy / Shield</th><th>Client Profile</th></tr></thead><tbody>' +
        rows.map(r => {
          const tone = r.action === "allow" ? "allowed" : (r.action === "rewrite" ? "info" : "blocked");
          return (
            "<tr>" +
              '<td class="domain">' + escapeHtml(r.domain) + "</td>" +
              '<td><span class="badge ' + tone + '">' + escapeHtml(r.action.toUpperCase()) + "</span></td>" +
              '<td><span class="code-pill">' + escapeHtml(r.source + (r.value ? " -> " + r.value : "")) + "</span></td>" +
              "<td>" + escapeHtml(r.profile) + "</td>" +
            "</tr>"
          );
        }).join("") +
        "</tbody></table>";
      toast("Completed 8-domain security policy self-test");
    } catch (err) {
      box.innerHTML = '<div class="empty-state">' + escapeHtml(err.message) + '</div>';
    }
  });

  $("#dev-insights-close")?.addEventListener("click", closeDeviceInsights);
  $("#device-insights-scrim")?.addEventListener("click", closeDeviceInsights);
  $("#dev-insights-logs-btn")?.addEventListener("click", () => {
    const ip = state.activeDeviceIp;
    closeDeviceInsights();
    if (ip) {
      switchPage("queries");
      if ($("#query-search")) {
        $("#query-search").value = ip;
        loadQueries().catch(() => {});
      }
    }
  });

  // Curated Blocklist Marketplace Category Filters & 1-Click Packs
  $$(".catalog-filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      $$(".catalog-filter-btn").forEach(b => b.classList.toggle("active", b === btn));
      state.catalogFilter = btn.dataset.cat || "all";
      renderCatalog();
    });
  });

  $$(".catalog-pack-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const pack = btn.dataset.pack || "core";
      const origText = btn.textContent;
      try {
        btn.disabled = true;
        btn.textContent = "Installing Pack...";
        const res = await api("/api/feeds/catalog", { method: "POST", body: { pack } });
        state.catalog = res.catalog || state.catalog;
        state.feeds = res.feeds || (await api("/api/feeds"));
        renderCatalog();
        renderFeeds();
        toast("Installed " + (res.added || 0) + " new lists from " + origText + " (" + (res.target_count || 0) + " total in pack)");
      } catch (err) {
        toast(err.message, true);
      } finally {
        btn.disabled = false;
        btn.textContent = origText;
      }
    });
  });

  // Preset Group Filter & Bulk Toggle
  $$(".preset-group-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      $$(".preset-group-btn").forEach(b => b.classList.toggle("active", b === btn));
      state.presetGroup = btn.dataset.group || "all";
      renderPresets();
    });
  });

  const handleBulkPresets = async (enable) => {
    try {
      const grp = state.presetGroup || "all";
      const res = await api("/api/rules/presets/bulk", { method: "POST", body: { enabled: enable, group: grp } });
      state.presets = res.presets || (await api("/api/rules/presets"));
      state.rules = await api("/api/rules");
      renderPresets();
      renderRules();
      toast((enable ? "Blocked " : "Unblocked ") + (grp === "all" ? "all 20 presets" : grp + " presets"));
    } catch (err) {
      toast(err.message, true);
    }
  };
  $("#presets-block-group-btn")?.addEventListener("click", () => handleBulkPresets(true));
  $("#presets-allow-group-btn")?.addEventListener("click", () => handleBulkPresets(false));

  // Instant Cross-Blocklist, Rule & Preset Attribution Lookup
  const runBlocklistSearch = async () => {
    const q = ($("#blocklist-search-input")?.value || "").trim();
    const box = $("#blocklist-search-results");
    const clearBtn = $("#blocklist-search-clear");
    if (!box) return;
    if (!q) {
      box.classList.add("hidden");
      clearBtn?.classList.add("hidden");
      return;
    }
    clearBtn?.classList.remove("hidden");
    box.classList.remove("hidden");
    box.innerHTML = '<div class="muted">Searching indexed blocklists, custom rules, and 20 service presets...</div>';
    try {
      const res = await api("/api/feeds/search?q=" + encodeURIComponent(q));
      const parts = [];
      (res.preset_matches || []).forEach(p => {
        parts.push(
          '<div class="live-pulse-row">' +
            '<div class="live-pulse-main">' +
              '<div class="live-pulse-domain-line"><span class="badge info">Preset</span><strong>' + escapeHtml(p.name) + '</strong></div>' +
              '<small class="muted">Matched domains: ' + escapeHtml((p.matched_domains || []).join(", ")) + '</small>' +
            '</div>' +
          '</div>'
        );
      });
      (res.rule_matches || []).forEach(r => {
        parts.push(
          '<div class="live-pulse-row">' +
            '<div class="live-pulse-main">' +
              '<div class="live-pulse-domain-line"><span class="badge ' + (r.action === "allow" ? "allowed" : "blocked") + '">Rule (' + escapeHtml(r.action) + ')</span><strong>' + escapeHtml(r.pattern) + '</strong></div>' +
              '<small class="muted">Scope: ' + escapeHtml(r.kind) + ' • Profile: ' + escapeHtml(r.profile) + '</small>' +
            '</div>' +
          '</div>'
        );
      });
      (res.feed_matches || []).forEach(f => {
        parts.push(
          '<div class="live-pulse-row">' +
            '<div class="live-pulse-main">' +
              '<div class="live-pulse-domain-line"><span class="badge blocked">Feed: ' + escapeHtml(f.feed_name) + '</span><strong>' + escapeHtml(f.domain) + '</strong></div>' +
              '<small class="muted">Category: ' + escapeHtml(f.category) + '</small>' +
            '</div>' +
            '<button type="button" class="btn-mini-action" data-action="quick-allow" data-domain="' + escapeHtml(f.domain) + '">Whitelist</button>' +
          '</div>'
        );
      });
      (res.catalog_matches || []).forEach(c => {
        parts.push(
          '<div class="live-pulse-row">' +
            '<div class="live-pulse-main">' +
              '<div class="live-pulse-domain-line"><span class="badge allowed">Marketplace Feed</span><strong>' + escapeHtml(c.name) + ' (' + escapeHtml(c.scale) + ')</strong></div>' +
              '<small class="muted">' + escapeHtml(c.url) + '</small>' +
            '</div>' +
          '</div>'
        );
      });
      if (!parts.length) {
        box.innerHTML =
          '<div class="live-pulse-row">' +
            '<div class="live-pulse-main"><strong>No blocklist or preset matches for "' + escapeHtml(q) + '"</strong><small class="muted">You can block or whitelist this domain directly as a custom rule.</small></div>' +
            '<div class="button-row">' +
              '<button type="button" class="btn-mini-action" data-action="quick-block" data-domain="' + escapeHtml(q) + '">Block Domain</button>' +
              '<button type="button" class="btn-mini-action" data-action="quick-allow" data-domain="' + escapeHtml(q) + '">Allow Domain</button>' +
            '</div>' +
          '</div>';
      } else {
        box.innerHTML = parts.slice(0, 12).join("");
      }
    } catch (err) {
      box.innerHTML = '<div class="empty-state">' + escapeHtml(err.message) + '</div>';
    }
  };
  $("#blocklist-search-btn")?.addEventListener("click", runBlocklistSearch);
  $("#blocklist-search-input")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      runBlocklistSearch();
    }
  });
  $("#blocklist-search-clear")?.addEventListener("click", () => {
    if ($("#blocklist-search-input")) $("#blocklist-search-input").value = "";
    $("#blocklist-search-results")?.classList.add("hidden");
    $("#blocklist-search-clear")?.classList.add("hidden");
  });

  // Curated Blocklist Quick-Fill
  $$(".preset-feed-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      $("#feed-name").value = btn.dataset.name || "";
      $("#feed-url").value = btn.dataset.url || "";
      $("#feed-category").value = btn.dataset.cat || "ads";
      $("#feed-format").value = btn.dataset.fmt || "auto";
      toast("Pre-filled " + (btn.dataset.name || "feed") + " — click Add Blocklist to save");
    });
  });

  $("#feed-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const category = $("#feed-category").value;
      await api("/api/feeds", {
        method: "POST",
        body: {
          name: $("#feed-name").value.trim(),
          url: $("#feed-url").value.trim(),
          category,
          format: $("#feed-format").value,
          enabled: true
        }
      });
      $("#feed-name").value = "";
      $("#feed-url").value = "";
      state.feeds = await api("/api/feeds");
      const profile = defaultProfile();
      if (profile && !(profile.categories || []).includes(category)) {
        const cfg = deepCopy(state.config);
        const target = cfg.profiles.find(item => item.id === profile.id) || cfg.profiles[0];
        target.categories = Array.from(new Set([...(target.categories || []), category])).sort();
        await saveConfig(cfg, {}, "Blocklist added and category enabled");
      } else {
        renderFeeds();
        toast("Blocklist added");
      }
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("#refresh-feeds")?.addEventListener("click", () => refreshFeed(null));

  $("#rule-action")?.addEventListener("change", () => {
    $("#rule-value-wrap").classList.toggle("hidden", $("#rule-action").value !== "rewrite");
  });

  $("#rule-kind")?.addEventListener("change", () => {
    const kind = $("#rule-kind").value;
    if ($("#rule-subdomains")) {
      $("#rule-subdomains").checked = kind === "suffix";
      $("#rule-subdomains").disabled = kind === "regex";
    }
  });

  $("#rule-subdomains")?.addEventListener("change", () => {
    if ($("#rule-kind") && $("#rule-kind").value !== "regex") {
      $("#rule-kind").value = $("#rule-subdomains").checked ? "suffix" : "exact";
    }
  });

  $("#rule-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const kindSelect = $("#rule-kind") ? $("#rule-kind").value : "";
      const kind = kindSelect === "regex"
        ? "regex"
        : ($("#rule-subdomains") && !$("#rule-subdomains").checked ? "exact" : (kindSelect || "suffix"));
      const ttlSeconds = Number($("#rule-ttl") ? $("#rule-ttl").value : 0);
      await api("/api/rules", {
        method: "POST",
        body: {
          pattern: $("#rule-pattern").value.trim(),
          kind,
          action: $("#rule-action").value,
          profile: $("#rule-profile").value,
          value: $("#rule-value").value.trim(),
          ttl_seconds: ttlSeconds
        }
      });
      $("#rule-pattern").value = "";
      $("#rule-value").value = "";
      await refreshRulesAndPresets();
      toast("Custom rule saved");
    } catch (error) {
      toast(error.message, true);
    }
  });

  // Bulk Rules Modal
  const openBulkModal = () => {
    fillProfiles();
    $("#bulk-rules-modal")?.classList.remove("hidden");
    $("#bulk-rules-scrim")?.classList.remove("hidden");
  };
  const closeBulkModal = () => {
    $("#bulk-rules-modal")?.classList.add("hidden");
    $("#bulk-rules-scrim")?.classList.add("hidden");
  };
  $("#bulk-rules-btn")?.addEventListener("click", openBulkModal);
  $("#bulk-modal-close")?.addEventListener("click", closeBulkModal);
  $("#bulk-rules-scrim")?.addEventListener("click", closeBulkModal);

  $("#bulk-import-submit")?.addEventListener("click", async () => {
    const text = ($("#bulk-rules-input") ? $("#bulk-rules-input").value : "").trim();
    if (!text) {
      toast("Paste one or more domain patterns first", true);
      return;
    }
    const btn = $("#bulk-import-submit");
    try {
      btn.disabled = true;
      btn.textContent = "Importing...";
      const res = await api("/api/rules/import", {
        method: "POST",
        body: {
          content: text,
          action: $("#bulk-rules-action").value,
          kind: $("#bulk-rules-kind").value,
          profile: $("#bulk-rules-profile").value
        }
      });
      toast("Imported " + res.added + " rules (" + res.skipped + " skipped)");
      $("#bulk-rules-input").value = "";
      closeBulkModal();
      closeDeviceInsights();
      await refreshRulesAndPresets();
    } catch (err) {
      toast(err.message, true);
    } finally {
      btn.disabled = false;
      btn.textContent = "Import Rules";
    }
  });

  $("#bulk-export-btn")?.addEventListener("click", () => {
    const lines = (state.rules || []).map(r => (r.kind === "suffix" ? "||" + r.pattern + "^" : r.pattern));
    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "lattice-rules.txt";
    a.click();
    URL.revokeObjectURL(url);
    toast("Exported " + lines.length + " rules");
  });

  $("#clear-expired-btn")?.addEventListener("click", async () => {
    try {
      const res = await api("/api/rules/clear_expired", { method: "POST", body: {} });
      toast("Cleared " + res.cleared + " expired rule(s)");
      await refreshRulesAndPresets();
    } catch (err) {
      toast(err.message, true);
    }
  });

  // Client Profiles Editor
  $("#add-profile-btn")?.addEventListener("click", () => {
    state.config.profiles = state.config.profiles || [];
    const num = state.config.profiles.length + 1;
    state.config.profiles.push({
      id: "profile_" + num,
      name: "Subnet Profile " + num,
      networks: ["192.168." + num + ".0/24"],
      categories: ["ads", "tracking", "malware"],
      rate_limit: 300,
      logging: true
    });
    renderProfilesEditor();
  });

  $("#save-profiles-btn")?.addEventListener("click", async () => {
    try {
      const cfg = deepCopy(state.config);
      const used = new Set();
      cfg.profiles = $$("#profiles-editor [data-profile-index]").map((row, idx) => {
        const orig = (state.config.profiles || [])[idx] || {};
        const nameVal = row.querySelector('[data-field="name"]').value.trim() || "Profile";
        let id = orig.id || slug(nameVal) || "profile_" + (idx + 1);
        while (used.has(id)) id += "_" + (idx + 1);
        used.add(id);
        const networks = row.querySelector('[data-field="networks"]').value.split(",").map(s => s.trim()).filter(Boolean);
        const categories = row.querySelector('[data-field="categories"]').value.split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
        const rate_limit = Number(row.querySelector('[data-field="rate_limit"]').value || 300);
        const logging = row.querySelector('[data-field="logging"]').checked;
        return { id, name: nameVal, networks, categories, rate_limit, logging };
      });
      await saveConfig(cfg, {}, "Client policy profiles saved");
    } catch (err) {
      toast(err.message, true);
    }
  });

  // DNS Settings & Upstreams
  $("#add-upstream")?.addEventListener("click", () => {
    const number = (state.config.upstreams || []).length + 1;
    state.config.upstreams.push({
      id: "upstream_" + number,
      name: "Custom DoT " + number,
      address: "1.1.1.1",
      port: 853,
      sni: "cloudflare-dns.com",
      enabled: true
    });
    renderUpstreamEditor();
    renderRouteEditor();
  });

  $$(".preset-upstream-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      state.config.upstreams = state.config.upstreams || [];
      const exists = state.config.upstreams.some(u => u.address === btn.dataset.addr);
      if (exists) {
        toast(btn.dataset.name + " is already in your upstream list");
        return;
      }
      state.config.upstreams.push({
        id: btn.dataset.id + "_" + Math.random().toString(36).slice(2, 5),
        name: btn.dataset.name,
        address: btn.dataset.addr,
        port: 853,
        sni: btn.dataset.sni,
        enabled: true
      });
      renderUpstreamEditor();
      renderRouteEditor();
      toast("Added " + btn.dataset.name + " — click Apply DNS Settings to activate");
    });
  });

  $("#add-local-record-btn")?.addEventListener("click", () => {
    state.config.local_records = state.config.local_records || [];
    state.config.local_records.push({ name: "nas.lan", type: "A", value: "192.168.1.100", ttl: 300 });
    renderLocalRecordsEditor();
  });

  $("#add-route")?.addEventListener("click", () => {
    const first = (state.config.upstreams || []).find(item => item.enabled !== false);
    if (!first) {
      toast("Enable at least one upstream DNS server first", true);
      return;
    }
    state.config.routes = state.config.routes || [];
    state.config.routes.push({ suffix: "internal.example.com", upstreams: [first.id] });
    renderRouteEditor();
  });

  $("#run-benchmark-btn")?.addEventListener("click", async () => {
    const container = $("#benchmark-results");
    if (!container) return;
    container.innerHTML = '<div class="empty-state">Probing DoT resolvers over TLS (Port 853)...</div>';
    try {
      const payload = await api("/api/upstreams/benchmark", { method: "POST", body: { domain: "cloudflare.com" } });
      const list = Array.isArray(payload) ? payload : (payload.upstreams || []);
      if (!list.length) {
        container.innerHTML = '<div class="empty-state">Benchmark returned no results.</div>';
        return;
      }
      const maxLat = Math.max(25, ...list.map(r => (r.healthy ? Number(r.latency || 0) : 0)));
      container.innerHTML = list.map(r => {
        const pct = r.healthy ? Math.max(6, Math.min(100, Math.round((r.latency / maxLat) * 100))) : 100;
        const tone = !r.healthy ? "bad" : r.latency < 35 ? "good" : r.latency < 80 ? "warn" : "purple";
        return (
          '<div class="benchmark-row">' +
            "<div>" +
              '<span class="benchmark-name">' + escapeHtml(r.name) + "</span>" +
              '<div class="benchmark-meta">' + escapeHtml(r.address) + ":853 • SNI: " + escapeHtml(r.sni) + "</div>" +
            "</div>" +
            svgBar(pct, tone) +
            '<div class="benchmark-latency ' + (!r.healthy ? "text-red" : "text-green") + '">' +
              (r.healthy ? Number(r.latency).toFixed(1) + " ms" : "Unreachable") +
            "</div>" +
            '<span class="badge ' + (r.dnssec ? "allowed" : "warn") + '">' + (r.dnssec ? "DNSSEC AD" : "Standard") + "</span>" +
          "</div>"
        );
      }).join("");
    } catch (err) {
      container.innerHTML = '<div class="empty-state">' + escapeHtml(err.message) + "</div>";
    }
  });

  $("#save-dns")?.addEventListener("click", async () => {
    try {
      const cfg = deepCopy(state.config);
      const oldUpstreams = state.config.upstreams || [];
      cfg.upstreams = collectUpstreams();
      const idMap = new Map(cfg.upstreams.map((item, idx) => [oldUpstreams[idx] && oldUpstreams[idx].id, item.id]));
      cfg.routes = collectRoutes().map(route => ({
        suffix: route.suffix,
        upstreams: route.upstreams.map(id => idMap.get(id) || id)
      }));
      cfg.local_records = collectLocalRecords();
      cfg.dnssec = $("#dnssec-toggle").checked;
      if ($("#safesearch-toggle")) cfg.safesearch = $("#safesearch-toggle").checked;
      if ($("#rebind-toggle")) cfg.rebinding_protection = $("#rebind-toggle").checked;
      if ($("#doh-canary-toggle")) cfg.block_doh_canary = $("#doh-canary-toggle").checked;
      if ($("#risky-tld-toggle")) cfg.block_risky_tlds = $("#risky-tld-toggle").checked;
      if ($("#punycode-toggle")) cfg.block_punycode = $("#punycode-toggle").checked;
      if ($("#doh-enabled-toggle")) cfg.doh_enabled = $("#doh-enabled-toggle").checked;
      cfg.cache.prefetch = $("#prefetch-toggle").checked;
      cfg.cache.serve_expired = $("#stale-toggle").checked;
      cfg.block_response = $("#block-response").value;
      if ($("#block-custom-ip")) cfg.block_custom_ip = $("#block-custom-ip").value.trim();
      if ($("#block-ttl")) cfg.block_ttl = Number($("#block-ttl").value || 30);
      await saveConfig(cfg, {}, "DNS settings validated and applied");
    } catch (error) {
      toast(error.message, true);
    }
  });

  const handleFlushCache = async (btn) => {
    try {
      if (btn) btn.disabled = true;
      await api("/api/cache/flush", { method: "POST", body: {} });
      await refreshStatus();
      toast("L1 wire cache & Unbound resolver cache flushed");
    } catch (err) {
      toast(err.message, true);
    } finally {
      if (btn) btn.disabled = false;
    }
  };
  $("#flush-cache-btn")?.addEventListener("click", () => handleFlushCache($("#flush-cache-btn")));
  $("#flush-l1-btn")?.addEventListener("click", () => handleFlushCache($("#flush-l1-btn")));
  $("#flush-cache")?.addEventListener("click", () => handleFlushCache($("#flush-cache")));

  // Private DNS & Platform Tabs
  $$(".platform-tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      $$(".platform-tab-btn").forEach(b => b.classList.toggle("active", b === btn));
      const plat = btn.dataset.platform;
      ["android", "railway", "apple", "browser", "router", "curl"].forEach(id => {
        const el = $("#platform-instructions-" + id);
        if (el) el.classList.toggle("hidden", id !== plat);
      });
    });
  });

  $("#copy-hostname-btn")?.addEventListener("click", () => {
    const host = (state.config && state.config.hostname) || "";
    if (!host) {
      toast("Configure a Private DNS hostname first", true);
      return;
    }
    navigator.clipboard.writeText(host).then(() => toast("Copied " + host)).catch(() => toast(host));
  });

  $("#copy-doh-btn")?.addEventListener("click", () => {
    const host = (state.config && state.config.hostname) || window.location.hostname;
    const url = "https://" + host + "/dns-query";
    navigator.clipboard.writeText(url).then(() => toast("Copied " + url)).catch(() => toast(url));
  });

  $("#frp-enabled")?.addEventListener("change", toggleFrpFields);
  $("#frp-auth")?.addEventListener("change", toggleFrpFields);

  $("#save-private")?.addEventListener("click", async () => {
    try {
      const cfg = deepCopy(state.config);
      cfg.hostname = $("#private-hostname").value.trim();
      cfg.email = $("#private-email").value.trim();
      cfg.public_target = $("#private-target").value.trim();
      cfg.frp.enabled = $("#frp-enabled").checked;
      cfg.frp.server = $("#frp-server").value.trim();
      cfg.frp.port = Number($("#frp-port").value || 7000);
      cfg.frp.auth = $("#frp-auth").value;
      cfg.frp.remote_port = 853;
      const secrets = {};
      if ($("#cloudflare-token").value.trim()) secrets.cloudflare = $("#cloudflare-token").value.trim();
      if ($("#frp-token").value.trim()) secrets.frp = $("#frp-token").value.trim();
      await saveConfig(cfg, secrets, "Private DNS configuration saved");
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("#sync-cloudflare")?.addEventListener("click", async () => {
    try {
      await api("/api/cloudflare/sync", { method: "POST", body: {} });
      toast("Cloudflare DNS synchronization started");
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("#issue-cert")?.addEventListener("click", async () => {
    try {
      await api("/api/tls/issue", { method: "POST", body: { agree: true } });
      toast("ACME DNS-01 certificate issuance started");
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("#generate-self-signed")?.addEventListener("click", async () => {
    const btn = $("#generate-self-signed");
    try {
      if (btn) btn.disabled = true;
      const hostVal = ($("#private-hostname") ? $("#private-hostname").value : "").trim();
      const res = await api("/api/tls/self-signed", { method: "POST", body: { hostname: hostVal } });
      toast("Activated SAN-matched TLS certificate for " + (res.hostname || "Private DNS"));
      await loadAll();
      await loadAndroidDoctor();
    } catch (error) {
      toast(error.message, true);
    } finally {
      if (btn) btn.disabled = false;
    }
  });

  $("#run-vpn-doctor")?.addEventListener("click", async () => {
    await loadVpnDoctor();
    toast("Verified 6 VPN & roaming continuity safeguards");
  });

  $("#dash-reconnect-upstreams-btn")?.addEventListener("click", async () => {
    const btn = $("#dash-reconnect-upstreams-btn");
    try {
      if (btn) btn.disabled = true;
      await api("/api/upstreams/reconnect", { method: "POST", body: {} });
      await refreshStatus();
      toast("Upstream TLS pool reset & resolver cache refreshed");
    } catch (err) {
      toast(err.message, true);
    } finally {
      if (btn) btn.disabled = false;
    }
  });

  $("#run-android-doctor")?.addEventListener("click", async () => {
    await loadAndroidDoctor();
    toast("Android Private DNS readiness verified");
  });

  $("#upload-cert-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await api("/api/tls/upload", {
        method: "POST",
        body: {
          certificate: $("#upload-cert-pem").value.trim(),
          private_key: $("#upload-key-pem").value.trim()
        }
      });
      $("#upload-cert-pem").value = "";
      $("#upload-key-pem").value = "";
      toast("TLS certificate validated and activated");
      await loadAll();
    } catch (err) {
      toast(err.message, true);
    }
  });

  $("#restart-frp")?.addEventListener("click", async () => {
    try {
      await api("/api/frp/restart", { method: "POST", body: {} });
      toast("FRP tunnel supervisor restarting...");
    } catch (error) {
      toast(error.message, true);
    }
  });

  // System Page
  $("#save-system")?.addEventListener("click", async () => {
    try {
      const cfg = deepCopy(state.config);
      cfg.privacy.mode = $("#privacy-mode").value;
      cfg.privacy.retention_days = Number($("#retention-days").value);
      cfg.cache.rrset_mb = Number($("#rrset-cache").value);
      cfg.cache.message_mb = Number($("#message-cache").value);
      await saveConfig(cfg, {}, "System settings saved");
    } catch (error) {
      toast(error.message, true);
    }
  });

  $("#preview-metrics-btn")?.addEventListener("click", async () => {
    const pre = $("#metrics-preview");
    if (!pre) return;
    try {
      const res = await fetch("/api/metrics");
      const text = await res.text();
      pre.textContent = text;
      pre.classList.remove("hidden");
      toast("Loaded Prometheus / OpenMetrics snapshot");
    } catch (err) {
      toast(err.message, true);
    }
  });

  $("#diagnostic-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    $("#diagnostic-friendly").classList.add("hidden");
    $("#diagnostic-raw-wrap").classList.add("hidden");
    try {
      const result = await api("/api/diagnostics/resolve", {
        method: "POST",
        body: {
          name: $("#diag-name").value.trim(),
          qtype: Number($("#diag-type").value),
          client: ($("#diag-client") ? $("#diag-client").value : "127.0.0.1").trim() || "127.0.0.1"
        }
      });
      const action = result.policy && result.policy.action;
      const resolver = result.resolver || {};
      const box = $("#diagnostic-friendly");
      box.className = "diagnostic-result " + (action === "deny" ? "bad" : action === "rewrite" ? "warn" : resolver.rcode === 0 || resolver.skipped ? "good" : "warn");
      if (action === "deny") {
        box.innerHTML = "<strong>Blocked by Policy</strong><p>Lattice blocks this query via " + escapeHtml(result.policy.source || "policy rule") + " (Profile: " + escapeHtml(result.policy.profile) + ").</p>";
      } else if (action === "rewrite") {
        box.innerHTML = "<strong>Rewritten Locally</strong><p>Lattice synthesizes local response " + escapeHtml(result.policy.value || "") + " (" + escapeHtml(result.policy.source) + ").</p>";
      } else if (resolver.rcode === 0) {
        const recs = (resolver.records || []).map(r => escapeHtml(r.type + " " + r.data + " (TTL " + r.ttl + "s)")).join(" • ");
        box.innerHTML = "<strong>Allowed & Resolved Normally</strong><p>Passed policy (" + escapeHtml(result.policy.profile) + ") and resolved in " + Number(resolver.latency || 0).toFixed(1) + " ms (" + Number(resolver.answers || 0) + " answer RRs, DNSSEC AD=" + Boolean(resolver.dnssec_authenticated) + ")" + (recs ? ": <code>" + recs + "</code>" : ".") + "</p>";
      } else {
        box.innerHTML = "<strong>Allowed, Resolver RCODE " + escapeHtml(resolver.rcode != null ? resolver.rcode : resolver.reason) + "</strong><p>" + escapeHtml(resolver.error || "Passed policy, upstream returned non-zero RCODE.") + "</p>";
      }
      box.classList.remove("hidden");
      $("#diagnostic-result").textContent = JSON.stringify(result, null, 2);
      $("#diagnostic-raw-wrap").classList.remove("hidden");
    } catch (error) {
      const box = $("#diagnostic-friendly");
      box.className = "diagnostic-result bad";
      box.innerHTML = "<strong>Diagnostic Trace Failed</strong><p>" + escapeHtml(error.message) + "</p>";
      box.classList.remove("hidden");
    }
  });

  $("#download-backup")?.addEventListener("click", async () => {
    try {
      const data = await api("/api/backup");
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "lattice-dns-backup-" + new Date().toISOString().slice(0, 10) + ".json";
      a.click();
      URL.revokeObjectURL(url);
      toast("Snapshot backup downloaded");
    } catch (err) {
      toast(err.message, true);
    }
  });

  $("#restore-backup-btn")?.addEventListener("click", async () => {
    const fileInput = $("#restore-file");
    if (!fileInput || !fileInput.files.length) {
      toast("Select a backup JSON file first", true);
      return;
    }
    try {
      const text = await fileInput.files[0].text();
      const payload = JSON.parse(text);
      await api("/api/restore", { method: "POST", body: payload });
      toast("Snapshot restored and applied");
      await loadAll();
    } catch (err) {
      toast("Restore failed: " + err.message, true);
    }
  });

  $("#refresh-audit")?.addEventListener("click", loadAudit);

  $("#save-advanced")?.addEventListener("click", async () => {
    try {
      const cfg = JSON.parse($("#config-editor").value);
      await saveConfig(cfg, {}, "Advanced configuration JSON validated and applied");
    } catch (error) {
      toast(error.message, true);
    }
  });

  // Chart Mode Switcher (Volume / Block % / Allow vs Block)
  $$(".chart-mode-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      $$(".chart-mode-btn").forEach(b => b.classList.toggle("active", b === btn));
      state.chartMode = btn.dataset.chartMode || "volume";
      const series = (state.status && state.status.dashboard && state.status.dashboard.series) || [];
      renderChart(series);
    });
  });

  // Dashboard 1-Click Security Shield Toggles
  $$("#dash-shields-grid .shield-tile").forEach(tile => {
    tile.addEventListener("click", async () => {
      const key = tile.dataset.shield;
      if (!key) return;
      const nextVal = !tile.classList.contains("active");
      try {
        tile.disabled = true;
        const res = await api("/api/security/shields", { method: "POST", body: { [key]: nextVal } });
        if (res.config) state.config = res.config;
        if (state.status && res.security_shields) state.status.security_shields = res.security_shields;
        renderSecurityShields(res.security_shields || state.config);
        renderDnsForms();
        toast((nextVal ? "Enabled " : "Disabled ") + (tile.querySelector("strong")?.textContent || key));
      } catch (err) {
        toast(err.message, true);
      } finally {
        tile.disabled = false;
      }
    });
  });

  $("#dash-jump-schedule-btn")?.addEventListener("click", () => {
    switchPage("blocking");
    const rulesTabBtn = $('.subnav-item[data-block-tab="rules"]');
    if (rulesTabBtn) rulesTabBtn.click();
    setTimeout(() => $("#schedule-card")?.scrollIntoView({ behavior: "smooth", block: "start" }), 60);
  });

  // Scheduled Curfew & Deep Focus Engine (with Day-of-Week & Profile support)
  let selectedSchedMode = "bedtime";
  const collectSelectedDays = () => {
    const active = $$("#sched-days-pills .day-pill.active").map(b => b.dataset.day);
    return active.length ? active : ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
  };

  $$("#sched-days-pills .day-pill").forEach(pill => {
    pill.addEventListener("click", () => {
      pill.classList.toggle("active");
    });
  });

  $$(".sched-day-preset").forEach(btn => {
    btn.addEventListener("click", () => {
      const targetDays = new Set((btn.dataset.days || "").split(","));
      $$("#sched-days-pills .day-pill").forEach(pill => {
        pill.classList.toggle("active", targetDays.has(pill.dataset.day));
      });
    });
  });

  $$(".sched-preset-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      selectedSchedMode = btn.dataset.mode || "bedtime";
      if ($("#sched-start")) $("#sched-start").value = btn.dataset.start || "22:00";
      if ($("#sched-end")) $("#sched-end").value = btn.dataset.end || "07:00";
      if ($("#sched-enabled")) $("#sched-enabled").checked = true;
      if (selectedSchedMode === "focus") {
        const wk = new Set(["mon", "tue", "wed", "thu", "fri"]);
        $$("#sched-days-pills .day-pill").forEach(p => p.classList.toggle("active", wk.has(p.dataset.day)));
      } else {
        $$("#sched-days-pills .day-pill").forEach(p => p.classList.add("active"));
      }
      try {
        const res = await api("/api/schedule", {
          method: "POST",
          body: {
            enabled: true,
            mode: selectedSchedMode,
            start: $("#sched-start").value,
            end: $("#sched-end").value,
            days: collectSelectedDays(),
            profile: $("#sched-profile")?.value || "*"
          }
        });
        renderSchedule(res.schedule, res.active);
        toast("Activated " + btn.textContent + " schedule");
      } catch (err) {
        toast(err.message, true);
      }
    });
  });

  const saveScheduleFromUI = async () => {
    try {
      const res = await api("/api/schedule", {
        method: "POST",
        body: {
          enabled: Boolean($("#sched-enabled")?.checked),
          mode: selectedSchedMode,
          start: $("#sched-start")?.value || "22:00",
          end: $("#sched-end")?.value || "07:00",
          days: collectSelectedDays(),
          profile: $("#sched-profile")?.value || "*"
        }
      });
      renderSchedule(res.schedule, res.active);
      toast(res.schedule.enabled ? "Scheduled blocking window saved" : "Schedule disabled");
    } catch (err) {
      toast(err.message, true);
    }
  };
  $("#save-schedule-btn")?.addEventListener("click", saveScheduleFromUI);
  $("#sched-enabled")?.addEventListener("change", saveScheduleFromUI);

  // Collapsible Onboarding Checklist
  if (safeGetStorage("lattice_setup_collapsed") === "1") {
    $("#setup-guide")?.classList.add("collapsed");
    if ($("#toggle-setup-guide-btn")) $("#toggle-setup-guide-btn").textContent = "Expand";
  }
  $("#toggle-setup-guide-btn")?.addEventListener("click", () => {
    const guide = $("#setup-guide");
    const btn = $("#toggle-setup-guide-btn");
    if (!guide || !btn) return;
    const collapsed = guide.classList.toggle("collapsed");
    btn.textContent = collapsed ? "Expand" : "Collapse";
    safeSetStorage("lattice_setup_collapsed", collapsed ? "1" : "0");
  });

  // QR Provisioning Mode Pills
  $$(".qr-mode-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      $$(".qr-mode-btn").forEach(b => b.classList.toggle("active", b === btn));
      loadQrCode(btn.dataset.qrTarget || "doh");
    });
  });

  // Global Command Palette (⌘K / Ctrl+K)
  let cmdActiveIndex = 0;
  let currentCmdItems = [];

  const getCommandCatalog = (queryText) => {
    const q = (queryText || "").trim().toLowerCase();
    const items = [
      { title: "Go to Dashboard", sub: "Real-time telemetry & KPI overview", badge: "Page", run: () => switchPage("dashboard") },
      { title: "Go to Query Log", sub: "Inspect live DNS queries & packet forensics", badge: "Page", run: () => switchPage("queries") },
      { title: "Go to Blocking & Rules", sub: "Manage blocklists, 12 presets & regex rules", badge: "Page", run: () => switchPage("blocking") },
      { title: "Go to DNS Settings & L1 Cache", sub: "Upstreams, L1 wire cache & split-horizon LAN", badge: "Page", run: () => switchPage("dns") },
      { title: "Go to Private DNS & Railway Setup", sub: "TLS certificates, Android Doctor & QR provisioning", badge: "Page", run: () => switchPage("private") },
      { title: "Go to System & Diagnostics", sub: "Privacy mode, Prometheus metrics & backups", badge: "Page", run: () => switchPage("system") },
      { title: "Install Recommended 4-Feed Security Bundle", sub: "StevenBlack, AdGuard SDN, URLHaus & Peter Lowe", badge: "Action", run: () => { switchPage("blocking"); $("#install-bundle-btn")?.click(); } },
      { title: "Flush L1 Wire Cache & Unbound Resolver Cache", sub: "Purge all cached DNS RRsets immediately", badge: "Action", run: () => $("#flush-l1-btn")?.click() },
      { title: "Run Android Private DNS Readiness Doctor", sub: "Verify TLS 1.3 ALPN dot, EDNS0 & SOA compliance", badge: "Verify", run: () => { switchPage("private"); loadAndroidDoctor(); } },
      { title: "Run Live DoT Upstream Benchmark", sub: "Compare Cloudflare, Quad9, Google, AdGuard & Mullvad", badge: "Action", run: () => { switchPage("dns"); $("#run-benchmark-btn")?.click(); } },
      { title: "Pause Policy Blocking for 5 Minutes", sub: "Temporarily bypass blocklists and rules", badge: "Snooze", run: async () => { const res = await api("/api/blocking/pause", { method: "POST", body: { seconds: 300 } }); updateSnoozeUI(res); toast("Blocking paused for 5m"); } },
      { title: "Resume Policy Blocking Immediately", sub: "Re-enable all blocklists and custom rules", badge: "Policy", run: async () => { const res = await api("/api/blocking/pause", { method: "POST", body: { seconds: 0 } }); updateSnoozeUI(res); toast("Policy blocking resumed"); } },
      { title: "Enable Bedtime Curfew Schedule (22:00–07:00)", sub: "Block social, video & gaming overnight automatically", badge: "Schedule", run: async () => { const res = await api("/api/schedule", { method: "POST", body: { enabled: true, mode: "bedtime", start: "22:00", end: "07:00" } }); renderSchedule(res.schedule, res.active); toast("Bedtime Curfew Schedule enabled"); } },
      { title: "Enable Deep Work / Study Schedule (09:00–17:00)", sub: "Block distractions during daytime work/study hours", badge: "Schedule", run: async () => { const res = await api("/api/schedule", { method: "POST", body: { enabled: true, mode: "focus", start: "09:00", end: "17:00" } }); renderSchedule(res.schedule, res.active); toast("Deep Work Schedule enabled"); } },
      { title: "Toggle Dark / Light Theme", sub: "Switch control plane color palette", badge: "UI", run: () => $("#theme-toggle")?.click() }
    ];

    (state.presets || []).forEach(p => {
      items.push({
        title: (p.blocked ? "Unblock " : "Block ") + p.name,
        sub: p.description,
        badge: p.blocked ? "Blocked" : "Preset",
        run: async () => {
          await api("/api/rules/presets/toggle", { method: "POST", body: { preset: p.id, enabled: !p.blocked } });
          toast((!p.blocked ? "Blocked " : "Unblocked ") + p.name);
          await refreshRulesAndPresets();
        }
      });
    });

    if (q && q.includes(".") && !q.includes(" ")) {
      items.unshift({
        title: "Trace Domain in Diagnostic Simulator: " + q,
        sub: "Test policy verdict & live Unbound resolution for " + q,
        badge: "Diagnostic",
        run: () => {
          switchPage("system");
          $("#diag-name").value = q;
          $("#diagnostic-form").dispatchEvent(new Event("submit", { cancelable: true }));
        }
      });
    }

    if (!q) return items.slice(0, 12);
    return items.filter(it => (it.title + " " + it.sub + " " + it.badge).toLowerCase().includes(q)).slice(0, 14);
  };

  const renderCmdResults = () => {
    const listEl = $("#cmd-results-list");
    const inputEl = $("#cmd-search-input");
    if (!listEl || !inputEl) return;
    currentCmdItems = getCommandCatalog(inputEl.value);
    if (cmdActiveIndex >= currentCmdItems.length) cmdActiveIndex = 0;
    if (!currentCmdItems.length) {
      listEl.innerHTML = '<div class="empty-state">No matching commands. Type a domain (e.g. example.com) to run a live trace.</div>';
      return;
    }
    listEl.innerHTML = currentCmdItems.map((it, idx) =>
      '<button type="button" class="cmd-item ' + (idx === cmdActiveIndex ? "active" : "") + '" data-cmd-idx="' + idx + '">' +
        '<div class="cmd-item-main">' +
          '<span class="cmd-item-title">' + escapeHtml(it.title) + "</span>" +
          '<span class="cmd-item-sub">' + escapeHtml(it.sub) + "</span>" +
        "</div>" +
        '<span class="badge info">' + escapeHtml(it.badge) + "</span>" +
      "</button>"
    ).join("");

    $$("#cmd-results-list .cmd-item").forEach(btn => {
      btn.addEventListener("click", () => {
        const item = currentCmdItems[Number(btn.dataset.cmdIdx)];
        closeCmdPalette();
        if (item && item.run) item.run();
      });
    });
  };

  const openCmdPalette = () => {
    const modal = $("#cmd-palette-modal");
    const scrim = $("#cmd-palette-scrim");
    const input = $("#cmd-search-input");
    if (!modal || !scrim || !input) return;
    cmdActiveIndex = 0;
    input.value = "";
    renderCmdResults();
    modal.classList.remove("hidden");
    scrim.classList.remove("hidden");
    setTimeout(() => input.focus(), 20);
  };

  const closeCmdPalette = () => {
    $("#cmd-palette-modal")?.classList.add("hidden");
    $("#cmd-palette-scrim")?.classList.add("hidden");
  };

  $("#cmd-palette-btn")?.addEventListener("click", openCmdPalette);
  $("#cmd-palette-scrim")?.addEventListener("click", closeCmdPalette);
  $("#cmd-search-input")?.addEventListener("input", () => {
    cmdActiveIndex = 0;
    renderCmdResults();
  });
  $("#cmd-search-input")?.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (currentCmdItems.length) {
        cmdActiveIndex = (cmdActiveIndex + 1) % currentCmdItems.length;
        renderCmdResults();
      }
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (currentCmdItems.length) {
        cmdActiveIndex = (cmdActiveIndex - 1 + currentCmdItems.length) % currentCmdItems.length;
        renderCmdResults();
      }
    } else if (e.key === "Enter") {
      e.preventDefault();
      const item = currentCmdItems[cmdActiveIndex];
      closeCmdPalette();
      if (item && item.run) item.run();
    }
  });

  // Global Keyboard Shortcuts
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) {
      e.preventDefault();
      openCmdPalette();
      return;
    }
    const tag = document.activeElement ? document.activeElement.tagName : "";
    if (e.key === "Escape") {
      closeQueryDrawer();
      closeBulkModal();
      closeCmdPalette();
      $("#snooze-menu")?.classList.add("hidden");
      return;
    }
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
    if (e.key === "/") {
      e.preventDefault();
      switchPage("queries");
      $("#query-search")?.focus();
    } else if (e.key === "r" || e.key === "R") {
      e.preventDefault();
      $("#refresh")?.click();
    }
  });
}

bindEvents();
setInterval(refreshStatus, 5000);
bootstrap().catch(error => {
  $("#auth").classList.remove("hidden");
  $("#auth-error").textContent = error.message;
});
