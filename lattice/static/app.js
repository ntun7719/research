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
    api("/api/rules/presets")
  ]);
  state.status = results[0];
  state.config = results[1].config;
  state.secrets = results[1].secrets || {};
  state.rules = results[2] || [];
  state.feeds = results[3] || [];
  state.devices = results[4] || [];
  state.presets = results[5] || [];
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
  if (!state.authenticated) return;
  try {
    state.status = await api("/api/status?window=" + state.timeWindow);
    renderStatus();
    renderPrivateStatus();
    if (state.page === "queries" && state.livePolling) {
      await loadQueries();
    }
  } catch (error) {
    toast(error.message, true);
  }
}

function renderAll() {
  renderStatus();
  renderRules();
  renderFeeds();
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
  const privateReady = healthy && Boolean(s.tls && s.tls.valid);

  $("#queries-total").textContent = number(total);
  $("#blocked-rate").textContent = (total ? (blocked / total) * 100 : 0).toFixed(1) + "%";
  $("#blocked-count").textContent = number(blocked) + " blocked requests.";
  $("#mean-latency").textContent = Number(dashboard.latency || 0).toFixed(1) + " ms";
  $("#policy-size").textContent = number((s.policy || {}).indexed_domains || 0);

  if ($("#pill-allowed")) $("#pill-allowed").textContent = number(allowed);
  if ($("#pill-blocked")) $("#pill-blocked").textContent = number(blocked);
  if ($("#pill-rewritten")) $("#pill-rewritten").textContent = number(rewritten);
  if ($("#pill-errors")) $("#pill-errors").textContent = number(errors);

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

  renderChart(dashboard.series || []);
  renderHealth(s.upstreams || []);
  renderSetupGuide();
  renderTopDomains(dashboard);
  renderTopology(s, state.config);
  renderDGA(threat);
  updateSnoozeUI(s.pause_blocking);
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
  const certDone = Boolean(s.tls && s.tls.valid && s.tls.hostname_matches !== false);
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
      title: "Expose TCP port 853 to Android clients",
      help: listenerDone ? "DoT listener is ready" : "Direct port 853 or FRP PROXY v1 bridge",
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

function renderChart(series) {
  const svg = $("#traffic-chart");
  if (!svg) return;
  if (!series.length) {
    svg.innerHTML = '<text x="500" y="125" text-anchor="middle" fill="currentColor" opacity="0.45" font-size="13">No query telemetry recorded in this window yet</text>';
    return;
  }
  const width = 1000;
  const height = 250;
  const padTop = 18;
  const padBottom = 26;
  const padX = 18;
  const chartHeight = height - padTop - padBottom;
  const max = Math.max(1, ...series.map(item => Number(item.total || 0)));

  const getCoord = (val, idx) => {
    const x = series.length === 1 ? width / 2 : padX + (idx * (width - padX * 2)) / (series.length - 1);
    const y = height - padBottom - (Number(val || 0) / max) * chartHeight;
    return { x: Number(x.toFixed(1)), y: Number(y.toFixed(1)) };
  };

  let grid = "";
  for (let i = 0; i <= 4; i++) {
    const y = padTop + (chartHeight / 4) * i;
    grid += '<line class="chart-grid" x1="' + padX + '" x2="' + (width - padX) + '" y1="' + y.toFixed(1) + '" y2="' + y.toFixed(1) + '"></line>';
  }

  let totalPoints = series.map((s, i) => getCoord(s.total, i));
  let blockedPoints = series.map((s, i) => getCoord(s.blocked, i));
  if (series.length === 1) {
    totalPoints = [{ x: padX, y: totalPoints[0].y }, { x: width - padX, y: totalPoints[0].y }];
    blockedPoints = [{ x: padX, y: blockedPoints[0].y }, { x: width - padX, y: blockedPoints[0].y }];
  }

  const totalPoly = totalPoints.map(p => p.x + "," + p.y).join(" ");
  const blockedPoly = blockedPoints.map(p => p.x + "," + p.y).join(" ");
  const firstX = totalPoints[0].x;
  const lastX = totalPoints[totalPoints.length - 1].x;
  const bottomY = height - padBottom;

  const totalArea = firstX + "," + bottomY + " " + totalPoly + " " + lastX + "," + bottomY;
  const blockedArea = firstX + "," + bottomY + " " + blockedPoly + " " + lastX + "," + bottomY;

  svg.innerHTML =
    "<defs>" +
      '<linearGradient id="grad-total" x1="0%" y1="0%" x2="0%" y2="100%">' +
        '<stop offset="0%" stop-color="var(--primary)" stop-opacity="0.32"/>' +
        '<stop offset="100%" stop-color="var(--primary)" stop-opacity="0.0"/>' +
      "</linearGradient>" +
      '<linearGradient id="grad-blocked" x1="0%" y1="0%" x2="0%" y2="100%">' +
        '<stop offset="0%" stop-color="var(--red)" stop-opacity="0.36"/>' +
        '<stop offset="100%" stop-color="var(--red)" stop-opacity="0.0"/>' +
      "</linearGradient>" +
    "</defs>" +
    grid +
    '<polygon class="chart-area-total" points="' + totalArea + '"></polygon>' +
    '<polygon class="chart-area-blocked" points="' + blockedArea + '"></polygon>' +
    '<polyline class="chart-line-total" points="' + totalPoly + '"></polyline>' +
    '<polyline class="chart-line-blocked" points="' + blockedPoly + '"></polyline>';
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
}

async function loadQueries() {
  const q = ($("#query-search") ? $("#query-search").value : "").trim().toLowerCase();
  const filter = $("#query-filter") ? $("#query-filter").value : "all";
  const qtype = $("#query-qtype-filter") ? $("#query-qtype-filter").value : "0";
  let url = "/api/queries?limit=300";
  if (q) url += "&q=" + encodeURIComponent(q);
  if (filter && filter !== "all") url += "&action=" + encodeURIComponent(filter);
  if (qtype && qtype !== "0") url += "&qtype=" + encodeURIComponent(qtype);

  state.queries = await api(url);
  renderQueries();
}

function renderQueries() {
  const search = ($("#query-search") ? $("#query-search").value : "").trim().toLowerCase();
  const filter = $("#query-filter") ? $("#query-filter").value : "all";
  const qtypeFilter = $("#query-qtype-filter") ? Number($("#query-qtype-filter").value) : 0;

  const rows = (state.queries || []).filter(row => {
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

function renderPresets() {
  const grid = $("#presets-grid");
  if (!grid) return;
  const presets = state.presets || [];
  if (!presets.length) {
    grid.innerHTML = '<div class="empty-state">No service presets available.</div>';
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
        return (
          "<tr>" +
            '<td class="domain">' + escapeHtml(rule.pattern) + "</td>" +
            "<td>" + (rule.kind === "suffix" ? "Domain & subdomains (*." + escapeHtml(rule.pattern) + ")" : "Exact hostname only") + "</td>" +
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
                "<small>" + escapeHtml(feed.category) + " • " + number(feed.domain_count) + " domains • " + escapeHtml(feed.url) + (feed.error ? " (" + escapeHtml(feed.error) + ")" : "") + "</small>" +
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
    : '<div class="empty-state">No subscription blocklists added yet. Add a list using the form or quick-fill buttons.</div>';

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
        '<td><span class="code-pill">' + escapeHtml(dev.ip) + "</span></td>" +
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
            '<button type="button" class="btn-mini-action save-dev-btn" data-ip="' + escapeHtml(dev.ip) + '">Save</button>' +
            '<button type="button" class="btn-mini-action del-dev-btn" data-ip="' + escapeHtml(dev.ip) + '">×</button>' +
          "</div>" +
        "</td>" +
      "</tr>"
    );
  }).join("");

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
  $("#prefetch-toggle").checked = Boolean(cfg.cache && cfg.cache.prefetch);
  $("#stale-toggle").checked = Boolean(cfg.cache && cfg.cache.serve_expired);
  $("#block-response").value = cfg.block_response || "nxdomain";
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

  const hostText = cfg.hostname || "dns.example.com";
  if ($("#instruction-hostname")) $("#instruction-hostname").textContent = hostText;
  if ($("#instruction-doh")) $("#instruction-doh").textContent = "https://" + hostText + "/dns-query";
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
  $$(".nav-item").forEach(item => item.classList.toggle("active", item.dataset.page === target));

  const titles = {
    dashboard: ["Dashboard", "Real-time encrypted DNS telemetry, policy enforcement, and upstream health."],
    queries: ["Query Log", "Inspect live DNS lookups, filter decisions, and packet forensics."],
    blocking: ["Blocking", "Configure protection categories, remote blocklists, custom rules, and client profiles."],
    dns: ["DNS Settings", "Manage encrypted DoT upstreams, local LAN records, and Unbound resolver behavior."],
    private: ["Private DNS", "Set up Android Private DNS, TLS certificates, Cloudflare DNS sync, and FRP transport."],
    system: ["System", "Privacy controls, cache sizing, resolution diagnostics, backups, and security audit logs."]
  };

  const info = titles[target] || [target, ""];
  $("#page-title").textContent = info[0];
  $("#page-description").textContent = info[1];

  closeMobileNav();
  closeQueryDrawer();

  if (target === "queries") loadQueries().catch(err => toast(err.message, true));
  if (target === "private") loadAndroidDoctor();
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
  localStorage.setItem("lattice_theme", theme);
}

/* ==================== ONE-TIME EVENT BINDINGS ==================== */

function bindEvents() {
  const savedTheme = localStorage.getItem("lattice_theme") || "dark";
  setTheme(savedTheme === "light" ? "light" : "dark");

  $("#theme-toggle")?.addEventListener("click", () => {
    const current = document.documentElement.dataset.theme || "dark";
    setTheme(current === "dark" ? "light" : "dark");
  });

  $$(".nav-item").forEach(button => {
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

  $("#rule-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await api("/api/rules", {
        method: "POST",
        body: {
          pattern: $("#rule-pattern").value.trim(),
          kind: $("#rule-subdomains").checked ? "suffix" : "exact",
          action: $("#rule-action").value,
          profile: $("#rule-profile").value,
          value: $("#rule-value").value.trim()
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
      cfg.cache.prefetch = $("#prefetch-toggle").checked;
      cfg.cache.serve_expired = $("#stale-toggle").checked;
      cfg.block_response = $("#block-response").value;
      await saveConfig(cfg, {}, "DNS settings validated and applied");
    } catch (error) {
      toast(error.message, true);
    }
  });

  const handleFlushCache = async (btn) => {
    try {
      if (btn) btn.disabled = true;
      await api("/api/cache/flush", { method: "POST", body: {} });
      toast("Unbound DNS cache flushed");
    } catch (err) {
      toast(err.message, true);
    } finally {
      if (btn) btn.disabled = false;
    }
  };
  $("#flush-cache-btn")?.addEventListener("click", () => handleFlushCache($("#flush-cache-btn")));
  $("#flush-cache")?.addEventListener("click", () => handleFlushCache($("#flush-cache")));

  // Private DNS & Platform Tabs
  $$(".platform-tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      $$(".platform-tab-btn").forEach(b => b.classList.toggle("active", b === btn));
      const plat = btn.dataset.platform;
      ["android", "apple", "browser", "curl"].forEach(id => {
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

  // Global Keyboard Shortcuts
  document.addEventListener("keydown", (e) => {
    const tag = document.activeElement ? document.activeElement.tagName : "";
    if (e.key === "Escape") {
      closeQueryDrawer();
      closeBulkModal();
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
