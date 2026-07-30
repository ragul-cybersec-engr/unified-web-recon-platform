/* ============================================================
   details.js -- Recon details page controller
   Depends on: utils.js (loaded before this script)
   Globals used: requireAuth, getToken, decodeJWT, logout,
     apiFetch, API, showToast, escapeHTML
   ============================================================ */

(function () {
  "use strict";

  // Declare global variables
  const requireAuth = window.requireAuth;
  const getToken = window.getToken;
  const decodeJWT = window.decodeJWT;
  const logout = window.logout;
  const apiFetch = window.apiFetch;
  const API = window.API;
  const showToast = window.showToast;
  const escapeHTML = window.escapeHTML;

  /* Auth gate */
  if (!requireAuth()) return;

  /* ---------- Parse URL params ---------- */
  var params = new URLSearchParams(window.location.search);
  var orgname = params.get("org");

  if (!orgname) {
    window.location.href = "./index.html";
    return;
  }

  /* ---------- DOM References ---------- */
  var detailTitle = document.getElementById("detail-title");
  var detailSubtitle = document.getElementById("detail-subtitle");
  var statSubdomains = document.getElementById("stat-subdomains");
  var statLive = document.getElementById("stat-live");
  var statPorts = document.getElementById("stat-ports");
  var domainSections = document.getElementById("domain-sections");
  var loadingState = document.getElementById("loading-state");
  var logoutBtn = document.getElementById("logout-btn");
  var headerUser = document.getElementById("header-user");
  var activeScanType = "extended";

  /* ---------- Init ---------- */
  (function init() {
    detailTitle.textContent = orgname;
    detailSubtitle.textContent = "Reconnaissance data for " + orgname;

    var token = getToken();
    if (token) {
      var payload = decodeJWT(token);
      if (payload && payload.sub) {
        headerUser.textContent = payload.sub;
      }
    }

    logoutBtn.addEventListener("click", logout);
    loadAllData();
  })();

  /* ---------- Data Fetching ---------- */

  async function loadAllData() {
    loadingState.style.display = "";

    try {
      var qp = "?orgname=" + encodeURIComponent(orgname);
      var results = await Promise.allSettled([
        apiFetch(API.reconHistory + "/" + encodeURIComponent(orgname), { method: "GET" }),
        apiFetch(API.subdomain + qp, { method: "GET" }),
        apiFetch(API.live + qp, { method: "GET" }),
        apiFetch(API.openports + qp, { method: "GET" }),
      ]);

      var reconEvents = [];
      var subdomains = [];
      var liveHosts = [];
      var openPorts = [];

      if (results[0].status === "fulfilled" && results[0].value.ok) {
        var historyData = await results[0].value.json();
        reconEvents = Array.isArray(historyData) ? historyData : [];
      }

      activeScanType = detectScanType(reconEvents);
      if (activeScanType === "domain") {
        detailSubtitle.textContent =
          "Domain scan mode stores subdomains only. Use Extended scan to collect open ports and live hosts.";
      } else {
        detailSubtitle.textContent = "Reconnaissance data for " + orgname;
      }

      /* Parse subdomain response */
      if (results[1].status === "fulfilled" && results[1].value.ok) {
        var data = await results[1].value.json();
        subdomains = Array.isArray(data) ? data : (data.subdomains || data.results || []);
      }

      /* Parse live hosts response */
      if (results[2].status === "fulfilled" && results[2].value.ok) {
        var data2 = await results[2].value.json();
        liveHosts = Array.isArray(data2) ? data2 : (data2.hosts || data2.results || []);
      }

      /* Parse open ports response */
      if (results[3].status === "fulfilled" && results[3].value.ok) {
        var data3 = await results[3].value.json();
        openPorts = Array.isArray(data3) ? data3 : (data3.ports || data3.results || []);
      }

      /* Update summary stats */
      statSubdomains.textContent = subdomains.length;
      statLive.textContent = activeScanType === "domain" ? "N/A" : liveHosts.length;
      statPorts.textContent = activeScanType === "domain" ? "N/A" : openPorts.length;

      /* Group data by domain and render */
      renderDomainSections(subdomains, liveHosts, openPorts);

    } catch (err) {
      showToast("error", "Data Load Failed", err.message);
    } finally {
      loadingState.style.display = "none";
    }
  }

  /* ---------- Rendering ---------- */

  function renderDomainSections(subdomains, liveHosts, openPorts) {
    domainSections.innerHTML = "";

    var domainMap = {};

    subdomains.forEach(function (item) {
      var domain = extractDomain(item);
      if (!domainMap[domain]) domainMap[domain] = { subdomains: [], liveHosts: [], openPorts: [] };
      domainMap[domain].subdomains.push(item);
    });

    liveHosts.forEach(function (item) {
      var domain = extractDomain(item);
      if (!domainMap[domain]) domainMap[domain] = { subdomains: [], liveHosts: [], openPorts: [] };
      domainMap[domain].liveHosts.push(item);
    });

    openPorts.forEach(function (item) {
      var domain = extractDomain(item);
      if (!domainMap[domain]) domainMap[domain] = { subdomains: [], liveHosts: [], openPorts: [] };
      domainMap[domain].openPorts.push(item);
    });

    var domainKeys = Object.keys(domainMap);

    if (domainKeys.length === 0) {
      domainSections.innerHTML =
        '<div class="empty-state" style="padding: 40px;">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="width:48px;height:48px;margin:0 auto 12px;opacity:0.35;">' +
            '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>' +
          '</svg>' +
          '<p>No reconnaissance data found for this organization yet.</p>' +
        '</div>';
      return;
    }

    domainKeys.forEach(function (domain, index) {
      var data = domainMap[domain];

      if (index > 0) {
        var divider = document.createElement("hr");
        divider.className = "section-divider";
        domainSections.appendChild(divider);
      }

      var section = document.createElement("div");
      section.className = "domain-section";
      section.innerHTML =
        '<div class="domain-section-header">' +
          '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--color-primary);">' +
            '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>' +
            '<path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>' +
          '</svg>' +
          '<span class="domain-badge">' + escapeHTML(domain) + '</span>' +
        '</div>' +
        '<div class="domain-tables">' +
          buildDataTable("Subdomains", data.subdomains, "subdomain") +
          buildDataTable("Live Hosts", data.liveHosts, "host") +
          buildDataTable("Open Ports", data.openPorts, "port") +
        '</div>';

      domainSections.appendChild(section);
    });
  }

  function buildDataTable(title, items, type) {
    if (activeScanType === "domain" && (type === "host" || type === "port")) {
      return '<div class="domain-table-group">' +
        '<h4>' + escapeHTML(title) + ' (not collected)</h4>' +
        '<div class="card" style="padding: 20px; text-align: center;">' +
          '<p style="color: var(--color-text-muted); font-size: 0.8125rem;">' +
          'Not collected in Domain scan mode. Use Extended scan for this data.' +
          '</p>' +
        '</div>' +
      '</div>';
    }

    if (!items || items.length === 0) {
      return '<div class="domain-table-group">' +
        '<h4>' + escapeHTML(title) + ' (0)</h4>' +
        '<div class="card" style="padding: 20px; text-align: center;">' +
          '<p style="color: var(--color-text-muted); font-size: 0.8125rem;">No ' + title.toLowerCase() + ' found</p>' +
        '</div>' +
      '</div>';
    }

    var isObject = typeof items[0] === "object" && items[0] !== null;
    var tableHTML = "";

    if (isObject) {
      var keys = Object.keys(items[0]);
      tableHTML = '<div class="table-wrapper"><table class="table"><thead><tr>';
      keys.forEach(function (k) { tableHTML += '<th>' + escapeHTML(k) + '</th>'; });
      tableHTML += '</tr></thead><tbody>';
      items.forEach(function (item) {
        tableHTML += '<tr>';
        keys.forEach(function (k) {
          var val = item[k];
          if (Array.isArray(val)) {
            tableHTML += '<td>' + val.map(function (v) { return escapeHTML(String(v)); }).join(", ") + '</td>';
          } else {
            tableHTML += '<td>' + escapeHTML(String(val != null ? val : "--")) + '</td>';
          }
        });
        tableHTML += '</tr>';
      });
      tableHTML += '</tbody></table></div>';
    } else {
      var colName = type === "port" ? "Port" : type === "host" ? "Host" : "Subdomain";
      tableHTML = '<div class="table-wrapper"><table class="table"><thead><tr><th>#</th><th>' + escapeHTML(colName) + '</th></tr></thead><tbody>';
      items.forEach(function (item, i) {
        tableHTML += '<tr><td>' + (i + 1) + '</td><td><code style="font-family: monospace; font-size: 0.8125rem;">' + escapeHTML(String(item)) + '</code></td></tr>';
      });
      tableHTML += '</tbody></table></div>';
    }

    return '<div class="domain-table-group">' +
      '<h4>' + escapeHTML(title) + ' (' + items.length + ')</h4>' +
      '<div class="card" style="overflow: hidden;">' + tableHTML + '</div>' +
    '</div>';
  }

  function extractDomain(item) {
    var value = "";

    if (typeof item === "string") {
      value = item;
    } else if (typeof item === "object" && item !== null) {
      value = item.domain || item.subdomain || item.host || item.hostname || item.target || item.url || item.name || "";
    }

    if (!value) return "unknown";

    try {
      value = value.replace(/^https?:\/\//, "");
      value = value.split(":")[0];
      var parts = value.split(".");
      if (parts.length >= 2) {
        return parts.slice(-2).join(".");
      }
      return value;
    } catch (e) {
      return value;
    }
  }

  function detectScanType(events) {
    if (!Array.isArray(events) || events.length === 0) {
      return "extended";
    }
    for (var i = events.length - 1; i >= 0; i--) {
      if (events[i] && events[i].scan_type) {
        return events[i].scan_type;
      }
    }
    return "extended";
  }

})();
