/* ============================================================
   dashboard.js -- scan dashboard controller
   ============================================================ */

(function () {
  "use strict";

  if (!requireAuth()) return;

  var reconForm = document.getElementById("recon-form");
  var orgInput = document.getElementById("orgname");
  var domainInputsContainer = document.getElementById("domain-inputs");
  var addDomainBtn = document.getElementById("add-domain-btn");
  var reconBtnText = document.getElementById("recon-btn-text");
  var reconBtnSpinner = document.getElementById("recon-btn-spinner");
  var reconSubmitBtn = document.getElementById("recon-submit-btn");
  var activeScansContainer = document.getElementById("active-scans");
  var activeEmpty = document.getElementById("active-empty");
  var logoutBtn = document.getElementById("logout-btn");
  var headerUser = document.getElementById("header-user");
  var scanModeNote = document.getElementById("scan-mode-note");
  var scanModeInputs = reconForm.querySelectorAll('input[name="scan_type"]');

  var refreshTimer = null;
  var activeLoadInFlight = false;
  var pendingActiveRefresh = false;
  var activeLoadErrorShown = false;
  var lastActiveSignature = "";

  function init() {
    var token = getToken();
    if (token) {
      var payload = decodeJWT(token);
      if (payload && payload.sub) {
        headerUser.textContent = payload.sub;
      }
    }

    reconForm.querySelector('input[name="scan_type"][value="extended"]').checked = true;
    updateScanModeNote();

    reconForm.addEventListener("submit", handleNewRecon);
    addDomainBtn.addEventListener("click", addDomainRow);
    logoutBtn.addEventListener("click", logout);
    scanModeInputs.forEach(function (input) {
      input.addEventListener("change", updateScanModeNote);
    });

    loadActiveScans();
    refreshTimer = setInterval(loadActiveScans, 7000);
    window.addEventListener("beforeunload", function () {
      if (refreshTimer) clearInterval(refreshTimer);
    });
  }

  function addDomainRow() {
    var row = document.createElement("div");
    row.className = "domain-row";
    row.innerHTML =
      '<input type="text" class="form-input domain-input" placeholder="e.g. example.com" required />' +
      '<button type="button" class="btn-remove-domain" aria-label="Remove domain">' +
      '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
      '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>' +
      "</svg>" +
      "</button>";

    row.querySelector(".btn-remove-domain").addEventListener("click", function () {
      row.remove();
    });

    domainInputsContainer.appendChild(row);
  }

  function setFormLoading(loading) {
    reconSubmitBtn.disabled = loading;
    reconBtnText.textContent = loading ? "Submitting..." : "Start Scan";
    reconBtnSpinner.style.display = loading ? "inline-block" : "none";
  }

  function getScanType() {
    var selected = reconForm.querySelector('input[name="scan_type"]:checked');
    return selected ? selected.value : "extended";
  }

  function formatScanTypeLabel(scanType) {
    return scanType === "domain"
      ? "Domain scan (subdomains only)"
      : "Extended scan (subdomains + ports + live hosts)";
  }

  function updateScanModeNote() {
    if (!scanModeNote) return;
    var scanType = getScanType();
    scanModeNote.textContent =
      scanType === "domain"
        ? "Domain scan completes after subdomain enumeration. Open ports/live hosts are not collected in this mode."
        : "Extended scan is recommended when you need open ports and live hosts.";
  }

  async function handleNewRecon(e) {
    e.preventDefault();

    var orgname = orgInput.value.trim();
    var scanType = getScanType();
    var domains = [];
    domainInputsContainer.querySelectorAll(".domain-input").forEach(function (el) {
      var val = el.value.trim();
      if (val) domains.push(val);
    });

    if (!orgname) {
      showToast("error", "Validation Error", "Organization name is required.");
      return;
    }
    if (domains.length === 0) {
      showToast("error", "Validation Error", "At least one domain is required.");
      return;
    }

    setFormLoading(true);

    try {
      var response = await apiFetch(API.newRecon, {
        method: "POST",
        body: JSON.stringify({
          orgname: orgname,
          domains: domains,
          scan_type: scanType,
        }),
      });

      if (!response.ok) {
        var errData = await response.json().catch(function () {
          return {};
        });
        throw new Error(errData.detail || "Failed to create scan job.");
      }

      var data = await response.json();
      var jobId = data.job_id || "";
      var reused = !!data.reused;
      var isCompleted = String(data.status || "").toLowerCase() === "completed";
      var successMessage;
      if (reused && isCompleted) {
        successMessage = (data.mode_message || "Using existing completed scan results.") + " Job " + jobId + ".";
      } else if (reused) {
        successMessage = (data.mode_message || formatScanTypeLabel(scanType)) + " Job " + jobId + " is already in progress.";
      } else {
        successMessage = (data.mode_message || formatScanTypeLabel(scanType)) + " Job " + jobId + " queued successfully.";
      }
      showToast(
        "success",
        "Scan Queued",
        successMessage
      );

      reconForm.reset();
      reconForm.querySelector('input[name="scan_type"][value="extended"]').checked = true;
      updateScanModeNote();

      var rows = domainInputsContainer.querySelectorAll(".domain-row");
      rows.forEach(function (row, idx) {
        if (idx > 0) row.remove();
      });

      loadActiveScans();
    } catch (err) {
      showToast("error", "Submission Failed", err.message || "Unable to start scan");
    } finally {
      setFormLoading(false);
    }
  }

  function renderActiveScans(records) {
    activeScansContainer.querySelectorAll(".scan-card").forEach(function (el) {
      el.remove();
    });

    if (!records.length) {
      activeEmpty.style.display = "block";
      return;
    }
    activeEmpty.style.display = "none";

    records.forEach(function (record) {
      var card = document.createElement("div");
      card.className = "scan-card";
      card.innerHTML =
        '<div class="scan-card-header">' +
        '<span class="scan-card-org">' +
        escapeHTML(record.orgname || "--") +
        "</span>" +
        statusBadge(record.status) +
        "</div>" +
        '<div class="scan-card-meta">' +
        '<div class="scan-card-meta-item"><span class="scan-card-meta-label">Mode</span><span>' +
        escapeHTML(formatScanTypeLabel(record.scan_type || "extended")) +
        "</span></div>" +
        '<div class="scan-card-meta-item"><span class="scan-card-meta-label">Domains</span><span>' +
        (record.domains && record.domains.length
          ? record.domains.map(function (d) {
              return escapeHTML(d);
            }).join(", ")
          : "--") +
        "</span></div>" +
        '<div class="scan-card-meta-item"><span class="scan-card-meta-label">Started</span><span>' +
        escapeHTML(formatDate(record.started_at)) +
        "</span></div>" +
        "</div>" +
        '<div style="margin-top:12px"><a class="btn btn-secondary btn-sm" href="./details.html?org=' +
        encodeURIComponent(record.orgname) +
        '">Open</a></div>';
      activeScansContainer.appendChild(card);
    });
  }

  async function loadActiveScans() {
    if (activeLoadInFlight) {
      pendingActiveRefresh = true;
      return;
    }
    activeLoadInFlight = true;
    try {
      var response = await apiFetch(API.allRecon + "?status=queued,running", { method: "GET" });
      if (!response.ok) {
        throw new Error("Failed to load scan records");
      }
      var data = await response.json();
      var records = Array.isArray(data) ? data : [];
      var signature = JSON.stringify(records.map(function (record) {
        return [
          record.job_id || "",
          record.orgname || "",
          record.status || "",
          record.scan_type || "",
          record.started_at || "",
          (record.domains || []).join(","),
        ];
      }));
      if (signature !== lastActiveSignature) {
        lastActiveSignature = signature;
        renderActiveScans(records);
      }
      activeLoadErrorShown = false;
    } catch (err) {
      if (!activeLoadErrorShown) {
        activeLoadErrorShown = true;
        showToast("error", "Load Failed", err.message || "Unable to load active scans.");
      }
    } finally {
      activeLoadInFlight = false;
      if (pendingActiveRefresh) {
        pendingActiveRefresh = false;
        loadActiveScans();
      }
    }
  }

  init();
})();
