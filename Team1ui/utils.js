/* ============================================================
   Shared utilities
   ============================================================ */

var API_BASE = window.location.origin.replace(/\/$/, "");
var API = {
  login: API_BASE + "/login",
  register: API_BASE + "/register",
  otpRequest: API_BASE + "/login-otp/request",
  otpVerify: API_BASE + "/login-otp/verify",
  newRecon: API_BASE + "/newrecon",
  allRecon: API_BASE + "/allrecon",
  reconHistory: API_BASE + "/recon",
  deleteRecon: API_BASE + "/recon",
  subdomain: API_BASE + "/subdomain",
  live: API_BASE + "/live",
  openports: API_BASE + "/openports",
  downloadRecon: API_BASE + "/recon",
  sendReconEmail: API_BASE + "/recon",
};

function saveToken(token) {
  localStorage.setItem("recon_jwt", token);
}

function getToken() {
  return localStorage.getItem("recon_jwt");
}

function removeToken() {
  localStorage.removeItem("recon_jwt");
}

function decodeJWT(token) {
  try {
    var payload = token.split(".")[1];
    return JSON.parse(atob(payload));
  } catch (e) {
    return null;
  }
}

function isTokenValid() {
  var token = getToken();
  if (!token) return false;
  var payload = decodeJWT(token);
  if (!payload || !payload.exp) return false;
  return Date.now() < payload.exp * 1000;
}

function authHeaders(contentType) {
  var headers = {
    Authorization: "Bearer " + getToken(),
  };
  if (contentType) {
    headers["Content-Type"] = contentType;
  }
  return headers;
}

function requireAuth() {
  if (!isTokenValid()) {
    removeToken();
    window.location.href = "/login.html";
    return false;
  }
  return true;
}

function logout() {
  removeToken();
  window.location.href = "/login.html";
}

(function initToastContainer() {
  if (document.getElementById("toast-container")) return;
  var container = document.createElement("div");
  container.id = "toast-container";
  container.className = "toast-container";
  container.setAttribute("role", "status");
  container.setAttribute("aria-live", "polite");
  document.body.appendChild(container);
})();

var TOAST_ICONS = {
  success:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
  error:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
  info:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
};

function showToast(type, title, message, duration) {
  duration = duration || 4000;
  var container = document.getElementById("toast-container");
  var toast = document.createElement("div");
  toast.className = "toast toast-" + type;
  toast.innerHTML =
    '<div class="toast-icon">' +
    (TOAST_ICONS[type] || TOAST_ICONS.info) +
    "</div>" +
    '<div class="toast-content">' +
    '<div class="toast-title">' +
    escapeHTML(title) +
    "</div>" +
    (message
      ? '<div class="toast-message">' + escapeHTML(message) + "</div>"
      : "") +
    "</div>" +
    '<button class="toast-close" aria-label="Dismiss notification">' +
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>' +
    "</button>";

  toast.querySelector(".toast-close").addEventListener("click", function () {
    dismissToast(toast);
  });

  container.appendChild(toast);
  var timer = setTimeout(function () {
    dismissToast(toast);
  }, duration);
  toast._timer = timer;
}

function dismissToast(toast) {
  if (toast._dismissed) return;
  toast._dismissed = true;
  clearTimeout(toast._timer);
  toast.classList.add("toast-exit");
  setTimeout(function () {
    toast.remove();
  }, 300);
}

function showConfirmModal(title, message, confirmLabel) {
  confirmLabel = confirmLabel || "Delete";
  return new Promise(function (resolve) {
    var existing = document.getElementById("confirm-modal-overlay");
    if (existing) existing.remove();

    var overlay = document.createElement("div");
    overlay.id = "confirm-modal-overlay";
    overlay.className = "modal-overlay";
    overlay.innerHTML =
      '<div class="modal" role="alertdialog" aria-labelledby="modal-title" aria-describedby="modal-desc">' +
      '<h3 id="modal-title">' +
      escapeHTML(title) +
      "</h3>" +
      '<p id="modal-desc">' +
      escapeHTML(message) +
      "</p>" +
      '<div class="modal-actions">' +
      '<button class="btn btn-secondary" id="modal-cancel">Cancel</button>' +
      '<button class="btn btn-destructive" id="modal-confirm">' +
      escapeHTML(confirmLabel) +
      "</button>" +
      "</div>" +
      "</div>";

    document.body.appendChild(overlay);
    requestAnimationFrame(function () {
      overlay.classList.add("active");
    });

    function close(result) {
      overlay.classList.remove("active");
      setTimeout(function () {
        overlay.remove();
      }, 260);
      resolve(result);
    }

    overlay.querySelector("#modal-cancel").addEventListener("click", function () {
      close(false);
    });
    overlay.querySelector("#modal-confirm").addEventListener("click", function () {
      close(true);
    });
    overlay.addEventListener("click", function (e) {
      if (e.target === overlay) close(false);
    });
  });
}

function escapeHTML(str) {
  if (str == null) return "";
  var div = document.createElement("div");
  div.textContent = String(str);
  return div.innerHTML;
}

function formatDate(isoString) {
  if (!isoString) return "--";
  try {
    var d = new Date(isoString);
    return d.toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch (e) {
    return isoString;
  }
}

function statusBadge(status) {
  var s = (status || "unknown").toLowerCase();
  var cls =
    s === "completed"
      ? "badge-completed"
      : s === "running"
        ? "badge-running"
        : s === "queued"
          ? "badge-queued"
          : "badge-failed";
  return (
    '<span class="badge ' +
    cls +
    '"><span class="badge-dot"></span>' +
    escapeHTML(s) +
    "</span>"
  );
}

function domainChips(domains) {
  if (!domains || !domains.length) return "--";
  return domains
    .map(function (d) {
      return '<span class="domain-chip">' + escapeHTML(d) + "</span>";
    })
    .join(" ");
}

async function apiFetch(url, options) {
  options = options || {};
  var method = (options.method || "GET").toUpperCase();
  var hasBody = options.body !== undefined && options.body !== null;
  var isFormData = typeof FormData !== "undefined" && options.body instanceof FormData;

  var headers = options.headers || {};
  if (!headers.Authorization) {
    headers.Authorization = "Bearer " + getToken();
  }
  if (!headers["Content-Type"] && hasBody && method !== "GET" && !isFormData) {
    headers["Content-Type"] = "application/json";
  }
  options.headers = headers;
  if (method === "GET" && !options.cache) {
    options.cache = "no-store";
  }

  var response = await fetch(url, options);
  if (response.status === 401) {
    removeToken();
    window.location.href = "/login.html";
    throw new Error("Session expired");
  }
  return response;
}

function _extractFilename(contentDisposition) {
  if (!contentDisposition) return null;
  var match = /filename="?([^"]+)"?/.exec(contentDisposition);
  return match && match[1] ? match[1] : null;
}

async function downloadAuthenticatedFile(url, fallbackFilename) {
  var response = await apiFetch(url, { method: "GET" });
  if (!response.ok) {
    var errData = await response.json().catch(function () {
      return {};
    });
    throw new Error(errData.detail || "Download failed");
  }
  var blob = await response.blob();
  var header =
    response.headers.get("Content-Disposition") ||
    response.headers.get("content-disposition");
  var filename = _extractFilename(header) || fallbackFilename || "report";

  var objectUrl = window.URL.createObjectURL(blob);
  var link = document.createElement("a");
  link.href = objectUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(objectUrl);
}
