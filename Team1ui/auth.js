/* ============================================================
   auth.js -- login/register/otp controller
   ============================================================ */

(function () {
  "use strict";

  if (isTokenValid()) {
    window.location.href = "./index.html";
    return;
  }

  var tabs = Array.prototype.slice.call(document.querySelectorAll(".auth-tab"));
  var panels = Array.prototype.slice.call(document.querySelectorAll(".auth-panel"));

  var loginForm = document.getElementById("login-form");
  var registerForm = document.getElementById("register-form");
  var otpForm = document.getElementById("otp-form");

  var loginBtn = document.getElementById("login-btn");
  var loginBtnText = document.getElementById("login-btn-text");
  var loginBtnSpinner = document.getElementById("login-btn-spinner");

  var registerBtn = document.getElementById("register-btn");
  var registerBtnText = document.getElementById("register-btn-text");
  var registerBtnSpinner = document.getElementById("register-btn-spinner");

  var requestOtpBtn = document.getElementById("request-otp-btn");
  var otpLoginBtn = document.getElementById("otp-login-btn");
  var otpBtnText = document.getElementById("otp-btn-text");
  var otpBtnSpinner = document.getElementById("otp-btn-spinner");
  var otpEmailInput = document.getElementById("otp-email");
  var otpCodeInput = document.getElementById("otp-code");
  var otpRequestedFor = "";

  function normalizeEmail(value) {
    return String(value || "").trim().toLowerCase();
  }

  function setOtpLoginEnabled(enabled) {
    otpLoginBtn.disabled = !enabled;
  }

  setOtpLoginEnabled(false);
  otpEmailInput.addEventListener("input", function () {
    if (normalizeEmail(otpEmailInput.value) !== otpRequestedFor) {
      setOtpLoginEnabled(false);
    }
  });

  function setButtonLoading(btn, textEl, spinnerEl, loading, busyText, idleText) {
    btn.disabled = loading;
    if (textEl) textEl.textContent = loading ? busyText : idleText;
    if (spinnerEl) spinnerEl.style.display = loading ? "inline-block" : "none";
  }

  function switchPanel(panelId) {
    tabs.forEach(function (tab) {
      tab.classList.toggle("active", tab.getAttribute("data-panel") === panelId);
    });
    panels.forEach(function (panel) {
      panel.classList.toggle("active", panel.id === panelId);
    });
  }

  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      switchPanel(tab.getAttribute("data-panel"));
    });
  });

  async function handleLogin(e) {
    e.preventDefault();
    var username = document.getElementById("username").value.trim();
    var password = document.getElementById("password").value;

    if (!username || !password) {
      showToast("error", "Validation Error", "Please enter email and password.");
      return;
    }

    setButtonLoading(loginBtn, loginBtnText, loginBtnSpinner, true, "Signing in...", "Sign In");

    try {
      var body = new URLSearchParams();
      body.append("username", username);
      body.append("password", password);

      var response = await fetch(API.login, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
      });

      if (!response.ok) {
        var errData = await response.json().catch(function () {
          return {};
        });
        throw new Error(errData.detail || "Invalid credentials");
      }

      var data = await response.json();
      saveToken(data.access_token);
      showToast("success", "Welcome", "Redirecting to scan dashboard...");
      setTimeout(function () {
        window.location.href = "./index.html";
      }, 450);
    } catch (err) {
      showToast("error", "Login Failed", err.message || "Unable to login");
    } finally {
      setButtonLoading(loginBtn, loginBtnText, loginBtnSpinner, false, "Signing in...", "Sign In");
    }
  }

  async function handleRegister(e) {
    e.preventDefault();
    var name = document.getElementById("register-name").value.trim();
    var email = document.getElementById("register-email").value.trim();
    var password = document.getElementById("register-password").value;

    if (!name || !email || !password) {
      showToast("error", "Validation Error", "Please fill all registration fields.");
      return;
    }

    setButtonLoading(registerBtn, registerBtnText, registerBtnSpinner, true, "Creating...", "Create Account");

    try {
      var response = await fetch(API.register, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: name, email: email, password: password }),
      });
      if (!response.ok) {
        var errData = await response.json().catch(function () {
          return {};
        });
        throw new Error(errData.detail || "Registration failed");
      }

      showToast("success", "Account Created", "You can now sign in with your password.");
      registerForm.reset();
      document.getElementById("username").value = email;
      switchPanel("signin-panel");
    } catch (err) {
      showToast("error", "Registration Failed", err.message);
    } finally {
      setButtonLoading(registerBtn, registerBtnText, registerBtnSpinner, false, "Creating...", "Create Account");
    }
  }

  async function handleRequestOtp() {
    var email = normalizeEmail(otpEmailInput.value);
    if (!email) {
      showToast("error", "Validation Error", "Enter your registered email first.");
      return;
    }

    requestOtpBtn.disabled = true;
    requestOtpBtn.textContent = "Requesting OTP...";
    setOtpLoginEnabled(false);

    try {
      var response = await fetch(API.otpRequest, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email }),
      });
      if (!response.ok) {
        var errData = await response.json().catch(function () {
          return {};
        });
        throw new Error(errData.detail || "OTP request failed");
      }
      otpRequestedFor = email;
      setOtpLoginEnabled(true);
      otpCodeInput.focus();
      showToast("success", "OTP Sent", "Check your email for the OTP code.");
    } catch (err) {
      otpRequestedFor = "";
      setOtpLoginEnabled(false);
      showToast("error", "OTP Request Failed", err.message);
    } finally {
      requestOtpBtn.disabled = false;
      requestOtpBtn.textContent = "Request OTP";
    }
  }

  async function handleOtpLogin(e) {
    e.preventDefault();
    var email = normalizeEmail(otpEmailInput.value);
    var otp = otpCodeInput.value.trim();
    if (!email || !otp) {
      showToast("error", "Validation Error", "Enter email and OTP.");
      return;
    }
    if (email !== otpRequestedFor) {
      showToast("error", "OTP Required", "Request OTP for this email before login.");
      return;
    }

    setButtonLoading(otpLoginBtn, otpBtnText, otpBtnSpinner, true, "Verifying...", "Login with OTP");

    try {
      var response = await fetch(API.otpVerify, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email, otp: otp }),
      });
      if (!response.ok) {
        var errData = await response.json().catch(function () {
          return {};
        });
        throw new Error(errData.detail || "OTP verification failed");
      }
      var data = await response.json();
      saveToken(data.access_token);
      showToast("success", "Authenticated", "Redirecting to scan dashboard...");
      setTimeout(function () {
        window.location.href = "./index.html";
      }, 450);
    } catch (err) {
      showToast("error", "OTP Login Failed", err.message);
    } finally {
      setButtonLoading(otpLoginBtn, otpBtnText, otpBtnSpinner, false, "Verifying...", "Login with OTP");
    }
  }

  loginForm.addEventListener("submit", handleLogin);
  registerForm.addEventListener("submit", handleRegister);
  requestOtpBtn.addEventListener("click", handleRequestOtp);
  otpForm.addEventListener("submit", handleOtpLogin);
})();
