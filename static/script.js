"use strict";

// ==================== STATE ====================

const state = {
  password_result: null,
  phishing_result: null,
  file_result: null,
};

// ==================== HELPERS ====================

function $(id) {
  return document.getElementById(id);
}

function escapeHTML(value) {
  const div = document.createElement("div");
  div.textContent = value === undefined || value === null ? "" : String(value);
  return div.innerHTML;
}

async function postJSON(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  let data;
  try {
    data = await response.json();
  } catch (_err) {
    throw new Error("The server returned an unexpected response.");
  }

  if (!response.ok) {
    throw new Error(data.error || `Request failed (${response.status})`);
  }
  return data;
}

async function postForm(url, formData) {
  const response = await fetch(url, { method: "POST", body: formData });

  let data;
  try {
    data = await response.json();
  } catch (_err) {
    throw new Error("The server returned an unexpected response.");
  }

  if (!response.ok) {
    throw new Error(data.error || `Request failed (${response.status})`);
  }
  return data;
}

function setLoading(container, message) {
  container.classList.remove("hidden");
  container.innerHTML = `
    <div class="state-message">
      <span class="spinner" aria-hidden="true"></span>
      <span>${escapeHTML(message)}</span>
    </div>
  `;
}

function setError(container, message) {
  container.classList.remove("hidden");
  container.innerHTML = `
    <div class="state-message error">
      <span aria-hidden="true">&#9888;</span>
      <span>${escapeHTML(message)}</span>
    </div>
  `;
}

function showResult(container, html) {
  container.classList.remove("hidden");
  container.innerHTML = html;
}

/** Map a 0-100 percentage-ish value to a tone class. */
function toneFromPercent(percent) {
  if (percent >= 70) return "tone-good";
  if (percent >= 40) return "tone-warn";
  return "tone-bad";
}

function buildMeter(percent, tone) {
  const clamped = Math.max(0, Math.min(100, percent));
  return `<div class="meter-track"><div class="meter-fill" style="width:${clamped}%"></div></div>`.replace(
    "meter-fill",
    `meter-fill ${tone}`
  );
}

function buildIndicatorList(items) {
  if (!Array.isArray(items) || items.length === 0) return "";
  return `<ul class="indicator-list">${items.map((item) => `<li>${escapeHTML(item)}</li>`).join("")}</ul>`;
}

function buildDetailGrid(details) {
  if (!details || typeof details !== "object") return "";
  const entries = Object.entries(details).filter(([, v]) => v !== null && v !== undefined && v !== "");
  if (entries.length === 0) return "";
  const items = entries
    .map(([key, value]) => {
      const label = key.replace(/_/g, " ");
      const displayValue = Array.isArray(value) ? value.join(", ") || "none" : String(value);
      return `
        <div class="detail-item">
          <span class="detail-label">${escapeHTML(label)}</span>
          <span class="detail-value">${escapeHTML(displayValue)}</span>
        </div>
      `;
    })
    .join("");
  return `<div class="detail-grid">${items}</div>`;
}

// ==================== NAVIGATION ====================

function showSection(sectionId) {
  document.querySelectorAll(".section").forEach((el) => {
    el.classList.toggle("hidden", el.id !== sectionId);
    el.classList.toggle("active", el.id === sectionId);
  });
  document.querySelectorAll(".nav-link").forEach((el) => {
    const isActive = el.dataset.section === sectionId;
    el.classList.toggle("active", isActive);
    el.setAttribute("aria-selected", isActive ? "true" : "false");
  });
  if (sectionId === "tips" && !state.tipsLoaded) {
    loadTips();
  }
  window.scrollTo({ top: 0, behavior: "smooth" });
  return false;
}

function initNavigation() {
  document.querySelectorAll(".nav-link").forEach((link) => {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      showSection(link.dataset.section);
    });
  });
  document.querySelectorAll("[data-goto]").forEach((btn) => {
    btn.addEventListener("click", () => showSection(btn.dataset.goto));
  });
}

// ==================== HEALTH / STATUS ====================

async function checkHealth() {
  const dot = document.querySelector("#statusPill .status-dot");
  const text = $("statusText");
  try {
    const response = await fetch("/api/health");
    if (!response.ok) throw new Error("offline");
    dot.classList.add("online");
    text.textContent = "System online";
  } catch (_err) {
    dot.classList.add("offline");
    text.textContent = "Connection issue";
  }
}

// ==================== PASSWORD CHECKER ====================

function renderPasswordResult(data) {
  const tone = toneFromPercent(data.percentage);
  const crack = data.crack_time || {};

  return `
    <div class="result-panel ${tone}">
      <div class="result-head">
        <span class="result-title">${escapeHTML(data.strength)}</span>
        <span class="result-score">${data.score}/${data.max_score} &middot; ${data.percentage}%</span>
      </div>
      ${buildMeter(data.percentage, tone)}
      <div class="result-body">
        ${buildIndicatorList(data.feedback)}
        <div class="recommendation-box">
          <strong>Estimated crack time</strong>
          <p>${escapeHTML(crack.estimated_time || "Unknown")} &mdash; assuming an offline attack against a properly salted hash. ${escapeHTML(crack.model || "")}</p>
        </div>
        ${buildDetailGrid({
          entropy_bits: data.entropy_bits ? `${data.entropy_bits} bits` : undefined,
          length: data.details && data.details.length,
        })}
      </div>
    </div>
  `;
}

async function checkPassword() {
  const input = $("passwordInput");
  const resultBox = $("passwordResult");
  const password = input.value;

  if (!password) {
    setError(resultBox, "Enter a password to analyze.");
    return;
  }

  setLoading(resultBox, "Analyzing password strength…");

  try {
    const data = await postJSON("/api/check-password", { password });
    state.password_result = data;
    showResult(resultBox, renderPasswordResult(data));
  } catch (error) {
    setError(resultBox, error.message);
  }
}

function initPasswordTools() {
  $("checkPasswordBtn").addEventListener("click", checkPassword);
  $("passwordInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") checkPassword();
  });

  const toggleBtn = $("togglePassword");
  const input = $("passwordInput");
  toggleBtn.addEventListener("click", () => {
    const isPassword = input.type === "password";
    input.type = isPassword ? "text" : "password";
    toggleBtn.textContent = isPassword ? "hide" : "show";
    toggleBtn.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
  });
}

// ==================== PHISHING DETECTOR ====================

function renderPhishingResult(data) {
  const percent = Math.max(0, 100 - data.risk_score * 10);
  const tone = toneFromPercent(percent);

  return `
    <div class="result-panel ${tone}">
      <div class="result-head">
        <span class="result-title">${escapeHTML(data.risk_level)}</span>
        <span class="result-score">Risk score ${data.risk_score}/10</span>
      </div>
      ${buildMeter(percent, tone)}
      <div class="result-body">
        ${buildIndicatorList(data.indicators)}
        <div class="recommendation-box">
          <strong>Recommendation</strong>
          <p>${escapeHTML(data.recommendation)}</p>
        </div>
        ${buildDetailGrid(data.details)}
      </div>
    </div>
  `;
}

async function checkPhishing() {
  const input = $("urlInput");
  const resultBox = $("phishingResult");
  const url = input.value.trim();

  if (!url) {
    setError(resultBox, "Enter a URL to analyze.");
    return;
  }

  setLoading(resultBox, "Analyzing URL…");

  try {
    const data = await postJSON("/api/check-phishing", { url });
    state.phishing_result = data;
    showResult(resultBox, renderPhishingResult(data));
  } catch (error) {
    setError(resultBox, error.message);
  }
}

function initPhishingTools() {
  $("checkPhishingBtn").addEventListener("click", checkPhishing);
  $("urlInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") checkPhishing();
  });
}

// ==================== FILE SCANNER ====================

function renderFileResult(data) {
  const percent = Math.max(0, 100 - (data.risk_score / 12) * 100);
  const tone = toneFromPercent(percent);

  return `
    <div class="result-panel ${tone}">
      <div class="result-head">
        <span class="result-title">${escapeHTML(data.threat_level)}</span>
        <span class="result-score">Risk score ${data.risk_score}</span>
      </div>
      ${buildMeter(percent, tone)}
      <div class="result-body">
        ${buildIndicatorList(data.indicators)}
        <div class="recommendation-box">
          <strong>Recommendation</strong>
          <p>${escapeHTML(data.recommendation)}</p>
        </div>
        ${buildDetailGrid(data.details)}
      </div>
    </div>
  `;
}

async function scanFilenameOnly() {
  const input = $("fileInput");
  const resultBox = $("fileResult");
  const filename = input.value.trim();

  if (!filename) {
    setError(resultBox, "Enter a filename to scan.");
    return;
  }

  setLoading(resultBox, "Scanning filename…");

  try {
    const data = await postJSON("/api/scan-file", { file: filename });
    state.file_result = data;
    showResult(resultBox, renderFileResult(data));
  } catch (error) {
    setError(resultBox, error.message);
  }
}

async function scanUploadedFile() {
  const fileInput = $("fileUploadInput");
  const resultBox = $("fileResult");
  const file = fileInput.files[0];

  if (!file) {
    setError(resultBox, "Choose a file to scan.");
    return;
  }

  const MAX_BYTES = 10 * 1024 * 1024;
  if (file.size > MAX_BYTES) {
    setError(resultBox, "File exceeds the 10 MB analysis limit.");
    return;
  }

  setLoading(resultBox, "Scanning file contents…");

  try {
    const formData = new FormData();
    formData.append("file", file);
    const data = await postForm("/api/scan-file", formData);
    state.file_result = data;
    showResult(resultBox, renderFileResult(data));
  } catch (error) {
    setError(resultBox, error.message);
  }
}

function initFileScanner() {
  $("scanFilenameBtn").addEventListener("click", scanFilenameOnly);
  $("fileInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") scanFilenameOnly();
  });

  const modeButtons = document.querySelectorAll(".mode-btn");
  const filenameGroup = $("filenameModeGroup");
  const uploadGroup = $("uploadModeGroup");

  modeButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      modeButtons.forEach((b) => {
        b.classList.toggle("active", b === btn);
        b.setAttribute("aria-selected", b === btn ? "true" : "false");
      });
      const isUpload = btn.dataset.mode === "upload";
      filenameGroup.classList.toggle("hidden", isUpload);
      uploadGroup.classList.toggle("hidden", !isUpload);
    });
  });

  const dropzone = $("dropzone");
  const fileUploadInput = $("fileUploadInput");
  const dropzoneTitle = $("dropzoneTitle");
  const scanUploadBtn = $("scanUploadBtn");

  function updateDropzoneLabel() {
    const file = fileUploadInput.files[0];
    if (file) {
      dropzoneTitle.textContent = file.name;
      scanUploadBtn.disabled = false;
    } else {
      dropzoneTitle.textContent = "Choose a file or drag it here";
      scanUploadBtn.disabled = true;
    }
  }

  fileUploadInput.addEventListener("change", updateDropzoneLabel);

  ["dragover", "dragenter"].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });
  });
  ["dragleave", "dragend"].forEach((evt) => {
    dropzone.addEventListener(evt, () => dropzone.classList.remove("dragover"));
  });
  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length) {
      fileUploadInput.files = e.dataTransfer.files;
      updateDropzoneLabel();
    }
  });

  scanUploadBtn.addEventListener("click", scanUploadedFile);
}

// ==================== SECURITY TIPS ====================

async function loadTips() {
  const resultBox = $("tipsResult");
  setLoading(resultBox, "Loading tips…");

  try {
    const response = await fetch("/api/security-tips");
    if (!response.ok) throw new Error("Could not load tips.");
    const data = await response.json();
    state.tipsLoaded = true;

    const items = (data.tips || [])
      .map(
        (tip, index) => `
        <div class="tip-item">
          <span class="tip-index">${String(index + 1).padStart(2, "0")}</span>
          <span>${escapeHTML(tip)}</span>
        </div>
      `
      )
      .join("");

    showResult(resultBox, `<div class="tips-grid">${items}</div>`);
  } catch (error) {
    setError(resultBox, error.message);
  }
}

// ==================== REPORT ====================

function renderReport(data) {
  const overall = data.overall_security_score;
  const tone = overall === null || overall === undefined ? "tone-warn" : toneFromPercent(overall);

  const componentRows = (data.components || [])
    .map(
      (c) => `
      <div class="component-row">
        <span class="component-name">${escapeHTML(c.name)}</span>
        <span class="component-status">${escapeHTML(c.status)} &middot; ${c.score_percent}%</span>
      </div>
    `
    )
    .join("");

  return `
    <div class="result-panel ${tone}">
      <div class="report-score-hero">
        <span class="report-score-number">${overall === null || overall === undefined ? "—" : overall}</span>
        <span class="report-score-label">${overall === null || overall === undefined ? "No checks run yet" : "composite score / 100"}</span>
      </div>
      <div class="result-body">
        ${componentRows ? `<div style="margin-bottom:14px">${componentRows}</div>` : ""}
        ${buildIndicatorList(data.recommendations)}
        <div class="recommendation-box">
          <strong>Next steps</strong>
          <p>${(data.next_steps || []).map(escapeHTML).join(" &middot; ")}</p>
        </div>
        <p style="margin-top:14px;font-size:12px;color:var(--text-faint)">${escapeHTML(data.note || "")}</p>
      </div>
    </div>
  `;
}

async function generateReport() {
  const resultBox = $("reportResult");
  setLoading(resultBox, "Compiling report…");

  try {
    const data = await postJSON("/api/generate-report", {
      password_result: state.password_result,
      phishing_result: state.phishing_result,
      file_result: state.file_result,
    });
    showResult(resultBox, renderReport(data));
  } catch (error) {
    setError(resultBox, error.message);
  }
}

function initReport() {
  $("generateReportBtn").addEventListener("click", generateReport);
}

// ==================== INIT ====================

document.addEventListener("DOMContentLoaded", () => {
  initNavigation();
  initPasswordTools();
  initPhishingTools();
  initFileScanner();
  initReport();
  checkHealth();
});
