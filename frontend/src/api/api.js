/**
 * src/api/api.js
 * Central API layer — all backend calls live here.
 */

export const BASE = import.meta.env.VITE_API_URL || "/api";

export function getToken()        { return sessionStorage.getItem("token"); }
export function saveToken(t)      { sessionStorage.setItem("token", t); }
export function clearToken()      { sessionStorage.removeItem("token"); }

function authHeaders() {
  const token = getToken();
  const impersonateId = sessionStorage.getItem("impersonation_id");
  const hasImpersonation = impersonateId && impersonateId !== "null" && impersonateId !== "undefined";
  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(hasImpersonation ? { "X-Impersonate-User": impersonateId } : {}),
  };
}

async function request(method, path, body) {
  const url = path.startsWith("http") ? path : `${BASE}${path}`;
  const res = await fetch(url, {
    method,
    headers: authHeaders(),
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });

  if (res.status === 401) {
    if (!window.location.pathname.includes("/login")) {
      clearToken();
      window.location.href = "/login";
    }
    
    // Try to get detail from response
    let detail = "Unauthorised";
    try {
      const data = await res.json();
      detail = data.detail || detail;
    } catch (_) {}
    throw new Error(detail);
  }

  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    let data = {};
    try {
      data = await res.json();
      detail = data.detail || JSON.stringify(data);
    } catch (_) {}
    const error = new Error(detail);
    error.response = { status: res.status, data };
    throw error;
  }

  if (res.status === 204) return null;

  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
      return await res.json();
  }
  return res;
}

// ── API object for axios-like usage ───────────────────────────────────────────
const api = {
    get: async (path) => ({ data: await request("GET", path) }),
    post: async (path, body) => ({ data: await request("POST", path, body) }),
    put: async (path, body) => ({ data: await request("PUT", path, body) }),
    delete: async (path) => ({ data: await request("DELETE", path) }),
};

export default api;

// ── Named exports for specific actions (original style) ───────────────────────
export const getMe = () => request("GET", "/auth/me");
export const login = (identifier, password, isAdmin = false) =>
    request("POST", "/auth/login", { username_or_email: identifier, password, is_admin: isAdmin });

export const register = (payload) => request("POST", "/auth/register", payload);
export const updateProfile = (data) => request('PUT', '/auth/me', data);
export const changePassword = (data) => request('POST', '/auth/change-password', data);

// ── Scan Groups / Campaigns ──────────────────────────────────────────────────
export const listScanGroups = () => request("GET", "/scan_groups");
export const createScanGroup = (data) => request("POST", "/scan_groups", data);
export const getScanGroup = (id) => request("GET", `/scan_groups/${id}`);
export const getGroupScans = (id) => request("GET", `/scan_groups/${id}/scans`);
export const startGroupDiscovery = (id, rawInput) => request("POST", `/scan_groups/${id}/discover`, { raw_input: rawInput });
export const startGroupScans = (id, selections, emailOptions) => 
    request("POST", `/scan_groups/${id}/scans/start`, { selections, email_options: emailOptions });

// ── Discovery ────────────────────────────────────────────────────────────────
export const discoverServices = (target, method) => request('POST', '/discover', { raw_input: target, input_type: method });
export const getDiscoveryStatus = (id) => request('GET',  `/discover/${id}/status`);
export const getDiscoveryResults = (id) => request('GET',  `/discover/${id}/results`);

// ── User Management (Admin Only) ───────────────────────────────────────────
export const listUsers = () => request("GET", "/users/");
export const getUser = (id) => request("GET", `/users/${id}`);
export const updateUserPermissions = (id, data) => request("PUT", `/users/${id}`, data);
export const deleteUser = (id) => request("DELETE", `/users/${id}`);

// ── Admin Tools ──────────────────────────────────────────────────────────
export const listDynamicChecks = () => request("GET", "/admin/dynamic-checks");
export const createDynamicCheck = (data) => request("POST", "/admin/dynamic-checks", data);
export const updateDynamicCheck = (id, data) => request("PUT", `/admin/dynamic-checks/${id}`, data);
export const deleteDynamicCheck = (id) => request("DELETE", `/admin/dynamic-checks/${id}`);
export const validateCustomRegex = (regex, sample) => request("POST", `/admin/dynamic-checks/validate-regex?regex=${encodeURIComponent(regex)}&sample_output=${encodeURIComponent(sample)}`);

// ── Reports ──────────────────────────────────────────────────────────────────
export const listReports = () => request("GET", "/reports");
export const createReport = (domain, mode, scanType = "web", emailFrom = null, emailTo = null) =>
  request("POST", "/reports", { 
    domain, 
    scan_mode: mode, 
    scan_type: scanType,
    email_from: emailFrom,
    email_to: emailTo
  });
export const getReportStatus = (id) => request("GET", `/reports/${id}/status`);
export const getReportDetails = (id, raw) => request("GET", `/reports/${id}/details${raw ? "?include_raw=true" : ""}`);
export const getReportEdits = (id) => request("GET", `/reports/${id}/edits`);
export const deleteReport = (id) => request("DELETE", `/reports/${id}`);
export const stopReport = (id) => request("POST", `/reports/${id}/stop`);
export const resumeReport = (id) => request("POST", `/reports/${id}/resume`);

export const compareReports = (a, b) => request("GET", `/reports/compare?scan1=${a}&scan2=${b}`);
export const compareCampaigns = (a, b) => request("GET", `/scan_groups/compare/all?group1=${a}&group2=${b}`);

export async function downloadComparisonReport(scan1, scan2) {
  const url = `${BASE}/reports/compare/download?scan1=${scan1}&scan2=${scan2}`;
  const res = await fetch(url, { headers: authHeaders() });
  if (res.status === 401) { clearToken(); window.location.href = "/login"; return; }
  if (!res.ok) throw new Error(`Comparison download failed: HTTP ${res.status}`);
  const blob = await res.blob();
  const disposition = res.headers.get("content-disposition") || "";
  let filename = `comparison_report_${scan1}_${scan2}.pdf`;
  const match = disposition.match(/filename=([^;]+)/);
  if (match) filename = match[1].replace(/['"]/g, "").trim();
  const a = Object.assign(document.createElement("a"), {
    href: URL.createObjectURL(blob),
    download: filename,
  });
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}

// ── Schedules ────────────────────────────────────────────────────────────────
export const listSchedules = () => request("GET", "/schedules");
export const getSchedule = (id) => request("GET", `/schedules/${id}`);
export const createSchedule = (data) => request("POST", "/schedules", data);
export const updateSchedule = (id, data) => request("PUT", `/schedules/${id}`, data);
export const deleteSchedule = (id) => request("DELETE", `/schedules/${id}`);

// ── Helpers ──────────────────────────────────────────────────────────────────
export const startScans = (selections, emailOptions) => request('POST', '/start', { selections, email_options: emailOptions });

export const uploadTargets = (file, scanType = "web", emailFrom = null, emailTo = null) => {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("scan_type", scanType);
  if (emailFrom) formData.append("email_from", emailFrom);
  if (emailTo) formData.append("email_to", emailTo);

  const token = getToken();
  return fetch(`${BASE}/reports/upload`, {
    method: "POST",
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: formData,
  }).then(async (res) => {
    if (!res.ok) {
      const j = await res.json().catch(() => ({}));
      throw new Error(j.detail || "Upload failed");
    }
    return res.json();
  });
};

export async function downloadReport(id) {
  const url = `${BASE}/reports/${id}/download`;
  const res = await fetch(url, { headers: authHeaders() });
  if (res.status === 401) { clearToken(); window.location.href = "/login"; return; }
  if (!res.ok) throw new Error(`Download failed: HTTP ${res.status}`);
  const blob = await res.blob();
  const disposition = res.headers.get("content-disposition") || "";
  let filename = `report_${id}.pdf`;
  const match = disposition.match(/filename=([^;]+)/);
  if (match) filename = match[1].replace(/['"]/g, "").trim();
  const a = Object.assign(document.createElement("a"), {
    href: URL.createObjectURL(blob),
    download: filename,
  });
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}

export async function updateReportResult(reportId, checkId, data) {
  return request("PUT", `/reports/${reportId}/results/${checkId}`, data);
}
