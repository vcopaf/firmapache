const invoke = window.__TAURI__.core.invoke;
const currentWindow = window.__TAURI__.webviewWindow.getCurrentWebviewWindow();

let config = null;
let developmentConfig = null;
let activeSigningSession = null;
let loadingSessions = false;
let certificates = [];
let signingIdentities = [];
let tokens = [];
let certificatesLoaded = false;
let tokenCertificateCache = null;
let cachePoll = null;
let signingInProgress = false;
let manualFile = null;
let manualResult = null;
let manualSigningInProgress = false;
let latestDiagnostics = null;
const windowMode = currentWindow.label === "signing" ? "signing" : "main";

function showError(error) {
  const banner = document.getElementById("error-banner");
  banner.textContent = String(error);
  banner.classList.remove("hidden");
  window.setTimeout(() => banner.classList.add("hidden"), 6000);
}

function setAppStatus(text, state = "pending") {
  const textElement = document.getElementById("app-status-text");
  const dot = document.getElementById("app-status-dot");
  if (!textElement || !dot) {
    return;
  }

  textElement.textContent = text;
  dot.className = `status-dot ${state}`;
}

function empty(element, text) {
  element.className = "list empty";
  element.textContent = text;
}

function item(title, details) {
  const article = document.createElement("article");
  article.className = "item";
  const heading = document.createElement("strong");
  heading.textContent = title;
  article.appendChild(heading);
  details.forEach((detail) => {
    if (!detail) {
      return;
    }
    const line = document.createElement("span");
    line.textContent = detail;
    article.appendChild(line);
  });
  return article;
}

function showItems(container, items) {
  container.className = "list";
  container.replaceChildren(...items);
}

function button(label, className, action) {
  const element = document.createElement("button");
  element.type = "button";
  element.textContent = label;
  if (className) {
    element.className = className;
  }
  element.addEventListener("click", action);
  return element;
}

function approximateSize(bytes) {
  if (bytes < 1024) {
    return `${bytes} B aprox.`;
  }
  return `${(bytes / 1024).toFixed(1)} KB aprox.`;
}

function yesNo(value) {
  return value ? "Si" : "No";
}

function serverUrl(server) {
  const scheme = server.https ? "https" : "http";
  const host = server.host === "127.0.0.1" ? "localhost" : server.host;
  return `${scheme}://${host}:${server.port}/`;
}

async function loadStatus() {
  setAppStatus("Iniciando servidor...");
  const status = await invoke("test_server_status");
  document.getElementById("service-name").textContent = status.service;
  document.getElementById("service-version").textContent = status.version;
  document.getElementById("service-mode").textContent = status.https ? "HTTPS" : "HTTP";
  document.getElementById("service-port").textContent = status.port;
  document.getElementById("active-library-path").textContent =
    status.pkcs11_library_path || "No detectado";
  const indicator = document.getElementById("service-indicator");
  indicator.textContent = status.active ? "Activo" : "No disponible";
  indicator.className = `badge ${status.active ? "active" : "pending"}`;
  setAppStatus("Servicio local operativo", "active");
}

async function loadConfig() {
  setAppStatus("Cargando configuracion...");
  config = await invoke("get_config");
  developmentConfig = await invoke("get_development_config");
  renderServerConfig(config.server);
  renderDevelopmentConfig(developmentConfig);
  document.getElementById("library-path").value = config.pkcs11.library_path || "";
}

function renderServerConfig(server) {
  document.getElementById("server-host").value = server.host || "127.0.0.1";
  document.getElementById("server-port").value = server.port || 4637;
  document.getElementById("server-https").checked = Boolean(server.https);
  document.getElementById("server-current-url").textContent = serverUrl(server);
  updateServerWarning();
}

async function selectLibrary() {
  const selected = await invoke("select_pkcs11_library");
  if (selected) {
    document.getElementById("library-path").value = selected;
  }
}

async function saveConfig() {
  if (!config) {
    await loadConfig();
  }
  const server = readServerConfigInput();
  if (!server) {
    return;
  }
  const serverView = await invoke("update_server_config", server);
  config = await invoke("get_config");
  renderServerConfig(config.server);
  config.pkcs11.library_path = document.getElementById("library-path").value;
  config = await invoke("save_config", { config });
  renderServerConfig(config.server);
  const message = document.getElementById("save-message");
  message.textContent = "Configuración guardada. Reinicie el servidor para aplicar cambios.";
  window.setTimeout(() => { message.textContent = ""; }, 2500);
  certificates = [];
  tokens = [];
  certificatesLoaded = false;
  renderTokenCertificateCache(null);
  await refreshTokenCertificateCache();
  document.getElementById("server-current-url").textContent = serverView.url;
}

async function restartServer() {
  setAppStatus("Reiniciando servidor...");
  await invoke("restart_server");
  await loadStatus();
  const message = document.getElementById("save-message");
  message.textContent = "Servidor reiniciado";
  window.setTimeout(() => { message.textContent = ""; }, 2500);
}

async function testServerStatus() {
  const status = await invoke("test_server_status");
  setAppStatus(`Servidor activo en ${status.url}`, "active");
  document.getElementById("server-current-url").textContent = status.url;
}

function readServerConfigInput() {
  const host = document.getElementById("server-host").value.trim();
  const portText = document.getElementById("server-port").value.trim();
  const https = document.getElementById("server-https").checked;
  const warning = document.getElementById("server-warning");
  warning.classList.add("hidden");
  warning.textContent = "";

  if (!host) {
    warning.textContent = "Host no puede estar vacío.";
    warning.classList.remove("hidden");
    return null;
  }
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    warning.textContent = "Puerto inválido. Use un número entre 1024 y 65535.";
    warning.classList.remove("hidden");
    return null;
  }
  if (host === "0.0.0.0") {
    warning.textContent = "0.0.0.0 expone el firmador en la red. No recomendado.";
    warning.classList.remove("hidden");
  }
  return { host, port, https };
}

function updateServerWarning() {
  const host = document.getElementById("server-host").value.trim();
  const warning = document.getElementById("server-warning");
  if (host === "0.0.0.0") {
    warning.textContent = "0.0.0.0 expone el firmador en la red. No recomendado.";
    warning.classList.remove("hidden");
    return;
  }
  if (!warning.textContent || warning.textContent.includes("0.0.0.0")) {
    warning.textContent = "";
    warning.classList.add("hidden");
  }
}

function renderDevelopmentConfig(development) {
  if (!document.getElementById("development-enabled")) {
    return;
  }
  document.getElementById("development-enabled").checked = Boolean(development.enabled);
  document.getElementById("development-auto-sign").checked = Boolean(development.auto_sign);
  document.getElementById("development-fallback").checked = Boolean(development.fallback_to_modal);
  document.getElementById("development-pin-env").value = development.pin_env || "MINI_FIRMADOR_DEV_PIN";
  document.getElementById("development-pin-status").textContent = development.pin_env_defined
    ? "Variable encontrada"
    : "Variable no encontrada";
  populateDevelopmentIdentities();
}

async function saveDevelopmentConfig() {
  const payload = readDevelopmentConfigInput();
  developmentConfig = await invoke("update_development_config", payload);
  renderDevelopmentConfig(developmentConfig);
  document.getElementById("development-message").textContent = "Modo desarrollo guardado";
  window.setTimeout(() => { document.getElementById("development-message").textContent = ""; }, 2500);
}

async function testDevelopmentConfig() {
  const result = await invoke("test_development_config");
  document.getElementById("development-message").textContent = result.ready
    ? "Configuración de desarrollo lista"
    : result.messages.join(" | ");
  developmentConfig = await invoke("get_development_config");
  renderDevelopmentConfig(developmentConfig);
}

function readDevelopmentConfigInput() {
  return {
    enabled: document.getElementById("development-enabled").checked,
    autoSign: document.getElementById("development-auto-sign").checked,
    defaultIdentityId: document.getElementById("development-identity").value,
    pinEnv: document.getElementById("development-pin-env").value.trim() || "MINI_FIRMADOR_DEV_PIN",
    fallbackToModal: document.getElementById("development-fallback").checked,
  };
}

async function loadTokens() {
  setAppStatus("Detectando token...");
  await loadTokenCertificateCache();
  if (!tokens.length) {
    setAppStatus("No se detectaron tokens", "error");
    return;
  }
  setAppStatus("Token detectado", "active");
}

async function loadCertificates() {
  setAppStatus("Cargando certificados...");
  await loadTokenCertificateCache();
  if (!certificates.length) {
    setAppStatus("No se encontraron certificados", "error");
    return;
  }
  setAppStatus("Certificados cargados", "active");
}

async function loadTokenCertificateCache() {
  const cache = await invoke("get_token_certificate_cache");
  applyTokenCertificateCache(cache);
  await loadSigningIdentities();
  if (!cache.loaded_at) {
    setAppStatus("Cargando tokens y certificados...", "pending");
    startCacheWarmupPoll();
  }
}

async function refreshTokenCertificateCache() {
  setAppStatus("Actualizando tokens y certificados...");
  renderCacheLoading();
  const cache = await invoke("refresh_tokens_and_certificates");
  applyTokenCertificateCache(cache);
  await refreshSigningIdentities();
  setAppStatus("Tokens y certificados actualizados", "active");
}

async function loadSigningIdentities() {
  signingIdentities = await invoke("list_signing_identities");
  renderCertificates();
  populateSigningIdentities();
}

async function refreshSigningIdentities() {
  signingIdentities = await invoke("refresh_signing_identities");
  renderCertificates();
  populateSigningIdentities();
}

function applyTokenCertificateCache(cache) {
  tokenCertificateCache = cache;
  tokens = cache.tokens || [];
  certificates = cache.certificates || [];
  certificatesLoaded = Boolean(cache.loaded_at);
  renderTokenCertificateCache(cache);
  renderTokens();
  renderCertificates();
}

function renderTokens() {
  const container = document.getElementById("tokens");
  if (!container) {
    return;
  }
  if (!tokens.length) {
    empty(container, certificatesLoaded ? "No se detectaron slots." : "Cargando tokens...");
    return;
  }
  showItems(container, tokens.map((token) => item(
    tokenName(token),
    [
      `Slot ${token.slot_id} - ${token.token_present ? "presente" : "ausente"}`,
      `${token.manufacturer || ""} ${token.model || ""}`.trim(),
      token.serial_number ? `Serial: ${token.serial_number}` : "",
    ],
  )));
}

function renderCertificates() {
  const container = document.getElementById("certificates");
  if (!container) {
    return;
  }
  if (signingIdentities.length) {
    showItems(container, signingIdentities.map((identity) => item(
      identityTitle(identity),
      [
        tokenGroupLabel(identity),
        `Subject: ${identity.subject || "-"}`,
        `Issuer: ${identity.issuer || "-"}`,
        `Vence: ${identity.not_after || "-"}`,
        `Slot: ${identity.slot_id}`,
        identity.certificate_id ? `ID certificado: ${identity.certificate_id}` : "",
        identity.is_default ? "Predeterminado: Si" : "",
        !identity.is_available ? "Estado: token/certificado no disponible" : "",
        identity.is_expired ? "Estado: certificado expirado" : "",
      ],
    )));
    return;
  }
  if (!certificates.length) {
    empty(container, certificatesLoaded ? "No se encontraron certificados." : "Cargando certificados...");
    return;
  }
  showItems(container, certificates.map((certificate) => item(
    certificateTitle(certificate),
    [
      `Subject: ${certificate.subject || "-"}`,
      `Issuer: ${certificate.issuer || "-"}`,
      `Vence: ${certificate.not_after || "-"}`,
      `Slot: ${certificate.slot_id}`,
      certificate.id ? `ID: ${certificate.id}` : "",
    ],
  )));
}

function renderTokenCertificateCache(cache) {
  const status = document.getElementById("cache-status");
  if (!status) {
    return;
  }
  if (!cache || !cache.loaded_at) {
    status.textContent = "Cargando tokens y certificados...";
    document.getElementById("cache-loaded-at").textContent = "-";
    document.getElementById("cache-token-count").textContent = "0";
    document.getElementById("cache-certificate-count").textContent = "0";
    document.getElementById("cache-library-path").textContent = "-";
    return;
  }
  status.textContent = "Cache cargada";
  document.getElementById("cache-loaded-at").textContent = new Date(cache.loaded_at).toLocaleString();
  document.getElementById("cache-token-count").textContent = cache.token_count;
  document.getElementById("cache-certificate-count").textContent = cache.certificate_count;
  document.getElementById("cache-library-path").textContent = cache.pkcs11_library_path || "-";
}

function renderCacheLoading() {
  const status = document.getElementById("cache-status");
  if (status) {
    status.textContent = "Actualizando...";
  }
}

function startCacheWarmupPoll() {
  if (windowMode !== "main" || cachePoll) {
    return;
  }
  let attempts = 0;
  cachePoll = window.setInterval(() => {
    attempts += 1;
    run(async () => {
      await loadTokenCertificateCache();
      if (tokenCertificateCache?.loaded_at || attempts >= 30) {
        window.clearInterval(cachePoll);
        cachePoll = null;
      }
    });
  }, 1000);
}

function tokenName(token) {
  const label = token.label || "Token";
  const serial = token.serial_number ? ` - serial ${token.serial_number}` : "";
  return `${label}${serial}`;
}

function tokenForSlot(slotId) {
  return tokens.find((token) => token.slot_id === slotId);
}

function certificateTitle(certificate) {
  return certificate.subject || certificate.label || "Certificado";
}

function certificateDetails(certificate) {
  return [
    certificateTitle(certificate),
    `Issuer: ${certificate.issuer || "-"}`,
    `Vence: ${certificate.not_after || "-"}`,
    `Slot: ${certificate.slot_id}`,
    `ID: ${certificate.id || "-"}`,
  ].join(" | ");
}

function identityTitle(identity) {
  return identity.subject || identity.certificate_label || identity.certificate_id || identity.identity_id;
}

function tokenGroupLabel(identity) {
  const label = identity.token_label || "Token";
  const serial = identity.token_serial ? ` - serial ${identity.token_serial}` : "";
  const slot = Number.isFinite(identity.slot_id) ? ` - slot ${identity.slot_id}` : "";
  const unavailable = identity.is_available ? "" : " - no disponible";
  return `${label}${serial}${slot}${unavailable}`;
}

function identityDetails(identity) {
  const flags = [];
  if (identity.is_default) {
    flags.push("predeterminado");
  }
  if (!identity.is_available) {
    flags.push("no disponible");
  }
  if (identity.is_expired) {
    flags.push("expirado");
  } else if (identity.expires_soon) {
    flags.push("vence pronto");
  }
  return [
    identityTitle(identity),
    `Issuer: ${identity.issuer || "-"}`,
    `Vence: ${identity.not_after || "-"}`,
    `Slot: ${identity.slot_id}`,
    `ID: ${identity.certificate_id || "-"}`,
    flags.length ? `[${flags.join(", ")}]` : "",
  ].filter(Boolean).join(" | ");
}

function availableSigningIdentities() {
  return signingIdentities.filter((identity) =>
    identity.certificate_id && identity.is_available && !identity.is_expired
  );
}

function clearSigningForm() {
  activeSigningSession = null;
  clearPin();
  clearSigningError();
  document.getElementById("modal-files").replaceChildren();
  document.getElementById("modal-session-id").textContent = "-";
  document.getElementById("modal-format").textContent = "-";
  document.getElementById("modal-language").textContent = "-";
  document.getElementById("modal-status").textContent = "esperando";
  document.getElementById("modal-approve").textContent = "Aprobar";
  setSigningProgress("Esperando firma", false);
}

async function showSigningSession(session) {
  activeSigningSession = session;
  document.getElementById("modal-session-id").textContent = session.id;
  document.getElementById("modal-format").textContent = humanSignFormat(session.format);
  document.getElementById("modal-language").textContent = session.language || "-";
  document.getElementById("modal-status").textContent = session.status;
  document.getElementById("modal-approve").textContent =
    session.format === "pdf" ? "Firmar PDF" : "Firmar JWS";
  showItems(document.getElementById("modal-files"), session.files.map((file) => item(
    file.name,
    [`Tamano: ${approximateSize(file.approximate_size_bytes)}`],
  )));
  clearPin();
  clearSigningError();
  setSigningProgress("Esperando firma", false);
  populateSigningCertificates();
  if (!certificatesLoaded) {
    await loadTokenCertificateCache();
    if (!certificatesLoaded) {
      await refreshTokenCertificateCache();
    }
  }
  updateApprovalState();
  document.getElementById("modal-pin").focus();
}

async function resolveSigningSession(action, session) {
  const approve = document.getElementById("modal-approve");
  const reject = document.getElementById("modal-reject");
  approve.disabled = true;
  reject.disabled = true;
  try {
    if (action === "approve") {
      const approval = selectedApprovalInput();
      if (!approval) {
        return;
      }
      signingInProgress = true;
      setSigningProgress(signingProgressText(session.format), true);
      try {
        await invoke("approve_signing_session", {
          sessionId: session.id,
          identityId: approval.identityId,
          pin: approval.pin,
        });
        setSigningProgress("Completando firma...", true);
        clearPin();
        clearSigningForm();
        if (windowMode === "signing") {
          await closeSigningWindow();
        }
      } catch (error) {
        clearPin();
        showSigningError(error);
        setSigningProgress("Error de firma", false);
        return;
      } finally {
        signingInProgress = false;
      }
    } else {
      await invoke("reject_signing_session", { sessionId: session.id });
      clearSigningForm();
      if (windowMode === "signing") {
        await closeSigningWindow();
      }
    }
    await loadSessions();
  } finally {
    updateApprovalState();
    reject.disabled = false;
  }
}

function sessionItem(session) {
  const article = item(
    session.files.map((file) => file.name).join(", "),
    [
      `ID: ${session.id}`,
      `Formato: ${humanSignFormat(session.format)} - Idioma: ${session.language || "-"}`,
      `Estado: ${session.status}`,
    ],
  );
  const actions = document.createElement("div");
  actions.className = "item-actions";
  actions.append(
    button("Ver solicitud", "secondary", () => run(() => openSigningWindow())),
    button("Rechazar", "danger", () => run(() => resolveSigningSession("reject", session))),
    button("Aprobar", "", () => run(() => openSigningWindow())),
  );
  article.appendChild(actions);
  return article;
}

async function loadSessions() {
  const container = document.getElementById("sessions");
  const sessions = await invoke("list_signing_sessions");
  const pending = sessions.filter((session) => session.status === "pending");

  if (windowMode === "main") {
    if (!pending.length) {
      empty(container, "Sin sesiones pendientes.");
      return;
    }
    showItems(container, pending.map(sessionItem));
    setAppStatus("Esperando firma", "pending");
    await openSigningWindow();
    return;
  }

  if (!pending.length) {
    clearSigningForm();
    return;
  }

  const nextSession = activeSigningSession
    ? pending.find((session) => session.id === activeSigningSession.id) || pending[0]
    : pending[0];
  if (!activeSigningSession || activeSigningSession.id !== nextSession.id) {
    await showSigningSession(nextSession);
  }
}

async function openSigningWindow() {
  await invoke("show_signing_window");
}

async function closeSigningWindow() {
  await invoke("hide_signing_window");
}

function populateSigningCertificates() {
  populateIdentitySelect("modal-certificate", updateApprovalState);
}

function populateManualCertificates() {
  populateIdentitySelect("manual-certificate", updateManualState);
}

function populateSigningIdentities() {
  populateSigningCertificates();
  populateManualCertificates();
  populateDevelopmentIdentities();
}

function populateIdentitySelect(selectId, onUpdate) {
  const select = document.getElementById(selectId);
  if (!select) {
    return;
  }

  const selectedValue = select.value;
  const options = signingIdentities.filter((identity) => identity.certificate_id);
  const available = availableSigningIdentities();
  const defaultIdentity = options.find((identity) => identity.is_default && identity.is_available && !identity.is_expired);
  select.replaceChildren();
  if (!options.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = certificatesLoaded
      ? "No hay identidades de firma disponibles"
      : "Cargando identidades de firma...";
    select.appendChild(option);
    select.disabled = true;
    onUpdate();
    return;
  }

  select.disabled = false;
  const needsExplicitSelection = !defaultIdentity && available.length !== 1;
  if (needsExplicitSelection) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "Seleccione una identidad de firma";
    select.appendChild(option);
  }

  const identitiesByToken = groupByIdentityToken(options);

  identitiesByToken.forEach((tokenIdentities) => {
    const group = document.createElement("optgroup");
    group.label = tokenGroupLabel(tokenIdentities[0]);
    tokenIdentities.forEach((identity) => {
      const option = document.createElement("option");
      option.value = identity.identity_id;
      option.textContent = identityDetails(identity);
      option.disabled = !identity.is_available || identity.is_expired;
      group.appendChild(option);
    });
    select.appendChild(group);
  });

  if ([...select.options].some((option) => option.value === selectedValue && !option.disabled)) {
    select.value = selectedValue;
  } else if (defaultIdentity) {
    select.value = defaultIdentity.identity_id;
  } else if (available.length === 1) {
    select.value = available[0].identity_id;
  }
  onUpdate();
}

function populateDevelopmentIdentities() {
  const select = document.getElementById("development-identity");
  if (!select) {
    return;
  }
  const selectedValue = developmentConfig?.default_identity_id || select.value;
  populateIdentitySelect("development-identity", () => {});
  if ([...select.options].some((option) => option.value === selectedValue && !option.disabled)) {
    select.value = selectedValue;
  }
}

function groupByIdentityToken(items) {
  const groups = new Map();
  items.forEach((item) => {
    const key = item.token_serial || `slot-${item.slot_id}`;
    const group = groups.get(key) || [];
    group.push(item);
    groups.set(key, group);
  });
  return groups;
}

function selectedApprovalInput() {
  const certificate = document.getElementById("modal-certificate");
  const identityId = certificate.value;
  const selectedOption = certificate.options[certificate.selectedIndex];
  const pin = document.getElementById("modal-pin").value;
  if (!identityId || selectedOption?.disabled) {
    showSigningError("Missing certificate selection");
    updateApprovalState();
    return null;
  }
  if (!pin) {
    showSigningError("Missing PIN");
    updateApprovalState();
    return null;
  }

  return {
    identityId,
    pin,
  };
}

function updateApprovalState() {
  const approve = document.getElementById("modal-approve");
  const certificate = document.getElementById("modal-certificate");
  const identityId = certificate.value;
  const selectedOption = certificate.options[certificate.selectedIndex];
  const pin = document.getElementById("modal-pin").value;
  approve.disabled = signingInProgress || !identityId || selectedOption?.disabled || !pin;
}

function humanSignFormat(format) {
  if (format === "pdf") {
    return "PDF/PAdES";
  }
  if (format === "jws") {
    return "JWS";
  }
  return format || "-";
}

function signingProgressText(format) {
  if (format === "pdf") {
    return "Firmando PDF... No retire el token.";
  }
  return "Firmando JWS... No retire el token.";
}

async function selectManualFile() {
  const selected = await invoke("select_manual_file");
  if (!selected) {
    return;
  }
  manualFile = selected;
  manualResult = null;
  clearManualError();
  document.getElementById("manual-file-name").textContent = selected.name;
  document.getElementById("manual-file-size").textContent = approximateSize(selected.size_bytes);
  document.getElementById("manual-file-type").textContent = selected.detected_type;
  document.getElementById("manual-output-format").textContent = selected.output_format;
  document.getElementById("manual-suggested-name").textContent = selected.suggested_file_name || "-";
  document.getElementById("manual-sign-message").textContent = "";
  renderManualMode(selected);
  if ((selected.detected_type === "JSON" || selected.detected_type === "PDF") && !certificatesLoaded) {
    await loadTokenCertificateCache();
    if (!certificatesLoaded) {
      await refreshTokenCertificateCache();
    }
  }
  updateManualState();
}

async function signManualFile() {
  const input = selectedManualApprovalInput();
  if (!input) {
    return;
  }

  manualSigningInProgress = true;
  updateManualState();
  setManualProgress(true, manualFile.detected_type === "PDF"
    ? "Firmando PDF... No retire el token."
    : "Firmando archivo... no retire el token");
  clearManualError();
  try {
    if (manualFile.detected_type === "PDF") {
      manualResult = await invoke("sign_pdf", {
        path: manualFile.path,
        identityId: input.identityId,
        pin: input.pin,
      });
      document.getElementById("manual-sign-message").textContent = "PDF firmado. Abriendo Guardar como...";
      await saveManualPdfResult();
    } else {
      manualResult = await invoke("sign_file_as_jws", {
        path: manualFile.path,
        identityId: input.identityId,
        pin: input.pin,
      });
      document.getElementById("manual-sign-message").textContent = "Archivo firmado. Abriendo Guardar como...";
      await saveManualResult();
    }
  } catch (error) {
    manualResult = null;
    showManualError(error);
  } finally {
    clearManualPin();
    manualSigningInProgress = false;
    setManualProgress(false);
    updateManualState();
  }
}

async function saveManualResult() {
  if (!manualResult) {
    showManualError("No hay resultado firmado para guardar");
    return;
  }
  const response = await invoke("save_signed_file", {
    jwsBase64: manualResult.jws_base64,
    suggestedFileName: manualFile?.suggested_file_name || manualResult.suggested_file_name,
  });
  if (response.saved) {
    document.getElementById("manual-sign-message").textContent = `Guardado: ${response.path}`;
  } else {
    document.getElementById("manual-sign-message").textContent = "Archivo firmado. Guardado cancelado.";
  }
}

async function saveManualPdfResult() {
  if (!manualResult) {
    showManualError("No hay PDF firmado para guardar");
    return;
  }
  const response = await invoke("save_pdf_file", {
    pdfBase64: manualResult.pdf_base64,
    suggestedFileName: manualFile?.suggested_file_name || manualResult.suggested_file_name,
  });
  if (response.saved) {
    document.getElementById("manual-sign-message").textContent = `Guardado: ${response.path}`;
  } else {
    document.getElementById("manual-sign-message").textContent = "PDF firmado. Guardado cancelado.";
  }
}

function selectedManualApprovalInput() {
  if (!manualFile) {
    showManualError("archivo no seleccionado");
    updateManualState();
    return null;
  }
  if (manualFile.detected_type !== "JSON" && manualFile.detected_type !== "PDF") {
    showManualError("Actualmente solo se admiten archivos JSON y PDF");
    updateManualState();
    return null;
  }
  if (manualFile.detected_type === "PDF" && !pdfReady(manualFile)) {
    showManualError("El PDF no cumple las comprobaciones basicas para firma");
    updateManualState();
    return null;
  }
  const certificate = document.getElementById("manual-certificate");
  const identityId = certificate.value;
  const selectedOption = certificate.options[certificate.selectedIndex];
  const pin = document.getElementById("manual-pin").value;
  if (!identityId || selectedOption?.disabled) {
    showManualError("certificado no seleccionado");
    updateManualState();
    return null;
  }
  if (!pin) {
    showManualError("PIN vacio");
    updateManualState();
    return null;
  }

  return {
    identityId,
    pin,
  };
}

function updateManualState() {
  const signButton = document.getElementById("manual-sign-file");
  const certificate = document.getElementById("manual-certificate");
  const pinInput = document.getElementById("manual-pin");
  const identityId = certificate.value;
  const selectedOption = certificate.options[certificate.selectedIndex];
  const pin = document.getElementById("manual-pin").value;
  if (!manualFile || manualFile.detected_type === "No soportado") {
    signButton.textContent = "Firmar";
    signButton.disabled = true;
  } else if (manualFile.detected_type === "PDF") {
    signButton.textContent = "Firmar PDF";
    signButton.disabled =
      manualSigningInProgress || !pdfReady(manualFile) || !identityId || selectedOption?.disabled || !pin;
  } else {
    signButton.textContent = "Firmar";
    signButton.disabled = manualSigningInProgress || !identityId || selectedOption?.disabled || !pin;
  }
  const needsCredentials = manualFile?.detected_type === "JSON" || manualFile?.detected_type === "PDF";
  certificate.disabled = manualSigningInProgress || !needsCredentials;
  pinInput.disabled = manualSigningInProgress || !needsCredentials;
}

async function setSelectedDefaultIdentity(selectId) {
  const select = document.getElementById(selectId);
  const identityId = select.value;
  const selectedOption = select.options[select.selectedIndex];
  if (!identityId || selectedOption?.disabled) {
    showError("Seleccione una identidad de firma para marcarla como predeterminada");
    return;
  }
  signingIdentities = await invoke("set_default_signing_identity", { identityId });
  populateSigningIdentities();
  renderCertificates();
  if (windowMode === "main") {
    setAppStatus("Identidad predeterminada actualizada", "active");
  }
}

async function clearDefaultIdentity() {
  signingIdentities = await invoke("clear_default_signing_identity");
  populateSigningIdentities();
  renderCertificates();
  if (windowMode === "main") {
    setAppStatus("Identidad predeterminada eliminada", "active");
  }
}

function setManualProgress(active, text = "Firmando archivo... no retire el token") {
  const textElement = document.getElementById("manual-sign-progress-text");
  if (textElement) {
    textElement.textContent = text;
  }
  document.getElementById("manual-sign-progress").classList.toggle("hidden", !active);
}

function showManualError(error) {
  const message = document.getElementById("manual-sign-error");
  message.textContent = String(error);
  message.classList.remove("hidden");
}

function clearManualError() {
  const message = document.getElementById("manual-sign-error");
  message.textContent = "";
  message.classList.add("hidden");
}

function clearManualPin() {
  document.getElementById("manual-pin").value = "";
  updateManualState();
}

function renderManualMode(file) {
  const isJson = file.detected_type === "JSON";
  const isPdf = file.detected_type === "PDF";
  const isUnsupported = file.detected_type === "No soportado";

  document.getElementById("manual-json-panel").classList.toggle("hidden", !(isJson || isPdf));
  document.getElementById("manual-pdf-panel").classList.toggle("hidden", !isPdf);
  document.getElementById("manual-unsupported-message").classList.toggle("hidden", !isUnsupported);
  document.getElementById("manual-pdf-progress").classList.add("hidden");

  if (isJson) {
    document.getElementById("manual-validation-status").textContent = "JSON listo para generar JWS.";
  } else if (isPdf) {
    renderManualPdfInfo(file.pdf_info);
  } else {
    document.getElementById("manual-validation-status").textContent =
      "Actualmente solo se admiten archivos JSON y PDF.";
  }
}

function renderManualPdfInfo(info) {
  const validHeader = Boolean(info?.valid_header);
  const hasEof = Boolean(info?.has_eof_marker);
  document.getElementById("manual-pdf-valid-header").textContent = validHeader ? "Si" : "No";
  document.getElementById("manual-pdf-has-eof").textContent = hasEof ? "Si" : "No";
  document.getElementById("manual-validation-status").textContent =
    validHeader && hasEof
      ? "PDF inspeccionado. Listo para firmar como ETSI.CAdES.detached."
      : "PDF inspeccionado, pero no cumple todas las comprobaciones basicas.";
}

function pdfReady(file) {
  return Boolean(file?.pdf_info?.valid_header && file?.pdf_info?.has_eof_marker);
}

async function selectAndValidateJws() {
  const selected = await invoke("select_file_to_validate");
  if (!selected) {
    return;
  }
  document.getElementById("validation-message").textContent = `Validando ${selected.name}...`;
  const report = await invoke("validate_jws_file", { path: selected.path });
  renderJwsValidation(selected, report);
  document.getElementById("validation-message").textContent = "Validacion JWS completada";
}

async function selectAndValidatePdf() {
  const selected = await invoke("select_file_to_validate");
  if (!selected) {
    return;
  }
  document.getElementById("validation-message").textContent = `Validando ${selected.name}...`;
  const report = await invoke("validate_pdf_file", { path: selected.path });
  renderPdfValidation(selected, report);
  document.getElementById("validation-message").textContent = "Validacion PDF completada";
}

function renderJwsValidation(selected, report) {
  const container = document.getElementById("jws-validation-result");
  showItems(container, [
    item(selected.name, [
      `Tamano: ${approximateSize(selected.size_bytes)}`,
      `Entrada detectada: ${report.detected_input}`,
      `Algoritmo: ${report.alg || "-"}`,
      `x5c presente: ${yesNo(report.has_x5c)}`,
      `Subject: ${report.certificate_subject || "-"}`,
      `Payload: ${approximateSize(report.payload_size_bytes)}`,
      `Firma RS256: ${report.valid ? "valida" : "invalida"}`,
      report.error ? `Error: ${report.error}` : "",
    ]),
  ]);
}

function renderPdfValidation(selected, report) {
  const container = document.getElementById("pdf-validation-result");
  showItems(container, [
    item(selected.name, [
      `Tamano: ${approximateSize(selected.size_bytes)}`,
      `Firma detectada: ${yesNo(report.signature_detected)}`,
      `ByteRange presente: ${yesNo(report.byte_range_present)}`,
      `Contents presente: ${yesNo(report.contents_present)}`,
      `Filter Adobe.PPKLite: ${yesNo(report.filter_adobe_ppklite)}`,
      `SubFilter ETSI.CAdES.detached: ${yesNo(report.subfilter_cades_detached)}`,
      `/M presente: ${yesNo(report.m_present)}`,
      `/Name presente: ${yesNo(report.name_present)}`,
      `/Reason presente: ${yesNo(report.reason_present)}`,
      `/Location presente: ${yesNo(report.location_present)}`,
      `/ContactInfo presente: ${yesNo(report.contact_info_present)}`,
      `Diagnostico estructural: ${report.structurally_valid ? "correcto" : "incompleto"}`,
      report.recommendation || "",
    ]),
  ]);
}

async function runSystemDiagnostics() {
  document.getElementById("validation-message").textContent = "Ejecutando diagnostico...";
  latestDiagnostics = await invoke("run_diagnostics");
  renderDiagnostics(latestDiagnostics);
  document.getElementById("validation-message").textContent = "Diagnostico completado";
}

function renderDiagnostics(report) {
  const container = document.getElementById("diagnostics-result");
  showItems(container, [
    item("Sistema", [
      `Version: ${report.app_version}`,
      `Servidor: ${report.server_https ? "HTTPS" : "HTTP"} ${report.server_host}:${report.server_port}`,
      `URL activa: ${report.server_url || "-"}`,
      `Estado servidor: ${report.server_active ? "activo" : "no disponible"}`,
      `Driver configurado: ${report.configured_pkcs11_library_path || "-"}`,
      `Driver detectado: ${report.detected_pkcs11_library_path || "-"}`,
      `Driver encontrado: ${yesNo(report.driver_found)}`,
      `Fuente driver: ${report.driver_source || "-"}`,
      `PC/SC disponible: ${yesNo(report.pcsc_available)}`,
      report.last_restart_error ? `Ultimo error de reinicio: ${report.last_restart_error}` : "",
      report.last_error ? `Ultimo error: ${report.last_error}` : "",
    ]),
    item("Modo desarrollo", [
      `Activado: ${yesNo(report.development_enabled)}`,
      `Autofirma: ${yesNo(report.development_auto_sign)}`,
      `Identidad dev: ${report.development_default_identity_id || "-"}`,
      `PIN env: ${report.development_pin_env || "-"}`,
      `PIN env definido: ${yesNo(report.development_pin_env_defined)}`,
    ]),
    item("Tokens y certificados", [
      `Tokens detectados: ${report.token_count}`,
      `Certificados detectados: ${report.certificate_count}`,
      `Identidades de firma: ${(report.identities || []).length}`,
      `Identidad predeterminada: ${report.default_identity_id || "-"}`,
      `Certificados expirados: ${report.expired_certificate_count || 0}`,
      `Vencen en menos de 30 dias: ${report.expiring_soon_certificate_count || 0}`,
      ...((report.certificates || []).slice(0, 6).map((certificate) =>
        `${certificate.subject || certificate.label || "Certificado"} | vence: ${certificate.not_after || "-"} | slot: ${certificate.slot_id}`
      )),
    ]),
    item("Identidades", [
      ...((report.identities || []).slice(0, 8).map((identity) =>
        `${identity.is_default ? "[predeterminada] " : ""}${identityTitle(identity)} | ${tokenGroupLabel(identity)} | disponible: ${yesNo(identity.is_available)}`
      )),
    ]),
  ]);
}

async function exportDiagnostics() {
  const response = await invoke("export_diagnostics");
  document.getElementById("validation-message").textContent = response.saved
    ? `Diagnostico exportado: ${response.path}`
    : "Exportacion cancelada";
}

function setSigningProgress(text, active) {
  const progress = document.getElementById("signing-progress");
  const progressText = document.getElementById("signing-progress-text");
  progressText.textContent = text;
  progress.classList.toggle("hidden", !active);
}

function showSigningError(error) {
  const message = document.getElementById("modal-sign-error");
  message.textContent = String(error);
  message.classList.remove("hidden");
}

function clearSigningError() {
  const message = document.getElementById("modal-sign-error");
  message.textContent = "";
  message.classList.add("hidden");
}

function clearPin() {
  document.getElementById("modal-pin").value = "";
  updateApprovalState();
}

async function run(task) {
  try {
    await task();
  } catch (error) {
    if (windowMode === "signing") {
      showSigningError(error);
      setSigningProgress("Error de firma", false);
    } else {
      showError(error);
      setAppStatus("Error", "error");
    }
  }
}

function configureWindowMode() {
  document.body.dataset.window = windowMode;
  if (windowMode === "signing") {
    document.getElementById("signing-view").classList.remove("hidden");
  }
}

function bindEvents() {
  if (windowMode === "main") {
    document.getElementById("refresh-all").addEventListener("click", () => run(async () => {
      await Promise.all([loadStatus(), loadConfig(), loadTokenCertificateCache(), loadSessions()]);
    }));
    document.getElementById("choose-library").addEventListener("click", () => run(selectLibrary));
    document.getElementById("save-config").addEventListener("click", () => run(saveConfig));
    document.getElementById("restart-server").addEventListener("click", () => run(restartServer));
    document.getElementById("test-server-status").addEventListener("click", () => run(testServerStatus));
    document.getElementById("server-host").addEventListener("input", () => {
      updateServerWarning();
      const server = readServerConfigInput();
      if (server) {
        document.getElementById("server-current-url").textContent = serverUrl(server);
      }
    });
    document.getElementById("server-port").addEventListener("input", () => {
      const server = readServerConfigInput();
      if (server) {
        document.getElementById("server-current-url").textContent = serverUrl(server);
      }
    });
    document.getElementById("server-https").addEventListener("change", () => {
      const server = readServerConfigInput();
      if (server) {
        document.getElementById("server-current-url").textContent = serverUrl(server);
      }
    });
    document.getElementById("test-token").addEventListener("click", () => run(refreshTokenCertificateCache));
    document.getElementById("refresh-token-cache").addEventListener("click", () => run(refreshTokenCertificateCache));
    document.getElementById("save-development-config").addEventListener("click", () => run(saveDevelopmentConfig));
    document.getElementById("test-development-config").addEventListener("click", () => run(testDevelopmentConfig));
    document.getElementById("development-identity").addEventListener("change", () => {
      document.getElementById("development-message").textContent = "";
    });
    document.getElementById("development-pin-env").addEventListener("input", () => {
      document.getElementById("development-pin-status").textContent = "Guardar o probar para verificar";
    });
    document.getElementById("reload-tokens").addEventListener("click", () => run(refreshTokenCertificateCache));
    document.getElementById("reload-certificates").addEventListener("click", () => run(refreshTokenCertificateCache));
    document.getElementById("reload-sessions").addEventListener("click", () => run(loadSessions));
    document.getElementById("manual-select-file").addEventListener("click", () => run(selectManualFile));
    document.getElementById("manual-sign-file").addEventListener("click", () => run(signManualFile));
    document.getElementById("manual-set-default-identity").addEventListener("click", () => run(() => setSelectedDefaultIdentity("manual-certificate")));
    document.getElementById("manual-clear-default-identity").addEventListener("click", () => run(clearDefaultIdentity));
    document.getElementById("validate-select-jws").addEventListener("click", () => run(selectAndValidateJws));
    document.getElementById("validate-select-pdf").addEventListener("click", () => run(selectAndValidatePdf));
    document.getElementById("run-diagnostics").addEventListener("click", () => run(runSystemDiagnostics));
    document.getElementById("export-diagnostics").addEventListener("click", () => run(exportDiagnostics));
    document.getElementById("manual-certificate").addEventListener("change", () => {
      clearManualError();
      updateManualState();
    });
    document.getElementById("manual-pin").addEventListener("input", () => {
      clearManualError();
      updateManualState();
    });
  }

  document.getElementById("close-sign-modal").addEventListener("click", () => run(closeSigningWindow));
  document.getElementById("modal-certificate").addEventListener("change", () => {
    clearSigningError();
    updateApprovalState();
  });
  document.getElementById("modal-set-default-identity").addEventListener("click", () => run(() => setSelectedDefaultIdentity("modal-certificate")));
  document.getElementById("modal-clear-default-identity").addEventListener("click", () => run(clearDefaultIdentity));
  document.getElementById("modal-pin").addEventListener("input", () => {
    clearSigningError();
    updateApprovalState();
  });
  document.getElementById("modal-approve").addEventListener("click", () => {
    if (activeSigningSession) {
      run(() => resolveSigningSession("approve", activeSigningSession));
    }
  });
  document.getElementById("modal-reject").addEventListener("click", () => {
    if (activeSigningSession) {
      run(() => resolveSigningSession("reject", activeSigningSession));
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && windowMode === "signing") {
      run(closeSigningWindow);
    }
  });
}

async function bootstrap() {
  configureWindowMode();
  bindEvents();
  if (windowMode === "main") {
    await Promise.all([loadStatus(), loadConfig(), loadTokenCertificateCache(), loadSessions()]);
  } else {
    clearSigningForm();
    await loadTokenCertificateCache();
    await loadSessions();
  }
}

run(bootstrap);

window.setInterval(() => {
  if (loadingSessions) {
    return;
  }
  loadingSessions = true;
  run(loadSessions).finally(() => {
    loadingSessions = false;
  });
}, 1000);
