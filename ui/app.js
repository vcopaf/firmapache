const invoke = window.__TAURI__.core.invoke;
const currentWindow = window.__TAURI__.webviewWindow.getCurrentWebviewWindow();

let config = null;
let developmentConfig = null;
let pkcs12Tokens = [];
let activeSigningSession = null;
let loadingSessions = false;
let certificates = [];
let signingIdentities = [];
let tokens = [];
let certificatesLoaded = false;
let tokenCertificateCache = null;
let cachePoll = null;
let signingInProgress = false;
let manualFiles = [];
let manualResults = [];
let manualSigningInProgress = false;
let latestDiagnostics = null;
let serviceStatus = null;
let sessionsSnapshot = [];
let activeSection = "inicio";
let developmentLastTest = "Sin ejecutar";
const windowMode = currentWindow.label === "signing" ? "signing" : "main";
const sectionTitles = {
  inicio: "Inicio",
  firmar: "Firma manual",
  solicitudes: "Solicitudes",
  identidades: "Identidades",
  validacion: "Validacion",
  configuracion: "Configuracion",
  diagnostico: "Diagnostico",
  acerca: "Acerca de",
};

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
  const sidebarText = document.getElementById("sidebar-status-text");
  const sidebarDot = document.getElementById("sidebar-status-dot");
  if (sidebarText && sidebarDot) {
    sidebarText.textContent = text;
    sidebarDot.className = `status-dot ${state}`;
  }
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

function fileNameFromPath(path) {
  return String(path || "").split(/[\\/]/).filter(Boolean).pop() || "archivo";
}

function yesNo(value) {
  return value ? "Si" : "No";
}

function serverUrl(server) {
  const scheme = server.https ? "https" : "http";
  const host = server.host === "127.0.0.1" ? "localhost" : server.host;
  return `${scheme}://${host}:${server.port}/`;
}

async function loadBrandLogo() {
  const logo = await invoke("get_brand_logo_data_url");
  document.querySelectorAll(".brand-logo, .dashboard-logo, .signing-logo").forEach((image) => {
    image.src = logo;
  });
}

function showSection(section) {
  if (!sectionTitles[section]) {
    return;
  }
  activeSection = section;
  document.body.dataset.section = section;
  document.getElementById("section-title").textContent = sectionTitles[section];
  document.querySelectorAll("[data-section]").forEach((element) => {
    element.classList.toggle("hidden-section", element.dataset.section !== section);
  });
  document.querySelectorAll("[data-section-target]").forEach((buttonElement) => {
    buttonElement.classList.toggle("active", buttonElement.dataset.sectionTarget === section);
  });
}

function currentDefaultIdentity() {
  return signingIdentities.find((identity) => identity.is_default)
    || availableSigningIdentities()[0]
    || signingIdentities[0]
    || null;
}

function activeDevelopmentIdentity() {
  const identityId = developmentConfig?.default_identity_id;
  if (!identityId) {
    return null;
  }
  return signingIdentities.find((identity) => identity.identity_id === identityId) || null;
}

function currentSigningState() {
  const devEnabled = Boolean(developmentConfig?.enabled);
  const autoSign = Boolean(developmentConfig?.auto_sign);
  const autoSignRequested = devEnabled && autoSign;
  const identity = activeDevelopmentIdentity();
  const hasLocalPin = Boolean(developmentConfig?.has_local_pin);
  const pinAvailable = Boolean(hasLocalPin || developmentConfig?.pin_env_defined);
  const issues = [];

  if (autoSignRequested) {
    if (!developmentConfig?.default_identity_id) {
      issues.push("identidad no configurada");
    } else if (!identity) {
      issues.push("identidad inexistente");
    } else {
      if (!identity.is_available) {
        issues.push("identidad no disponible");
      }
      if (identity.is_expired) {
        issues.push("certificado expirado");
      }
    }
    if (!pinAvailable) {
      issues.push("PIN no disponible");
    }
  }

  const warning = autoSignRequested && issues.length > 0;
  const willAutoSign = autoSignRequested && !warning;
  const mode = willAutoSign ? "autosign" : warning ? "autosign-warning" : "manual";
  const visibleIdentity = identity || currentDefaultIdentity();
  const behaviorLabel = willAutoSign ? "Autofirma" : "Confirmación manual";
  const badgeText = willAutoSign
    ? "🟢 Autofirma activa"
    : warning
      ? "🟠 Autofirma incompleta"
      : "🔵 Confirmación manual";
  const tooltip = willAutoSign
    ? "Las solicitudes pueden firmarse automáticamente."
    : warning
      ? `Configuración incompleta: ${issues.join(", ")}. Se usará confirmación manual.`
      : "Todas las firmas requieren aprobación manual.";
  const modalReason = (() => {
    if (!autoSignRequested) {
      return "La autofirma está desactivada.";
    }
    if (!pinAvailable) {
      return "No existe PIN almacenado.";
    }
    if (!developmentConfig?.default_identity_id) {
      return "No hay identidad configurada para autofirma.";
    }
    if (!identity || !identity.is_available) {
      return "La identidad configurada no está disponible.";
    }
    if (identity.is_expired) {
      return "El certificado configurado para autofirma está expirado.";
    }
    return "Se requiere aprobación manual para esta solicitud.";
  })();

  return {
    mode,
    modeLabel: behaviorLabel,
    behaviorLabel,
    badgeText,
    tooltip,
    devEnabled,
    autoSign,
    autoSignRequested,
    willAutoSign,
    warning,
    issues,
    identity,
    visibleIdentity,
    provider: visibleIdentity?.provider === "pkcs12" ? "PKCS#12" : visibleIdentity ? "PKCS#11" : "-",
    identityName: visibleIdentity ? identityShortTitle(visibleIdentity) : "Sin identidad configurada",
    tokenName: visibleIdentity ? tokenGroupLabel(visibleIdentity) : "-",
    pinStatus: hasLocalPin ? "Recordado localmente" : developmentConfig?.pin_env_defined ? "Variable compatible" : "No recordado",
    behavior: willAutoSign
      ? "Las solicitudes POST /sign serán firmadas automáticamente."
      : "Las solicitudes POST /sign requerirán aprobación manual.",
    modalReason,
  };
}

function renderSigningState() {
  const state = currentSigningState();
  renderGlobalModeBadge(state);
  renderDashboardSigningSummary(state);
  renderDevelopmentStatePanel(state);
  renderSigningWindowContext(state);
  updateDashboard();
}

function renderGlobalModeBadge(state) {
  const badge = document.getElementById("global-mode-badge");
  if (badge) {
    badge.textContent = state.badgeText;
    badge.className = `mode-badge ${state.mode}`;
    badge.title = state.tooltip;
  }
  const sidebarMode = document.getElementById("sidebar-signing-mode");
  if (sidebarMode) {
    sidebarMode.textContent = state.willAutoSign ? "Autofirma activa" : "Confirmación manual";
    sidebarMode.title = state.tooltip;
  }
}

function renderDashboardSigningSummary(state) {
  const card = document.getElementById("signing-summary-card");
  if (!card) {
    return;
  }
  card.classList.toggle("hidden", !state.willAutoSign);
  card.className = `card signing-summary-card ${state.mode}`;
  card.classList.toggle("hidden", !state.willAutoSign);
  const badge = document.getElementById("signing-summary-badge");
  badge.textContent = state.badgeText;
  badge.className = `mode-badge ${state.mode}`;
  badge.title = state.tooltip;
  document.getElementById("signing-summary-mode").textContent = state.modeLabel;
  document.getElementById("signing-summary-autosign").textContent = state.willAutoSign
    ? "Activa"
    : state.warning
      ? "Incompleta"
      : "Desactivada";
  document.getElementById("signing-summary-provider").textContent = state.provider;
  document.getElementById("signing-summary-pin").textContent = state.pinStatus;
  document.getElementById("signing-summary-identity").textContent = state.identityName;
  document.getElementById("signing-summary-token").textContent = state.tokenName;
  document.getElementById("signing-summary-behavior").textContent = state.warning
    ? `${state.behavior} Configuración incompleta: ${state.issues.join(", ")}.`
    : state.behavior;
}

function renderDevelopmentStatePanel(state) {
  const panel = document.getElementById("development-state-panel");
  if (!panel) {
    return;
  }
  panel.className = `state-panel ${state.mode}`;
  document.getElementById("development-state-title").textContent = state.warning ? "Autofirma incompleta" : state.modeLabel;
  document.getElementById("development-state-mode").textContent = state.modeLabel;
  document.getElementById("development-state-autosign").textContent = state.willAutoSign
    ? "Activa"
    : state.warning
      ? "Incompleta"
      : "Desactivada";
  document.getElementById("development-state-provider").textContent = state.provider;
  document.getElementById("development-state-pin").textContent = state.pinStatus;
  document.getElementById("development-state-last-test").textContent = developmentLastTest;
  document.getElementById("development-state-identity").textContent = state.identityName;
  document.getElementById("development-state-behavior").textContent = state.warning
    ? `Configuración incompleta: ${state.issues.join(", ")}. Se abrirá aprobación manual.`
    : state.behavior;
}

function renderSigningWindowContext(state = currentSigningState()) {
  const context = document.getElementById("modal-signing-context");
  if (!context) {
    return;
  }
  context.textContent = state.modalReason;
}

function updateDashboard() {
  if (windowMode !== "main") {
    return;
  }
  const badge = document.getElementById("dashboard-status-badge");
  if (!badge) {
    return;
  }
  const server = config?.server || null;
  const signingState = currentSigningState();
  const fallbackUrl = serviceStatus?.url
    || (serviceStatus ? `${serviceStatus.https ? "https" : "http"}://localhost:${serviceStatus.port}/` : "-");
  const pendingCount = sessionsSnapshot.filter((session) => session.status === "pending").length;
  const defaultIdentity = signingState.visibleIdentity;
  badge.textContent = serviceStatus?.active ? "Activo" : "Consultando";
  badge.className = `badge ${serviceStatus?.active ? "active" : "pending"}`;
  document.getElementById("dashboard-url").textContent = server ? serverUrl(server) : fallbackUrl;
  document.getElementById("dashboard-provider").textContent =
    tokenCertificateCache?.pkcs11_library_path || config?.pkcs11?.library_path || "No configurado";
  document.getElementById("dashboard-token-count").textContent =
    String(tokens.length || tokenCertificateCache?.token_count || 0);
  document.getElementById("dashboard-cert-count").textContent =
    String(signingIdentities.length || certificates.length || tokenCertificateCache?.certificate_count || 0);
  document.getElementById("dashboard-pending").textContent = String(pendingCount);
  document.getElementById("dashboard-dev-mode").textContent = signingState.warning
    ? "Autofirma incompleta"
    : signingState.modeLabel;
  document.getElementById("dashboard-version").textContent = serviceStatus?.version || "0.1.0";
  document.getElementById("dashboard-release-channel").textContent = serviceStatus?.release_channel || "stable";
  document.getElementById("dashboard-build-date").textContent = serviceStatus?.build_date || "-";
  document.getElementById("dashboard-git-commit").textContent = serviceStatus?.git_commit || "-";
  document.getElementById("dashboard-default-identity").textContent =
    defaultIdentity ? `${identityShortTitle(defaultIdentity)} - ${tokenGroupLabel(defaultIdentity)}` : "Sin identidad disponible";
  renderAbout();
}

async function loadStatus() {
  setAppStatus("Iniciando servidor...");
  const status = await invoke("test_server_status");
  serviceStatus = status;
  document.getElementById("service-name").textContent = status.service;
  document.getElementById("service-version").textContent = status.version;
  document.getElementById("service-build-date").textContent = status.build_date || "-";
  document.getElementById("service-git-commit").textContent = status.git_commit || "-";
  document.getElementById("service-release-channel").textContent = status.release_channel || "-";
  document.getElementById("service-mode").textContent = status.https ? "HTTPS" : "HTTP";
  document.getElementById("service-port").textContent = status.port;
  document.getElementById("active-library-path").textContent =
    status.pkcs11_library_path || "No detectado";
  const indicator = document.getElementById("service-indicator");
  indicator.textContent = status.active ? "Activo" : "No disponible";
  indicator.className = `badge ${status.active ? "active" : "pending"}`;
  setAppStatus("FirMapache operativo", "active");
  renderAbout();
  updateDashboard();
}

function renderAbout() {
  if (windowMode !== "main") {
    return;
  }
  const status = serviceStatus || {};
  const setText = (id, value) => {
    const element = document.getElementById(id);
    if (element) {
      element.textContent = value || "-";
    }
  };
  setText("about-version", status.version || "0.1.0");
  setText("about-release-channel", status.release_channel || "stable");
  setText("about-build-date", status.build_date || "-");
  setText("about-git-commit", status.git_commit || "-");
  setText("about-license", status.license || "GPL-3.0");
  setText("about-author", status.author || "Vladimir Copa Fabian");
  setText("about-contact", status.contact_email || "vcopafabian@gmail.com");
  const badge = document.getElementById("about-release-badge");
  if (badge) {
    badge.textContent = `v${status.version || "0.1.0"}`;
  }
  const repository = document.getElementById("about-repository");
  if (repository) {
    repository.textContent = status.repository_url || "https://github.com/vcopaf/firmapache";
    repository.href = status.repository_url || "https://github.com/vcopaf/firmapache";
  }
}

async function loadConfig() {
  setAppStatus("Cargando configuracion...");
  config = await invoke("get_config");
  developmentConfig = await invoke("get_development_config");
  pkcs12Tokens = await invoke("list_pkcs12_tokens");
  renderServerConfig(config.server);
  renderDevelopmentConfig(developmentConfig);
  renderPkcs12Tokens();
  document.getElementById("library-path").value = config.pkcs11.library_path || "";
  renderSigningState();
}

function renderServerConfig(server) {
  document.getElementById("server-host").value = server.host || "127.0.0.1";
  document.getElementById("server-port").value = server.port || 4637;
  document.getElementById("server-https").checked = Boolean(server.https);
  document.getElementById("server-current-url").textContent = serverUrl(server);
  updateDashboard();
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
  if (!document.getElementById("signing-behavior-manual")) {
    return;
  }
  const autoSignSelected = Boolean(development.enabled && development.auto_sign);
  document.getElementById("signing-behavior-manual").checked = !autoSignSelected;
  document.getElementById("signing-behavior-autosign").checked = autoSignSelected;
  document.getElementById("development-remember-pin").checked = Boolean(development.remember_pin);
  document.getElementById("development-pin").value = "";
  document.getElementById("development-pin-status").textContent = development.has_local_pin
    ? "Recordado localmente"
    : development.pin_env_defined
      ? "Variable de entorno compatible encontrada"
      : "Ingrese PIN/contraseña para guardar o probar";
  document.getElementById("development-pin-warning").classList.toggle("hidden", !development.remember_pin);
  updateSigningBehaviorConfigVisibility();
  populateDevelopmentIdentities();
  renderSigningState();
}

async function saveDevelopmentConfig() {
  const payload = readDevelopmentConfigInput();
  developmentConfig = await invoke("update_development_config", payload);
  renderDevelopmentConfig(developmentConfig);
  document.getElementById("development-pin").value = "";
  document.getElementById("development-message").textContent = "Comportamiento de firma guardado";
  renderSigningState();
  window.setTimeout(() => { document.getElementById("development-message").textContent = ""; }, 2500);
}

async function testDevelopmentConfig() {
  const result = await invoke("test_development_config", {
    pin: document.getElementById("development-pin").value || null,
  });
  document.getElementById("development-message").textContent = result.ready
    ? "✓ Autofirma configurada correctamente"
    : result.messages.join(" | ");
  developmentLastTest = result.ready ? "Correcta" : "Con errores";
  developmentConfig = await invoke("get_development_config");
  renderDevelopmentConfig(developmentConfig);
  document.getElementById("development-pin").value = "";
  renderSigningState();
}

async function selectPkcs12File() {
  const selected = await invoke("select_pkcs12_file");
  if (selected) {
    document.getElementById("pkcs12-path").value = selected;
  }
}

async function addPkcs12Token() {
  const id = document.getElementById("pkcs12-id").value.trim();
  pkcs12Tokens = await invoke("add_pkcs12_token", {
    id,
    label: document.getElementById("pkcs12-label").value,
    path: document.getElementById("pkcs12-path").value,
    password: document.getElementById("pkcs12-password").value,
    rememberPassword: document.getElementById("pkcs12-remember-password").checked,
    passwordEnv: null,
  });
  renderPkcs12Tokens();
  await refreshSigningIdentities();
  document.getElementById("pkcs12-password").value = "";
  document.getElementById("development-message").textContent =
    "✓ Token importado ✓ Identidad registrada";
  await maybeSetImportedTokenAsDefault(id);
}

async function generateP12Token() {
  const id = document.getElementById("create-p12-id").value.trim();
  const label = document.getElementById("create-p12-label").value.trim();
  const commonName = document.getElementById("create-p12-cn").value.trim();
  const organization = document.getElementById("create-p12-o").value.trim();
  const country = document.getElementById("create-p12-c").value.trim().toUpperCase();
  const validityDays = Number(document.getElementById("create-p12-days").value);
  const password = document.getElementById("create-p12-password").value;
  const confirm = document.getElementById("create-p12-password-confirm").value;
  const message = document.getElementById("pkcs12-create-message");
  if (message) {
    message.textContent = "";
  }
  if (!id || !label || !commonName || !organization || !country) {
    showError("Complete los datos del token virtual.");
    return;
  }
  if (!Number.isInteger(validityDays) || validityDays < 1) {
    showError("La vigencia debe ser un número de días mayor a 0.");
    return;
  }
  if (country.length !== 2) {
    showError("País / C debe tener 2 letras, por ejemplo BO.");
    return;
  }
  if (!password) {
    showError("Ingrese una contraseña para proteger el P12/PFX.");
    return;
  }
  if (password !== confirm) {
    showError("La contraseña y la confirmación no coinciden");
    return;
  }
  if (message) {
    message.textContent = "Seleccione dónde guardar el archivo .p12/.pfx...";
  }
  const outputPath = await invoke("select_p12_output_path", { fileName: `${id}.p12` });
  if (!outputPath) {
    if (message) {
      message.textContent = "Creación cancelada.";
    }
    return;
  }
  try {
    document.getElementById("generate-p12-token").disabled = true;
    if (message) {
      message.textContent = "Creando token virtual...";
    }
    const response = await invoke("generate_virtual_token_p12", {
      input: {
        id,
        label,
        common_name: commonName,
        organization,
        country,
        validity_days: validityDays,
        password,
        output_path: outputPath,
      },
    });
    pkcs12Tokens = await invoke("list_pkcs12_tokens");
    renderPkcs12Tokens();
    await refreshSigningIdentities();
    if (message) {
      message.textContent = `✓ Token virtual creado y registrado: ${response.path || outputPath}`;
    }
    await maybeSetIdentityAsDefault(response.identity_id);
  } finally {
    document.getElementById("generate-p12-token").disabled = false;
    document.getElementById("create-p12-password").value = "";
    document.getElementById("create-p12-password-confirm").value = "";
  }
}

async function removePkcs12Token(id) {
  const shouldRemove = window.confirm("¿Quitar este token virtual de FirMapache? El archivo .p12/.pfx no se eliminará del disco.");
  if (!shouldRemove) {
    return;
  }
  pkcs12Tokens = await invoke("remove_pkcs12_token", { id });
  renderPkcs12Tokens();
  developmentConfig = await invoke("get_development_config");
  await refreshSigningIdentities();
  populateDevelopmentIdentities();
  renderSigningState();
  document.getElementById("pkcs12-create-message").textContent =
    "Token virtual quitado. Sus identidades se actualizaron.";
}

async function testPkcs12Token(id) {
  const token = await invoke("test_pkcs12_token", { id });
  pkcs12Tokens = pkcs12Tokens.map((current) => current.id === id ? token : current);
  renderPkcs12Tokens();
}

function readDevelopmentConfigInput() {
  const autoSignSelected = document.getElementById("signing-behavior-autosign")?.checked || false;
  return {
    enabled: autoSignSelected,
    autoSign: autoSignSelected,
    defaultIdentityId: document.getElementById("development-identity").value,
    pinEnv: developmentConfig?.pin_env || "FIRMAPACHE_DEV_PIN",
    rememberPin: document.getElementById("development-remember-pin").checked,
    pin: document.getElementById("development-pin").value || null,
    fallbackToModal: true,
  };
}

function updateSigningBehaviorConfigVisibility() {
  const panel = document.getElementById("autosign-config-panel");
  if (!panel) {
    return;
  }
  const autoSignSelected = document.getElementById("signing-behavior-autosign")?.checked || false;
  panel.classList.toggle("hidden", !autoSignSelected);
  document.getElementById("save-signing-behavior")?.classList.toggle("hidden", autoSignSelected);
  document.querySelectorAll(".behavior-option").forEach((option) => {
    const input = option.querySelector("input");
    option.classList.toggle("selected", Boolean(input?.checked));
  });
}

function renderPkcs12Tokens() {
  const container = document.getElementById("pkcs12-tokens");
  if (!container) {
    return;
  }
  if (!pkcs12Tokens.length) {
    empty(container, "Sin tokens virtuales.");
    return;
  }
  showItems(container, pkcs12Tokens.map((token) => {
    const article = item(token.label || token.id, [
      `ID: ${token.id}`,
      `Path: ${token.path}`,
      `Archivo existe: ${yesNo(token.path_exists)}`,
      `Contraseña local: ${yesNo(token.has_local_password)}`,
      token.password_env ? `Variable compatible: ${token.password_env}` : "",
      token.password_env ? `Variable definida: ${yesNo(token.password_env_defined)}` : "",
      token.identity?.subject ? `Subject: ${token.identity.subject}` : "Certificado: no leíble",
    ]);
    const actions = document.createElement("div");
    actions.className = "item-actions";
    actions.append(
      button("Probar", "secondary", () => run(() => testPkcs12Token(token.id))),
      button("Eliminar", "danger", () => run(() => removePkcs12Token(token.id))),
    );
    article.appendChild(actions);
    return article;
  }));
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
  renderSigningState();
}

async function refreshSigningIdentities() {
  signingIdentities = await invoke("refresh_signing_identities");
  renderCertificates();
  populateSigningIdentities();
  renderSigningState();
}

function applyTokenCertificateCache(cache) {
  tokenCertificateCache = cache;
  tokens = cache.tokens || [];
  certificates = cache.certificates || [];
  certificatesLoaded = Boolean(cache.loaded_at);
  renderTokenCertificateCache(cache);
  renderTokens();
  renderCertificates();
  updateDashboard();
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
    renderIdentityCards(container, signingIdentities);
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

function renderIdentityCards(container, identities) {
  container.className = "identity-grid";
  const groups = groupByIdentityToken(identities);
  const elements = [];
  groups.forEach((tokenIdentities) => {
    const group = document.createElement("section");
    group.className = "identity-group";
    const title = document.createElement("h3");
    title.textContent = tokenGroupLabel(tokenIdentities[0]);
    group.appendChild(title);
    tokenIdentities.forEach((identity) => group.appendChild(identityCard(identity)));
    elements.push(group);
  });
  container.replaceChildren(...elements);
}

function identityCard(identity) {
  const article = document.createElement("article");
  article.className = "identity-card";
  const signingState = currentSigningState();
  const usedByAutoSign = signingState.identity?.identity_id === identity.identity_id;
  const activeDefault = identity.is_default || usedByAutoSign;
  if (!identity.is_available || identity.is_expired) {
    article.classList.add("muted");
  }
  if (activeDefault) {
    article.classList.add("active-identity");
  }

  const header = document.createElement("div");
  header.className = "identity-card-header";
  const title = document.createElement("strong");
  title.textContent = identityShortTitle(identity);
  header.appendChild(title);

  const badges = document.createElement("div");
  badges.className = "identity-badges";
  if (usedByAutoSign) {
    badges.appendChild(identityBadge("✓ Utilizada por autofirma", "active"));
  } else if (identity.is_default) {
    badges.appendChild(identityBadge("✓ Identidad activa", "active"));
  }
  if (identity.provider === "pkcs12") {
    badges.appendChild(identityBadge("PKCS#12", "dev"));
  } else {
    badges.appendChild(identityBadge("PKCS#11", ""));
  }
  if (!identity.is_available) {
    badges.appendChild(identityBadge("No disponible", "warning"));
  } else if (identity.is_expired) {
    badges.appendChild(identityBadge("Expirada", "warning"));
  } else if (identity.expires_soon) {
    badges.appendChild(identityBadge("Vence pronto", "warning"));
  } else {
    badges.appendChild(identityBadge("Activo", "active"));
  }
  header.appendChild(badges);
  article.appendChild(header);

  const meta = document.createElement("div");
  meta.className = "identity-meta";
  [
    `Emisor: ${identity.issuer || "-"}`,
    `Vence: ${identity.not_after || "-"}`,
    `Slot: ${Number.isFinite(identity.slot_id) ? identity.slot_id : "-"}`,
  ].forEach((text) => {
    const span = document.createElement("span");
    span.textContent = text;
    meta.appendChild(span);
  });
  article.appendChild(meta);

  const details = document.createElement("details");
  details.className = "identity-details";
  const summary = document.createElement("summary");
  summary.textContent = "Ver detalles tecnicos";
  details.appendChild(summary);
  [
    `Subject: ${identity.subject || "-"}`,
    `Issuer: ${identity.issuer || "-"}`,
    `ID identidad: ${identity.identity_id || "-"}`,
    `ID certificado: ${identity.certificate_id || "-"}`,
    `Serial: ${identity.token_serial || "-"}`,
    `Slot: ${Number.isFinite(identity.slot_id) ? identity.slot_id : "-"}`,
    `Token: ${tokenGroupLabel(identity)}`,
  ].forEach((text) => {
    const line = document.createElement("span");
    line.textContent = text;
    details.appendChild(line);
  });
  article.appendChild(details);
  return article;
}

function identityBadge(text, variant) {
  const badge = document.createElement("span");
  badge.className = `identity-badge ${variant || ""}`;
  badge.textContent = text;
  return badge;
}

function renderTokenCertificateCache(cache) {
  const status = document.getElementById("cache-status");
  if (!status) {
    return;
  }
  if (!cache || !cache.loaded_at) {
    status.textContent = "Esperando deteccion de tokens...";
    document.getElementById("cache-loaded-at").textContent = "-";
    document.getElementById("cache-token-count").textContent = "0";
    document.getElementById("cache-certificate-count").textContent = "0";
    document.getElementById("cache-library-path").textContent = "-";
    return;
  }
  const eventText = cache.last_event ? ` - ${humanCacheEvent(cache.last_event)}` : "";
  const backend = cache.watcher_backend ? cache.watcher_backend.toUpperCase() : "cache";
  const eventAt = cache.last_event_at ? ` (${new Date(cache.last_event_at).toLocaleTimeString()})` : "";
  status.textContent = `${cache.watcher_active ? "Watcher activo" : "Cache cargada"} - ${backend}${eventText}${eventAt}`;
  document.getElementById("cache-loaded-at").textContent = `${timeAgo(cache.loaded_at)} (${new Date(cache.loaded_at).toLocaleString()})`;
  document.getElementById("cache-token-count").textContent = cache.token_count;
  document.getElementById("cache-certificate-count").textContent = cache.certificate_count;
  document.getElementById("cache-library-path").textContent = cache.pkcs11_library_path || "-";
}

function humanCacheEvent(event) {
  const events = {
    insert: "token insertado",
    remove: "token retirado",
    change: "token cambiado",
    unchanged: "sin cambios",
    cache_hit: "cache vigente",
    persisted_cache_loaded: "cache persistida",
    refresh_skipped_same_serial: "serial sin cambios",
    driver_missing: "driver no detectado",
  };
  return events[event] || event;
}

function timeAgo(dateText) {
  const elapsedSeconds = Math.max(0, Math.floor((Date.now() - new Date(dateText).getTime()) / 1000));
  if (elapsedSeconds < 60) {
    return `actualizado hace ${elapsedSeconds} segundos`;
  }
  const elapsedMinutes = Math.floor(elapsedSeconds / 60);
  return `actualizado hace ${elapsedMinutes} min`;
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

function identityShortTitle(identity) {
  const subject = identityTitle(identity);
  const cn = subject.match(/CN\s*=\s*([^,]+)/i);
  return (cn?.[1] || subject).trim();
}

function tokenGroupLabel(identity) {
  if (identity.provider === "pkcs12") {
    return `[PKCS#12] ${identity.token_label || identity.virtual_token_id || "Token virtual"}`;
  }
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

function identityOptionText(identity) {
  const flags = [];
  if (identity.is_default) {
    flags.push("predeterminada");
  }
  if (!identity.is_available) {
    flags.push("no disponible");
  }
  if (identity.is_expired) {
    flags.push("expirada");
  }
  const provider = identity.provider === "pkcs12" ? "P12" : `slot ${identity.slot_id}`;
  const suffix = flags.length ? ` (${flags.join(", ")})` : "";
  return `${identityShortTitle(identity)} - ${provider} - vence ${identity.not_after || "-"}${suffix}`;
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
  renderSigningWindowContext();
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
  renderSigningWindowContext();
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
  const status = document.createElement("span");
  status.className = `identity-badge ${session.status === "pending" ? "warning" : session.status === "approved" ? "active" : ""}`;
  status.textContent = session.status;
  article.appendChild(status);
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
  sessionsSnapshot = sessions;
  updateDashboard();
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
      option.textContent = identityOptionText(identity);
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
  updatePinLabels("modal-certificate", "modal-pin");
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
  const selected = await invoke("select_manual_files");
  if (!selected?.length) {
    return;
  }
  const knownPaths = new Set(manualFiles.map((file) => file.path));
  manualFiles.push(...selected.filter((file) => !knownPaths.has(file.path)));
  manualResults = [];
  clearManualError();
  document.getElementById("manual-sign-message").textContent = "";
  renderManualFiles();
  if (manualSupportedFiles().length && !certificatesLoaded) {
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
  const destination = await invoke("select_manual_output_directory");
  if (!destination) {
    document.getElementById("manual-sign-message").textContent = "Firma cancelada: carpeta destino no seleccionada.";
    return;
  }

  manualSigningInProgress = true;
  manualResults = [];
  updateManualState();
  setManualProgress(true, `Firmando archivos... 0 / ${manualSupportedFiles().length} completados`);
  clearManualError();
  const filesToSign = manualSupportedFiles();
  const signedFiles = [];
  let completed = 0;
  try {
    for (const file of filesToSign) {
      setManualProgress(true, `Firmando ${file.name}... ${completed} / ${filesToSign.length} completados`);
      try {
        const signed = await signOneManualFile(file, input);
        const entryName = signedZipEntryName(file);
        signedFiles.push({
          name: entryName,
          data_base64: signed.base64,
        });
        manualResults.push({
          ok: true,
          inputName: file.name,
          outputName: entryName,
          path: "Pendiente de ZIP",
        });
      } catch (error) {
        manualResults.push({
          ok: false,
          inputName: file.name,
          error: String(error),
        });
      } finally {
        completed += 1;
        setManualProgress(true, `Firmando archivos... ${completed} / ${filesToSign.length} completados`);
        renderManualResults();
      }
    }
    let outputPath = null;
    if (signedFiles.length === 1) {
      setManualProgress(true, "Guardando archivo firmado...");
      const saved = await invoke("save_manual_output_file", {
        directory: destination,
        dataBase64: signedFiles[0].data_base64,
        suggestedFileName: signedFiles[0].name,
      });
      outputPath = saved.path;
      manualResults = manualResults.map((result) => result.ok ? {
        ...result,
        outputName: fileNameFromPath(outputPath),
        path: outputPath,
      } : result);
      renderManualResults();
    } else if (signedFiles.length > 1) {
      setManualProgress(true, "Comprimiendo archivos firmados...");
      const zip = await invoke("save_manual_output_zip", {
        directory: destination,
        files: signedFiles,
      });
      outputPath = zip.path;
      manualResults = manualResults.map((result) => result.ok ? { ...result, path: outputPath } : result);
      renderManualResults();
    }
    const successCount = manualResults.filter((result) => result.ok).length;
    const errorCount = manualResults.length - successCount;
    document.getElementById("manual-sign-message").textContent =
      outputPath
        ? `Resultado: ${successCount} archivos firmados, ${errorCount} con error. Guardado: ${outputPath}`
        : `Resultado: ${successCount} archivos firmados, ${errorCount} con error.`;
  } finally {
    clearManualPin();
    manualSigningInProgress = false;
    setManualProgress(false);
    updateManualState();
  }
}

async function signOneManualFile(file, input) {
  if (file.detected_type === "PDF") {
    const result = await invoke("sign_pdf", {
      path: file.path,
      identityId: input.identityId,
      pin: input.pin,
    });
    return {
      base64: result.pdf_base64,
      suggestedFileName: file.suggested_file_name || result.suggested_file_name,
    };
  }
  const result = await invoke("sign_file_as_jws", {
    path: file.path,
    identityId: input.identityId,
    pin: input.pin,
  });
  return {
    base64: result.jws_base64,
    suggestedFileName: file.suggested_file_name || result.suggested_file_name,
  };
}

function removeManualFile(index) {
  manualFiles.splice(index, 1);
  manualResults = [];
  renderManualFiles();
  updateManualState();
}

function clearManualFiles() {
  manualFiles = [];
  manualResults = [];
  clearManualError();
  document.getElementById("manual-sign-message").textContent = "";
  renderManualFiles();
  updateManualState();
}

function manualSupportedFiles() {
  return manualFiles.filter((file) => file.supported && (file.detected_type === "JSON" || file.detected_type === "PDF") && (file.detected_type !== "PDF" || pdfReady(file)));
}

function manualUnsupportedFiles() {
  return manualFiles.filter((file) => !file.supported || (file.detected_type === "PDF" && !pdfReady(file)));
}

function renderManualFiles() {
  const container = document.getElementById("manual-files");
  if (!container) {
    return;
  }
  container.replaceChildren();
  if (!manualFiles.length) {
    container.className = "manual-files empty";
    container.textContent = "Sin archivos seleccionados.";
  } else {
    container.className = "manual-files";
    manualFiles.forEach((file, index) => {
      container.appendChild(manualFileRow(file, index));
    });
  }
  renderManualSummary();
  renderManualMode();
  renderManualResults();
}

function manualFileRow(file, index) {
  const supported = file.supported && (file.detected_type !== "PDF" || pdfReady(file));
  const row = document.createElement("article");
  row.className = `manual-file-row ${supported ? "supported" : "unsupported"}`;

  const status = document.createElement("span");
  status.className = "manual-file-status";
  status.textContent = supported ? "✓" : "!";
  row.appendChild(status);

  const body = document.createElement("div");
  const title = document.createElement("strong");
  title.textContent = file.name;
  body.appendChild(title);

  const meta = document.createElement("span");
  meta.textContent = `${file.detected_type} → ${file.output_format} · ${approximateSize(file.size_bytes)} · ${manualFileValidationText(file)}`;
  body.appendChild(meta);
  row.appendChild(body);

  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "text-button danger-text";
  remove.textContent = "Quitar";
  remove.addEventListener("click", () => removeManualFile(index));
  row.appendChild(remove);
  return row;
}

function manualFileValidationText(file) {
  if (file.detected_type === "JSON") {
    return "Listo para JWS";
  }
  if (file.detected_type === "PDF") {
    return pdfReady(file) ? "PDF listo" : "PDF inválido";
  }
  return "No soportado";
}

function signedZipEntryName(file) {
  const originalName = fileNameFromPath(file.name || file.path || "firmado");
  const dotIndex = originalName.lastIndexOf(".");
  const stem = dotIndex > 0 ? originalName.slice(0, dotIndex) : originalName;
  const extension = file.detected_type === "PDF" ? "pdf" : "jws";
  return `${stem}_firmado.${extension}`;
}

function renderManualSummary() {
  const supportedCount = manualSupportedFiles().length;
  const unsupportedCount = manualUnsupportedFiles().length;
  document.getElementById("manual-file-count").textContent =
    `${manualFiles.length} ${manualFiles.length === 1 ? "seleccionado" : "seleccionados"}`;
  document.getElementById("manual-supported-count").textContent = String(supportedCount);
  document.getElementById("manual-unsupported-count").textContent = String(unsupportedCount);
  const validation = document.getElementById("manual-validation-status");
  if (!manualFiles.length) {
    validation.textContent = "Sin archivos.";
  } else if (unsupportedCount) {
    validation.textContent = `${supportedCount} listos, ${unsupportedCount} no soportados o inválidos.`;
  } else {
    validation.textContent = `${supportedCount} archivos listos para firmar.`;
  }
  document.getElementById("manual-clear-files").disabled = manualSigningInProgress || manualFiles.length === 0;
}

function renderManualResults() {
  const container = document.getElementById("manual-results");
  if (!container) {
    return;
  }
  container.replaceChildren();
  container.classList.toggle("hidden", manualResults.length === 0);
  if (!manualResults.length) {
    return;
  }
  const title = document.createElement("h3");
  title.textContent = "Resultado";
  container.appendChild(title);
  const list = document.createElement("div");
  list.className = "manual-result-list";
  manualResults.forEach((result) => {
    const row = document.createElement("article");
    row.className = `manual-result-row ${result.ok ? "ok" : "error"}`;
    const status = document.createElement("span");
    status.textContent = result.ok ? "✓" : "✗";
    row.appendChild(status);
    const body = document.createElement("div");
    const name = document.createElement("strong");
    name.textContent = result.ok ? result.outputName : result.inputName;
    body.appendChild(name);
    const detail = document.createElement("small");
    detail.textContent = result.ok ? result.path : `Error: ${result.error}`;
    body.appendChild(detail);
    row.appendChild(body);
    list.appendChild(row);
  });
  container.appendChild(list);
}

function selectedManualApprovalInput() {
  if (!manualFiles.length) {
    showManualError("No hay archivos seleccionados");
    updateManualState();
    return null;
  }
  const filesToSign = manualSupportedFiles();
  if (!filesToSign.length) {
    showManualError("No hay archivos JSON o PDF válidos para firmar");
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
  const selectButton = document.getElementById("manual-select-file");
  const identityId = certificate.value;
  const selectedOption = certificate.options[certificate.selectedIndex];
  const pin = document.getElementById("manual-pin").value;
  const supportedCount = manualSupportedFiles().length;
  updatePinLabels("manual-certificate", "manual-pin");
  signButton.textContent = supportedCount === 1 ? "Firmar 1 archivo" : `Firmar ${supportedCount} archivos`;
  signButton.disabled =
    manualSigningInProgress || supportedCount === 0 || !identityId || selectedOption?.disabled || !pin;
  const needsCredentials = supportedCount > 0;
  certificate.disabled = manualSigningInProgress || !needsCredentials;
  pinInput.disabled = manualSigningInProgress || !needsCredentials;
  selectButton.disabled = manualSigningInProgress;
  document.getElementById("manual-clear-files").disabled = manualSigningInProgress || manualFiles.length === 0;
}

function updatePinLabels(selectId, inputId) {
  const select = document.getElementById(selectId);
  const input = document.getElementById(inputId);
  const identity = signingIdentities.find((identity) => identity.identity_id === select.value);
  const label = document.querySelector(`label[for="${inputId}"]`);
  if (!label || !input) {
    return;
  }
  if (identity?.provider === "pkcs12") {
    label.textContent = "PIN / contraseña P12";
    input.placeholder = "Ingrese la contraseña del P12 para esta firma";
  } else {
    label.textContent = "PIN del token";
    input.placeholder = "Ingrese el PIN para esta firma";
  }
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

async function maybeSetImportedTokenAsDefault(tokenId) {
  const identity = signingIdentities.find((item) => item.virtual_token_id === tokenId && item.is_available);
  if (identity) {
    await maybeSetIdentityAsDefault(identity.identity_id);
  }
}

async function maybeSetIdentityAsDefault(identityId) {
  if (!identityId) {
    return;
  }
  const shouldUse = window.confirm("¿Desea usar esta identidad como predeterminada?");
  if (!shouldUse) {
    return;
  }
  signingIdentities = await invoke("set_default_signing_identity", { identityId });
  populateSigningIdentities();
  renderCertificates();
  if (developmentConfig) {
    developmentConfig.default_identity_id = identityId;
    populateDevelopmentIdentities();
  }
  setAppStatus("Identidad predeterminada actualizada", "active");
}

function togglePasswordVisibility(inputId) {
  const input = document.getElementById(inputId);
  if (!input) {
    return;
  }
  const visible = input.type === "text";
  input.type = visible ? "password" : "text";
  document.querySelectorAll(`[data-toggle-password="${inputId}"]`).forEach((toggle) => {
    toggle.textContent = visible ? "👁" : "🙈";
    toggle.setAttribute("aria-label", visible ? "Mostrar PIN" : "Ocultar PIN");
  });
  input.focus({ preventScroll: true });
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

function renderManualMode() {
  const hasSupported = manualSupportedFiles().length > 0;
  const hasPdf = manualFiles.some((file) => file.detected_type === "PDF");
  const hasUnsupported = manualUnsupportedFiles().length > 0;

  document.getElementById("manual-json-panel").classList.toggle("hidden", !hasSupported);
  document.getElementById("manual-pdf-panel").classList.toggle("hidden", !hasPdf);
  document.getElementById("manual-unsupported-message").classList.toggle("hidden", !hasUnsupported);
  document.getElementById("manual-pdf-progress").classList.add("hidden");
  renderManualPdfInfo();
}

function renderManualPdfInfo() {
  const pdfFiles = manualFiles.filter((file) => file.detected_type === "PDF");
  const validHeaderCount = pdfFiles.filter((file) => file.pdf_info?.valid_header).length;
  const eofCount = pdfFiles.filter((file) => file.pdf_info?.has_eof_marker).length;
  document.getElementById("manual-pdf-valid-header").textContent =
    pdfFiles.length ? `${validHeaderCount} / ${pdfFiles.length}` : "-";
  document.getElementById("manual-pdf-has-eof").textContent =
    pdfFiles.length ? `${eofCount} / ${pdfFiles.length}` : "-";
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
  document.getElementById("diagnostics-message").textContent = "Ejecutando...";
  latestDiagnostics = await invoke("run_diagnostics");
  renderDiagnostics(latestDiagnostics);
  document.getElementById("validation-message").textContent = "Diagnostico completado";
  document.getElementById("diagnostics-message").textContent = "Diagnostico completado";
}

function renderDiagnostics(report) {
  const container = document.getElementById("diagnostics-result");
  showItems(container, [
    item("Sistema", [
      `Aplicacion: ${report.app_name || "FirMapache"}`,
      `Version: ${report.app_version}`,
      `Build date: ${report.build_date || "-"}`,
      `Commit: ${report.git_commit || "-"}`,
      `Canal: ${report.release_channel || "stable"}`,
      `Servidor: ${report.server_https ? "HTTPS" : "HTTP"} ${report.server_host}:${report.server_port}`,
      `URL activa: ${report.server_url || "-"}`,
      `Estado servidor: ${report.server_active ? "activo" : "no disponible"}`,
      `Driver configurado: ${report.configured_pkcs11_library_path || "-"}`,
      `Driver detectado: ${report.detected_pkcs11_library_path || "-"}`,
      `Driver encontrado: ${yesNo(report.driver_found)}`,
      `Fuente driver: ${report.driver_source || "-"}`,
      `PC/SC disponible: ${yesNo(report.pcsc_available)}`,
      `Watcher activo: ${yesNo(report.watcher_active)}`,
      `Watcher backend: ${report.watcher_backend || "-"}`,
      `Ultimo evento watcher: ${report.watcher_last_event || "-"}`,
      `Hora ultimo evento: ${report.watcher_last_event_at || "-"}`,
      `Ultima actualizacion tokens: ${report.token_cache_loaded_at || "-"}`,
      `Ultima actualizacion certificados: ${report.certificate_cache_loaded_at || "-"}`,
      `Cache hits/misses: ${report.cache_hits || 0}/${report.cache_misses || 0}`,
      report.last_restart_error ? `Ultimo error de reinicio: ${report.last_restart_error}` : "",
      report.last_error ? `Ultimo error: ${report.last_error}` : "",
    ]),
    item("Comportamiento de firma", [
      `Comportamiento: ${report.signing_mode || "-"}`,
      `Autofirma efectiva: ${yesNo(report.signing_auto_sign_will_run)}`,
      `Identidad activa: ${report.signing_active_identity_name || report.signing_active_identity_id || "-"}`,
      `Proveedor activo: ${report.signing_active_provider || "-"}`,
      `PIN recordado: ${yesNo(report.signing_pin_remembered)}`,
      (report.signing_state_issues || []).length ? `Advertencias: ${report.signing_state_issues.join(", ")}` : "",
      `Autofirma configurada: ${yesNo(report.development_enabled && report.development_auto_sign)}`,
      `Autofirma: ${yesNo(report.development_auto_sign)}`,
      `Identidad configurada: ${report.development_default_identity_id || "-"}`,
      `PIN local recordado: ${yesNo(report.development_has_local_pin)}`,
      report.development_pin_env ? `Variable compatible: ${report.development_pin_env}` : "",
      report.development_pin_env ? `Variable definida: ${yesNo(report.development_pin_env_defined)}` : "",
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
    item("Tokens virtuales P12", [
      ...((report.pkcs12_tokens || []).slice(0, 8).map((token) =>
        `${token.label || token.id} | path: ${yesNo(token.path_exists)} | contraseña local: ${yesNo(token.has_local_password)} | cert: ${yesNo(token.certificate_readable)} | ${token.subject || "-"}`
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
  } else {
    showSection(activeSection);
  }
}

function bindEvents() {
  if (windowMode === "main") {
    document.querySelectorAll("[data-section-target]").forEach((navButton) => {
      navButton.addEventListener("click", () => showSection(navButton.dataset.sectionTarget));
    });
    document.getElementById("sidebar-toggle").addEventListener("click", () => {
      document.body.classList.toggle("sidebar-collapsed");
    });
    document.getElementById("quick-sign-file").addEventListener("click", () => showSection("firmar"));
    document.getElementById("quick-open-sessions").addEventListener("click", () => showSection("solicitudes"));
    document.getElementById("quick-refresh-tokens").addEventListener("click", () => run(refreshTokenCertificateCache));
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
    document.getElementById("save-signing-behavior").addEventListener("click", () => run(saveDevelopmentConfig));
    document.getElementById("save-development-config").addEventListener("click", () => run(saveDevelopmentConfig));
    document.getElementById("test-development-config").addEventListener("click", () => run(testDevelopmentConfig));
    document.getElementById("signing-behavior-manual").addEventListener("change", () => {
      updateSigningBehaviorConfigVisibility();
      document.getElementById("development-message").textContent = "Guarde el comportamiento para aplicar el cambio.";
    });
    document.getElementById("signing-behavior-autosign").addEventListener("change", () => {
      updateSigningBehaviorConfigVisibility();
      document.getElementById("development-message").textContent = "Guarde el comportamiento para aplicar el cambio.";
    });
    document.getElementById("choose-pkcs12-file").addEventListener("click", () => run(selectPkcs12File));
    document.getElementById("add-pkcs12-token").addEventListener("click", () => run(addPkcs12Token));
    document.getElementById("generate-p12-token").addEventListener("click", () => run(generateP12Token));
    document.getElementById("development-identity").addEventListener("change", () => {
      document.getElementById("development-message").textContent = "";
    });
    document.getElementById("development-pin").addEventListener("input", () => {
      document.getElementById("development-pin-status").textContent = "Listo para guardar o probar";
    });
    document.getElementById("development-remember-pin").addEventListener("change", (event) => {
      document.getElementById("development-pin-warning").classList.toggle("hidden", !event.target.checked);
    });
    document.getElementById("reload-tokens").addEventListener("click", () => run(refreshTokenCertificateCache));
    document.getElementById("reload-certificates").addEventListener("click", () => run(refreshTokenCertificateCache));
    document.getElementById("reload-sessions").addEventListener("click", () => run(loadSessions));
    document.getElementById("manual-select-file").addEventListener("click", () => run(selectManualFile));
    document.getElementById("manual-clear-files").addEventListener("click", clearManualFiles);
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

  document.querySelectorAll("[data-toggle-password]").forEach((toggle) => {
    toggle.addEventListener("mousedown", (event) => event.preventDefault());
    toggle.addEventListener("click", () => togglePasswordVisibility(toggle.dataset.togglePassword));
  });

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
  await loadBrandLogo();
  bindEvents();
  if (windowMode === "main") {
    await Promise.all([loadStatus(), loadConfig(), loadTokenCertificateCache(), loadSessions()]);
    window.setInterval(() => {
      run(loadTokenCertificateCache);
    }, 10000);
  } else {
    clearSigningForm();
    await loadConfig();
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
