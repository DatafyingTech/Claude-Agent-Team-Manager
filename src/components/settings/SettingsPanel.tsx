import { useState, useEffect, useCallback, type CSSProperties } from "react";
import { readTextFile, writeTextFile, readFile, writeFile, exists, mkdir } from "@tauri-apps/plugin-fs";
import { open, save } from "@tauri-apps/plugin-dialog";
import { getVersion } from "@tauri-apps/api/app";
import { invoke } from "@tauri-apps/api/core";
import { homeDir } from "@tauri-apps/api/path";
import { useUiStore } from "@/store/ui-store";
import { useTreeStore } from "@/store/tree-store";
import { join } from "@/utils/paths";
import { toast } from "@/components/common/Toast";

interface AppSettings {
  apiKey: string;
  teamColor: string;
  agentColor: string;
  accentColor: string;
  autoSave: boolean;
  theme: "dark" | "light";
}

const DEFAULT_SETTINGS: AppSettings = {
  apiKey: "",
  teamColor: "#4a9eff",
  agentColor: "#f0883e",
  accentColor: "#4a9eff",
  autoSave: true,
  theme: "dark",
};

const labelStyle: CSSProperties = {
  fontSize: 12,
  textTransform: "uppercase",
  color: "var(--text-secondary)",
  marginBottom: 4,
  display: "block",
  letterSpacing: "0.5px",
};

const inputStyle: CSSProperties = {
  background: "var(--bg-primary, #0d1117)",
  border: "1px solid var(--border-color, #21262d)",
  color: "var(--text-primary, #e6edf3)",
  padding: 8,
  borderRadius: 6,
  width: "100%",
  fontSize: 13,
  outline: "none",
  boxSizing: "border-box",
  transition: "border-color 0.15s",
};

const sectionStyle: CSSProperties = {
  fontSize: 11,
  textTransform: "uppercase",
  letterSpacing: "1px",
  color: "var(--text-secondary)",
  borderBottom: "1px solid var(--border-color)",
  paddingBottom: 6,
  marginTop: 20,
  marginBottom: 12,
  fontWeight: 600,
};

/**
 * Persist the chosen project path (and optionally theme) to ~/.aui/settings.json
 * so they survive restarts. Pass null for path to clear the saved path (reset to home).
 */
async function saveProjectPath(path: string | null, theme?: "dark" | "light") {
  const home = await homeDir();
  const auiDir = join(home, ".aui");
  if (!(await exists(auiDir))) {
    await mkdir(auiDir, { recursive: true });
  }
  const settingsPath = join(auiDir, "settings.json");
  let current: Record<string, unknown> = {};
  try {
    if (await exists(settingsPath)) {
      current = JSON.parse(await readTextFile(settingsPath));
    }
  } catch {
    // Start fresh
  }
  if (path) {
    current.projectPath = path;
  } else {
    delete current.projectPath;
  }
  if (theme) {
    current.theme = theme;
  }
  await writeTextFile(settingsPath, JSON.stringify(current, null, 2));
}

export function SettingsPanel() {
  const settingsOpen = useUiStore((s) => s.settingsOpen);
  const toggleSettings = useUiStore((s) => s.toggleSettings);
  const setTheme = useUiStore((s) => s.setTheme);
  const projectPath = useTreeStore((s) => s.projectPath);

  const [settings, setSettings] = useState<AppSettings>(DEFAULT_SETTINGS);
  const [loading, setLoading] = useState(false);
  const [apiKeyVisible, setApiKeyVisible] = useState(false);
  const [version, setVersion] = useState("0.6.3");
  const [includeSkills, setIncludeSkills] = useState(false);

  useEffect(() => {
    getVersion().then(v => setVersion(v)).catch(() => {});
  }, []);

  // Load settings on open
  useEffect(() => {
    if (!settingsOpen || !projectPath) return;
    let cancelled = false;
    setLoading(true);

    (async () => {
      try {
        const settingsPath = join(projectPath, ".aui", "settings.json");
        if (await exists(settingsPath)) {
          const raw = await readTextFile(settingsPath);
          const parsed = JSON.parse(raw);
          if (!cancelled) {
            const loaded = { ...DEFAULT_SETTINGS, ...parsed };
            setSettings(loaded);
            setTheme(loaded.theme);
          }
        }
      } catch {
        // Use defaults
      }
      if (!cancelled) setLoading(false);
    })();

    return () => { cancelled = true; };
  }, [settingsOpen, projectPath]);

  const handleSave = async () => {
    if (!projectPath) return;
    try {
      const auiDir = join(projectPath, ".aui");
      if (!(await exists(auiDir))) {
        await mkdir(auiDir, { recursive: true });
      }
      const settingsPath = join(auiDir, "settings.json");
      await writeTextFile(settingsPath, JSON.stringify(settings, null, 2));

      // Apply color overrides to CSS variables
      const root = document.documentElement;
      if (settings.accentColor) root.style.setProperty("--accent-blue", settings.accentColor);

      // Apply and persist theme
      setTheme(settings.theme);
      await saveProjectPath(null, settings.theme);

      toast("Settings saved", "success");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Failed to save settings", "error");
    }
  };

  if (!settingsOpen) return null;

  return (
    <div
      style={{
        position: "fixed",
        top: "var(--toolbar-height)",
        right: 0,
        bottom: 0,
        width: 400,
        background: "var(--bg-secondary)",
        borderLeft: "1px solid var(--border-color)",
        boxShadow: "-4px 0 24px var(--shadow-panel)",
        display: "flex",
        flexDirection: "column",
        zIndex: 150,
        animation: "slideInRight 0.2s ease",
      }}
    >
      {/* Header */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "14px 16px 12px",
          borderBottom: "1px solid var(--border-color)",
          flexShrink: 0,
        }}
      >
        <span style={{ fontWeight: 700, fontSize: 16, color: "var(--text-primary)" }}>
          Settings
        </span>
        <button
          onClick={toggleSettings}
          style={{
            background: "transparent",
            border: "none",
            color: "var(--text-secondary)",
            cursor: "pointer",
            fontSize: 18,
            padding: "0 4px",
            lineHeight: 1,
          }}
        >
          ×
        </button>
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflow: "auto", padding: 16 }}>
        {loading ? (
          <div style={{ color: "var(--text-secondary)", fontSize: 13, padding: 20, textAlign: "center" }}>
            Loading...
          </div>
        ) : (
          <>
            {/* Version Info */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "8px 12px",
                background: "rgba(74,158,255,0.06)",
                border: "1px solid var(--border-color)",
                borderRadius: 6,
                marginBottom: 16,
              }}
            >
              <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>Version</span>
              <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>
                {`ATM v${version}`}
              </span>
            </div>

            {/* Project Folder */}
            <div style={sectionStyle}>Project Folder</div>
            <div style={{ marginBottom: 16 }}>
              <div
                style={{
                  ...inputStyle,
                  fontSize: 12,
                  fontFamily: "monospace",
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  marginBottom: 8,
                }}
                title={projectPath ?? ""}
              >
                {projectPath ?? "Not set"}
              </div>
              <div style={{ display: "flex", gap: 6 }}>
                <button
                  onClick={async () => {
                    try {
                      const selected = await open({ directory: true, multiple: false });
                      if (!selected || typeof selected !== "string") return;
                      await saveProjectPath(selected);
                      await useTreeStore.getState().loadProject(selected);
                      useTreeStore.getState().autoGroupByPrefix();
                      toast("Project folder changed", "success");
                    } catch (err) {
                      toast(err instanceof Error ? err.message : "Failed to change folder", "error");
                    }
                  }}
                  style={{
                    flex: 1,
                    padding: "8px 12px",
                    background: "transparent",
                    color: "var(--accent-blue, #4a9eff)",
                    border: "1px solid var(--accent-blue, #4a9eff)",
                    borderRadius: 6,
                    cursor: "pointer",
                    fontSize: 12,
                    fontWeight: 600,
                  }}
                >
                  Browse
                </button>
                <button
                  onClick={async () => {
                    try {
                      const home = await homeDir();
                      await saveProjectPath(null);
                      await useTreeStore.getState().loadProject(home);
                      useTreeStore.getState().autoGroupByPrefix();
                      toast("Reset to home directory", "success");
                    } catch (err) {
                      toast(err instanceof Error ? err.message : "Failed to reset", "error");
                    }
                  }}
                  style={{
                    flex: 1,
                    padding: "8px 12px",
                    background: "transparent",
                    color: "var(--text-secondary)",
                    border: "1px solid var(--border-color)",
                    borderRadius: 6,
                    cursor: "pointer",
                    fontSize: 12,
                    fontWeight: 600,
                  }}
                >
                  Reset to Home
                </button>
              </div>
              <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 4 }}>
                Agents and skills are loaded from this folder's .claude/ directory
              </div>
            </div>

            {/* API Key */}
            <div style={sectionStyle}>Claude API</div>
            <div style={{ marginBottom: 16 }}>
              <label style={labelStyle}>API Key</label>
              <div style={{ display: "flex", gap: 6 }}>
                <input
                  type={apiKeyVisible ? "text" : "password"}
                  style={{ ...inputStyle, flex: 1 }}
                  value={settings.apiKey}
                  onChange={(e) => setSettings({ ...settings, apiKey: e.target.value })}
                  placeholder="sk-ant-..."
                />
                <button
                  onClick={() => setApiKeyVisible(!apiKeyVisible)}
                  style={{
                    background: "transparent",
                    border: "1px solid var(--border-color)",
                    color: "var(--text-secondary)",
                    borderRadius: 4,
                    cursor: "pointer",
                    padding: "4px 8px",
                    fontSize: 11,
                    whiteSpace: "nowrap",
                  }}
                >
                  {apiKeyVisible ? "Hide" : "Show"}
                </button>
              </div>
              <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 4 }}>
                Used for the Chat panel. Stored locally in .aui/settings.json
              </div>
            </div>

            {/* Colors */}
            <div style={sectionStyle}>Colors</div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
              <div>
                <label style={labelStyle}>Team Color</label>
                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  <input
                    type="color"
                    value={settings.teamColor}
                    onChange={(e) => setSettings({ ...settings, teamColor: e.target.value })}
                    style={{ width: 32, height: 32, border: "none", borderRadius: 4, cursor: "pointer", background: "none" }}
                  />
                  <input
                    style={{ ...inputStyle, flex: 1 }}
                    value={settings.teamColor}
                    onChange={(e) => setSettings({ ...settings, teamColor: e.target.value })}
                  />
                </div>
              </div>

              <div>
                <label style={labelStyle}>Agent Color</label>
                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  <input
                    type="color"
                    value={settings.agentColor}
                    onChange={(e) => setSettings({ ...settings, agentColor: e.target.value })}
                    style={{ width: 32, height: 32, border: "none", borderRadius: 4, cursor: "pointer", background: "none" }}
                  />
                  <input
                    style={{ ...inputStyle, flex: 1 }}
                    value={settings.agentColor}
                    onChange={(e) => setSettings({ ...settings, agentColor: e.target.value })}
                  />
                </div>
              </div>
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={labelStyle}>Accent Color</label>
              <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                <input
                  type="color"
                  value={settings.accentColor}
                  onChange={(e) => setSettings({ ...settings, accentColor: e.target.value })}
                  style={{ width: 32, height: 32, border: "none", borderRadius: 4, cursor: "pointer", background: "none" }}
                />
                <input
                  style={{ ...inputStyle, flex: 1 }}
                  value={settings.accentColor}
                  onChange={(e) => setSettings({ ...settings, accentColor: e.target.value })}
                />
              </div>
            </div>

            {/* Preferences */}
            <div style={sectionStyle}>Preferences</div>

            {/* Theme toggle */}
            <div style={{ marginBottom: 16 }}>
              <span style={labelStyle}>Theme</span>
              <div style={{ display: "flex", gap: 8 }}>
                {(["dark", "light"] as const).map((t) => (
                  <button
                    key={t}
                    onClick={() => { setSettings({ ...settings, theme: t }); setTheme(t); }}
                    style={{
                      flex: 1,
                      padding: "8px 0",
                      background: settings.theme === t ? "var(--accent-blue)" : "var(--bg-elevated)",
                      color: settings.theme === t ? "#fff" : "var(--text-secondary)",
                      border: `1px solid ${settings.theme === t ? "var(--accent-blue)" : "var(--border-color)"}`,
                      borderRadius: 6,
                      cursor: "pointer",
                      fontSize: 13,
                      fontWeight: settings.theme === t ? 600 : 400,
                      transition: "all 0.15s",
                    }}
                  >
                    {t === "dark" ? "🌙 Dark" : "☀️ Light"}
                  </button>
                ))}
              </div>
            </div>

            <label
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                cursor: "pointer",
                marginBottom: 12,
              }}
            >
              <input
                type="checkbox"
                checked={settings.autoSave}
                onChange={(e) => setSettings({ ...settings, autoSave: e.target.checked })}
                style={{ width: 16, height: 16, cursor: "pointer" }}
              />
              <span style={{ fontSize: 13, color: "var(--text-primary)" }}>
                Auto-save tree metadata on changes
              </span>
            </label>

            {/* Save */}
            <button
              onClick={handleSave}
              style={{
                width: "100%",
                padding: "10px 16px",
                marginTop: 16,
                background: "var(--accent-blue)",
                color: "white",
                border: "none",
                borderRadius: 6,
                cursor: "pointer",
                fontSize: 13,
                fontWeight: 600,
              }}
            >
              Save Settings
            </button>

            {/* Data */}
            <div style={sectionStyle}>Data</div>

            <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
              <button
                onClick={async () => {
                  try {
                    if (includeSkills) {
                      const zipData = await useTreeStore.getState().exportTreeAsZip();
                      const filePath = await save({
                        filters: [{ name: "ATM Export (ZIP)", extensions: ["atm.zip"] }],
                        defaultPath: "tree-export.atm.zip",
                      });
                      if (!filePath) return;
                      await writeFile(filePath, zipData);
                      toast("Tree exported as ZIP with skills", "success");
                    } else {
                      const json = useTreeStore.getState().exportTreeAsJson();
                      const filePath = await save({
                        filters: [{ name: "AUI Export", extensions: ["aui.json"] }],
                        defaultPath: "tree-export.aui.json",
                      });
                      if (!filePath) return;
                      await writeTextFile(filePath, json);
                      toast("Tree exported successfully", "success");
                    }
                  } catch (err) {
                    toast(`Export failed: ${err instanceof Error ? err.message : "Unknown error"}`, "error");
                  }
                }}
                style={{
                  flex: 1,
                  padding: "8px 12px",
                  background: "transparent",
                  color: "var(--accent-green, #3fb950)",
                  border: "1px solid var(--accent-green, #3fb950)",
                  borderRadius: 6,
                  cursor: "pointer",
                  fontSize: 12,
                  fontWeight: 600,
                  transition: "background 0.15s",
                }}
                onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(63, 185, 80, 0.1)"; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
              >
                {includeSkills ? "Export as ZIP" : "Export Tree"}
              </button>
              <button
                onClick={async () => {
                  try {
                    const selected = await open({
                      filters: [{ name: "ATM Export", extensions: ["aui.json", "atm.zip"] }],
                    });
                    if (!selected) return;
                    const filePath = typeof selected === "string" ? selected : null;
                    if (!filePath) return;

                    if (filePath.endsWith(".atm.zip")) {
                      const data = await readFile(filePath);
                      await useTreeStore.getState().importTreeFromZip(data);
                      toast("Tree imported from ZIP (with skills)", "success");
                    } else {
                      const json = await readTextFile(filePath);
                      useTreeStore.getState().importTreeFromJson(json);
                      toast("Tree imported successfully", "success");
                    }
                  } catch (err) {
                    toast(`Import failed: ${err instanceof Error ? err.message : "Unknown error"}`, "error");
                  }
                }}
                style={{
                  flex: 1,
                  padding: "8px 12px",
                  background: "transparent",
                  color: "var(--accent-blue, #4a9eff)",
                  border: "1px solid var(--accent-blue, #4a9eff)",
                  borderRadius: 6,
                  cursor: "pointer",
                  fontSize: 12,
                  fontWeight: 600,
                  transition: "background 0.15s",
                }}
                onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(74, 158, 255, 0.1)"; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
              >
                Import Tree
              </button>
            </div>
            <label
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                cursor: "pointer",
                marginBottom: 8,
                marginTop: 4,
              }}
            >
              <input
                type="checkbox"
                checked={includeSkills}
                onChange={(e) => setIncludeSkills(e.target.checked)}
                style={{ width: 14, height: 14, cursor: "pointer" }}
              />
              <span style={{ fontSize: 12, color: "var(--text-primary)" }}>
                Include skill files (export as .atm.zip)
              </span>
            </label>
            <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 4 }}>
              Export saves your tree layout and metadata. ZIP includes skill files. Import supports both .aui.json and .atm.zip.
            </div>
          </>
        )}

        {/* Remote Access */}
        <RemoteAccessSection />

        {/* Advanced */}
        <div style={sectionStyle}>Advanced</div>

        <button
          onClick={async () => {
            if (!projectPath) return;
            try {
              const { open: shellOpen } = await import("@tauri-apps/plugin-shell");
              const settingsPath = join(projectPath, ".claude", "settings.json");
              await shellOpen(settingsPath);
            } catch {
              toast("Could not open settings file", "error");
            }
          }}
          style={{
            width: "100%",
            padding: "8px 12px",
            background: "transparent",
            color: "var(--text-secondary)",
            border: "1px solid var(--border-color)",
            borderRadius: 6,
            cursor: "pointer",
            fontSize: 12,
            fontWeight: 500,
            transition: "border-color 0.15s, color 0.15s",
          }}
          onMouseEnter={(e) => { e.currentTarget.style.borderColor = "rgba(255,255,255,0.25)"; e.currentTarget.style.color = "var(--text-primary)"; }}
          onMouseLeave={(e) => { e.currentTarget.style.borderColor = "var(--border-color)"; e.currentTarget.style.color = "var(--text-secondary)"; }}
        >
          Open Claude Settings File
        </button>
        <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 4 }}>
          Opens .claude/settings.json in your default editor
        </div>
      </div>
    </div>
  );
}

// ─── Remote Access Section ─────────────────────────────────────────

interface RemoteInfo {
  url: string;
  port: number;
  ip: string;
  pin: string;
  certFingerprint: string;
  qrDataUri?: string;
}

const modeTabStyle = (active: boolean): CSSProperties => ({
  flex: 1,
  padding: "8px 0",
  background: active ? "var(--accent-blue)" : "transparent",
  color: active ? "#fff" : "var(--text-secondary)",
  border: active ? "none" : "1px solid var(--border-color)",
  borderRadius: 6,
  cursor: "pointer",
  fontSize: 12,
  fontWeight: 600,
  transition: "all 0.15s",
});

function RemoteAccessSection() {
  const remoteConfig = useUiStore((s) => s.remoteConfig);
  const remoteConnected = useUiStore((s) => s.remoteConnected);
  const remoteClientCount = useUiStore((s) => s.remoteClientCount);
  const setRemoteConfig = useUiStore((s) => s.setRemoteConfig);
  const saveRemoteConfigFn = useUiStore((s) => s.saveRemoteConfig);
  const connectRemote = useUiStore((s) => s.connectRemote);
  const disconnectRemote = useUiStore((s) => s.disconnectRemote);
  const relayStatus = useUiStore((s) => s.relayStatus);
  const connectRelay = useUiStore((s) => s.connectRelay);
  const connectRelayPersistent = useUiStore((s) => s.connectRelayPersistent);
  const disconnectRelay = useUiStore((s) => s.disconnectRelay);
  const loadPairedDevices = useUiStore((s) => s.loadPairedDevices);
  const revokePairingFn = useUiStore((s) => s.revokePairing);
  const projectPath = useTreeStore((s) => s.projectPath);

  const saveRemoteConfig = useCallback(async () => {
    if (projectPath) await saveRemoteConfigFn(projectPath);
  }, [projectPath, saveRemoteConfigFn]);

  const [remoteInfo, setRemoteInfo] = useState<RemoteInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [serverRunning, setServerRunning] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // ── LAN mode toggle ──
  const handleLanToggle = async (enabled: boolean) => {
    setLoading(true);
    setRemoteConfig({ enabled });
    try {
      if (enabled) {
        // Register event listeners BEFORE starting server so we don't miss
        // the remote-server-started event (which sets _connected = true).
        await connectRemote();
        const info = await invoke<RemoteInfo>("start_remote_server", {
          port: remoteConfig.port,
          exposeOnNetwork: remoteConfig.exposeOnNetwork,
        });
        try {
          const qrDataUri = await invoke<string>("generate_qr_code", { url: info.url });
          info.qrDataUri = qrDataUri;
        } catch { /* QR optional */ }
        setRemoteInfo(info);
        setServerRunning(true);
      } else {
        try { await invoke("stop_remote_server"); } catch { /* ignore */ }
        disconnectRemote();
        setRemoteInfo(null);
        setServerRunning(false);
      }
    } catch (err) {
      console.warn("[Settings] Remote server error:", err);
      toast(err instanceof Error ? err.message : String(err), "error");
      setRemoteConfig({ enabled: false });
    }
    await saveRemoteConfig();
    setLoading(false);
  };

  // ── Cloud mode toggle ──
  const handleCloudToggle = async (enabled: boolean) => {
    setLoading(true);
    setRemoteConfig({ enabled });
    try {
      if (enabled) {
        // Use persistent mode — registers desktop, no room code needed for paired devices
        await connectRelayPersistent(remoteConfig.relayUrl);

        // Also create an ephemeral room for initial pairing of new devices
        await connectRelay(remoteConfig.relayUrl);

        // Generate QR code with relay info — read fresh state after await
        const status = useUiStore.getState().relayStatus;
        if (status.roomCode) {
          const relayHttps = remoteConfig.relayUrl.replace("wss://", "https://");
          const qrContent = `${relayHttps}?code=${status.roomCode}`;
          try {
            const qrDataUri = await invoke<string>("generate_qr_code", { url: qrContent });
            setRemoteInfo({
              url: remoteConfig.relayUrl,
              port: 0,
              ip: "",
              pin: "",
              certFingerprint: "",
              qrDataUri,
            });
          } catch { /* QR optional */ }
        }
        setServerRunning(true);

        // Load paired devices
        loadPairedDevices().catch(() => {});
      } else {
        disconnectRelay();
        setRemoteInfo(null);
        setServerRunning(false);
      }
    } catch (err) {
      console.warn("[Settings] Cloud relay error:", err);
      const msg = err instanceof Error ? err.message : String(err);
      toast(msg || "Could not connect to relay server. The server may be unavailable.", "error");
      setRemoteConfig({ enabled: false });
    }
    await saveRemoteConfig();
    setLoading(false);
  };

  const handleToggle = (enabled: boolean) => {
    if (remoteConfig.mode === "cloud") {
      handleCloudToggle(enabled);
    } else {
      handleLanToggle(enabled);
    }
  };

  const handleModeSwitch = async (mode: "lan" | "cloud") => {
    if (mode === remoteConfig.mode) return;
    // If currently enabled, disable first
    if (remoteConfig.enabled) {
      await handleToggle(false);
    }
    setRemoteConfig({ mode });
    await saveRemoteConfig();
  };

  const dotColor = serverRunning ? "#3fb950" : loading ? "#f0883e" : "#f85149";

  return (
    <>
      <div style={sectionStyle}>Remote Access</div>

      {/* Mode selector */}
      <div style={{ display: "flex", gap: 6, marginBottom: 12 }}>
        <button style={modeTabStyle(remoteConfig.mode === "lan")} onClick={() => handleModeSwitch("lan")}>
          LAN
        </button>
        <button style={modeTabStyle(remoteConfig.mode === "cloud")} onClick={() => handleModeSwitch("cloud")}>
          Cloud
        </button>
      </div>
      <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 12 }}>
        {remoteConfig.mode === "lan"
          ? "Direct connection on the same WiFi network. Fastest latency."
          : "Connect from anywhere via encrypted cloud relay. Works over the internet."}
      </div>

      {/* Enable toggle */}
      <label
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          cursor: "pointer",
          marginBottom: 12,
        }}
      >
        <input
          type="checkbox"
          checked={remoteConfig.enabled}
          onChange={(e) => handleToggle(e.target.checked)}
          disabled={loading}
          style={{ width: 16, height: 16, cursor: "pointer" }}
        />
        <span style={{ fontSize: 13, color: "var(--text-primary)" }}>
          {remoteConfig.mode === "cloud" ? "Enable cloud remote access" : "Enable LAN remote access"}
        </span>
      </label>

      {remoteConfig.enabled && (
        <div style={{ marginBottom: 16 }}>
          {/* Connection status */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: "8px 12px",
              background: "rgba(74,158,255,0.06)",
              border: "1px solid var(--border-color)",
              borderRadius: 6,
              marginBottom: 12,
            }}
          >
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: dotColor,
                flexShrink: 0,
              }}
            />
            <span style={{ fontSize: 12, color: "var(--text-primary)", flex: 1 }}>
              {remoteConfig.mode === "cloud"
                ? (relayStatus.connected
                  ? (relayStatus.clientConnected
                    ? `Connected \u00b7 Mobile paired`
                    : `Waiting for mobile \u00b7 Room ${relayStatus.roomCode || "..."}`)
                  : loading ? "Connecting to relay..." : "Disconnected")
                : (serverRunning
                  ? `Running${remoteClientCount > 0 ? ` \u00b7 ${remoteClientCount} client${remoteClientCount !== 1 ? "s" : ""}` : ""}`
                  : loading ? "Starting..." : "Stopped")}
            </span>
          </div>

          {/* ── Cloud mode: Room code + QR ── */}
          {remoteConfig.mode === "cloud" && relayStatus.roomCode && (
            <>
              {/* Room code display */}
              <div style={{ marginBottom: 12 }}>
                <label style={labelStyle}>Room Code</label>
                <div
                  style={{
                    fontSize: 32,
                    fontWeight: 700,
                    letterSpacing: "4px",
                    color: "var(--accent-blue)",
                    textAlign: "center",
                    padding: "12px 0",
                    fontFamily: "monospace",
                    cursor: "pointer",
                    userSelect: "all",
                  }}
                  onClick={() => {
                    navigator.clipboard.writeText(relayStatus.roomCode || "");
                    toast("Room code copied", "success");
                  }}
                  title="Click to copy"
                >
                  {relayStatus.roomCode}
                </div>
                <div style={{ fontSize: 11, color: "var(--text-secondary)", textAlign: "center" }}>
                  Enter this code on your phone, or scan the QR code below
                </div>
              </div>
            </>
          )}

          {/* QR Code (both modes) */}
          {remoteInfo?.qrDataUri && (
            <div
              style={{
                textAlign: "center",
                marginBottom: 12,
                padding: 12,
                background: "#fff",
                borderRadius: 8,
              }}
            >
              <img
                src={remoteInfo.qrDataUri}
                alt="QR Code"
                style={{ width: 180, height: 180, imageRendering: "pixelated" }}
              />
              <div style={{ fontSize: 11, color: "#333", marginTop: 6 }}>
                Scan with your phone to connect
              </div>
            </div>
          )}

          {/* ── LAN mode: URL and PIN ── */}
          {remoteConfig.mode === "lan" && remoteInfo && (
            <div style={{ marginBottom: 12 }}>
              <label style={labelStyle}>Server URL</label>
              <div
                style={{
                  ...inputStyle,
                  fontSize: 12,
                  fontFamily: "monospace",
                  cursor: "pointer",
                  userSelect: "all",
                }}
                onClick={() => {
                  navigator.clipboard.writeText(remoteInfo.url);
                  toast("URL copied", "success");
                }}
                title="Click to copy"
              >
                {remoteInfo.url}
              </div>
            </div>
          )}

          {remoteConfig.mode === "lan" && remoteInfo?.pin && (
            <div style={{ marginBottom: 12 }}>
              <label style={labelStyle}>PIN Code</label>
              <div
                style={{
                  fontSize: 28,
                  fontWeight: 700,
                  letterSpacing: "6px",
                  color: "var(--accent-blue)",
                  textAlign: "center",
                  padding: "8px 0",
                  fontFamily: "monospace",
                }}
              >
                {remoteInfo.pin}
              </div>
              <div style={{ fontSize: 11, color: "var(--text-secondary)", textAlign: "center" }}>
                Enter this PIN on your phone to authenticate
              </div>
            </div>
          )}

          {/* E2E encryption badge (cloud mode) */}
          {remoteConfig.mode === "cloud" && (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                padding: "6px 10px",
                background: "rgba(63, 185, 80, 0.08)",
                border: "1px solid rgba(63, 185, 80, 0.2)",
                borderRadius: 6,
                marginBottom: 12,
              }}
            >
              <span style={{ fontSize: 12 }}>&#128274;</span>
              <span style={{ fontSize: 11, color: "#3fb950" }}>
                End-to-end encrypted — relay cannot read your data
              </span>
            </div>
          )}

          {/* ── LAN mode config ── */}
          {remoteConfig.mode === "lan" && (
            <>
              <div style={{ marginBottom: 8 }}>
                <label style={labelStyle}>Port</label>
                <input
                  type="number"
                  min={1024}
                  max={65535}
                  style={{ ...inputStyle, width: 100 }}
                  value={remoteConfig.port}
                  onChange={(e) => setRemoteConfig({ port: parseInt(e.target.value) || 5175 })}
                  onBlur={saveRemoteConfig}
                />
              </div>

              <label
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  cursor: "pointer",
                  marginBottom: 8,
                }}
              >
                <input
                  type="checkbox"
                  checked={remoteConfig.exposeOnNetwork}
                  onChange={(e) => {
                    setRemoteConfig({ exposeOnNetwork: e.target.checked });
                    saveRemoteConfig();
                  }}
                  style={{ width: 14, height: 14, cursor: "pointer" }}
                />
                <span style={{ fontSize: 12, color: "var(--text-primary)" }}>
                  Expose on local network (0.0.0.0)
                </span>
              </label>
              <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 4 }}>
                When disabled, only accessible from this machine (127.0.0.1).
                Enable to allow connections from other devices on your LAN.
              </div>
            </>
          )}

          {/* ── Paired Devices (cloud mode) ── */}
          {remoteConfig.mode === "cloud" && relayStatus.pairedDevices.length > 0 && (
            <div style={{ marginBottom: 12 }}>
              <div style={{ ...labelStyle, marginBottom: 8 }}>Paired Devices</div>
              {relayStatus.pairedDevices.map((device) => (
                <div
                  key={device.pairingId}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    padding: "8px 10px",
                    background: "rgba(74,158,255,0.06)",
                    border: "1px solid var(--border-color)",
                    borderRadius: 6,
                    marginBottom: 6,
                  }}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 12, color: "var(--text-primary)", fontWeight: 500 }}>
                      {device.deviceName || "Mobile Device"}
                    </div>
                    <div style={{ fontSize: 10, color: "var(--text-secondary)" }}>
                      Last used: {new Date(device.lastUsed).toLocaleDateString()} &middot; Expires: {new Date(device.expiresAt).toLocaleDateString()}
                    </div>
                  </div>
                  <button
                    onClick={() => revokePairingFn(device.pairingId)}
                    style={{
                      background: "transparent",
                      border: "1px solid rgba(248,81,73,0.3)",
                      color: "#f85149",
                      borderRadius: 4,
                      cursor: "pointer",
                      padding: "3px 8px",
                      fontSize: 10,
                      fontWeight: 600,
                      flexShrink: 0,
                    }}
                  >
                    Revoke
                  </button>
                </div>
              ))}
            </div>
          )}

          {remoteConfig.mode === "cloud" && relayStatus.persistentMode && relayStatus.pairedDevices.length === 0 && (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                padding: "6px 10px",
                background: "rgba(74,158,255,0.06)",
                border: "1px solid var(--border-color)",
                borderRadius: 6,
                marginBottom: 12,
                fontSize: 11,
                color: "var(--text-secondary)",
              }}
            >
              No paired devices yet. Connect a phone using the room code above to pair it.
            </div>
          )}

          {/* ── Advanced section (cloud mode) ── */}
          {remoteConfig.mode === "cloud" && (
            <>
              <button
                onClick={() => setShowAdvanced(!showAdvanced)}
                style={{
                  background: "none",
                  border: "none",
                  color: "var(--text-secondary)",
                  fontSize: 11,
                  cursor: "pointer",
                  padding: "4px 0",
                  textDecoration: "underline",
                }}
              >
                {showAdvanced ? "Hide advanced" : "Advanced settings"}
              </button>
              {showAdvanced && (
                <div style={{ marginTop: 8 }}>
                  <label style={labelStyle}>Custom Relay URL</label>
                  <input
                    type="text"
                    style={{ ...inputStyle, fontSize: 12, fontFamily: "monospace" }}
                    value={remoteConfig.relayUrl}
                    onChange={(e) => setRemoteConfig({ relayUrl: e.target.value })}
                    onBlur={saveRemoteConfig}
                    placeholder="wss://atm-relay.datafying.tech"
                  />
                  <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 4 }}>
                    Self-host the relay server for full control. Default: wss://atm-relay.datafying.tech
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </>
  );
}
