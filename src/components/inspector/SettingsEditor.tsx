import { useState, useEffect, type CSSProperties, type KeyboardEvent } from "react";
import Editor from "@monaco-editor/react";
import { useTreeStore } from "@/store/tree-store";
import { useUiStore } from "@/store/ui-store";
import type { AuiNode } from "@/types/aui-node";
import type { SettingsConfig } from "@/types/settings";

const MODEL_OPTIONS = [
  "",
  "claude-sonnet-4-5-20250929",
  "claude-opus-4-6",
  "claude-haiku-4-5-20251001",
];

const MODE_OPTIONS = ["", "default", "acceptEdits", "bypassPermissions", "plan", "dontAsk"];

const labelStyle: CSSProperties = {
  fontSize: 12,
  textTransform: "uppercase",
  color: "var(--text-secondary)",
  marginBottom: 4,
  display: "block",
  letterSpacing: "0.5px",
};

const inputStyle: CSSProperties = {
  background: "#1a1a2e",
  border: "1px solid #2a2a4a",
  color: "white",
  padding: 8,
  borderRadius: 4,
  width: "100%",
  fontSize: 13,
  outline: "none",
};

const fieldStyle: CSSProperties = {
  marginBottom: 16,
};

// -- Tag Input (reused pattern) --

interface TagInputProps {
  tags: string[];
  onChange: (tags: string[]) => void;
}

function TagInput({ tags, onChange }: TagInputProps) {
  const [input, setInput] = useState("");

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      const tag = input.trim();
      if (tag && !tags.includes(tag)) {
        onChange([...tags, tag]);
      }
      setInput("");
    }
    if (e.key === "Backspace" && input === "" && tags.length > 0) {
      onChange(tags.slice(0, -1));
    }
  };

  return (
    <div
      style={{
        ...inputStyle,
        display: "flex",
        flexWrap: "wrap",
        gap: 4,
        padding: 4,
        minHeight: 36,
        alignItems: "center",
      }}
    >
      {tags.map((tag) => (
        <span
          key={tag}
          style={{
            background: "var(--bg-surface)",
            color: "var(--accent-blue)",
            padding: "2px 8px",
            borderRadius: 3,
            fontSize: 12,
            display: "inline-flex",
            alignItems: "center",
            gap: 4,
          }}
        >
          {tag}
          <button
            type="button"
            onClick={() => onChange(tags.filter((t) => t !== tag))}
            style={{
              background: "none",
              border: "none",
              color: "var(--text-secondary)",
              cursor: "pointer",
              padding: 0,
              fontSize: 14,
              lineHeight: 1,
            }}
          >
            x
          </button>
        </span>
      ))}
      <input
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder={tags.length === 0 ? "Type and press Enter" : ""}
        style={{
          background: "transparent",
          border: "none",
          color: "white",
          outline: "none",
          flex: 1,
          minWidth: 80,
          fontSize: 13,
          padding: "4px",
        }}
      />
    </div>
  );
}

// -- Key-Value Editor --

interface EnvPair {
  key: string;
  value: string;
}

interface KeyValueEditorProps {
  pairs: EnvPair[];
  onChange: (pairs: EnvPair[]) => void;
}

function KeyValueEditor({ pairs, onChange }: KeyValueEditorProps) {
  const updatePair = (index: number, field: "key" | "value", val: string) => {
    const next = pairs.map((p, i) => (i === index ? { ...p, [field]: val } : p));
    onChange(next);
  };

  const removePair = (index: number) => {
    onChange(pairs.filter((_, i) => i !== index));
  };

  const addPair = () => {
    onChange([...pairs, { key: "", value: "" }]);
  };

  return (
    <div>
      {pairs.map((pair, i) => (
        <div key={i} style={{ display: "flex", gap: 4, marginBottom: 4 }}>
          <input
            style={{ ...inputStyle, flex: 1 }}
            value={pair.key}
            onChange={(e) => updatePair(i, "key", e.target.value)}
            placeholder="KEY"
          />
          <input
            style={{ ...inputStyle, flex: 2 }}
            value={pair.value}
            onChange={(e) => updatePair(i, "value", e.target.value)}
            placeholder="value"
          />
          <button
            type="button"
            onClick={() => removePair(i)}
            style={{
              background: "transparent",
              border: "1px solid #2a2a4a",
              color: "var(--text-secondary)",
              borderRadius: 4,
              cursor: "pointer",
              padding: "0 8px",
              fontSize: 14,
            }}
          >
            x
          </button>
        </div>
      ))}
      <button
        type="button"
        onClick={addPair}
        style={{
          background: "transparent",
          border: "1px dashed #2a2a4a",
          color: "var(--text-secondary)",
          borderRadius: 4,
          cursor: "pointer",
          padding: "6px 12px",
          fontSize: 12,
          width: "100%",
        }}
      >
        + Add Row
      </button>
    </div>
  );
}

// -- SettingsEditor --

interface SettingsEditorProps {
  node: AuiNode;
}

export function SettingsEditor({ node }: SettingsEditorProps) {
  const updateNode = useTreeStore((s) => s.updateNode);
  const saveNode = useTreeStore((s) => s.saveNode);
  const theme = useUiStore((s) => s.theme);

  const cfg = (node.config as SettingsConfig | null) ?? {};

  const [defaultMode, setDefaultMode] = useState(cfg.defaultMode ?? "");
  const [model, setModel] = useState(cfg.model ?? "");
  const [permAllow, setPermAllow] = useState<string[]>(cfg.permissions?.allow ?? []);
  const [permDeny, setPermDeny] = useState<string[]>(cfg.permissions?.deny ?? []);
  const [envPairs, setEnvPairs] = useState<EnvPair[]>(
    Object.entries(cfg.env ?? {}).map(([key, value]) => ({ key, value })),
  );
  const [allowedTools, setAllowedTools] = useState<string[]>(cfg.allowedTools ?? []);
  const [rawMode, setRawMode] = useState(false);
  const [rawJson, setRawJson] = useState("");
  const [savedAt, setSavedAt] = useState<number | null>(null);

  useEffect(() => {
    const c = (node.config as SettingsConfig | null) ?? {};
    setDefaultMode(c.defaultMode ?? "");
    setModel(c.model ?? "");
    setPermAllow(c.permissions?.allow ?? []);
    setPermDeny(c.permissions?.deny ?? []);
    setEnvPairs(Object.entries(c.env ?? {}).map(([key, value]) => ({ key, value })));
    setAllowedTools(c.allowedTools ?? []);
    setSavedAt(null);
  }, [node.id, node.config]);

  const resetForm = () => {
    const c = (node.config as SettingsConfig | null) ?? {};
    setDefaultMode(c.defaultMode ?? "");
    setModel(c.model ?? "");
    setPermAllow(c.permissions?.allow ?? []);
    setPermDeny(c.permissions?.deny ?? []);
    setEnvPairs(Object.entries(c.env ?? {}).map(([key, value]) => ({ key, value })));
    setAllowedTools(c.allowedTools ?? []);
  };

  const buildConfig = (): SettingsConfig => {
    const env: Record<string, string> = {};
    for (const p of envPairs) {
      if (p.key.trim()) env[p.key.trim()] = p.value;
    }

    return {
      ...(defaultMode ? { defaultMode } : {}),
      ...(model ? { model } : {}),
      ...(permAllow.length || permDeny.length
        ? {
            permissions: {
              ...(permAllow.length ? { allow: permAllow } : {}),
              ...(permDeny.length ? { deny: permDeny } : {}),
            },
          }
        : {}),
      ...(Object.keys(env).length ? { env } : {}),
      ...(allowedTools.length ? { allowedTools } : {}),
      ...(cfg.hooks ? { hooks: cfg.hooks } : {}),
    };
  };

  const handleSave = () => {
    let config: SettingsConfig;

    if (rawMode) {
      try {
        config = JSON.parse(rawJson) as SettingsConfig;
      } catch {
        return; // invalid JSON, don't save
      }
    } else {
      config = buildConfig();
    }

    updateNode(node.id, {
      config,
      lastModified: Date.now(),
    });
    saveNode(node.id);

    const now = Date.now();
    setSavedAt(now);
    setTimeout(() => {
      setSavedAt((prev) => (prev === now ? null : prev));
    }, 2000);
  };

  const toggleRawMode = () => {
    if (!rawMode) {
      setRawJson(JSON.stringify(buildConfig(), null, 2));
    }
    setRawMode(!rawMode);
  };

  if (rawMode) {
    return (
      <div>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
          <label style={labelStyle}>Raw JSON</label>
          <button
            onClick={toggleRawMode}
            style={{
              background: "transparent",
              border: "1px solid var(--accent-blue)",
              color: "var(--accent-blue)",
              borderRadius: 4,
              cursor: "pointer",
              padding: "4px 8px",
              fontSize: 11,
            }}
          >
            Form View
          </button>
        </div>
        <Editor
          height={500}
          language="json"
          theme={theme === "light" ? "vs" : "vs-dark"}
          value={rawJson}
          onChange={(v) => setRawJson(v ?? "")}
          options={{
            minimap: { enabled: false },
            fontSize: 13,
            lineNumbers: "on",
            scrollBeyondLastLine: false,
          }}
        />
        <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 12 }}>
          <button
            onClick={handleSave}
            style={{
              flex: 1,
              padding: "8px 16px",
              background: "var(--accent-blue)",
              color: "white",
              border: "none",
              borderRadius: 4,
              cursor: "pointer",
              fontSize: 13,
              fontWeight: 600,
            }}
          >
            Save
          </button>
          {savedAt !== null && (
            <span
              style={{
                color: "var(--accent-green)",
                fontSize: 12,
                fontWeight: 600,
                whiteSpace: "nowrap",
              }}
            >
              Saved!
            </span>
          )}
        </div>
      </div>
    );
  }

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 12 }}>
        <button
          onClick={toggleRawMode}
          style={{
            background: "transparent",
            border: "1px solid var(--accent-blue)",
            color: "var(--accent-blue)",
            borderRadius: 4,
            cursor: "pointer",
            padding: "4px 8px",
            fontSize: 11,
          }}
        >
          Raw JSON
        </button>
      </div>

      <div style={fieldStyle}>
        <label style={labelStyle}>Default Mode</label>
        <select
          style={inputStyle}
          value={defaultMode}
          onChange={(e) => setDefaultMode(e.target.value)}
        >
          {MODE_OPTIONS.map((m) => (
            <option key={m} value={m}>
              {m || "(default)"}
            </option>
          ))}
        </select>
      </div>

      <div style={fieldStyle}>
        <label style={labelStyle}>Model</label>
        <select
          style={inputStyle}
          value={model}
          onChange={(e) => setModel(e.target.value)}
        >
          {MODEL_OPTIONS.map((m) => (
            <option key={m} value={m}>
              {m || "(default)"}
            </option>
          ))}
        </select>
      </div>

      <div style={fieldStyle}>
        <label style={labelStyle}>Permissions Allow</label>
        <TagInput tags={permAllow} onChange={setPermAllow} />
      </div>

      <div style={fieldStyle}>
        <label style={labelStyle}>Permissions Deny</label>
        <TagInput tags={permDeny} onChange={setPermDeny} />
      </div>

      <div style={fieldStyle}>
        <label style={labelStyle}>Environment Variables</label>
        <KeyValueEditor pairs={envPairs} onChange={setEnvPairs} />
      </div>

      <div style={fieldStyle}>
        <label style={labelStyle}>Allowed Tools</label>
        <TagInput tags={allowedTools} onChange={setAllowedTools} />
      </div>

      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <button
          onClick={handleSave}
          style={{
            flex: 1,
            padding: "8px 16px",
            background: "var(--accent-blue)",
            color: "white",
            border: "none",
            borderRadius: 4,
            cursor: "pointer",
            fontSize: 13,
            fontWeight: 600,
          }}
        >
          Save
        </button>
        <button
          onClick={resetForm}
          style={{
            padding: "8px 16px",
            background: "transparent",
            color: "var(--text-secondary)",
            border: "1px solid var(--border-color)",
            borderRadius: 4,
            cursor: "pointer",
            fontSize: 13,
            fontWeight: 600,
          }}
        >
          Discard
        </button>
        {savedAt !== null && (
          <span
            style={{
              color: "var(--accent-green)",
              fontSize: 12,
              fontWeight: 600,
              whiteSpace: "nowrap",
            }}
          >
            Saved!
          </span>
        )}
      </div>
    </div>
  );
}
