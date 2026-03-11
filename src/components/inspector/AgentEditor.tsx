import { useState, useEffect, useCallback, type CSSProperties, type KeyboardEvent } from "react";
import Editor from "@monaco-editor/react";
import { MarkdownEditor } from "./MarkdownEditor";
import { useTreeStore } from "@/store/tree-store";
import { useAutosave } from "@/hooks/useAutosave";
import { getApiKey, generateText } from "@/services/claude-api";
import { toast } from "@/components/common/Toast";
import type { AuiNode, NodeVariable } from "@/types/aui-node";
import { VariableEditor } from "./VariableEditor";
import type { AgentConfig } from "@/types/agent";

const MODEL_OPTIONS = [
  "",
  "claude-sonnet-4-5-20250929",
  "claude-opus-4-6",
  "claude-haiku-4-5-20251001",
];

const PERMISSION_OPTIONS = [
  "",
  "default",
  "acceptEdits",
  "bypassPermissions",
  "plan",
  "dontAsk",
];

// -- Shared styles --

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
  transition: "border-color 0.15s",
};

const fieldStyle: CSSProperties = {
  marginBottom: 16,
};

const sectionHeaderStyle: CSSProperties = {
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

// -- Tag Input component --

interface TagInputProps {
  tags: string[];
  onChange: (tags: string[]) => void;
}

function TagInput({ tags, onChange }: TagInputProps) {
  const [input, setInput] = useState("");

  const addTag = useCallback(
    (raw: string) => {
      const tag = raw.trim();
      if (tag && !tags.includes(tag)) {
        onChange([...tags, tag]);
      }
    },
    [tags, onChange],
  );

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      addTag(input);
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

// -- AgentEditor --

interface AgentEditorProps {
  node: AuiNode;
}

export function AgentEditor({ node }: AgentEditorProps) {
  const updateNode = useTreeStore((s) => s.updateNode);
  const saveNode = useTreeStore((s) => s.saveNode);

  const cfg = (node.config as AgentConfig | null) ?? { name: node.name };

  const [name, setName] = useState(cfg.name);
  const [description, setDescription] = useState(cfg.description ?? "");
  const [model, setModel] = useState(cfg.model ?? "");
  const [permissionMode, setPermissionMode] = useState(cfg.permissionMode ?? "");
  const [maxTurns, setMaxTurns] = useState(cfg.maxTurns ?? 0);
  const [tools, setTools] = useState<string[]>(cfg.tools ?? []);
  const [disallowedTools, setDisallowedTools] = useState<string[]>(cfg.disallowedTools ?? []);
  const [skills, setSkills] = useState<string[]>(cfg.skills ?? []);
  const [color, setColor] = useState(cfg.color ?? "");
  const [variables, setVariables] = useState<NodeVariable[]>(node.variables);
  const [promptBody, setPromptBody] = useState(node.promptBody);
  const [errors, setErrors] = useState<string[]>(node.validationErrors);
  const [hooksOpen, setHooksOpen] = useState(false);
  const [generating, setGenerating] = useState(false);

  const projectPath = useTreeStore((s) => s.projectPath);

  const handleGenerate = useCallback(async () => {
    if (!projectPath || !name.trim()) return;
    setGenerating(true);
    try {
      const apiKey = await getApiKey(projectPath);
      if (!apiKey) {
        toast("No API key configured. Go to Settings to add one.", "error");
        setGenerating(false);
        return;
      }
      const result = await generateText(apiKey, `This is a Claude Code agent named "${name}". Write a concise 1-2 sentence description for what this agent does based on its name. Be specific. Only output the description text, nothing else.`);
      if (result.trim()) {
        const generated = result.trim();
        setDescription(generated);
        toast("Description generated", "success");
        // Immediately persist the generated description (don't rely on autosave debounce)
        const updatedConfig: AgentConfig = {
          name,
          ...(generated ? { description: generated } : {}),
          ...(model ? { model } : {}),
          ...(permissionMode
            ? { permissionMode: permissionMode as AgentConfig["permissionMode"] }
            : {}),
          ...(maxTurns ? { maxTurns } : {}),
          ...(tools.length ? { tools } : {}),
          ...(disallowedTools.length ? { disallowedTools } : {}),
          ...(skills.length ? { skills } : {}),
          ...(color ? { color } : {}),
          ...(cfg.hooks ? { hooks: cfg.hooks } : {}),
          ...(cfg.allowedCommands?.length ? { allowedCommands: cfg.allowedCommands } : {}),
        };
        updateNode(node.id, {
          name,
          config: updatedConfig,
          promptBody,
          variables: variables.filter((v) => v.name.trim()),
          lastModified: Date.now(),
        });
        saveNode(node.id);
      }
    } catch (err) {
      toast(err instanceof Error ? err.message : "Generation failed", "error");
    }
    setGenerating(false);
  }, [projectPath, name, model, permissionMode, maxTurns, tools, disallowedTools, skills, color, cfg.hooks, cfg.allowedCommands, node.id, promptBody, variables, updateNode, saveNode]);

  // Re-init when node changes
  useEffect(() => {
    const c = (node.config as AgentConfig | null) ?? { name: node.name };
    setName(c.name);
    setDescription(c.description ?? "");
    setModel(c.model ?? "");
    setPermissionMode(c.permissionMode ?? "");
    setMaxTurns(c.maxTurns ?? 0);
    setTools(c.tools ?? []);
    setDisallowedTools(c.disallowedTools ?? []);
    setSkills(c.skills ?? []);
    setColor(c.color ?? "");
    setVariables(node.variables);
    setPromptBody(node.promptBody);
    setErrors(node.validationErrors);
  }, [node.id, node.config, node.promptBody, node.validationErrors, node.name, node.variables]);

  const resetForm = () => {
    const c = (node.config as AgentConfig | null) ?? { name: node.name };
    setName(c.name);
    setDescription(c.description ?? "");
    setModel(c.model ?? "");
    setPermissionMode(c.permissionMode ?? "");
    setMaxTurns(c.maxTurns ?? 0);
    setTools(c.tools ?? []);
    setDisallowedTools(c.disallowedTools ?? []);
    setSkills(c.skills ?? []);
    setColor(c.color ?? "");
    setVariables(node.variables);
    setPromptBody(node.promptBody);
    setErrors(node.validationErrors);
  };

  const handleSave = () => {
    const updatedConfig: AgentConfig = {
      name,
      ...(description ? { description } : {}),
      ...(model ? { model } : {}),
      ...(permissionMode
        ? { permissionMode: permissionMode as AgentConfig["permissionMode"] }
        : {}),
      ...(maxTurns ? { maxTurns } : {}),
      ...(tools.length ? { tools } : {}),
      ...(disallowedTools.length ? { disallowedTools } : {}),
      ...(skills.length ? { skills } : {}),
      ...(color ? { color } : {}),
      ...(cfg.hooks ? { hooks: cfg.hooks } : {}),
      ...(cfg.allowedCommands?.length ? { allowedCommands: cfg.allowedCommands } : {}),
    };

    updateNode(node.id, {
      name,
      config: updatedConfig,
      promptBody,
      variables: variables.filter((v) => v.name.trim()),
      lastModified: Date.now(),
    });
    saveNode(node.id);
  };

  // Autosave on changes
  useAutosave(
    handleSave,
    [name, description, model, permissionMode, maxTurns, tools, disallowedTools, skills, color, variables, promptBody],
    node.id,
  );

  const handleValidate = () => {
    const errs: string[] = [];
    if (!name.trim()) errs.push("Name is required");
    if (maxTurns < 0) errs.push("Max turns must be non-negative");
    setErrors(errs);
    updateNode(node.id, { validationErrors: errs });
  };

  const hooksJson = cfg.hooks ? JSON.stringify(cfg.hooks, null, 2) : "{}";

  return (
    <div>
      {/* Identity Section */}
      <div style={sectionHeaderStyle}>Identity</div>

      {/* Name */}
      <div style={fieldStyle}>
        <label style={labelStyle}>Name</label>
        <input
          style={inputStyle}
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
      </div>

      {/* Description */}
      <div style={fieldStyle}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
          <label style={{ ...labelStyle, marginBottom: 0 }}>Description</label>
          <button
            onClick={handleGenerate}
            disabled={generating || !name.trim()}
            style={{
              padding: "2px 10px",
              fontSize: 10,
              fontWeight: 600,
              background: generating ? "var(--border-color)" : "var(--accent-purple)",
              color: "white",
              border: "none",
              borderRadius: 10,
              cursor: generating || !name.trim() ? "default" : "pointer",
              opacity: generating || !name.trim() ? 0.5 : 1,
              transition: "opacity 0.15s",
            }}
          >
            {generating ? "Generating..." : "Generate"}
          </button>
        </div>
        <textarea
          rows={3}
          style={{ ...inputStyle, resize: "vertical" }}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
      </div>

      {/* Behavior Section */}
      <div style={sectionHeaderStyle}>Behavior</div>

      {/* Model */}
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

      {/* Permission Mode */}
      <div style={fieldStyle}>
        <label style={labelStyle}>Permission Mode</label>
        <select
          style={inputStyle}
          value={permissionMode}
          onChange={(e) => setPermissionMode(e.target.value)}
        >
          {PERMISSION_OPTIONS.map((p) => (
            <option key={p} value={p}>
              {p || "(default)"}
            </option>
          ))}
        </select>
      </div>

      {/* Max Turns */}
      <div style={fieldStyle}>
        <label style={labelStyle}>Max Turns</label>
        <input
          type="number"
          style={inputStyle}
          value={maxTurns}
          onChange={(e) => setMaxTurns(Number(e.target.value))}
          min={0}
        />
      </div>

      {/* Capabilities Section */}
      <div style={sectionHeaderStyle}>Capabilities</div>

      {/* Tools */}
      <div style={fieldStyle}>
        <label style={labelStyle}>Tools</label>
        <TagInput tags={tools} onChange={setTools} />
      </div>

      {/* Disallowed Tools */}
      <div style={fieldStyle}>
        <label style={labelStyle}>Disallowed Tools</label>
        <TagInput tags={disallowedTools} onChange={setDisallowedTools} />
      </div>

      {/* Skills */}
      <div style={fieldStyle}>
        <label style={labelStyle}>Skills</label>
        <TagInput tags={skills} onChange={setSkills} />
      </div>

      {/* Appearance Section */}
      <div style={sectionHeaderStyle}>Appearance</div>

      {/* Color */}
      <div style={fieldStyle}>
        <label style={labelStyle}>Color</label>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input
            style={{ ...inputStyle, flex: 1 }}
            value={color}
            onChange={(e) => setColor(e.target.value)}
            placeholder="#4a9eff"
          />
          <div
            style={{
              width: 28,
              height: 28,
              borderRadius: 4,
              border: "1px solid #2a2a4a",
              background: color || "#4a9eff",
              flexShrink: 0,
            }}
          />
        </div>
      </div>

      {/* Variables Section */}
      <div style={sectionHeaderStyle}>
        Variables ({variables.filter((v) => v.name.trim()).length})
      </div>

      <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 10, lineHeight: 1.4 }}>
        API keys, passwords, notes, and config values available to this agent.
      </div>

      <VariableEditor variables={variables} onChange={setVariables} />

      {/* Advanced Section - Hooks (collapsible) */}
      <div style={sectionHeaderStyle}>Advanced</div>

      <div style={fieldStyle}>
        <div
          onClick={() => setHooksOpen(!hooksOpen)}
          style={{
            cursor: "pointer",
            fontSize: 12,
            color: "var(--text-secondary)",
            marginBottom: hooksOpen ? 8 : 0,
            userSelect: "none",
          }}
        >
          Hooks {hooksOpen ? "\u25BE" : "\u25B8"}
        </div>
        {hooksOpen && (
          <Editor
            height={100}
            language="json"
            theme="vs-dark"
            value={hooksJson}
            options={{
              readOnly: true,
              minimap: { enabled: false },
              fontSize: 12,
              lineNumbers: "off",
              scrollBeyondLastLine: false,
              renderLineHighlight: "none",
            }}
          />
        )}
      </div>

      {/* Prompt Body */}
      <div style={fieldStyle}>
        <label style={labelStyle}>Prompt Body</label>
        <MarkdownEditor
          value={promptBody}
          onChange={setPromptBody}
          height={400}
        />
      </div>

      {/* Validation Errors */}
      {errors.length > 0 && (
        <div
          style={{
            marginBottom: 16,
            padding: 8,
            background: "rgba(248,81,73,0.1)",
            border: "1px solid rgba(248,81,73,0.3)",
            borderRadius: 4,
          }}
        >
          {errors.map((err, i) => (
            <div key={i} style={{ color: "#f85149", fontSize: 12 }}>
              {err}
            </div>
          ))}
        </div>
      )}

      {/* Action Buttons */}
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <button
          onClick={handleValidate}
          style={{
            flex: 1,
            padding: "8px 16px",
            background: "transparent",
            color: "var(--accent-blue)",
            border: "1px solid var(--accent-blue)",
            borderRadius: 4,
            cursor: "pointer",
            fontSize: 13,
            fontWeight: 600,
          }}
        >
          Validate
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
      </div>
    </div>
  );
}
