import { useState, useEffect } from "react";
import Editor from "@monaco-editor/react";
import { readTextFile, writeTextFile } from "@tauri-apps/plugin-fs";
import { useUiStore } from "@/store/ui-store";

function detectLanguage(filePath: string): string {
  if (filePath.endsWith(".md")) return "markdown";
  if (filePath.endsWith(".json")) return "json";
  if (filePath.endsWith(".yaml") || filePath.endsWith(".yml")) return "yaml";
  if (filePath.endsWith(".toml")) return "toml";
  if (filePath.endsWith(".ts") || filePath.endsWith(".tsx")) return "typescript";
  if (filePath.endsWith(".js") || filePath.endsWith(".jsx")) return "javascript";
  return "plaintext";
}

interface FileViewerProps {
  filePath: string;
  language?: string;
}

export function FileViewer({ filePath, language }: FileViewerProps) {
  const theme = useUiStore((s) => s.theme);
  const [content, setContent] = useState<string | null>(null);
  const [editedContent, setEditedContent] = useState("");
  const [editing, setEditing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setEditing(false);

    readTextFile(filePath)
      .then((text) => {
        if (!cancelled) {
          setContent(text);
          setEditedContent(text);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to read file");
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [filePath]);

  const handleSave = async () => {
    try {
      await writeTextFile(filePath, editedContent);
      setContent(editedContent);
      setEditing(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save file");
    }
  };

  const lang = language ?? detectLanguage(filePath);

  if (loading) {
    return (
      <div style={{ padding: 16, color: "var(--text-secondary)", fontSize: 13 }}>
        Loading...
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ padding: 16, color: "#f44336", fontSize: 13 }}>
        {error}
      </div>
    );
  }

  return (
    <div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 8,
        }}
      >
        <span
          style={{
            fontSize: 11,
            color: "var(--text-secondary)",
            wordBreak: "break-all",
          }}
        >
          {filePath}
        </span>
        <div style={{ display: "flex", gap: 4, flexShrink: 0 }}>
          <button
            onClick={() => {
              if (editing) {
                setEditedContent(content ?? "");
              }
              setEditing(!editing);
            }}
            style={{
              background: "transparent",
              border: "1px solid var(--accent-blue)",
              color: "var(--accent-blue)",
              borderRadius: 4,
              cursor: "pointer",
              padding: "3px 8px",
              fontSize: 11,
            }}
          >
            {editing ? "Cancel" : "Edit"}
          </button>
          {editing && (
            <button
              onClick={handleSave}
              style={{
                background: "var(--accent-blue)",
                border: "none",
                color: "white",
                borderRadius: 4,
                cursor: "pointer",
                padding: "3px 8px",
                fontSize: 11,
              }}
            >
              Save
            </button>
          )}
        </div>
      </div>
      <Editor
        height={300}
        language={lang}
        theme={theme === "light" ? "vs" : "vs-dark"}
        value={editing ? editedContent : (content ?? "")}
        onChange={editing ? (v) => setEditedContent(v ?? "") : undefined}
        options={{
          readOnly: !editing,
          minimap: { enabled: false },
          fontSize: 13,
          lineNumbers: lang === "markdown" ? "off" : "on",
          wordWrap: "on",
          scrollBeyondLastLine: false,
          renderLineHighlight: editing ? "line" : "none",
          padding: { top: 8 },
        }}
      />
    </div>
  );
}
