import Editor from "@monaco-editor/react";
import { useUiStore } from "@/store/ui-store";

interface MarkdownEditorProps {
  value: string;
  onChange?: (value: string) => void;
  readOnly?: boolean;
  height?: string | number;
}

export function MarkdownEditor({
  value,
  onChange,
  readOnly = false,
  height = "300px",
}: MarkdownEditorProps) {
  const theme = useUiStore((s) => s.theme);
  return (
    <Editor
      height={height}
      language="markdown"
      theme={theme === "light" ? "vs" : "vs-dark"}
      value={value}
      onChange={(v) => onChange?.(v ?? "")}
      options={{
        readOnly,
        wordWrap: "on",
        minimap: { enabled: false },
        fontSize: 13,
        lineNumbers: "off",
        scrollBeyondLastLine: false,
        renderLineHighlight: readOnly ? "none" : "line",
        padding: { top: 8 },
      }}
    />
  );
}
