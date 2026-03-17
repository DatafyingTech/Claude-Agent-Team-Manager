import { useEffect, useSyncExternalStore } from "react";

type ToastType = "success" | "error" | "info";

interface ToastEntry {
  id: number;
  message: string;
  type: ToastType;
  leaving: boolean;
}

// ---- module-level store ----
let nextId = 0;
let toasts: ToastEntry[] = [];
const listeners = new Set<() => void>();

function notify() {
  listeners.forEach((l) => l());
}

function getSnapshot(): ToastEntry[] {
  return toasts;
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function removeToast(id: number) {
  toasts = toasts.filter((t) => t.id !== id);
  notify();
}

function markLeaving(id: number) {
  toasts = toasts.map((t) => (t.id === id ? { ...t, leaving: true } : t));
  notify();
  setTimeout(() => removeToast(id), 300);
}

export function toast(message: string, type: ToastType = "info") {
  const id = nextId++;
  toasts = [{ id, message, type, leaving: false }, ...toasts].slice(0, 5);
  notify();
  setTimeout(() => markLeaving(id), 3000);
}

// ---- colors ----
const borderColors: Record<ToastType, string> = {
  success: "var(--accent-green)",
  error: "#f85149",
  info: "var(--accent-blue)",
};

// ---- components ----
function ToastItem({ entry }: { entry: ToastEntry }) {
  return (
    <div
      style={{
        background: "var(--bg-toast)",
        borderLeft: `4px solid ${borderColors[entry.type]}`,
        border: `1px solid var(--border-color)`,
        borderLeftWidth: 4,
        borderRadius: 6,
        padding: "10px 16px",
        color: "var(--text-primary)",
        fontSize: 13,
        boxShadow: "0 2px 12px var(--shadow-dropdown)",
        animation: entry.leaving
          ? "aui-toast-out 0.3s forwards"
          : "aui-toast-in 0.25s ease-out",
        pointerEvents: "auto" as const,
        maxWidth: 320,
        wordBreak: "break-word" as const,
      }}
    >
      {entry.message}
    </div>
  );
}

export function ToastContainer() {
  const entries = useSyncExternalStore(subscribe, getSnapshot);

  // Inject keyframes once
  useEffect(() => {
    const id = "aui-toast-keyframes";
    if (document.getElementById(id)) return;
    const style = document.createElement("style");
    style.id = id;
    style.textContent = `
      @keyframes aui-toast-in {
        from { opacity: 0; transform: translateX(60px); }
        to   { opacity: 1; transform: translateX(0); }
      }
      @keyframes aui-toast-out {
        from { opacity: 1; transform: translateX(0); }
        to   { opacity: 0; transform: translateX(60px); }
      }
    `;
    document.head.appendChild(style);
  }, []);

  if (entries.length === 0) return null;

  return (
    <div
      style={{
        position: "fixed",
        bottom: 16,
        right: 16,
        display: "flex",
        flexDirection: "column",
        gap: 8,
        zIndex: 10000,
        pointerEvents: "none",
      }}
    >
      {entries.map((entry) => (
        <ToastItem key={entry.id} entry={entry} />
      ))}
    </div>
  );
}
