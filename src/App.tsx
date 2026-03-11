import { useEffect, useRef } from "react";
import { homeDir } from "@tauri-apps/api/path";
import { readTextFile, exists } from "@tauri-apps/plugin-fs";
import { ReactFlowProvider } from "@xyflow/react";
import { TreeCanvas } from "./components/tree/TreeCanvas";
import { InspectorPanel } from "./components/inspector/InspectorPanel";
import { ContextHub } from "./components/context-hub/ContextHub";
import { Toolbar } from "./components/common/Toolbar";
import { ValidationBanner } from "./components/common/ValidationBanner";
import { CreateNodeDialog } from "./components/dialogs/CreateNodeDialog";
import { DeleteConfirmDialog } from "./components/dialogs/DeleteConfirmDialog";
// ChatPanel removed — CLI-based chat doesn't work in Tauri's webview
import { SettingsPanel } from "./components/settings/SettingsPanel";
import { SchedulePanel } from "./components/schedule/SchedulePanel";
import { ToastContainer, toast } from "./components/common/Toast";
import { SetupWizard } from "./components/setup/SetupWizard";
import { useTreeStore } from "./store/tree-store";
import { useUiStore } from "./store/ui-store";
import { startWatching } from "./services/file-watcher";

function App() {
  const inspectorOpen = useUiStore((s) => s.inspectorOpen);
  const createDialogOpen = useUiStore((s) => s.createDialogOpen);
  const closeCreateDialog = useUiStore((s) => s.closeCreateDialog);
  const deleteDialogNodeId = useUiStore((s) => s.deleteDialogNodeId);
  const closeDeleteDialog = useUiStore((s) => s.closeDeleteDialog);
  const projectPath = useTreeStore((s) => s.projectPath);
  const loadProject = useTreeStore((s) => s.loadProject);
  const syncFromDisk = useTreeStore((s) => s.syncFromDisk);
  const nodes = useTreeStore((s) => s.nodes);
  const createAgentNode = useTreeStore((s) => s.createAgentNode);
  const createSkillNode = useTreeStore((s) => s.createSkillNode);
  const createGroupNode = useTreeStore((s) => s.createGroupNode);
  const createPipelineNode = useTreeStore((s) => s.createPipelineNode);
  const assignSkillToNode = useTreeStore((s) => s.assignSkillToNode);
  const deleteNodeFromDisk = useTreeStore((s) => s.deleteNodeFromDisk);
  const unwatchRef = useRef<(() => void) | null>(null);

  const deleteNodeName = deleteDialogNodeId
    ? nodes.get(deleteDialogNodeId)?.name ?? ""
    : "";

  const handleCreate = async (kind: "agent" | "skill" | "group" | "pipeline", name: string, description: string, parentId: string | null, skillIds: string[]) => {
    try {
      const resolvedParentId = parentId ?? useUiStore.getState().createDialogParentId ?? undefined;
      if (kind === "agent") await createAgentNode(name, description, resolvedParentId);
      else if (kind === "pipeline") createPipelineNode(name, description, resolvedParentId);
      else if (kind === "group") createGroupNode(name, description, resolvedParentId);
      else await createSkillNode(name, description, resolvedParentId);

      // Assign selected skills to the newly created node
      if (skillIds.length > 0) {
        const store = useTreeStore.getState();
        // Find the node we just created (last node added with matching name)
        for (const [id, node] of store.nodes) {
          if (node.name === name || node.name === name.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')) {
            for (const skillId of skillIds) {
              assignSkillToNode(id, skillId);
            }
            break;
          }
        }
      }

      toast(`Created ${name}`, "success");
      closeCreateDialog();
      useTreeStore.getState().autoGroupByPrefix();
    } catch (err) {
      toast(err instanceof Error ? err.message : "Failed to create", "error");
    }
  };

  const handleDelete = async () => {
    if (!deleteDialogNodeId) return;
    const name = nodes.get(deleteDialogNodeId)?.name ?? "";
    try {
      await deleteNodeFromDisk(deleteDialogNodeId);
      toast(`Deleted ${name}`, "success");
      closeDeleteDialog();
    } catch (err) {
      toast(err instanceof Error ? err.message : "Failed to delete", "error");
    }
  };

  // Global keyboard shortcuts
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      // Don't trigger shortcuts when typing in inputs
      const tag = (e.target as HTMLElement)?.tagName;
      const isInput = tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";

      if (e.ctrlKey && e.key === "n" && !isInput) {
        e.preventDefault();
        useUiStore.getState().openCreateDialog();
      }
      if (e.ctrlKey && e.key === "f") {
        e.preventDefault();
        const searchInput = document.querySelector<HTMLInputElement>(
          'input[placeholder*="Search nodes"]'
        );
        searchInput?.focus();
      }
      // Ctrl+I — toggle inspector
      if (e.ctrlKey && e.key === "i" && !isInput) {
        e.preventDefault();
        useUiStore.getState().toggleInspector();
      }
      // Ctrl+Shift+D — deploy selected team
      if (e.ctrlKey && e.shiftKey && e.key === "D" && !isInput) {
        e.preventDefault();
        const nodeId = useUiStore.getState().selectedNodeId;
        if (nodeId) {
          const node = useTreeStore.getState().nodes.get(nodeId);
          if (node?.kind === "group") {
            // Click the deploy button if it exists
            const deployBtn = document.querySelector<HTMLButtonElement>(
              'button:not([disabled])'
            );
            // Find the deploy button by its text content
            const buttons = document.querySelectorAll("button");
            for (const btn of buttons) {
              if (btn.textContent === "Deploy Team") {
                btn.click();
                break;
              }
            }
          }
        }
      }
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Load project on mount — use saved projectPath if available, else home directory
  useEffect(() => {
    (async () => {
      const home = await homeDir();
      let targetPath = home;

      try {
        const settingsPath = `${home.replace(/[\\/]+$/, "")}/.aui/settings.json`;
        if (await exists(settingsPath)) {
          const raw = await readTextFile(settingsPath);
          const parsed = JSON.parse(raw);
          if (parsed.projectPath && typeof parsed.projectPath === "string") {
            if (await exists(parsed.projectPath)) {
              targetPath = parsed.projectPath;
            }
          }
        }
      } catch {
        // Fall back to home directory
      }

      console.log("[ATM] Loading project from:", targetPath);
      console.log("[ATM] Platform:", navigator.userAgent);
      await loadProject(targetPath);
      useTreeStore.getState().autoGroupByPrefix();
    })();
  }, [loadProject]);

  // Set up file watcher when project path changes
  useEffect(() => {
    if (!projectPath) return;

    let cancelled = false;

    startWatching(projectPath, (changedPaths) => {
      if (!cancelled) {
        syncFromDisk(changedPaths);
      }
    })
      .then((unwatch) => {
        if (cancelled) {
          unwatch();
        } else {
          unwatchRef.current = unwatch;
        }
      })
      .catch(() => {
        // File watching is non-critical — silently ignore errors
      });

    return () => {
      cancelled = true;
      if (unwatchRef.current) {
        unwatchRef.current();
        unwatchRef.current = null;
      }
    };
  }, [projectPath, syncFromDisk]);

  return (
    <div className="app">
      <Toolbar />
      <div className="main-content">
        <div className="tree-panel">
          <ValidationBanner />
          <ReactFlowProvider>
            <TreeCanvas />
          </ReactFlowProvider>
        </div>
        {inspectorOpen && (
          <div className="inspector-panel">
            <InspectorPanel />
          </div>
        )}
      </div>
      <ContextHub />
      <CreateNodeDialog
        open={createDialogOpen}
        onClose={closeCreateDialog}
        onCreate={handleCreate}
      />
      <DeleteConfirmDialog
        open={!!deleteDialogNodeId}
        nodeName={deleteNodeName}
        onClose={closeDeleteDialog}
        onConfirm={handleDelete}
      />
      <SettingsPanel />
      <SchedulePanelWrapper />
      <SetupWizard />
      <ToastContainer />
    </div>
  );
}

function SchedulePanelWrapper() {
  const open = useUiStore((s) => s.scheduleOpen);
  const toggle = useUiStore((s) => s.toggleSchedule);
  if (!open) return null;
  return <SchedulePanel onClose={toggle} />;
}

export default App;
