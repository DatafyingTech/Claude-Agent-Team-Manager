import { create } from "zustand";
import { readTextFile, writeTextFile, exists, mkdir, remove } from "@tauri-apps/plugin-fs";
import type { AuiNode, TreeMetadata, TreeExport, PipelineStep } from "@/types/aui-node";
import { scanProject } from "@/services/file-scanner";
import { parseAgentFile } from "@/services/agent-parser";
import { parseSkillFile } from "@/services/skill-parser";
import { parseSettingsFile } from "@/services/settings-parser";
import { writeNodeFile } from "@/services/file-writer";
import { join, normalizePath, getFileName, generateNodeId, titleCase } from "@/utils/paths";
import { detectTeam } from "@/utils/grouping";
import { isWindows } from "@/utils/platform";
import {
  loadLayoutIndex,
  saveLayoutIndex,
  saveLayout,
  loadLayout,
  deleteLayout as deleteLayoutFile,
} from "@/services/layout-service";
import { getVersion } from "@tauri-apps/api/app";
import { packExportZip, unpackExportZip } from "@/services/zip-service";

interface TreeState {
  nodes: Map<string, AuiNode>;
  skillNameCache: Map<string, string>;
  rootId: string | null;
  projectPath: string | null;
  loading: boolean;
  error: string | null;
  metadata: TreeMetadata | null;
  currentLayoutId: string | null;
  layouts: Array<{ id: string; name: string; lastModified: number }>;
  clipboard: { nodes: AuiNode[]; sourceParentId: string | null } | null;
  appVersion: string;
}

interface TreeActions {
  loadProject(path: string): Promise<void>;
  addNode(node: AuiNode): void;
  updateNode(id: string, updates: Partial<AuiNode>): void;
  removeNode(id: string): void;
  reparentNode(id: string, newParentId: string | null): void;
  saveNode(id: string): Promise<void>;
  syncFromDisk(changedPaths: string[]): Promise<void>;
  saveTreeMetadata(): Promise<void>;
  loadTreeMetadata(projectPath: string): Promise<TreeMetadata | null>;
  createAgentNode(name: string, description: string, parentId?: string): Promise<void>;
  createSkillNode(name: string, description: string, parentId?: string): Promise<void>;
  createGroupNode(name: string, description: string, parentId?: string): void;
  createPipelineNode(name: string, description: string, parentId?: string): void;
  updatePipelineSteps(nodeId: string, steps: PipelineStep[]): void;
  deployPipeline(nodeId: string, options?: { skipLaunch?: boolean }): Promise<void>;
  cacheSkillName(id: string, name: string): void;
  assignSkillToNode(nodeId: string, skillId: string): void;
  removeSkillFromNode(nodeId: string, skillId: string): void;
  removeNodeFromCanvas(id: string): string | null;
  deleteNodeFromDisk(id: string): Promise<void>;
  exportTeamAsSkill(teamId: string): Promise<string>;
  generateTeamSkillFiles(teamId: string): Promise<string[]>;
  saveCompanyPlan(): Promise<string>;
  exportTreeAsJson(): string;
  exportTreeAsZip(): Promise<Uint8Array>;
  importTreeFromJson(json: string): void;
  importTreeFromZip(data: Uint8Array): Promise<void>;
  createStickyNote(text: string, color: string, position: { x: number; y: number }): string;
  updateStickyNote(id: string, updates: { text?: string; color?: string }): void;
  deleteStickyNote(id: string): void;
  autoGroupByPrefix(): void;
  loadLayouts(): Promise<void>;
  saveCurrentAsLayout(name: string): Promise<string>;
  switchLayout(layoutId: string): Promise<void>;
  deleteLayout(layoutId: string): Promise<void>;
  renameLayout(layoutId: string, newName: string): Promise<void>;
  createBlankLayout(name: string): Promise<string>;
  saveNodePosition(nodeId: string, pos: { x: number; y: number }): void;
  saveNodePositions(positions: Record<string, { x: number; y: number }>): void;
  clearNodePosition(nodeId: string): void;
  copyNodes(nodeId: string): void;
  duplicateNodes(nodeId: string): Promise<string | null>;
  pasteNodes(targetParentId: string): Promise<string | null>;
}

type TreeStore = TreeState & TreeActions;

function createRootNode(name: string): AuiNode {
  return {
    id: "root",
    name,
    kind: "human",
    parentId: null,
    team: null,
    sourcePath: "",
    config: null,
    promptBody: "",
    tags: [],
    lastModified: Date.now(),
    validationErrors: [],
    assignedSkills: [],
    variables: [],
    launchPrompt: "",
    pipelineSteps: [],
  };
}

function classifyFile(path: string): "agent" | "skill" | "settings" | "context" | null {
  const p = normalizePath(path);
  // .claude/agents/*.md → agent
  if (p.includes("/.claude/agents/") && p.endsWith(".md")) return "agent";
  // .claude/skills/*/SKILL.md → skill
  if (p.includes("/.claude/skills/") && p.endsWith(".md")) return "skill";
  // .claude/settings*.json → settings
  if (p.includes("/.claude/settings") && p.endsWith(".json")) return "settings";
  // CLAUDE.md, CLAUDE.local.md, .claude/rules/*.md → context
  if (p.endsWith("/CLAUDE.md") || p.endsWith("/CLAUDE.local.md")) return "context";
  if (p.includes("/.claude/rules/") && p.endsWith(".md")) return "context";
  return null;
}

async function parseFile(
  filePath: string,
  kind: "agent" | "skill" | "settings" | "context",
): Promise<AuiNode | null> {
  switch (kind) {
    case "agent":
      return parseAgentFile(filePath);
    case "skill":
      return parseSkillFile(filePath);
    case "settings":
      return parseSettingsFile(filePath);
    case "context": {
      // Context files (CLAUDE.md, rules) are plain markdown — create node directly
      const content = await readTextFile(filePath);
      return {
        id: generateNodeId(filePath),
        name: getFileName(filePath),
        kind: "context",
        parentId: null,
        team: null,
        sourcePath: filePath,
        config: null,
        promptBody: content,
        tags: [],
        lastModified: Date.now(),
        validationErrors: [],
        assignedSkills: [],
        variables: [],
        launchPrompt: "",
        pipelineSteps: [],
      };
    }
  }
}

// ── Node cloning helpers ────────────────────────────

function collectDescendantNodes(nodes: Map<string, AuiNode>, parentId: string): AuiNode[] {
  const result: AuiNode[] = [];
  for (const [, node] of nodes) {
    if (node.parentId === parentId) {
      result.push(node);
      result.push(...collectDescendantNodes(nodes, node.id));
    }
  }
  return result;
}

async function findUniqueFilePath(dir: string, baseName: string, ext: string): Promise<string> {
  let filePath = join(dir, `${baseName}${ext}`);
  if (!(await exists(filePath))) return filePath;
  for (let i = 2; i <= 20; i++) {
    filePath = join(dir, `${baseName}-${i}${ext}`);
    if (!(await exists(filePath))) return filePath;
  }
  return join(dir, `${baseName}-${Date.now().toString(36).slice(-5)}${ext}`);
}

async function cloneNodeTree(
  sourceNodes: AuiNode[],
  rootNodeId: string,
  targetParentId: string | null,
  projectPath: string,
): Promise<{ clonedNodes: Map<string, AuiNode>; newRootId: string } | null> {
  if (sourceNodes.length === 0) return null;

  const idMap = new Map<string, string>();
  const sourcePathMap = new Map<string, string>();

  // First pass: generate new IDs (and write files for file-backed nodes)
  for (const node of sourceNodes) {
    const isCloneRoot = node.id === rootNodeId;
    const newName = isCloneRoot ? `${node.name} (copy)` : node.name;
    const slug = newName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");

    if (node.kind === "agent" && node.sourcePath) {
      const dir = join(projectPath, ".claude", "agents");
      if (!(await exists(dir))) await mkdir(dir, { recursive: true });
      const filePath = await findUniqueFilePath(dir, slug, ".md");
      await writeTextFile(filePath, node.promptBody || `---\nname: ${newName}\ndescription: ""\n---\n`);
      idMap.set(node.id, generateNodeId(filePath));
      sourcePathMap.set(node.id, filePath);
    } else if (node.kind === "skill" && node.sourcePath) {
      const skillDir = join(projectPath, ".claude", "skills", slug);
      if (!(await exists(skillDir))) await mkdir(skillDir, { recursive: true });
      const filePath = join(skillDir, "SKILL.md");
      await writeTextFile(filePath, node.promptBody || `---\nname: ${slug}\ndescription: ""\n---\n`);
      idMap.set(node.id, generateNodeId(filePath));
      sourcePathMap.set(node.id, filePath);
    } else if (node.kind === "context" && node.sourcePath) {
      const parts = normalizePath(node.sourcePath).split("/");
      const fileName = parts.pop() ?? "context.md";
      const dir = parts.join("/");
      const baseName = fileName.replace(/\.md$/, "");
      const copyBaseName = isCloneRoot ? `${baseName}-copy` : baseName;
      if (dir) {
        const filePath = await findUniqueFilePath(dir, copyBaseName, ".md");
        await writeTextFile(filePath, node.promptBody || "");
        idMap.set(node.id, generateNodeId(filePath));
        sourcePathMap.set(node.id, filePath);
      } else {
        idMap.set(node.id, `ctx-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
      }
    } else {
      // Virtual node (group, pipeline, human)
      const prefix = node.kind === "pipeline" ? "pipeline" : "group";
      idMap.set(node.id, `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
    }
  }

  // Second pass: create cloned AuiNode objects with remapped IDs
  const clonedNodes = new Map<string, AuiNode>();
  let newRootId = "";

  for (const node of sourceNodes) {
    const newId = idMap.get(node.id)!;
    const isCloneRoot = node.id === rootNodeId;

    const newParentId = isCloneRoot
      ? targetParentId
      : (idMap.get(node.parentId!) ?? node.parentId);

    const cloned: AuiNode = {
      ...node,
      id: newId,
      name: isCloneRoot ? `${node.name} (copy)` : node.name,
      parentId: newParentId,
      sourcePath: sourcePathMap.get(node.id) ?? "",
      lastModified: Date.now(),
      validationErrors: [],
      pipelineSteps: node.pipelineSteps.map((step) => ({
        ...step,
        id: `step-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        teamId: idMap.get(step.teamId) ?? step.teamId,
      })),
    };

    clonedNodes.set(cloned.id, cloned);
    if (isCloneRoot) newRootId = cloned.id;
  }

  return { clonedNodes, newRootId };
}

export const useTreeStore = create<TreeStore>()((set, get) => ({
  nodes: new Map(),
  skillNameCache: new Map(),
  rootId: null,
  projectPath: null,
  loading: false,
  error: null,
  metadata: null,
  currentLayoutId: null,
  layouts: [],
  clipboard: null,
  appVersion: "",

  async loadProject(path: string) {
    set({ loading: true, error: null });
    try {
      // Ensure .aui directory exists before any read/write operations
      try {
        const auiDir = join(path, ".aui");
        if (!(await exists(auiDir))) {
          await mkdir(auiDir, { recursive: true });
        }
      } catch (dirErr) {
        console.warn("[ATM] Could not create .aui directory:", dirErr);
      }

      const filePaths = await scanProject(path);
      const nodes = new Map<string, AuiNode>();

      // Load metadata first to get owner name and hierarchy
      const metadata = await get().loadTreeMetadata(path);
      const ownerName = metadata?.owner.name ?? "Owner";

      // Create synthetic human root node
      const root = createRootNode(ownerName);
      nodes.set(root.id, root);

      // Parse all discovered files
      for (const filePath of filePaths) {
        const kind = classifyFile(filePath);
        if (!kind) continue;
        // Settings nodes should not appear in the tree — they're managed via the Settings panel
        if (kind === "settings") continue;

        try {
          const node = await parseFile(filePath, kind);
          if (node) {
            // Apply saved hierarchy if available
            if (metadata?.hierarchy[node.id] !== undefined) {
              node.parentId = metadata.hierarchy[node.id];
            } else if (!node.parentId) {
              node.parentId = "root";
            }
            nodes.set(node.id, node);
          }
        } catch (e) {
          console.warn("[ATM] Failed to parse file:", filePath, e);
        }
      }

      // Restore group/pipeline nodes from metadata (they have no files on disk)
      if (metadata?.groups) {
        for (const g of metadata.groups) {
          nodes.set(g.id, {
            id: g.id,
            name: g.name,
            kind: g.kind === "pipeline" ? "pipeline" : "group",
            parentId: g.parentId,
            team: g.team,
            sourcePath: "",
            config: null,
            promptBody: g.description,
            tags: [],
            lastModified: Date.now(),
            validationErrors: [],
            assignedSkills: g.assignedSkills ?? [],
            variables: (g.variables ?? []).map((v: any) => ({ ...v, type: v.type ?? "text" })),
            launchPrompt: g.launchPrompt ?? "",
            pipelineSteps: g.pipelineSteps ?? [],
          });
        }
      }

      // Restore skillNameCache from metadata + rebuild from live skill nodes
      const skillNameCache = new Map<string, string>();
      if (metadata?.skillNameCache) {
        for (const [k, v] of Object.entries(metadata.skillNameCache)) {
          skillNameCache.set(k, v);
        }
      }
      // Always rebuild from live nodes (authoritative source)
      let skillCount = 0;
      for (const [id, node] of nodes) {
        if (node.kind === "skill" && node.name) {
          skillNameCache.set(id, node.name);
          skillCount++;
        }
      }
      console.log(`[ATM] Loaded ${nodes.size} nodes (${skillCount} skills, ${skillNameCache.size} cached names)`);

      const appVersion = await getVersion();

      set({
        nodes,
        skillNameCache,
        rootId: "root",
        projectPath: path,
        metadata,
        loading: false,
        appVersion,
      });

      // Save metadata (non-fatal — don't crash load if this fails)
      try {
        await get().saveTreeMetadata();
      } catch (saveErr) {
        console.warn("[ATM] Failed to save metadata during load (non-fatal):", saveErr);
      }

      // Load saved layouts after the tree is fully loaded (non-fatal)
      try {
        await get().loadLayouts();
      } catch (layoutErr) {
        console.warn("[ATM] Failed to load layouts (non-fatal):", layoutErr);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("[ATM] loadProject failed:", err);
      set({
        error: `Failed to load project: ${msg}`,
        loading: false,
      });
    }
  },

  addNode(node: AuiNode) {
    set((state) => {
      const next = new Map(state.nodes);
      next.set(node.id, node);
      return { nodes: next };
    });
  },

  updateNode(id: string, updates: Partial<AuiNode>) {
    set((state) => {
      const existing = state.nodes.get(id);
      if (!existing) return state;
      const next = new Map(state.nodes);
      next.set(id, { ...existing, ...updates, id });
      return { nodes: next };
    });
  },

  removeNode(id: string) {
    set((state) => {
      const next = new Map(state.nodes);
      next.delete(id);
      return { nodes: next };
    });
  },

  reparentNode(id: string, newParentId: string | null) {
    set((state) => {
      const existing = state.nodes.get(id);
      if (!existing) return state;
      const next = new Map(state.nodes);
      next.set(id, { ...existing, parentId: newParentId });
      return { nodes: next };
    });
    // Persist hierarchy change
    get().saveTreeMetadata();
  },

  async saveNode(id: string) {
    const node = get().nodes.get(id);
    if (!node) return;
    try {
      await writeNodeFile(node);
    } catch (err) {
      set({
        error: err instanceof Error ? err.message : "Failed to save node",
      });
    }
  },

  async syncFromDisk(changedPaths: string[]) {
    const { nodes } = get();
    const next = new Map(nodes);

    for (const filePath of changedPaths) {
      const kind = classifyFile(filePath);
      if (!kind) continue;

      try {
        const node = await parseFile(filePath, kind);
        if (node) {
          // Preserve existing parentId if already in tree
          const existing = next.get(node.id);
          if (existing) {
            node.parentId = existing.parentId;
          }
          next.set(node.id, node);
        }
      } catch {
        // Skip unparseable files
      }
    }

    set({ nodes: next });
  },

  async saveTreeMetadata() {
    const { projectPath, nodes, metadata } = get();
    if (!projectPath) return;

    const hierarchy: Record<string, string | null> = {};
    const positions = metadata?.positions ?? {};

    // Collect group/pipeline nodes for persistence (they have no files on disk)
    const groups: TreeMetadata["groups"] = [];

    for (const [id, node] of nodes) {
      if (id === "root") continue;
      hierarchy[id] = node.parentId;

      if (node.kind === "group" || node.kind === "pipeline") {
        groups.push({
          id: node.id,
          name: node.name,
          description: node.promptBody,
          parentId: node.parentId,
          team: node.team,
          assignedSkills: node.assignedSkills,
          variables: node.variables,
          launchPrompt: node.launchPrompt,
          kind: node.kind === "pipeline" ? "pipeline" : "group",
          pipelineSteps: node.pipelineSteps.length > 0 ? node.pipelineSteps : undefined,
        });
      }
    }

    // Serialize skillNameCache
    const snc: Record<string, string> = {};
    for (const [k, v] of get().skillNameCache) {
      snc[k] = v;
    }

    const updated: TreeMetadata = {
      owner: metadata?.owner ?? { name: "Owner", description: "" },
      hierarchy,
      positions,
      groups: groups.length > 0 ? groups : undefined,
      lastModified: Date.now(),
      skillNameCache: Object.keys(snc).length > 0 ? snc : undefined,
    };

    try {
      const auiDir = join(projectPath, ".aui");
      if (!(await exists(auiDir))) {
        await mkdir(auiDir, { recursive: true });
      }
      const metaPath = join(projectPath, ".aui", "tree.json");
      await writeTextFile(metaPath, JSON.stringify(updated, null, 2));
      set({ metadata: updated });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error("[ATM] saveTreeMetadata failed:", err);
      set({ error: `Failed to save tree metadata: ${msg}` });
    }
  },

  async loadTreeMetadata(
    projectPath: string,
  ): Promise<TreeMetadata | null> {
    try {
      const metaPath = join(projectPath, ".aui", "tree.json");
      if (!(await exists(metaPath))) return null;
      const raw = await readTextFile(metaPath);
      return JSON.parse(raw) as TreeMetadata;
    } catch {
      return null;
    }
  },

  async createAgentNode(name: string, description: string, parentId?: string) {
    const { projectPath } = get();
    if (!projectPath) return;

    const agentsDir = join(projectPath, ".claude", "agents");
    if (!(await exists(agentsDir))) {
      await mkdir(agentsDir, { recursive: true });
    }

    const filePath = join(agentsDir, `${name}.md`);
    const displayName = titleCase(name);
    const content = `---\nname: ${displayName}\ndescription: ${description}\n---\n\n# ${displayName}\n\n${description}\n`;

    await writeTextFile(filePath, content);

    const resolvedParent = parentId ?? "root";
    const id = generateNodeId(filePath);
    const node: AuiNode = {
      id,
      name: displayName,
      kind: "agent",
      parentId: resolvedParent,
      team: null,
      sourcePath: filePath,
      config: null,
      promptBody: content,
      tags: [],
      lastModified: Date.now(),
      validationErrors: [],
      assignedSkills: [],
      variables: [],
      launchPrompt: "",
      pipelineSteps: [],
    };

    // Atomic: add node + position near parent in one state update
    set((state) => {
      const next = new Map(state.nodes);
      next.set(id, node);

      const parentPos = state.metadata?.positions?.[resolvedParent];
      if (parentPos && state.metadata) {
        const siblingCount = Array.from(next.values()).filter(
          (n) => n.parentId === resolvedParent && n.id !== id,
        ).length;
        const pos = { x: parentPos.x + (siblingCount % 3) * 300, y: parentPos.y + 160 };
        return { nodes: next, metadata: { ...state.metadata, positions: { ...state.metadata.positions, [id]: pos } } };
      }

      return { nodes: next };
    });
  },

  async createSkillNode(name: string, description: string, parentId?: string) {
    const { projectPath } = get();
    if (!projectPath) return;

    const skillDir = join(projectPath, ".claude", "skills", name);
    if (!(await exists(skillDir))) {
      await mkdir(skillDir, { recursive: true });
    }

    const filePath = join(skillDir, "SKILL.md");
    const displayName = titleCase(name);
    const content = `---\nname: ${name}\ndescription: ${description}\n---\n\n# ${displayName}\n\n## Steps\n\n1. Define steps here\n\n## Notes\n- ${description}\n`;

    await writeTextFile(filePath, content);

    const resolvedParent = parentId ?? "root";
    const id = generateNodeId(filePath);
    const node: AuiNode = {
      id,
      name: displayName,
      kind: "skill",
      parentId: resolvedParent,
      team: null,
      sourcePath: filePath,
      config: null,
      promptBody: content,
      tags: [],
      lastModified: Date.now(),
      validationErrors: [],
      assignedSkills: [],
      variables: [],
      launchPrompt: "",
      pipelineSteps: [],
    };

    // Atomic: add node + position near parent in one state update
    set((state) => {
      const next = new Map(state.nodes);
      next.set(id, node);

      const parentPos = state.metadata?.positions?.[resolvedParent];
      if (parentPos && state.metadata) {
        const siblingCount = Array.from(next.values()).filter(
          (n) => n.parentId === resolvedParent && n.id !== id,
        ).length;
        const pos = { x: parentPos.x + (siblingCount % 3) * 300, y: parentPos.y + 160 };
        return { nodes: next, metadata: { ...state.metadata, positions: { ...state.metadata.positions, [id]: pos } } };
      }

      return { nodes: next };
    });
  },

  createGroupNode(name: string, description: string, parentId?: string) {
    const id = `group-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const resolvedParent = parentId ?? "root";
    const node: AuiNode = {
      id,
      name,
      kind: "group",
      parentId: resolvedParent,
      team: null,
      sourcePath: "",
      config: null,
      promptBody: description,
      tags: [],
      lastModified: Date.now(),
      validationErrors: [],
      assignedSkills: [],
      variables: [],
      launchPrompt: "",
      pipelineSteps: [],
    };

    // Atomic: add node + position near parent in one state update
    set((state) => {
      const next = new Map(state.nodes);
      next.set(id, node);

      const parentPos = state.metadata?.positions?.[resolvedParent];
      if (parentPos && state.metadata) {
        const siblingCount = Array.from(next.values()).filter(
          (n) => n.parentId === resolvedParent && n.id !== id,
        ).length;
        const pos = { x: parentPos.x + (siblingCount % 3) * 300, y: parentPos.y + 160 };
        return { nodes: next, metadata: { ...state.metadata, positions: { ...state.metadata.positions, [id]: pos } } };
      }

      return { nodes: next };
    });

    get().saveTreeMetadata();
  },

  createPipelineNode(name: string, description: string, parentId?: string) {
    const id = `pipeline-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const resolvedParent = parentId ?? "root";
    const node: AuiNode = {
      id,
      name,
      kind: "pipeline",
      parentId: resolvedParent,
      team: null,
      sourcePath: "",
      config: null,
      promptBody: description,
      tags: [],
      lastModified: Date.now(),
      validationErrors: [],
      assignedSkills: [],
      variables: [],
      launchPrompt: "",
      pipelineSteps: [],
    };

    // Atomic: add node + position near parent in one state update
    set((state) => {
      const next = new Map(state.nodes);
      next.set(id, node);

      const parentPos = state.metadata?.positions?.[resolvedParent];
      if (parentPos && state.metadata) {
        const siblingCount = Array.from(next.values()).filter(
          (n) => n.parentId === resolvedParent && n.id !== id,
        ).length;
        const pos = { x: parentPos.x + (siblingCount % 3) * 300, y: parentPos.y + 160 };
        return { nodes: next, metadata: { ...state.metadata, positions: { ...state.metadata.positions, [id]: pos } } };
      }

      return { nodes: next };
    });

    get().saveTreeMetadata();
  },

  updatePipelineSteps(nodeId: string, steps: PipelineStep[]) {
    set((state) => {
      const existing = state.nodes.get(nodeId);
      if (!existing || existing.kind !== "pipeline") return state;
      const next = new Map(state.nodes);
      next.set(nodeId, { ...existing, pipelineSteps: steps, lastModified: Date.now() });
      return { nodes: next };
    });
    get().saveTreeMetadata();
  },

  async deployPipeline(nodeId: string, options?: { skipLaunch?: boolean }) {
    const { nodes, projectPath } = get();
    if (!projectPath) return;

    const pipeline = nodes.get(nodeId);
    if (!pipeline || pipeline.kind !== "pipeline") return;
    if (pipeline.pipelineSteps.length === 0) return;

    const slug = pipeline.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
    const pipelineDir = join(projectPath, ".aui", `pipeline-${slug}`);

    if (!(await exists(pipelineDir))) {
      await mkdir(pipelineDir, { recursive: true });
    }

    // Resolve skill name helper
    const { skillNameCache } = get();
    const resolveSkillName = (sid: string): string | null => {
      const n = nodes.get(sid);
      if (n?.name) return n.name;
      const cached = skillNameCache.get(sid);
      if (cached) return cached;
      return null;
    };

    // Helper: read skill file from disk
    const readSkillFile = async (skillSlug: string): Promise<string> => {
      try {
        const path = join(projectPath, ".claude", "skills", skillSlug, "SKILL.md");
        if (await exists(path)) return await readTextFile(path);
      } catch { /* ignore */ }
      return "";
    };

    // Build step metadata for cross-referencing
    const stepMetas: { teamName: string; teamSlug: string; objective: string }[] = [];
    for (const step of pipeline.pipelineSteps) {
      const teamNode = nodes.get(step.teamId);
      const tName = teamNode?.name ?? "Unknown Team";
      const tSlug = tName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
      stepMetas.push({
        teamName: tName,
        teamSlug: tSlug,
        objective: step.prompt || "Complete the tasks assigned to this team.",
      });
    }

    // Generate primer for each step
    const primerPaths: string[] = [];
    const stepTeamNames: string[] = [];
    const outputPaths: string[] = [];

    for (let i = 0; i < pipeline.pipelineSteps.length; i++) {
      const step = pipeline.pipelineSteps[i];
      const teamNode = nodes.get(step.teamId);
      if (!teamNode) continue;

      const teamSlug = teamNode.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
      stepTeamNames.push(teamNode.name);

      const outputPath = join(pipelineDir, `step-${i + 1}-output.md`);
      outputPaths.push(outputPath);

      // Get root context
      const rootNode = nodes.get("root");
      const rootName = rootNode?.name ?? "Unknown";
      const rootDesc = rootNode?.promptBody ?? "";
      const globalSkillNames = (rootNode?.assignedSkills ?? [])
        .map((sid) => resolveSkillName(sid))
        .filter((n): n is string => n !== null);
      // Also include pipeline-level skills
      const pipelineSkillNames = (pipeline.assignedSkills ?? [])
        .map((sid: string) => resolveSkillName(sid))
        .filter((n: string | null): n is string => n !== null);
      globalSkillNames.push(...pipelineSkillNames);
      const globalVars = (rootNode?.variables ?? []).filter((v: any) => v.name?.trim());
      const pipelineVars = pipeline.variables.filter((v) => v.name.trim());

      // Sibling teams
      const siblingTeams: string[] = [];
      for (const n of nodes.values()) {
        if (n.kind === "group" && n.parentId === "root" && n.id !== teamNode.id) {
          siblingTeams.push(n.name);
        }
      }

      // Children of the team
      const children: AuiNode[] = [];
      for (const n of nodes.values()) {
        if (n.parentId === teamNode.id) children.push(n);
      }

      // Read manager skill
      const managerSkillContent = await readSkillFile(`${teamSlug}-manager`);

      // Build agent blocks
      const agentBlocks: string[] = [];
      for (const agent of children) {
        const agentSlug = agent.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
        const skillContent = await readSkillFile(`${teamSlug}-${agentSlug}`);
        let block = `\n### Agent: ${agent.name} (slug: "${agentSlug}")\n`;
        if (agent.promptBody) block += `Role: ${agent.promptBody}\n`;
        if (agent.variables.length > 0) {
          block += `Variables:\n${agent.variables.map((v) => `  - [${v.type ?? "text"}] ${v.name}: ${v.value || "(not set)"}`).join("\n")}\n`;
        }
        if (skillContent) {
          block += `\n<skill-file name="${teamSlug}-${agentSlug}">\n${skillContent}\n</skill-file>\n`;
        }
        agentBlocks.push(block);
      }

      // Team skills
      const teamSkillBlocks: string[] = [];
      for (const sid of teamNode.assignedSkills) {
        const sName = resolveSkillName(sid);
        if (sName) teamSkillBlocks.push(`- /${sName}`);
      }

      const objective = step.prompt || "Complete the tasks assigned to this team.";

      // Build previous/next step context
      let prevStepsSection = "";
      if (i > 0) {
        const prevLines = stepMetas.slice(0, i).map((s, idx) =>
          `  ${idx + 1}. **${s.teamName}** — ${s.objective}`
        );
        const prevOutputPath = outputPaths[i - 1];
        prevStepsSection = `
## Previous Steps (completed before you)
${prevLines.join("\n")}

**IMPORTANT:** The previous step wrote a handoff summary. Read it now:
\`${prevOutputPath}\`
Use the Read tool to read this file and incorporate any relevant context, decisions, or outputs from the previous team into your work.
`;
      }

      let nextStepsSection = "";
      if (i < stepMetas.length - 1) {
        const nextLines = stepMetas.slice(i + 1).map((s, idx) =>
          `  ${i + 2 + idx}. **${s.teamName}** — ${s.objective}`
        );
        nextStepsSection = `
## Next Steps (will run after you)
${nextLines.join("\n")}
`;
      }

      const primer = `You are being deployed as the senior team manager for "${teamNode.name}".
This is step ${i + 1} of ${pipeline.pipelineSteps.length} in pipeline "${pipeline.name}".

## Company / Organization Context
- **Owner:** ${rootName}
${rootDesc ? `- **Description:** ${rootDesc}` : ""}
${globalSkillNames.length > 0 ? `- **Global Skills (MUST load and use via Skill tool):** ${globalSkillNames.map(s => `/${s}`).join(", ")}` : ""}
${siblingTeams.length > 0 ? `- **Other Teams:** ${siblingTeams.join(", ")}` : ""}
${globalVars.length > 0 ? `\n### Global Variables\n${globalVars.map((v: any) => `- [${v.type ?? "text"}] ${v.name}: ${v.value || "(not set)"}`).join("\n")}` : ""}
${pipelineVars.length > 0 ? `\n### Pipeline Variables\n${pipelineVars.map((v) => `- [${v.type ?? "text"}] ${v.name}: ${v.value || "(not set)"}`).join("\n")}` : ""}
${prevStepsSection}
## Team: ${teamNode.name}
${teamNode.promptBody || "(no description)"}
${teamSkillBlocks.length > 0 ? `\n### Team Skills\nYou MUST load and actively use each of these skills by invoking them with the Skill tool:\n${teamSkillBlocks.join("\n")}` : ""}
${teamNode.variables.length > 0 ? `\n### Team Variables\n${teamNode.variables.map((v) => `- [${v.type ?? "text"}] ${v.name}: ${v.value || "(not set)"}`).join("\n")}` : ""}

## Your Manager Skill File
${managerSkillContent ? `<skill-file name="${teamSlug}-manager">\n${managerSkillContent}\n</skill-file>` : "(no manager skill file found)"}

## Team Roster (${children.length} agents)
${agentBlocks.join("\n")}

## OBJECTIVE
${objective}
${nextStepsSection}
## DEPLOYMENT INSTRUCTIONS
You MUST follow these steps exactly:

1. **Create the team** — Use \`TeamCreate\` with team name \`${teamSlug}\`
2. **Spawn each agent** — For each agent listed above, use the \`Task\` tool with:
   - \`team_name: "${teamSlug}"\`
   - \`subagent_type: "general-purpose"\`
   - \`name: "<agent-slug>"\` (slugs listed above per agent)
   - Include their FULL skill file content in the prompt
3. **Create and assign tasks** — Use \`TaskCreate\` to break the objective into tasks, then \`TaskUpdate\` with \`owner\` to assign
4. **Coordinate** — Monitor progress via \`TaskList\`, resolve conflicts
5. **Write handoff summary** — When all tasks are done, use the Write tool to write a summary of what was accomplished, key decisions, and any outputs to:
   \`${outputPath}\`
   This file will be read by the next team in the pipeline. Include: what was done, key files created/modified, important decisions, and anything the next team needs to know.
6. **Shut down** — After writing the handoff, shut down the team
${teamSkillBlocks.length > 0 || globalSkillNames.length > 0 ? `\n## SKILLS — MANDATORY\nYou MUST invoke each skill listed above using the \`Skill\` tool before beginning work. These skills contain critical context, tools, and instructions that are required for this deployment. Do NOT skip loading any skill.` : ""}
IMPORTANT: Each agent already has their full skill file content above. Pass it directly in their spawn prompt.
`;

      const primerPath = join(pipelineDir, `step-${i + 1}-primer.md`);
      await writeTextFile(primerPath, primer);
      primerPaths.push(primerPath);
    }

    // Write initial status.json
    const statusPath = join(pipelineDir, "status.json");
    const statusInit = {
      pipeline: pipeline.name,
      totalSteps: primerPaths.length,
      startedAt: new Date().toISOString(),
      steps: stepTeamNames.map((name, i) => ({
        step: i + 1,
        team: name,
        status: "pending",
        startedAt: null as string | null,
        completedAt: null as string | null,
      })),
    };
    await writeTextFile(statusPath, JSON.stringify(statusInit, null, 2));

    // Generate deploy script
    const statusWinPath = statusPath.replace(/\//g, "\\");

    if (isWindows) {
      const esc = (s: string) => s.replace(/"/g, '`"');
      const lines: string[] = [
        `Remove-Item Env:CLAUDECODE -ErrorAction SilentlyContinue`,
        `$ErrorActionPreference = 'Continue'`,
        `$startTime = Get-Date`,
        ``,
        `Write-Host ""`,
        `Write-Host "================================================================" -ForegroundColor Cyan`,
        `Write-Host "  PIPELINE: ${esc(pipeline.name)}" -ForegroundColor Cyan`,
        `Write-Host "  Steps: ${primerPaths.length} | Started: $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Yellow`,
        `Write-Host "================================================================" -ForegroundColor Cyan`,
        `Write-Host ""`,
        ``,
        `$failed = $false`,
      ];

      for (let i = 0; i < primerPaths.length; i++) {
        const winPath = primerPaths[i].replace(/\//g, "\\").replace(/'/g, "''");
        const tName = stepTeamNames[i]?.replace(/"/g, '`"') ?? "Team";
        lines.push(``);
        lines.push(`# --- Step ${i + 1} ---`);
        lines.push(`if (-not $failed) {`);
        lines.push(`  $stepStart = Get-Date`);
        lines.push(`  Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] Step ${i + 1}/${primerPaths.length}: ${tName}" -ForegroundColor Green`);
        lines.push(`  Write-Host "  Starting Claude Code session..." -ForegroundColor DarkGray`);
        lines.push(`  `);
        // Update status.json to "running"
        lines.push(`  $status = Get-Content '${statusWinPath.replace(/'/g, "''")}' | ConvertFrom-Json`);
        lines.push(`  $status.steps[${i}].status = 'running'`);
        lines.push(`  $status.steps[${i}].startedAt = (Get-Date -Format o)`);
        lines.push(`  $status | ConvertTo-Json -Depth 5 | Set-Content '${statusWinPath.replace(/'/g, "''")}' -Encoding UTF8`);
        lines.push(`  `);
        lines.push(`  claude --dangerously-skip-permissions "Read the deployment primer at '${winPath}' using the Read tool and follow ALL instructions in it exactly. Start immediately."`);
        lines.push(`  $exitCode = $LASTEXITCODE`);
        lines.push(`  $elapsed = (Get-Date) - $stepStart`);
        lines.push(`  `);
        // Update status.json to completed/failed
        lines.push(`  $status = Get-Content '${statusWinPath.replace(/'/g, "''")}' | ConvertFrom-Json`);
        lines.push(`  if ($exitCode -ne 0) {`);
        lines.push(`    $status.steps[${i}].status = 'failed'`);
        lines.push(`    Write-Host "  FAILED (exit code $exitCode) after $($elapsed.ToString('hh\\:mm\\:ss'))" -ForegroundColor Red`);
        lines.push(`    $failed = $true`);
        lines.push(`  } else {`);
        lines.push(`    $status.steps[${i}].status = 'completed'`);
        lines.push(`    Write-Host "  Completed in $($elapsed.ToString('hh\\:mm\\:ss'))" -ForegroundColor Green`);
        lines.push(`  }`);
        lines.push(`  $status.steps[${i}].completedAt = (Get-Date -Format o)`);
        lines.push(`  $status | ConvertTo-Json -Depth 5 | Set-Content '${statusWinPath.replace(/'/g, "''")}' -Encoding UTF8`);
        lines.push(`  Write-Host ""`);
        lines.push(`}`);
      }

      lines.push(``);
      lines.push(`$totalElapsed = (Get-Date) - $startTime`);
      lines.push(`Write-Host "================================================================" -ForegroundColor Cyan`);
      lines.push(`if ($failed) {`);
      lines.push(`  Write-Host "  PIPELINE FAILED -- check output above" -ForegroundColor Red`);
      lines.push(`} else {`);
      lines.push(`  Write-Host "  PIPELINE COMPLETE" -ForegroundColor Green`);
      lines.push(`}`);
      lines.push(`Write-Host "  Total time: $($totalElapsed.ToString('hh\\:mm\\:ss'))" -ForegroundColor Yellow`);
      lines.push(`Write-Host "================================================================" -ForegroundColor Cyan`);
      lines.push(`Write-Host ""`);
      lines.push(`Read-Host "Press Enter to close"`);

      const scriptPath = join(pipelineDir, "deploy.ps1");
      await writeTextFile(scriptPath, "\uFEFF" + lines.join("\r\n"));
      const winScriptPath = scriptPath.replace(/\//g, "\\");
      if (!options?.skipLaunch) {
        const { invoke } = await import("@tauri-apps/api/core");
        await invoke("open_terminal", { scriptPath: winScriptPath });
      }
    } else {
      const esc = (s: string) => s.replace(/'/g, "'\\''");
      const lines: string[] = [
        "#!/bin/bash",
        "unset CLAUDECODE",
        `START_TIME=$(date +%s)`,
        ``,
        `echo ''`,
        `echo '================================================================'`,
        `echo '  PIPELINE: ${esc(pipeline.name)}'`,
        `echo "  Steps: ${primerPaths.length} | Started: $(date +%H:%M:%S)"`,
        `echo '================================================================'`,
        `echo ''`,
        ``,
        `FAILED=0`,
      ];

      for (let i = 0; i < primerPaths.length; i++) {
        const path = primerPaths[i].replace(/'/g, "'\\''");
        const tName = stepTeamNames[i]?.replace(/'/g, "'\\''") ?? "Team";
        lines.push(``);
        lines.push(`# --- Step ${i + 1} ---`);
        lines.push(`if [ $FAILED -eq 0 ]; then`);
        lines.push(`  STEP_START=$(date +%s)`);
        lines.push(`  echo "[$(date +%H:%M:%S)] Step ${i + 1}/${primerPaths.length}: ${tName}"`);
        lines.push(`  echo "  Starting Claude Code session..."`);
        lines.push(`  claude --dangerously-skip-permissions "Read the deployment primer at '${path}' using the Read tool and follow ALL instructions in it exactly. Start immediately."`);
        lines.push(`  EXIT_CODE=$?`);
        lines.push(`  STEP_ELAPSED=$(( $(date +%s) - STEP_START ))`);
        lines.push(`  if [ $EXIT_CODE -ne 0 ]; then`);
        lines.push(`    echo "  FAILED (exit code $EXIT_CODE) after ${`$((STEP_ELAPSED/60))`}m ${`$((STEP_ELAPSED%60))`}s"`);
        lines.push(`    FAILED=1`);
        lines.push(`  else`);
        lines.push(`    echo "  Completed in ${`$((STEP_ELAPSED/60))`}m ${`$((STEP_ELAPSED%60))`}s"`);
        lines.push(`  fi`);
        lines.push(`  echo ''`);
        lines.push(`fi`);
      }

      lines.push(``);
      lines.push(`TOTAL_ELAPSED=$(( $(date +%s) - START_TIME ))`);
      lines.push(`echo '================================================================'`);
      lines.push(`if [ $FAILED -ne 0 ]; then`);
      lines.push(`  echo '  PIPELINE FAILED -- check output above'`);
      lines.push(`else`);
      lines.push(`  echo '  PIPELINE COMPLETE'`);
      lines.push(`fi`);
      lines.push(`echo "  Total time: $((TOTAL_ELAPSED/60))m $((TOTAL_ELAPSED%60))s"`);
      lines.push(`echo '================================================================'`);
      lines.push(`echo ''`);
      lines.push(`read -p 'Press Enter to close'`);

      const scriptPath = join(pipelineDir, "deploy.sh");
      await writeTextFile(scriptPath, lines.join("\n"));
      const { Command } = await import("@tauri-apps/plugin-shell");
      const chmod = Command.create("bash", ["-c", `chmod +x '${scriptPath}'`]);
      await chmod.execute();
      if (!options?.skipLaunch) {
        const { invoke } = await import("@tauri-apps/api/core");
        await invoke("open_terminal", { scriptPath });
      }
    }
  },

  cacheSkillName(id: string, name: string) {
    set((state) => {
      const next = new Map(state.skillNameCache);
      next.set(id, name);
      return { skillNameCache: next };
    });
  },

  assignSkillToNode(nodeId: string, skillId: string) {
    set((state) => {
      const existing = state.nodes.get(nodeId);
      if (!existing) return state;
      if (existing.assignedSkills.includes(skillId)) return state;
      const next = new Map(state.nodes);
      next.set(nodeId, {
        ...existing,
        assignedSkills: [...existing.assignedSkills, skillId],
      });
      return { nodes: next };
    });
    get().saveTreeMetadata();
  },

  removeSkillFromNode(nodeId: string, skillId: string) {
    set((state) => {
      const existing = state.nodes.get(nodeId);
      if (!existing) return state;
      const next = new Map(state.nodes);
      next.set(nodeId, {
        ...existing,
        assignedSkills: existing.assignedSkills.filter((s) => s !== skillId),
      });
      return { nodes: next };
    });
    get().saveTreeMetadata();
  },

  removeNodeFromCanvas(id: string): string | null {
    const { nodes } = get();
    const node = nodes.get(id);
    if (!node || id === "root") return null;

    const name = node.name;
    const parentId = node.parentId ?? "root";

    set((state) => {
      const next = new Map(state.nodes);

      if (node.kind === "group" || node.kind === "pipeline") {
        // For group/pipeline nodes, recursively remove all descendants too
        function collectDescendants(pid: string): string[] {
          const ids: string[] = [];
          for (const [cid, cnode] of next) {
            if (cnode.parentId === pid) {
              ids.push(cid);
              ids.push(...collectDescendants(cid));
            }
          }
          return ids;
        }
        for (const descId of collectDescendants(id)) {
          next.delete(descId);
        }
      } else {
        // For non-group nodes, reparent children to the removed node's parent
        for (const [childId, childNode] of next) {
          if (childNode.parentId === id) {
            next.set(childId, { ...childNode, parentId });
          }
        }
      }

      next.delete(id);
      return { nodes: next };
    });

    // Clean up saved positions for removed nodes
    const { metadata } = get();
    if (metadata?.positions) {
      const positions = { ...metadata.positions };
      delete positions[id];
      if (node.kind === "group" || node.kind === "pipeline") {
        // Also clean descendant positions
        for (const key of Object.keys(positions)) {
          if (!get().nodes.has(key)) delete positions[key];
        }
      }
      set({ metadata: { ...metadata, positions } });
    }

    // Persist updated hierarchy
    get().saveTreeMetadata();
    return name;
  },

  async deleteNodeFromDisk(id: string) {
    const { nodes } = get();
    const node = nodes.get(id);
    if (!node) return;

    // Recursively collect all descendant IDs (children, grandchildren, etc.)
    function collectDescendants(parentId: string): string[] {
      const ids: string[] = [];
      for (const [childId, childNode] of nodes) {
        if (childNode.parentId === parentId) {
          ids.push(childId);
          ids.push(...collectDescendants(childId));
        }
      }
      return ids;
    }

    const allIds = [id, ...collectDescendants(id)];

    // Delete files from disk for all nodes being removed
    for (const nodeId of allIds) {
      const n = nodes.get(nodeId);
      if (!n?.sourcePath) continue;

      try {
        await remove(n.sourcePath);

        // For skills, also remove the parent directory
        if (n.kind === "skill") {
          const parts = normalizePath(n.sourcePath).split("/");
          parts.pop(); // remove filename
          const parentDir = parts.join("/");
          try {
            await remove(parentDir, { recursive: true });
          } catch {
            // Silently ignore — directory may not be empty or already removed
          }
        }
      } catch {
        // Silently ignore — file may already be removed
      }
    }

    set((state) => {
      const next = new Map(state.nodes);
      for (const nodeId of allIds) {
        next.delete(nodeId);
      }
      return { nodes: next };
    });

    // Clean up saved positions for deleted nodes
    const { metadata } = get();
    if (metadata?.positions) {
      const positions = { ...metadata.positions };
      for (const nodeId of allIds) {
        delete positions[nodeId];
      }
      set({ metadata: { ...metadata, positions } });
    }

    // Persist updated metadata after removing nodes
    get().saveTreeMetadata();
  },

  async exportTeamAsSkill(teamId: string) {
    const { nodes, projectPath } = get();
    if (!projectPath) throw new Error("No project loaded");

    const team = nodes.get(teamId);
    if (!team || team.kind !== "group") throw new Error("Not a team node");

    const slugName = team.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");

    // Collect direct agents (children) of this team
    const agents: AuiNode[] = [];
    for (const n of nodes.values()) {
      if (n.parentId === teamId) agents.push(n);
    }

    // Collect root node for global context
    const rootNode = nodes.get("root");

    // Resolve a skill ID to its display name (nodes map → skillNameCache → null)
    const { skillNameCache } = get();
    const resolveSkillName = (sid: string): string | null => {
      const n = nodes.get(sid);
      if (n?.name) return n.name;
      const cached = skillNameCache.get(sid);
      if (cached) return cached;
      return null;
    };

    // Collect global skills from root
    const globalSkillNames = (rootNode?.assignedSkills ?? [])
      .map((sid) => resolveSkillName(sid))
      .filter((n): n is string => n !== null);

    // Collect team-level skills
    const teamSkillNames = team.assignedSkills
      .map((sid) => resolveSkillName(sid))
      .filter((n): n is string => n !== null);

    // Collect all sibling teams for company context
    const siblingTeams: AuiNode[] = [];
    for (const n of nodes.values()) {
      if (n.kind === "group" && n.parentId === "root" && n.id !== teamId) {
        siblingTeams.push(n);
      }
    }

    // Helper: get full skill content by name
    function getSkillContent(skillId: string): string {
      const skillNode = nodes.get(skillId);
      if (skillNode?.promptBody) {
        // Extract meaningful content (strip frontmatter markers)
        return skillNode.promptBody.replace(/^---[\s\S]*?---\s*/, "").trim();
      }
      return "";
    }

    // Build detailed agent profile
    function buildAgentProfile(agent: AuiNode): string {
      let block = `### ${agent.name}\n\n`;

      if (agent.promptBody) {
        block += `**Role:** ${agent.promptBody}\n\n`;
      }

      // Agent config details
      const cfg = agent.config as Record<string, unknown> | null;
      if (cfg) {
        if (cfg.model) block += `**Model:** \`${cfg.model}\`\n`;
        if (cfg.permissionMode) block += `**Permission Mode:** \`${cfg.permissionMode}\`\n`;
        if (cfg.maxTurns) block += `**Max Turns:** ${cfg.maxTurns}\n`;
        if (Array.isArray(cfg.tools) && cfg.tools.length > 0) {
          block += `**Tools:** ${(cfg.tools as string[]).map((t) => `\`${t}\``).join(", ")}\n`;
        }
        if (Array.isArray(cfg.disallowedTools) && cfg.disallowedTools.length > 0) {
          block += `**Disallowed Tools:** ${(cfg.disallowedTools as string[]).map((t) => `\`${t}\``).join(", ")}\n`;
        }
      }

      // Agent skills
      const skillNames = agent.assignedSkills
        .map((sid) => resolveSkillName(sid))
        .filter((n): n is string => n !== null);
      if (skillNames.length > 0) {
        block += `\n**Skills:**\n`;
        for (const sName of skillNames) {
          block += `- \`/${sName}\`\n`;
        }
      }

      // Agent variables
      if (agent.variables.length > 0) {
        block += `\n**Environment Variables:**\n`;
        for (const v of agent.variables) {
          block += `- [${v.type ?? "text"}] \`${v.name}\`: ${v.value ? `\`${v.value}\`` : "(to be provided)"}\n`;
        }
      }

      // Sub-agents
      const subAgents: AuiNode[] = [];
      for (const n of nodes.values()) {
        if (n.parentId === agent.id) subAgents.push(n);
      }
      if (subAgents.length > 0) {
        block += `\n**Sub-agents:**\n`;
        for (const sub of subAgents) {
          block += `- **${sub.name}**`;
          if (sub.promptBody) block += ` — ${sub.promptBody}`;
          block += "\n";
        }
      }

      block += "\n";
      return block;
    }

    // ── Build the comprehensive skill file ──
    let content = `---\nname: ${slugName}\ndescription: "${team.name} — deployable team skill generated by AUI"\n---\n\n`;
    content += `# ${team.name}\n\n`;
    if (team.promptBody) content += `> ${team.promptBody}\n\n`;

    // Slash command activation
    content += `## Activation\n\n`;
    content += `Invoke this team with \`/${slugName}\` or by saying "deploy the ${team.name}".\n\n`;

    // Company context
    content += `## Company Context\n\n`;
    content += `**Organization:** ${rootNode?.name ?? "Unknown"}\n`;
    if (rootNode?.promptBody) content += `**Description:** ${rootNode.promptBody}\n`;
    content += `**This Team:** ${team.name} (${agents.length} agents)\n`;
    if (siblingTeams.length > 0) {
      content += `**Other Teams:** ${siblingTeams.map((t) => t.name).join(", ")}\n`;
    }
    content += "\n";

    // Global skills
    if (globalSkillNames.length > 0) {
      content += `## Global Skills (MANDATORY — All Agents MUST Load)\n\n`;
      content += `These skills are assigned at the organization level. Every agent MUST load and use each skill by invoking it with the \`Skill\` tool:\n\n`;
      for (const sName of globalSkillNames) {
        content += `- \`/${sName}\` — **MUST invoke** using \`Skill\` tool\n`;
      }
      content += "\n";
    }

    // Team-level skills
    if (teamSkillNames.length > 0) {
      content += `## Team Skills (MANDATORY — All Agents MUST Load)\n\n`;
      content += `All agents on this team MUST load and use these skills by invoking them with the \`Skill\` tool:\n\n`;
      for (const sName of teamSkillNames) {
        content += `- \`/${sName}\`\n`;
        // Include skill content inline
        const sid = team.assignedSkills.find((id) => {
          const n = nodes.get(id);
          return n?.name === sName;
        });
        if (sid) {
          const skillContent = getSkillContent(sid);
          if (skillContent && skillContent.length < 500) {
            content += `  > ${skillContent.split("\n").join("\n  > ")}\n`;
          }
        }
      }
      content += "\n";
    }

    // Team variables
    if (team.variables.length > 0) {
      content += `## Team Variables\n\n`;
      content += `These environment variables are available to the team:\n\n`;
      content += `| Type | Variable | Value |\n|------|----------|-------|\n`;
      for (const v of team.variables) {
        content += `| ${v.type ?? "text"} | \`${v.name}\` | ${v.value ? `\`${v.value}\`` : "*(to be provided)*"} |\n`;
      }
      content += "\n";
    }

    // Detailed team roster
    content += `## Team Roster (${agents.length} agents)\n\n`;
    for (const agent of agents) {
      content += buildAgentProfile(agent);
    }

    // Inter-agent coordination rules
    content += `## Coordination Rules\n\n`;
    content += `1. **Team Lead:** The deploying Claude instance acts as the team manager ("${team.name}" lead)\n`;
    content += `2. **Communication:** Agents communicate through the team lead via SendMessage. Direct peer messaging is allowed for tightly-coupled tasks\n`;
    content += `3. **Task Assignment:** The team lead creates tasks (TaskCreate) and assigns them to agents by name\n`;
    content += `4. **Skill Invocation:** Agents MUST invoke their assigned skills using the \`Skill\` tool at the start of their work. Skills contain critical context and instructions — do NOT skip any skill\n`;
    content += `5. **Conflict Resolution:** If agents produce conflicting outputs, the team lead resolves by evaluating against the launch prompt goals\n`;
    content += `6. **File Ownership:** Each agent should work on distinct files to avoid merge conflicts. If overlap is unavoidable, coordinate via the team lead\n\n`;

    // Launch prompt / deployment instructions
    content += `## Deployment Instructions\n\n`;
    content += `**IMPORTANT: This skill MUST be run using Claude Code's agent team mode.**\n\n`;
    content += `When this skill is activated:\n\n`;
    content += `1. **Create the team** — Use \`TeamCreate\` with team name \`${slugName}\`\n`;
    content += `2. **Spawn agents** — Use the \`Task\` tool to spawn each agent as a teammate:\n`;
    for (const agent of agents) {
      const agentSlug = agent.name.toLowerCase().replace(/[^a-z0-9]+/g, "-");
      const skillNames = agent.assignedSkills
        .map((sid) => resolveSkillName(sid))
        .filter((n): n is string => n !== null);
      content += `   - **${agent.name}** (\`name: "${agentSlug}"\`, \`subagent_type: "general-purpose"\`)`;
      if (agent.promptBody) content += `\n     Role: ${agent.promptBody}`;
      if (skillNames.length > 0) content += `\n     Skills: ${skillNames.join(", ")}`;
      if (agent.variables.length > 0) content += `\n     Variables: ${agent.variables.map((v) => `[${v.type ?? "text"}] ${v.name}=${v.value || "..."}`).join(", ")}`;
      content += "\n";
    }
    content += `3. **Create tasks** — Break the user's request into discrete tasks using \`TaskCreate\` and assign to agents using \`TaskUpdate\` with the \`owner\` parameter\n`;
    content += `4. **Set dependencies** — Use \`TaskUpdate\` with \`addBlockedBy\` to establish task ordering where needed\n`;
    content += `5. **Monitor progress** — Check \`TaskList\` periodically. When agents send messages, they are delivered automatically\n`;
    content += `6. **Coordinate** — The team lead oversees all agents, resolves conflicts, and ensures deliverables integrate correctly\n`;
    content += `7. **Report** — When all tasks complete, compile a summary of what was accomplished and present to the user\n`;
    content += `8. **Shutdown** — Send \`shutdown_request\` to each agent, then call \`TeamDelete\` to clean up\n\n`;

    // Launch prompt
    if (team.launchPrompt) {
      content += `## Default Launch Prompt\n\n`;
      content += `When deploying this team, use the following as the initial task:\n\n`;
      content += `> ${team.launchPrompt.split("\n").join("\n> ")}\n\n`;
    }

    // Success criteria
    content += `## Success Criteria\n\n`;
    content += `The team deployment is considered successful when:\n\n`;
    content += `- All assigned tasks are marked as completed\n`;
    content += `- No unresolved errors or blockers remain\n`;
    content += `- The team lead has verified the integrated output\n`;
    content += `- A summary report has been delivered to the user\n`;

    // Write to disk
    const skillDir = join(projectPath, ".claude", "skills", slugName);
    if (!(await exists(skillDir))) {
      await mkdir(skillDir, { recursive: true });
    }
    const filePath = join(skillDir, "SKILL.md");
    await writeTextFile(filePath, content);

    // Add to tree
    const id = generateNodeId(filePath);
    const skillNode: AuiNode = {
      id,
      name: team.name,
      kind: "skill",
      parentId: "root",
      team: null,
      sourcePath: filePath,
      config: null,
      promptBody: content,
      tags: ["team-skill"],
      lastModified: Date.now(),
      validationErrors: [],
      assignedSkills: [],
      variables: [],
      launchPrompt: "",
      pipelineSteps: [],
    };

    set((state) => {
      const next = new Map(state.nodes);
      next.set(id, skillNode);
      return { nodes: next };
    });

    return filePath;
  },

  async generateTeamSkillFiles(teamId: string) {
    const { nodes, projectPath, skillNameCache } = get();
    if (!projectPath) throw new Error("No project loaded");

    const team = nodes.get(teamId);
    if (!team || team.kind !== "group") throw new Error("Not a team node");

    const teamSlug = team.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
    const rootNode = nodes.get("root");

    // Resolve a skill ID to its display name (nodes map → skillNameCache → null)
    const resolveSkillName = (sid: string): string | null => {
      const n = nodes.get(sid);
      if (n?.name) return n.name;
      const cached = skillNameCache.get(sid);
      if (cached) return cached;
      return null;
    };

    // Collect direct agents (children) of this team
    const agents: AuiNode[] = [];
    for (const n of nodes.values()) {
      if (n.parentId === teamId) agents.push(n);
    }

    // Team-level skills
    const teamSkillNames = team.assignedSkills
      .map((sid) => resolveSkillName(sid))
      .filter((n): n is string => n !== null);

    const generatedPaths: string[] = [];

    // 1) Generate skill file for the TEAM NODE (senior manager) — only if missing
    const managerDir = join(projectPath, ".claude", "skills", `${teamSlug}-manager`);
    const managerPath = join(managerDir, "SKILL.md");

    if (await exists(managerPath)) {
      generatedPaths.push(managerPath);
    } else {
    if (!(await exists(managerDir))) await mkdir(managerDir, { recursive: true });

    // Build a rich, context-aware manager skill file
    const teamDesc = team.promptBody || "";
    const agentNames = agents.map((a) => a.name).join(", ");
    const descSuffix = teamDesc ? ` ${teamDesc.replace(/"/g, "'")}` : "";

    let managerContent = `---\nname: ${teamSlug}-manager\n`;
    managerContent += `description: "Senior manager for the ${team.name} team (${agents.length} agents).${descSuffix} Orchestrate task delegation, quality review, and cross-agent coordination to deliver cohesive results. Use this skill when leading or coordinating the ${team.name} team on any objective."\n`;
    managerContent += `---\n\n`;

    managerContent += `This skill guides senior management of the ${team.name} team — a group of ${agents.length} specialist agents`;
    if (teamDesc) managerContent += ` focused on ${teamDesc.endsWith(".") ? teamDesc.slice(0, -1) : teamDesc.toLowerCase()}`;
    managerContent += `. Your role is to transform high-level objectives into coordinated, parallel workstreams that produce high-quality results efficiently.\n\n`;

    managerContent += `The user provides a goal, project brief, or set of requirements. You break it down, delegate to the right specialists, monitor quality, and synthesize the final output.\n\n`;

    managerContent += `## Coordination Strategy\n\n`;
    managerContent += `Before delegating, understand the full scope of the objective and design a plan:\n`;
    managerContent += `- **Decompose**: Break the objective into discrete, well-scoped tasks with clear acceptance criteria. Each task should be completable by a single agent without ambiguity.\n`;
    managerContent += `- **Parallelize**: Identify which tasks can run concurrently and which have dependencies. Maximize parallel execution — ${agents.length} agents sitting idle is wasted capacity.\n`;
    managerContent += `- **Match**: Assign tasks to the agent whose expertise best fits. Never assign work outside an agent's domain when a better-suited teammate exists.\n`;
    managerContent += `- **Sequence**: Order dependent tasks so blockers are resolved early. Front-load research and discovery tasks before implementation tasks.\n\n`;

    managerContent += `**CRITICAL**: Write task descriptions that are specific enough for an agent to execute without follow-up questions. Include context, constraints, expected output format, and definition of done. Vague tasks produce vague results.\n\n`;

    if (agents.length > 0) {
      managerContent += `## Your Team\n\n`;
      managerContent += `You manage ${agents.length} specialist agents. Know their strengths and assign accordingly:\n\n`;
      for (const agent of agents) {
        const agentCfg = agent.config as Record<string, unknown> | null;
        const model = agentCfg?.model ? ` (${agentCfg.model})` : "";
        const agentSkills = agent.assignedSkills
          .map((sid) => resolveSkillName(sid))
          .filter((n): n is string => n !== null);
        const skillNote = agentSkills.length > 0 ? ` | Skills: ${agentSkills.map((s) => `\`/${s}\``).join(", ")}` : "";
        managerContent += `- **${agent.name}**${model}: ${agent.promptBody || "Team member"}${skillNote}\n`;
      }
      managerContent += "\n";
    }

    if (teamSkillNames.length > 0) {
      managerContent += `## Team Skills\n\n`;
      managerContent += `These skills are available to the team and can be invoked as slash commands:\n\n`;
      managerContent += `${teamSkillNames.map((s) => `- \`/${s}\``).join("\n")}\n\n`;
    }

    if (team.variables.length > 0) {
      managerContent += `## Team Configuration\n\n`;
      for (const v of team.variables) {
        managerContent += `- [${v.type ?? "text"}] **${v.name}**: ${v.value || "(to be provided at runtime)"}\n`;
      }
      managerContent += "\n";
    }

    managerContent += `## Quality Standards\n\n`;
    managerContent += `Every deliverable from your team must meet these criteria before you consider a task complete:\n\n`;
    managerContent += `- **Correctness**: The output actually solves the stated problem. Verify, don't assume.\n`;
    managerContent += `- **Completeness**: Nothing is left half-done or marked "TODO". If a task has acceptance criteria, all criteria are met.\n`;
    managerContent += `- **Consistency**: Work from different agents fits together cohesively — naming conventions, style, tone, and approach are aligned.\n`;
    managerContent += `- **Quality**: The output reflects professional standards. No sloppy shortcuts, no placeholder content in final deliverables.\n\n`;
    managerContent += `When reviewing agent work, check for these qualities. Send work back with specific, actionable feedback if it falls short. "This isn't good enough" is not feedback — "The error handling in function X doesn't cover the timeout case" is.\n\n`;

    managerContent += `## Escalation & Conflict Resolution\n\n`;
    managerContent += `- **Blocked agents**: If an agent reports they're stuck, diagnose whether it's a missing dependency (reassign/create a new task), unclear requirements (clarify directly), or a genuine technical obstacle (escalate to the user).\n`;
    managerContent += `- **Conflicting approaches**: When two agents produce incompatible work, decide which approach better serves the objective. Don't compromise into a worse hybrid — pick the stronger direction and have the other agent align.\n`;
    managerContent += `- **Scope creep**: If you discover the objective is larger than initially understood, pause and communicate this to the user before expanding the workload. Don't silently balloon the project.\n`;
    managerContent += `- **User escalation**: Escalate to the user when you need requirements clarification, when trade-offs require a product decision, or when something is fundamentally blocked.\n\n`;

    managerContent += `## Communication Protocol\n\n`;
    managerContent += `- Use \`TaskCreate\` to define tasks with detailed descriptions and clear acceptance criteria.\n`;
    managerContent += `- Use \`TaskUpdate\` with \`owner\` to assign tasks to agents by name: ${agentNames || "your team members"}.\n`;
    managerContent += `- Use \`SendMessage\` to provide context, answer questions, give feedback, or redirect agents. Be specific and concise.\n`;
    managerContent += `- Use \`TaskList\` regularly to track progress and identify stalled work early.\n`;
    managerContent += `- **Do NOT micromanage**: Once a task is clearly defined and assigned, let the agent execute. Intervene only on quality issues or blockers.\n`;
    managerContent += `- **Do NOT go silent**: When all agents are working, proactively monitor and prepare the synthesis/integration phase.\n\n`;

    managerContent += `## Completion & Reporting\n\n`;
    managerContent += `When all tasks are complete and quality-checked:\n\n`;
    managerContent += `1. Verify that the combined output cohesively addresses the original objective.\n`;
    managerContent += `2. Compile a concise summary: what was accomplished, key decisions made, any caveats or follow-up items.\n`;
    managerContent += `3. Present the final result to the user with confidence — you've already verified quality, so stand behind your team's work.\n`;

    await writeTextFile(managerPath, managerContent);
    generatedPaths.push(managerPath);
    } // end if !exists managerPath

    // 2) Generate skill file for EACH AGENT — only if missing
    for (const agent of agents) {
      const agentSlug = agent.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
      const agentDir = join(projectPath, ".claude", "skills", `${teamSlug}-${agentSlug}`);
      const agentPath = join(agentDir, "SKILL.md");

      if (await exists(agentPath)) {
        generatedPaths.push(agentPath);
        continue;
      }

      if (!(await exists(agentDir))) await mkdir(agentDir, { recursive: true });

      // Build rich context from agent data
      const cfg = agent.config as Record<string, unknown> | null;
      const agentDescSafe = agent.promptBody ? ` ${agent.promptBody.replace(/"/g, "'")}` : "";
      const agentSkillNames = agent.assignedSkills
        .map((sid) => resolveSkillName(sid))
        .filter((n): n is string => n !== null);

      // Collect teammates (other agents on the same team)
      const teammates = agents.filter((a) => a.id !== agent.id);

      // Collect sub-agents
      const subAgents: AuiNode[] = [];
      for (const n of nodes.values()) {
        if (n.parentId === agent.id) subAgents.push(n);
      }

      // --- Frontmatter ---
      let agentContent = `---\nname: ${teamSlug}-${agentSlug}\n`;
      agentContent += `description: "${agent.name} — specialist agent on the ${team.name} team.${agentDescSafe} Handles assigned tasks with domain expertise, delivers quality results, and coordinates with teammates. Use this skill when operating as ${agent.name} within the ${team.name} team."\n`;
      agentContent += `---\n\n`;

      // --- Overview ---
      agentContent += `This skill defines the role of ${agent.name} on the ${team.name} team`;
      if (agent.promptBody) {
        agentContent += ` — ${agent.promptBody.endsWith(".") ? agent.promptBody.slice(0, -1) : agent.promptBody}`;
      }
      agentContent += `. You receive tasks from the team's senior manager, execute them with care and expertise, and deliver results that meet professional standards.\n\n`;

      agentContent += `The senior manager assigns you tasks via the task system. Each task includes context, requirements, and acceptance criteria. Your job is to deliver complete, high-quality work — not to ask clarifying questions about things you can figure out yourself.\n\n`;

      // --- Role & Domain Guidelines ---
      agentContent += `## Role & Domain Guidelines\n\n`;
      if (agent.promptBody) {
        agentContent += `Your core focus: ${agent.promptBody}\n\n`;
        agentContent += `When working in this domain:\n`;
        agentContent += `- **Own your expertise**: You were chosen for this role because of your specialization. Make confident decisions within your domain rather than deferring everything upward.\n`;
        agentContent += `- **Think holistically**: Don't just complete the literal task — consider how your work fits into the broader team objective. Flag integration issues early.\n`;
        agentContent += `- **Be thorough**: Cover edge cases, validate assumptions, and test your work before reporting completion. A "done" task that needs rework costs more than taking extra time upfront.\n`;
      } else {
        agentContent += `You are a versatile team member. Approach each task methodically:\n`;
        agentContent += `- **Understand before acting**: Read the full task description and think about the approach before diving in.\n`;
        agentContent += `- **Deliver complete work**: Partial results or placeholder content are not acceptable as final deliverables.\n`;
        agentContent += `- **Communicate clearly**: When reporting results, be specific about what you did and any decisions you made.\n`;
      }
      agentContent += "\n";

      // --- Skills & Tools ---
      if (agentSkillNames.length > 0 || (cfg && (cfg.tools || cfg.allowedCommands))) {
        agentContent += `## Skills & Tools\n\n`;
        if (agentSkillNames.length > 0) {
          agentContent += `**Assigned skills** (invoke as slash commands):\n\n`;
          agentContent += `${agentSkillNames.map((s) => `- \`/${s}\``).join("\n")}\n\n`;
          agentContent += `Use these skills proactively when they apply to your task. They represent capabilities specifically chosen for your role.\n\n`;
        }
        if (cfg) {
          const toolItems: string[] = [];
          if (Array.isArray(cfg.tools) && cfg.tools.length > 0) {
            toolItems.push(`**Allowed tools**: ${(cfg.tools as string[]).map((t) => `\`${t}\``).join(", ")}`);
          }
          if (Array.isArray(cfg.allowedCommands) && cfg.allowedCommands.length > 0) {
            toolItems.push(`**Allowed commands**: ${(cfg.allowedCommands as string[]).map((c) => `\`${c}\``).join(", ")}`);
          }
          if (cfg.model) {
            toolItems.push(`**Model**: \`${cfg.model}\``);
          }
          if (toolItems.length > 0) {
            agentContent += `${toolItems.join("\n")}\n\n`;
          }
        }
      }

      // --- Agent variables ---
      if (agent.variables.length > 0) {
        agentContent += `## Configuration\n\n`;
        agentContent += `These variables define your operating parameters:\n\n`;
        for (const v of agent.variables) {
          agentContent += `- [${v.type ?? "text"}] **${v.name}**: ${v.value || "(to be provided at runtime)"}\n`;
        }
        agentContent += "\n";
      }

      // --- Sub-agents ---
      if (subAgents.length > 0) {
        agentContent += `## Sub-agents\n\n`;
        agentContent += `You can delegate work to these sub-agents when appropriate:\n\n`;
        for (const sub of subAgents) {
          agentContent += `- **${sub.name}**`;
          if (sub.promptBody) agentContent += `: ${sub.promptBody}`;
          agentContent += "\n";
        }
        agentContent += "\n";
      }

      // --- Collaboration ---
      if (teammates.length > 0) {
        agentContent += `## Collaboration\n\n`;
        agentContent += `You work alongside ${teammates.length} teammate${teammates.length > 1 ? "s" : ""} on the ${team.name} team:\n\n`;
        for (const tm of teammates) {
          agentContent += `- **${tm.name}**: ${tm.promptBody || "Team member"}\n`;
        }
        agentContent += "\n";
        agentContent += `When your work intersects with a teammate's domain, coordinate through the senior manager or send a direct message via \`SendMessage\`. Don't duplicate effort — if someone else is better suited for a subtask, flag it rather than doing it poorly yourself.\n\n`;
      }

      // --- Deliverables & Quality ---
      agentContent += `## Deliverables & Quality\n\n`;
      agentContent += `Every task you complete should meet these standards:\n\n`;
      agentContent += `- **Complete**: All acceptance criteria from the task description are satisfied. Nothing is left as "TODO" or "placeholder".\n`;
      agentContent += `- **Correct**: Your output actually solves the problem. Test and verify before marking done.\n`;
      agentContent += `- **Clean**: Professional quality — well-structured, properly formatted, no rough edges.\n`;
      agentContent += `- **Contextual**: Your work fits the broader team objective, not just the isolated task.\n\n`;
      agentContent += `If you realize mid-task that the requirements are ambiguous or the scope is larger than expected, message the senior manager immediately rather than guessing or delivering partial work.\n\n`;

      // --- Work Protocol ---
      agentContent += `## Work Protocol\n\n`;
      agentContent += `1. Check \`TaskList\` for tasks assigned to you.\n`;
      agentContent += `2. Read the full task description carefully. Understand the context, constraints, and definition of done before starting.\n`;
      agentContent += `3. Mark the task \`in_progress\` using \`TaskUpdate\`.\n`;
      agentContent += `4. Execute the task thoroughly. Verify your own work against the acceptance criteria.\n`;
      agentContent += `5. Mark the task \`completed\` and send a concise summary to the senior manager via \`SendMessage\` — what you did, key decisions made, anything the team should know.\n`;
      agentContent += `6. Check \`TaskList\` for the next available task. Don't wait to be told — pick up work proactively.\n\n`;
      agentContent += `**IMPORTANT**: If you get stuck or blocked, report it immediately via \`SendMessage\` to the senior manager. Sitting idle without communicating wastes everyone's time. Explain what's blocking you and what you've already tried.\n`;

      await writeTextFile(agentPath, agentContent);
      generatedPaths.push(agentPath);
    }

    return generatedPaths;
  },

  async saveCompanyPlan() {
    const { nodes, projectPath, skillNameCache } = get();
    if (!projectPath) throw new Error("No project loaded");

    // Resolve a skill ID to its display name (nodes map → skillNameCache → null)
    const resolveSkillName = (sid: string): string | null => {
      const n = nodes.get(sid);
      if (n?.name) return n.name;
      const cached = skillNameCache.get(sid);
      if (cached) return cached;
      return null;
    };

    const planDir = join(projectPath, ".aui", "company-plan");
    if (!(await exists(planDir))) {
      await mkdir(planDir, { recursive: true });
    }

    // Collect top-level teams (groups whose parent is root)
    const teams: AuiNode[] = [];
    const standaloneAgents: AuiNode[] = [];
    const standaloneSkills: AuiNode[] = [];
    const pipelines: AuiNode[] = [];

    for (const [id, node] of nodes) {
      if (id === "root") continue;
      if (node.parentId === "root" || !node.parentId) {
        if (node.kind === "group") teams.push(node);
        else if (node.kind === "pipeline") pipelines.push(node);
        else if (node.kind === "agent") standaloneAgents.push(node);
        else if (node.kind === "skill") standaloneSkills.push(node);
      }
    }

    // Helper to collect descendants
    function getChildren(parentId: string): AuiNode[] {
      const children: AuiNode[] = [];
      for (const n of nodes.values()) {
        if (n.parentId === parentId) children.push(n);
      }
      return children;
    }

    // Build README.md — overview document
    let readme = `# Company Plan\n\n`;
    readme += `> Generated by AUI on ${new Date().toISOString().split("T")[0]}\n\n`;
    readme += `## Overview\n\n`;
    readme += `- **Teams:** ${teams.length}\n`;
    readme += `- **Standalone Agents:** ${standaloneAgents.length}\n`;
    readme += `- **Skills:** ${standaloneSkills.length}\n\n`;

    if (teams.length > 0) {
      readme += `## Teams\n\n`;
      for (const team of teams) {
        const agents = getChildren(team.id);
        readme += `### ${team.name}\n\n`;
        if (team.promptBody) readme += `${team.promptBody}\n\n`;
        readme += `- **Agents:** ${agents.length}\n`;
        const teamSkills = team.assignedSkills
          .map((sid) => resolveSkillName(sid))
          .filter((n): n is string => n !== null);
        if (teamSkills.length > 0) {
          readme += `- **Team Skills:** ${teamSkills.join(", ")}\n`;
        }
        readme += "\n";

        if (agents.length > 0) {
          readme += `| Agent | Role | Skills |\n|-------|------|--------|\n`;
          for (const agent of agents) {
            const skills = agent.assignedSkills
              .map((sid) => resolveSkillName(sid))
              .filter((n): n is string => n !== null);
            readme += `| ${agent.name} | ${agent.promptBody || "—"} | ${skills.join(", ") || "—"} |\n`;
          }
          readme += "\n";
        }
      }
    }

    if (standaloneAgents.length > 0) {
      readme += `## Standalone Agents\n\n`;
      for (const agent of standaloneAgents) {
        readme += `- **${agent.name}**`;
        if (agent.promptBody) readme += ` — ${agent.promptBody}`;
        readme += "\n";
      }
      readme += "\n";
    }

    if (standaloneSkills.length > 0) {
      readme += `## Skills Library\n\n`;
      for (const skill of standaloneSkills) {
        readme += `- **${skill.name}**`;
        if (skill.promptBody) {
          const firstLine = skill.promptBody.split("\n").find(
            (l) => l.trim() && !l.startsWith("#") && !l.startsWith("---"),
          );
          if (firstLine) readme += ` — ${firstLine.trim().slice(0, 100)}`;
        }
        readme += "\n";
      }
      readme += "\n";
    }

    await writeTextFile(join(planDir, "README.md"), readme);

    // Write individual team files
    for (const team of teams) {
      const agents = getChildren(team.id);
      const teamSkills = team.assignedSkills
        .map((sid) => resolveSkillName(sid))
        .filter((n): n is string => n !== null);
      const slug = team.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");

      let teamMd = `# ${team.name}\n\n`;
      if (team.promptBody) teamMd += `${team.promptBody}\n\n`;
      if (teamSkills.length > 0) {
        teamMd += `## Team Skills\n\n${teamSkills.map((s) => `- ${s}`).join("\n")}\n\n`;
      }
      teamMd += `## Agents\n\n`;
      for (const agent of agents) {
        const skills = agent.assignedSkills
          .map((sid) => resolveSkillName(sid))
          .filter((n): n is string => n !== null);
        teamMd += `### ${agent.name}\n\n`;
        if (agent.promptBody) teamMd += `${agent.promptBody}\n\n`;
        if (skills.length > 0) {
          teamMd += `**Skills:** ${skills.join(", ")}\n\n`;
        }

        // Sub-agents
        const subAgents = getChildren(agent.id);
        if (subAgents.length > 0) {
          teamMd += `**Sub-agents:**\n\n`;
          for (const sub of subAgents) {
            teamMd += `- ${sub.name}`;
            if (sub.promptBody) teamMd += ` — ${sub.promptBody}`;
            teamMd += "\n";
          }
          teamMd += "\n";
        }
      }

      await writeTextFile(join(planDir, `${slug}.md`), teamMd);
    }

    return planDir;
  },

  exportTreeAsJson(): string {
    const { nodes, metadata, skillNameCache } = get();

    const hierarchy: Record<string, string | null> = {};
    const groups: TreeExport["groups"] = [];
    const nodeArray: AuiNode[] = [];

    for (const [id, node] of nodes) {
      if (id === "root") continue;
      if (node.kind === "note") {
        // Notes are free-floating, include in nodeArray but not hierarchy
        nodeArray.push(node);
        continue;
      }
      hierarchy[id] = node.parentId;
      nodeArray.push(node);

      if (node.kind === "group" || node.kind === "pipeline") {
        groups.push({
          id: node.id,
          name: node.name,
          description: node.promptBody,
          parentId: node.parentId,
          team: node.team,
          assignedSkills: node.assignedSkills,
          variables: node.variables,
          launchPrompt: node.launchPrompt,
          kind: node.kind === "pipeline" ? "pipeline" : "group",
          pipelineSteps: node.pipelineSteps.length > 0 ? node.pipelineSteps : undefined,
        });
      }
    }

    const snc: Record<string, string> = {};
    for (const [k, v] of skillNameCache) {
      snc[k] = v;
    }

    const exportData: TreeExport = {
      version: "1.0",
      exportedAt: Date.now(),
      appVersion: get().appVersion || "0.7.1",
      owner: metadata?.owner ?? { name: "Unknown", description: "" },
      nodes: nodeArray,
      hierarchy,
      positions: metadata?.positions ?? {},
      groups,
      skillNameCache: snc,
    };

    return JSON.stringify(exportData, null, 2);
  },

  async exportTreeAsZip(): Promise<Uint8Array> {
    const json = get().exportTreeAsJson();
    const { nodes, projectPath } = get();
    const skillFiles = new Map<string, string>();

    if (projectPath) {
      for (const [, node] of nodes) {
        if (node.kind === "skill" && node.sourcePath) {
          try {
            const content = await readTextFile(node.sourcePath);
            // Extract skill folder name from path: .../skills/{name}/SKILL.md
            const parts = normalizePath(node.sourcePath).split("/");
            const skillsIdx = parts.lastIndexOf("skills");
            if (skillsIdx >= 0 && skillsIdx < parts.length - 1) {
              const relativePath = parts.slice(skillsIdx + 1).join("/");
              skillFiles.set(relativePath, content);
            }
          } catch {
            console.warn(`[ATM] Could not read skill file: ${node.sourcePath}`);
          }
        }
      }

      // Also collect skills assigned to groups
      for (const [, node] of nodes) {
        if ((node.kind === "group" || node.kind === "pipeline") && node.assignedSkills.length > 0) {
          for (const skillId of node.assignedSkills) {
            const skillNode = nodes.get(skillId);
            if (skillNode?.kind === "skill" && skillNode.sourcePath && !skillFiles.has(skillNode.sourcePath)) {
              try {
                const content = await readTextFile(skillNode.sourcePath);
                const parts = normalizePath(skillNode.sourcePath).split("/");
                const skillsIdx = parts.lastIndexOf("skills");
                if (skillsIdx >= 0 && skillsIdx < parts.length - 1) {
                  const relativePath = parts.slice(skillsIdx + 1).join("/");
                  skillFiles.set(relativePath, content);
                }
              } catch {
                console.warn(`[ATM] Could not read assigned skill file: ${skillNode.sourcePath}`);
              }
            }
          }
        }
      }
    }

    return packExportZip(json, skillFiles);
  },

  importTreeFromJson(json: string) {
    const data = JSON.parse(json) as TreeExport;
    if (data.version !== "1.0") {
      set({ error: `Unsupported export version: ${data.version}` });
      return;
    }

    const nodes = new Map<string, AuiNode>();

    // Recreate root node with imported owner
    const root = createRootNode(data.owner.name);
    nodes.set("root", root);

    // Restore all exported nodes
    for (const node of data.nodes) {
      nodes.set(node.id, node);
    }

    // Restore group/pipeline nodes from the groups array (in case they weren't in nodes)
    for (const g of data.groups) {
      if (!nodes.has(g.id)) {
        nodes.set(g.id, {
          id: g.id,
          name: g.name,
          kind: g.kind === "pipeline" ? "pipeline" : "group",
          parentId: g.parentId,
          team: g.team,
          sourcePath: "",
          config: null,
          promptBody: g.description,
          tags: [],
          lastModified: Date.now(),
          validationErrors: [],
          assignedSkills: g.assignedSkills ?? [],
          variables: g.variables ?? [],
          launchPrompt: g.launchPrompt ?? "",
          pipelineSteps: g.pipelineSteps ?? [],
        });
      }
    }

    // Restore skill name cache
    const skillNameCache = new Map<string, string>();
    for (const [k, v] of Object.entries(data.skillNameCache)) {
      skillNameCache.set(k, v);
    }

    // Build metadata from imported data
    const metadata: TreeMetadata = {
      owner: data.owner,
      hierarchy: data.hierarchy,
      positions: data.positions,
      groups: data.groups.length > 0 ? data.groups : undefined,
      lastModified: Date.now(),
    };

    set({ nodes, skillNameCache, metadata, rootId: "root" });

    // Persist to disk
    get().saveTreeMetadata();
  },

  async importTreeFromZip(data: Uint8Array) {
    const { treeJson, skillFiles } = unpackExportZip(data);
    const { projectPath } = get();

    // Write extracted skill files to ~/.claude/skills/
    if (projectPath && skillFiles.size > 0) {
      for (const [relativePath, content] of skillFiles) {
        try {
          const skillPath = join(projectPath, ".claude", "skills", relativePath);
          // Ensure directory exists (e.g., ~/.claude/skills/skill-name/)
          const parts = relativePath.split("/");
          if (parts.length > 1) {
            const dir = join(projectPath, ".claude", "skills", ...parts.slice(0, -1));
            if (!(await exists(dir))) {
              await mkdir(dir, { recursive: true });
            }
          }
          await writeTextFile(skillPath, content);
        } catch (err) {
          console.warn(`[ATM] Failed to write skill file ${relativePath}:`, err);
        }
      }
    }

    // Import the tree data
    get().importTreeFromJson(treeJson);

    // Rescan to pick up newly written skill files
    if (projectPath) {
      await get().loadProject(projectPath);
    }
  },

  createStickyNote(text: string, color: string, position: { x: number; y: number }): string {
    const id = `note-${Date.now().toString(36)}`;
    const node: AuiNode = {
      id,
      name: "Note",
      kind: "note",
      parentId: null,
      team: null,
      sourcePath: "",
      config: null,
      promptBody: text,
      tags: [`color:${color}`],
      lastModified: Date.now(),
      validationErrors: [],
      assignedSkills: [],
      variables: [],
      launchPrompt: "",
      pipelineSteps: [],
    };
    set((state) => {
      const next = new Map(state.nodes);
      next.set(id, node);
      const positions = { ...state.metadata?.positions, [id]: position };
      return {
        nodes: next,
        metadata: state.metadata ? { ...state.metadata, positions } : null,
      };
    });
    get().saveTreeMetadata();
    return id;
  },

  updateStickyNote(id: string, updates: { text?: string; color?: string }) {
    const node = get().nodes.get(id);
    if (!node || node.kind !== "note") return;
    const changes: Partial<AuiNode> = { lastModified: Date.now() };
    if (updates.text !== undefined) changes.promptBody = updates.text;
    if (updates.color !== undefined) {
      changes.tags = [...node.tags.filter((t) => !t.startsWith("color:")), `color:${updates.color}`];
    }
    set((state) => {
      const next = new Map(state.nodes);
      next.set(id, { ...node, ...changes });
      return { nodes: next };
    });
    get().saveTreeMetadata();
  },

  deleteStickyNote(id: string) {
    set((state) => {
      const next = new Map(state.nodes);
      next.delete(id);
      const positions = { ...state.metadata?.positions };
      delete positions[id];
      return {
        nodes: next,
        metadata: state.metadata ? { ...state.metadata, positions } : null,
      };
    });
    get().saveTreeMetadata();
  },

  autoGroupByPrefix() {
    set((state) => {
      const next = new Map(state.nodes);
      for (const [id, node] of next) {
        if (id === "root" || node.kind === "note") continue;
        const team = detectTeam(node.name);
        next.set(id, { ...node, team });
      }
      return { nodes: next };
    });
  },

  async loadLayouts() {
    const { projectPath } = get();
    if (!projectPath) return;

    const index = await loadLayoutIndex(projectPath);
    if (index) {
      set({
        layouts: index.layouts,
        currentLayoutId: index.activeLayoutId,
      });
    } else {
      // No index exists — create a default layout from the current tree.json
      const defaultId = `layout-${Date.now()}`;
      await get().saveTreeMetadata();
      const { metadata } = get();
      if (metadata) {
        await saveLayout(projectPath, defaultId, metadata);
      }
      const newIndex = {
        activeLayoutId: defaultId,
        layouts: [{ id: defaultId, name: "Default", lastModified: Date.now() }],
      };
      await saveLayoutIndex(projectPath, newIndex);
      set({
        layouts: newIndex.layouts,
        currentLayoutId: defaultId,
      });
    }
  },

  async saveCurrentAsLayout(name: string): Promise<string> {
    const { projectPath } = get();
    if (!projectPath) throw new Error("No project loaded");

    const layoutId = `layout-${Date.now()}`;

    // Save current tree state first
    await get().saveTreeMetadata();
    const { metadata } = get();
    if (!metadata) throw new Error("No metadata to save");

    // Save the metadata as a layout file
    await saveLayout(projectPath, layoutId, metadata);

    // Update the index
    const { layouts } = get();
    const newEntry = { id: layoutId, name, lastModified: Date.now() };
    const updatedLayouts = [...layouts, newEntry];
    await saveLayoutIndex(projectPath, {
      activeLayoutId: layoutId,
      layouts: updatedLayouts,
    });

    set({
      layouts: updatedLayouts,
      currentLayoutId: layoutId,
    });

    return layoutId;
  },

  async switchLayout(layoutId: string) {
    const { projectPath, currentLayoutId } = get();
    if (!projectPath) return;
    if (layoutId === currentLayoutId) return;

    // a. Save current tree state to the current layout file
    await get().saveTreeMetadata();
    const { metadata: currentMeta } = get();
    if (currentMeta && currentLayoutId) {
      await saveLayout(projectPath, currentLayoutId, currentMeta);
    }

    // b. Load the target layout's TreeMetadata
    const targetMeta = await loadLayout(projectPath, layoutId);
    if (!targetMeta) {
      set({ error: `Layout ${layoutId} not found` });
      return;
    }

    // c. Reconstruct the node map by re-scanning files from disk.
    //    This ensures file-based nodes are always present even if the
    //    current node map was sparse (e.g., coming from a blank layout).
    const filePaths = await scanProject(projectPath);
    const next = new Map<string, AuiNode>();

    // Root node with the target layout's owner info
    const ownerName = targetMeta.owner?.name ?? "Owner";
    next.set("root", createRootNode(ownerName));

    // Parse all discovered files and apply the target layout's hierarchy
    for (const filePath of filePaths) {
      const kind = classifyFile(filePath);
      if (!kind || kind === "settings") continue;

      try {
        const node = await parseFile(filePath, kind);
        if (node) {
          node.parentId = targetMeta.hierarchy[node.id] !== undefined
            ? targetMeta.hierarchy[node.id]
            : "root";
          next.set(node.id, node);
        }
      } catch {
        // Skip unparseable files
      }
    }

    // Restore group/pipeline nodes from the target layout
    if (targetMeta.groups) {
      for (const g of targetMeta.groups) {
        next.set(g.id, {
          id: g.id,
          name: g.name,
          kind: g.kind === "pipeline" ? "pipeline" : "group",
          parentId: g.parentId,
          team: g.team,
          sourcePath: "",
          config: null,
          promptBody: g.description,
          tags: [],
          lastModified: Date.now(),
          validationErrors: [],
          assignedSkills: g.assignedSkills ?? [],
          variables: g.variables ?? [],
          launchPrompt: g.launchPrompt ?? "",
          pipelineSteps: g.pipelineSteps ?? [],
        });
      }
    }

    // d. Update state
    const { layouts } = get();
    const updatedLayouts = layouts.map((l) =>
      l.id === currentLayoutId ? { ...l, lastModified: Date.now() } : l,
    );
    await saveLayoutIndex(projectPath, {
      activeLayoutId: layoutId,
      layouts: updatedLayouts,
    });

    set({
      nodes: next,
      currentLayoutId: layoutId,
      metadata: targetMeta,
      layouts: updatedLayouts,
    });
  },

  async deleteLayout(layoutId: string) {
    const { projectPath, currentLayoutId, layouts } = get();
    if (!projectPath) return;

    // Can't delete the active layout
    if (layoutId === currentLayoutId) return;

    await deleteLayoutFile(projectPath, layoutId);

    const updatedLayouts = layouts.filter((l) => l.id !== layoutId);
    await saveLayoutIndex(projectPath, {
      activeLayoutId: currentLayoutId!,
      layouts: updatedLayouts,
    });

    set({ layouts: updatedLayouts });
  },

  async renameLayout(layoutId: string, newName: string) {
    const { projectPath, currentLayoutId, layouts } = get();
    if (!projectPath) return;

    const updatedLayouts = layouts.map((l) =>
      l.id === layoutId ? { ...l, name: newName, lastModified: Date.now() } : l,
    );

    await saveLayoutIndex(projectPath, {
      activeLayoutId: currentLayoutId!,
      layouts: updatedLayouts,
    });

    set({ layouts: updatedLayouts });
  },

  async createBlankLayout(name: string): Promise<string> {
    const { projectPath, currentLayoutId } = get();
    if (!projectPath) throw new Error("No project loaded");

    const layoutId = `layout-${Date.now()}`;

    // Save current tree state to the current layout first
    await get().saveTreeMetadata();
    const { metadata: currentMeta } = get();
    if (currentMeta && currentLayoutId) {
      await saveLayout(projectPath, currentLayoutId, currentMeta);
    }

    // Create blank metadata with only the root node
    const blankMeta: TreeMetadata = {
      owner: get().metadata?.owner ?? { name: "Owner", description: "" },
      hierarchy: {},
      positions: {},
      groups: undefined,
      lastModified: Date.now(),
    };

    // Save the blank layout file
    await saveLayout(projectPath, layoutId, blankMeta);

    // Update the index
    const { layouts } = get();
    const newEntry = { id: layoutId, name, lastModified: Date.now() };
    const updatedLayouts = [...layouts, newEntry];
    await saveLayoutIndex(projectPath, {
      activeLayoutId: layoutId,
      layouts: updatedLayouts,
    });

    // Switch to blank canvas: only the root node with a clean slate
    const next = new Map<string, AuiNode>();
    next.set("root", createRootNode(blankMeta.owner?.name ?? "You"));

    set({
      nodes: next,
      currentLayoutId: layoutId,
      metadata: blankMeta,
      layouts: updatedLayouts,
    });

    return layoutId;
  },

  saveNodePosition(nodeId: string, pos: { x: number; y: number }) {
    const { metadata } = get();
    if (!metadata) return;
    const positions = { ...metadata.positions, [nodeId]: pos };
    set({ metadata: { ...metadata, positions } });
  },

  saveNodePositions(positions: Record<string, { x: number; y: number }>) {
    const { metadata } = get();
    if (!metadata) return;
    const merged = { ...metadata.positions, ...positions };
    set({ metadata: { ...metadata, positions: merged } });
  },

  clearNodePosition(nodeId: string) {
    const { metadata } = get();
    if (!metadata) return;
    const positions = { ...metadata.positions };
    delete positions[nodeId];
    set({ metadata: { ...metadata, positions } });
  },

  copyNodes(nodeId: string) {
    const { nodes } = get();
    const source = nodes.get(nodeId);
    if (!source || nodeId === "root") return;

    const descendants = collectDescendantNodes(nodes, nodeId);
    const allNodes = [{ ...source }, ...descendants.map((n) => ({ ...n }))];

    set({ clipboard: { nodes: allNodes, sourceParentId: source.parentId } });
  },

  async duplicateNodes(nodeId: string): Promise<string | null> {
    const { nodes, projectPath } = get();
    if (!projectPath) return null;
    const source = nodes.get(nodeId);
    if (!source || nodeId === "root") return null;

    const descendants = collectDescendantNodes(nodes, nodeId);
    const allSource = [source, ...descendants];

    const result = await cloneNodeTree(allSource, nodeId, source.parentId, projectPath);
    if (!result) return null;

    set((state) => {
      const next = new Map(state.nodes);
      for (const [id, node] of result.clonedNodes) {
        next.set(id, node);
      }
      return { nodes: next };
    });

    get().saveTreeMetadata();
    return result.newRootId;
  },

  async pasteNodes(targetParentId: string): Promise<string | null> {
    const { clipboard, projectPath } = get();
    if (!clipboard || clipboard.nodes.length === 0 || !projectPath) return null;

    const rootNodeId = clipboard.nodes[0].id;
    const result = await cloneNodeTree(clipboard.nodes, rootNodeId, targetParentId, projectPath);
    if (!result) return null;

    set((state) => {
      const next = new Map(state.nodes);
      for (const [id, node] of result.clonedNodes) {
        next.set(id, node);
      }
      return { nodes: next };
    });

    get().saveTreeMetadata();
    return result.newRootId;
  },
}));
