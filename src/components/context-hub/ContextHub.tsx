import { useState, useEffect, useMemo, useRef } from "react";
import { readDir, readTextFile, writeTextFile, exists, mkdir } from "@tauri-apps/plugin-fs";
import { open } from "@tauri-apps/plugin-dialog";
import matter from "gray-matter";
import { useUiStore } from "@/store/ui-store";
import { useTreeStore } from "@/store/tree-store";
import { join, getFileName, titleCase, generateNodeId } from "@/utils/paths";
import { detectTeam, getTeamColor } from "@/utils/grouping";
import { scanAllSkills } from "@/services/skill-scanner";
import { toast } from "@/components/common/Toast";

// ── Types for catalog items ─────────────────────────────

interface CatalogItem {
  id: string;
  name: string;
  description: string;
  kind: "agent" | "skill" | "group";
  team: string | null;
  sourcePath: string;
  model?: string;
  permissionMode?: string;
  tools?: string[];
  skills?: string[];
  assignedSkillCount?: number;
  agentCount?: number;
}

type FilterChip = "All" | "Skills" | "Teams" | "Agents";
const FILTERS: FilterChip[] = ["All", "Skills", "Teams", "Agents"];

// ── Filesystem scanning (independent of store) ──────────

async function scanSkills(projectPath: string): Promise<CatalogItem[]> {
  const skills = await scanAllSkills(projectPath);
  return skills.map((s) => {
    // Extract folder name from sourcePath (e.g. ".../skills/gsd-review/SKILL.md" -> "gsd-review")
    const parts = s.sourcePath.replace(/\\/g, "/").split("/");
    const folderName = parts.length >= 2 ? parts[parts.length - 2] : s.name;
    return {
      id: s.id,
      name: s.name,
      description: s.description,
      kind: "skill" as const,
      team: detectTeam(folderName),
      sourcePath: s.sourcePath,
    };
  });
}

async function scanAgents(projectPath: string): Promise<CatalogItem[]> {
  const items: CatalogItem[] = [];
  const agentsDir = join(projectPath, ".claude", "agents");

  try {
    if (!(await exists(agentsDir))) return [];
    const entries = await readDir(agentsDir);

    for (const entry of entries) {
      if (!entry.isFile || !entry.name.endsWith(".md")) continue;
      const filePath = join(agentsDir, entry.name);
      try {
        const raw = await readTextFile(filePath);
        const parsed = matter(raw);
        const baseName = getFileName(filePath);
        const name = parsed.data?.name
          ? String(parsed.data.name)
          : titleCase(baseName);
        const description = parsed.data?.description
          ? String(parsed.data.description)
          : "";

        items.push({
          id: generateNodeId(filePath),
          name,
          description,
          kind: "agent",
          team: detectTeam(baseName),
          sourcePath: filePath,
          model: parsed.data?.model ? String(parsed.data.model) : undefined,
          permissionMode: parsed.data?.permissionMode
            ? String(parsed.data.permissionMode)
            : undefined,
          tools: Array.isArray(parsed.data?.tools) ? parsed.data.tools : undefined,
          skills: Array.isArray(parsed.data?.skills) ? parsed.data.skills : undefined,
        });
      } catch {
        items.push({
          id: generateNodeId(filePath),
          name: titleCase(getFileName(filePath)),
          description: "",
          kind: "agent",
          team: detectTeam(getFileName(filePath)),
          sourcePath: filePath,
        });
      }
    }
  } catch {
    // Directory read failed
  }

  return items.sort((a, b) => a.name.localeCompare(b.name));
}

// ── Bento Card ──────────────────────────────────────────

const KIND_COLORS: Record<string, string> = {
  agent: "#f0883e",
  skill: "#3fb950",
  group: "#4a9eff",
};

function BentoCard({
  item,
  isOnTree,
  onAddToTree,
  onEdit,
}: {
  item: CatalogItem;
  isOnTree: boolean;
  onAddToTree: () => void;
  onEdit: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const color = KIND_COLORS[item.kind] ?? "#4a9eff";

  return (
    <div
      style={{
        background: "var(--bg-surface, #1c2333)",
        border: `1px solid ${expanded ? color : "var(--border-color)"}`,
        borderRadius: 10,
        overflow: "hidden",
        transition: "border-color 0.2s ease, box-shadow 0.2s ease",
        cursor: "pointer",
        boxShadow: expanded ? `0 4px 20px rgba(0,0,0,0.3)` : "none",
      }}
    >
      {/* Card header */}
      <div
        onClick={() => setExpanded(!expanded)}
        style={{ padding: "12px 14px", display: "flex", alignItems: "flex-start", gap: 10 }}
      >
        {/* Accent dot */}
        <div
          style={{
            width: 10, height: 10, borderRadius: "50%",
            background: color, flexShrink: 0, marginTop: 4,
          }}
        />

        <div style={{ flex: 1, minWidth: 0 }}>
          {/* Name */}
          <div
            style={{
              fontWeight: 600, fontSize: 14, color: "var(--text-primary)",
              overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            }}
          >
            {item.name}
          </div>

          {/* Description */}
          {item.description && (
            <div
              style={{
                fontSize: 12, color: "var(--text-secondary)", marginTop: 2,
                lineHeight: 1.3, overflow: "hidden",
                display: "-webkit-box", WebkitLineClamp: expanded ? 10 : 1,
                WebkitBoxOrient: "vertical",
              }}
            >
              {item.description}
            </div>
          )}

          {/* Badges */}
          <div style={{ display: "flex", gap: 6, marginTop: 6, flexWrap: "wrap" }}>
            <Badge text={item.kind === "group" ? "team" : item.kind} bg={color} color="#fff" />
            {item.team && (
              <Badge
                text={item.team}
                bg={`${getTeamColor(item.team)}22`}
                color={getTeamColor(item.team)}
                border={`${getTeamColor(item.team)}44`}
              />
            )}
            {isOnTree && (
              <Badge text="On Tree" bg="rgba(76,175,80,0.15)" color="#3fb950" border="rgba(76,175,80,0.3)" />
            )}
            {item.kind === "group" && item.agentCount !== undefined && item.agentCount > 0 && (
              <Badge
                text={`${item.agentCount} agent${item.agentCount > 1 ? "s" : ""}`}
                bg="rgba(255,152,0,0.15)"
                color="#f0883e"
                border="rgba(255,152,0,0.3)"
              />
            )}
            {item.kind === "group" && item.assignedSkillCount !== undefined && item.assignedSkillCount > 0 && (
              <Badge
                text={`${item.assignedSkillCount} skill${item.assignedSkillCount > 1 ? "s" : ""}`}
                bg="rgba(76,175,80,0.15)"
                color="#3fb950"
                border="rgba(76,175,80,0.3)"
              />
            )}
          </div>
        </div>

        {/* Chevron */}
        <div
          style={{
            color: "var(--text-secondary)", fontSize: 14, flexShrink: 0,
            transition: "transform 0.2s",
            transform: expanded ? "rotate(180deg)" : "rotate(0deg)", marginTop: 2,
          }}
        >
          &#x25BE;
        </div>
      </div>

      {/* Expanded panel */}
      {expanded && (
        <div
          style={{
            borderTop: "1px solid var(--border-color)",
            padding: "10px 14px",
            animation: "fadeIn 0.15s ease",
          }}
        >
          {/* Agent details */}
          {item.kind === "agent" && (
            <div style={{ marginBottom: 10 }}>
              {item.model && <DetailRow label="Model" value={item.model} />}
              {item.permissionMode && <DetailRow label="Mode" value={item.permissionMode} />}
              {item.tools?.length ? <DetailRow label="Tools" value={item.tools.join(", ")} /> : null}
              {item.skills?.length ? <DetailRow label="Skills" value={item.skills.join(", ")} /> : null}
            </div>
          )}

          {/* Source path */}
          {item.sourcePath && (
            <div
              style={{
                fontSize: 10, color: "var(--text-secondary)",
                marginBottom: 10, wordBreak: "break-all", opacity: 0.7,
              }}
            >
              {item.sourcePath}
            </div>
          )}

          {/* Actions */}
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {!isOnTree && item.kind !== "group" ? (
              <ActionButton label="Add to Tree" color="#3fb950" onClick={(e) => { e.stopPropagation(); onAddToTree(); }} />
            ) : (
              <ActionButton label="View on Tree" color="var(--accent-blue)" onClick={(e) => { e.stopPropagation(); onEdit(); }} />
            )}
            {item.kind !== "group" && (
              <ActionButton label="Edit" color="var(--accent-blue)" onClick={(e) => { e.stopPropagation(); onEdit(); }} />
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function Badge({ text, bg, color, border }: { text: string; bg: string; color: string; border?: string }) {
  return (
    <span
      style={{
        fontSize: 10, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em",
        background: bg, color, padding: "1px 8px", borderRadius: 10,
        border: border ? `1px solid ${border}` : "none",
      }}
    >
      {text}
    </span>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: "flex", gap: 8, marginBottom: 3 }}>
      <span style={{ fontSize: 11, color: "var(--text-secondary)", minWidth: 50 }}>{label}:</span>
      <span style={{ fontSize: 11, color: "var(--text-primary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {value}
      </span>
    </div>
  );
}

function ActionButton({ label, color, onClick }: { label: string; color: string; onClick: (e: React.MouseEvent) => void }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "5px 12px", fontSize: 11, fontWeight: 600,
        background: "transparent", border: `1px solid ${color}`, color,
        borderRadius: 6, cursor: "pointer", transition: "background 0.15s",
      }}
      onMouseEnter={(e) => { e.currentTarget.style.background = `${color}18`; }}
      onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
    >
      {label}
    </button>
  );
}

// ── Section Header ──────────────────────────────────────

function SectionHeader({ label, count }: { label: string; count: number }) {
  return (
    <div
      style={{
        fontSize: 11,
        fontWeight: 700,
        textTransform: "uppercase",
        letterSpacing: "0.06em",
        color: "var(--text-secondary)",
        padding: "12px 0 6px",
        borderBottom: "1px solid var(--bg-hover-subtle)",
        marginBottom: 8,
      }}
    >
      {label} ({count})
    </div>
  );
}

// ── Import helpers ───────────────────────────────────────

function toRawGitHubUrl(url: string): string {
  try {
    const u = new URL(url);
    if (u.hostname === "raw.githubusercontent.com") return url;
    if (u.hostname === "github.com") {
      const parts = u.pathname.split("/").filter(Boolean);
      if (parts.length >= 4 && parts[2] === "blob") {
        const [user, repo, , branch, ...rest] = parts;
        return `https://raw.githubusercontent.com/${user}/${repo}/${branch}/${rest.join("/")}`;
      }
    }
  } catch {
    // not a valid URL
  }
  return url;
}

function deriveSkillSlug(content: string, fallbackPath?: string): string {
  const parsed = matter(content);
  if (parsed.data?.name) {
    return String(parsed.data.name)
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
  }
  if (fallbackPath) {
    const base = getFileName(fallbackPath);
    return base.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  }
  return `imported-skill-${Date.now()}`;
}

async function importSkillContent(
  content: string,
  projectPath: string,
  addNode: ReturnType<typeof useTreeStore.getState>["addNode"],
  setSkillItems: React.Dispatch<React.SetStateAction<CatalogItem[]>>,
  fallbackPath?: string,
) {
  const slug = deriveSkillSlug(content, fallbackPath);
  const skillDir = join(projectPath, ".claude", "skills", slug);
  if (!(await exists(skillDir))) {
    await mkdir(skillDir, { recursive: true });
  }
  const filePath = join(skillDir, "SKILL.md");
  await writeTextFile(filePath, content);

  const parsed = matter(content);
  const name = parsed.data?.name ? String(parsed.data.name) : titleCase(slug);
  const description = parsed.data?.description ? String(parsed.data.description) : "";
  const id = generateNodeId(filePath);

  addNode({
    id,
    name,
    kind: "skill",
    parentId: "root",
    team: detectTeam(slug),
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
  });

  setSkillItems((prev) => [
    ...prev,
    { id, name, description, kind: "skill", team: detectTeam(slug), sourcePath: filePath },
  ]);

  return name;
}

// ── Import Dropdown ──────────────────────────────────────

function ImportDropdown({
  projectPath,
  addNode,
  setSkillItems,
  onClose,
}: {
  projectPath: string;
  addNode: ReturnType<typeof useTreeStore.getState>["addNode"];
  setSkillItems: React.Dispatch<React.SetStateAction<CatalogItem[]>>;
  onClose: () => void;
}) {
  const [mode, setMode] = useState<"menu" | "url">("menu");
  const [urlValue, setUrlValue] = useState("");
  const [importing, setImporting] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [onClose]);

  const handleFileImport = async () => {
    try {
      const selected = await open({ filters: [{ name: "Markdown", extensions: ["md"] }] });
      if (!selected) return;
      const filePath = typeof selected === "string" ? selected : null;
      if (!filePath) return;
      setImporting(true);
      const content = await readTextFile(filePath);
      const name = await importSkillContent(content, projectPath, addNode, setSkillItems, filePath);
      toast(`Imported skill "${name}"`, "success");
      onClose();
    } catch (err) {
      toast(`Import failed: ${err instanceof Error ? err.message : "Unknown error"}`, "error");
    } finally {
      setImporting(false);
    }
  };

  const handleUrlImport = async () => {
    if (!urlValue.trim()) return;
    setImporting(true);
    try {
      const rawUrl = toRawGitHubUrl(urlValue.trim());
      // Use Rust-side fetch to bypass webview CORS/CSP restrictions
      const { invoke } = await import("@tauri-apps/api/core");
      const content = await invoke<string>("fetch_url", { url: rawUrl });
      if (!content || content.trim().length === 0) throw new Error("Empty response from URL");
      const name = await importSkillContent(content, projectPath, addNode, setSkillItems, rawUrl);
      toast(`Imported skill "${name}" from URL`, "success");
      onClose();
    } catch (err) {
      toast(`Import failed: ${err instanceof Error ? err.message : "Unknown error"}`, "error");
    } finally {
      setImporting(false);
    }
  };

  const menuItemStyle: React.CSSProperties = {
    display: "block",
    width: "100%",
    padding: "8px 12px",
    fontSize: 12,
    fontWeight: 500,
    color: "var(--text-primary)",
    background: "transparent",
    border: "none",
    borderRadius: 4,
    cursor: "pointer",
    textAlign: "left" as const,
    transition: "background 0.12s",
  };

  return (
    <div
      ref={dropdownRef}
      style={{
        position: "absolute",
        top: "100%",
        right: 0,
        marginTop: 4,
        width: 260,
        background: "var(--bg-surface, #1c2333)",
        border: "1px solid var(--border-color)",
        borderRadius: 8,
        boxShadow: "0 8px 24px var(--shadow-panel)",
        zIndex: 200,
        padding: 6,
      }}
    >
      {mode === "menu" ? (
        <>
          <button
            style={menuItemStyle}
            onClick={handleFileImport}
            disabled={importing}
            onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-hover-subtle)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
          >
            From File...
          </button>
          <button
            style={menuItemStyle}
            onClick={() => setMode("url")}
            disabled={importing}
            onMouseEnter={(e) => { e.currentTarget.style.background = "var(--bg-hover-subtle)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
          >
            From GitHub URL
          </button>
        </>
      ) : (
        <div style={{ padding: 4 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 6 }}>
            GitHub URL
          </div>
          <input
            type="text"
            value={urlValue}
            onChange={(e) => setUrlValue(e.target.value)}
            placeholder="https://github.com/user/repo/blob/main/skill.md"
            autoFocus
            onKeyDown={(e) => { if (e.key === "Enter") handleUrlImport(); }}
            style={{
              width: "100%",
              boxSizing: "border-box",
              padding: "7px 10px",
              fontSize: 12,
              background: "var(--bg-input)",
              border: "1px solid var(--border-subtle)",
              borderRadius: 6,
              color: "var(--text-primary)",
              outline: "none",
              marginBottom: 8,
            }}
          />
          <div style={{ display: "flex", gap: 6, justifyContent: "flex-end" }}>
            <button
              onClick={() => setMode("menu")}
              style={{
                padding: "5px 10px", fontSize: 11, fontWeight: 600,
                background: "transparent", border: "1px solid var(--border-color)",
                color: "var(--text-secondary)", borderRadius: 6, cursor: "pointer",
              }}
            >
              Back
            </button>
            <button
              onClick={handleUrlImport}
              disabled={importing || !urlValue.trim()}
              style={{
                padding: "5px 14px", fontSize: 11, fontWeight: 600,
                background: "var(--accent-blue)", border: "none", color: "#fff",
                borderRadius: 6, cursor: importing ? "wait" : "pointer",
                opacity: importing || !urlValue.trim() ? 0.5 : 1,
              }}
            >
              {importing ? "Importing..." : "Import"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Utility Button ───────────────────────────────────────

function UtilityButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: "4px 12px", fontSize: 11, fontWeight: 600,
        background: "var(--bg-input)", border: "1px solid var(--border-input)",
        color: "var(--text-secondary)", borderRadius: 6, cursor: "pointer",
        transition: "all 0.15s",
      }}
      onMouseEnter={(e) => { e.currentTarget.style.borderColor = "var(--border-input-hover)"; e.currentTarget.style.color = "var(--text-primary)"; }}
      onMouseLeave={(e) => { e.currentTarget.style.borderColor = "var(--border-input)"; e.currentTarget.style.color = "var(--text-secondary)"; }}
    >
      {label}
    </button>
  );
}

// ── Main Context Hub ────────────────────────────────────

export function ContextHub() {
  const contextHubOpen = useUiStore((s) => s.contextHubOpen);
  const toggleContextHub = useUiStore((s) => s.toggleContextHub);
  const selectNode = useUiStore((s) => s.selectNode);
  const projectPath = useTreeStore((s) => s.projectPath);
  const treeNodes = useTreeStore((s) => s.nodes);
  const addNode = useTreeStore((s) => s.addNode);

  const [skillItems, setSkillItems] = useState<CatalogItem[]>([]);
  const [agentItems, setAgentItems] = useState<CatalogItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");
  const [activeFilter, setActiveFilter] = useState<FilterChip>("All");
  const [importOpen, setImportOpen] = useState(false);
  const loadProject = useTreeStore((s) => s.loadProject);
  const saveCompanyPlan = useTreeStore((s) => s.saveCompanyPlan);

  // Get top-level team nodes from tree store (not agents nested inside teams)
  const teamItems = useMemo<CatalogItem[]>(() => {
    const items: CatalogItem[] = [];
    for (const [, node] of treeNodes) {
      if (node.kind !== "group") continue;
      // Only include top-level teams — skip agents nested inside other teams
      const parent = node.parentId ? treeNodes.get(node.parentId) : null;
      if (parent?.kind === "group") continue;

      // Count all agents (children) under this team
      let agentCount = 0;
      for (const [, child] of treeNodes) {
        if (child.parentId === node.id) agentCount++;
      }

      items.push({
        id: node.id,
        name: node.name,
        description: node.promptBody,
        kind: "group",
        team: node.team,
        sourcePath: "",
        assignedSkillCount: node.assignedSkills.length,
        agentCount,
      });
    }
    return items.sort((a, b) => a.name.localeCompare(b.name));
  }, [treeNodes]);

  // Scan filesystem when hub opens
  useEffect(() => {
    if (!contextHubOpen || !projectPath) return;
    let cancelled = false;
    setLoading(true);

    const load = async () => {
      try {
        const [skills, agents] = await Promise.all([
          scanSkills(projectPath),
          scanAgents(projectPath),
        ]);
        if (!cancelled) {
          setSkillItems(skills);
          setAgentItems(agents);
        }
      } catch {
        // Silently handle
      }
      if (!cancelled) setLoading(false);
    };

    load();
    return () => { cancelled = true; };
  }, [contextHubOpen, projectPath]);

  // Build filtered + searched items
  const { sections, totalCount } = useMemo(() => {
    const q = search.toLowerCase();
    const matchesSearch = (item: CatalogItem) => {
      if (!q) return true;
      return (
        item.name.toLowerCase().includes(q) ||
        item.description.toLowerCase().includes(q) ||
        (item.team ?? "").toLowerCase().includes(q)
      );
    };

    const filteredTeams = (activeFilter === "All" || activeFilter === "Teams")
      ? teamItems.filter(matchesSearch) : [];
    const filteredSkills = (activeFilter === "All" || activeFilter === "Skills")
      ? skillItems.filter(matchesSearch) : [];
    const filteredAgents = (activeFilter === "All" || activeFilter === "Agents")
      ? agentItems.filter(matchesSearch) : [];

    return {
      sections: [
        { label: "Teams", items: filteredTeams },
        { label: "Skills", items: filteredSkills },
        { label: "Agents", items: filteredAgents },
      ].filter((s) => s.items.length > 0),
      totalCount: filteredTeams.length + filteredSkills.length + filteredAgents.length,
    };
  }, [search, activeFilter, teamItems, skillItems, agentItems]);

  const isOnTree = (itemId: string) => treeNodes.has(itemId);

  const handleAddToTree = (item: CatalogItem) => {
    if (!treeNodes.has(item.id)) {
      addNode({
        id: item.id,
        name: item.name,
        kind: item.kind,
        parentId: "root",
        team: item.team,
        sourcePath: item.sourcePath,
        config: null,
        promptBody: item.description,
        tags: [],
        lastModified: Date.now(),
        validationErrors: [],
        assignedSkills: [],
        variables: [],
        launchPrompt: "",
        pipelineSteps: [],
      });
    }
  };

  const handleEdit = (item: CatalogItem) => {
    if (treeNodes.has(item.id)) {
      selectNode(item.id);
      toggleContextHub();
    }
  };

  const handleNewClick = () => {
    useUiStore.getState().openCreateDialog();
    toggleContextHub();
  };

  if (!contextHubOpen) return null;

  return (
    <div
      style={{
        position: "fixed", top: "var(--toolbar-height)", right: 0, bottom: 0,
        width: 480, background: "var(--bg-secondary)",
        borderLeft: "1px solid var(--border-color)",
        boxShadow: "-4px 0 24px var(--shadow-panel)",
        display: "flex", flexDirection: "column", zIndex: 100,
        animation: "slideInRight 0.2s ease",
      }}
    >
      {/* Glass-morphism header */}
      <div
        style={{
          flexShrink: 0,
          background: "var(--bg-secondary)",
          borderBottom: "1px solid var(--border-subtle)",
          padding: "14px 16px 12px",
        }}
      >
        {/* Title row */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <span style={{ fontWeight: 700, fontSize: 16, color: "var(--text-primary)" }}>Catalog</span>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <div style={{ position: "relative" }}>
              <button
                onClick={() => setImportOpen((v) => !v)}
                style={{
                  padding: "5px 14px", fontSize: 12, fontWeight: 600,
                  background: "transparent", border: "1px solid var(--border-color)", color: "var(--text-primary)",
                  borderRadius: 8, cursor: "pointer",
                  transition: "border-color 0.15s",
                }}
                onMouseEnter={(e) => { e.currentTarget.style.borderColor = "var(--border-input-hover)"; }}
                onMouseLeave={(e) => { e.currentTarget.style.borderColor = "var(--border-color)"; }}
              >
                Import
              </button>
              {importOpen && projectPath && (
                <ImportDropdown
                  projectPath={projectPath}
                  addNode={addNode}
                  setSkillItems={setSkillItems}
                  onClose={() => setImportOpen(false)}
                />
              )}
            </div>
            <button
              onClick={handleNewClick}
              style={{
                padding: "5px 14px", fontSize: 12, fontWeight: 600,
                background: "var(--accent-blue)", border: "none", color: "#fff",
                borderRadius: 8, cursor: "pointer",
                transition: "opacity 0.15s",
              }}
              onMouseEnter={(e) => { e.currentTarget.style.opacity = "0.85"; }}
              onMouseLeave={(e) => { e.currentTarget.style.opacity = "1"; }}
            >
              + New
            </button>
            <button
              onClick={toggleContextHub}
              style={{
                background: "transparent", border: "none",
                color: "var(--text-secondary)", cursor: "pointer",
                fontSize: 18, padding: "0 4px", lineHeight: 1,
              }}
            >
              &#xd7;
            </button>
          </div>
        </div>

        {/* Utility row */}
        <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap" }}>
          <UtilityButton label="Refresh" onClick={() => { if (projectPath) loadProject(projectPath); }} />
          <UtilityButton label="Save Plan" onClick={async () => {
            try {
              const dir = await saveCompanyPlan();
              toast(`Plan saved to ${dir}`, "success");
            } catch (err) {
              toast(err instanceof Error ? err.message : "Failed", "error");
            }
          }} />
        </div>

        {/* Search input */}
        <div style={{ position: "relative", marginBottom: 10 }}>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search skills, agents, teams..."
            style={{
              width: "100%", boxSizing: "border-box",
              padding: "8px 30px 8px 12px",
              background: "var(--bg-input)",
              border: "1px solid var(--border-input)",
              borderRadius: 8, color: "var(--text-primary)",
              fontSize: 13, outline: "none",
              transition: "border-color 0.2s",
            }}
            onFocus={(e) => { e.currentTarget.style.borderColor = "rgba(74,158,255,0.4)"; }}
            onBlur={(e) => { e.currentTarget.style.borderColor = "var(--border-input)"; }}
          />
          {search && (
            <button
              onClick={() => setSearch("")}
              style={{
                position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)",
                background: "none", border: "none", color: "var(--text-secondary)",
                cursor: "pointer", fontSize: 14, padding: 0,
              }}
            >
              &#xd7;
            </button>
          )}
        </div>

        {/* Filter pills */}
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {FILTERS.map((chip) => {
            const isActive = activeFilter === chip;
            return (
              <button
                key={chip}
                onClick={() => setActiveFilter(chip)}
                style={{
                  padding: "4px 14px",
                  fontSize: 12,
                  fontWeight: 600,
                  borderRadius: 20,
                  border: isActive ? "1px solid transparent" : "1px solid var(--border-subtle)",
                  background: isActive ? "var(--accent-blue)" : "transparent",
                  color: isActive ? "#fff" : "var(--text-secondary)",
                  cursor: "pointer",
                  transition: "all 0.15s ease",
                  letterSpacing: "0.02em",
                }}
                onMouseEnter={(e) => {
                  if (!isActive) e.currentTarget.style.borderColor = "var(--border-input-hover)";
                }}
                onMouseLeave={(e) => {
                  if (!isActive) e.currentTarget.style.borderColor = "var(--border-subtle)";
                }}
              >
                {chip}
              </button>
            );
          })}
        </div>
      </div>

      {/* Content area */}
      <div style={{ flex: 1, overflow: "auto", padding: 16 }}>
        {loading ? (
          <div style={{ color: "var(--text-secondary)", fontSize: 13, padding: "40px 0", textAlign: "center" }}>
            Scanning files...
          </div>
        ) : totalCount === 0 ? (
          <div style={{ color: "var(--text-secondary)", fontSize: 13, padding: "40px 0", textAlign: "center" }}>
            {search ? "No matches found" : "No items found"}
          </div>
        ) : (
          <div>
            {sections.map((section) => (
              <div key={section.label}>
                <SectionHeader label={section.label} count={section.items.length} />
                <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 4 }}>
                  {section.items.map((item) => (
                    <BentoCard
                      key={item.id}
                      item={item}
                      isOnTree={isOnTree(item.id)}
                      onAddToTree={() => handleAddToTree(item)}
                      onEdit={() => handleEdit(item)}
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
