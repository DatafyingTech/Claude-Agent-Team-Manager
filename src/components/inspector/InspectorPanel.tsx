import { useState, useMemo, useEffect, useCallback, type CSSProperties } from "react";
import { useUiStore } from "@/store/ui-store";
import { useTreeStore } from "@/store/tree-store";
import { AgentEditor } from "./AgentEditor";
import { SkillEditor } from "./SkillEditor";
import { GroupEditor } from "./GroupEditor";
import { PipelineEditor } from "./PipelineEditor";
import { SettingsEditor } from "./SettingsEditor";
import { MarkdownEditor } from "./MarkdownEditor";
import { useAutosave } from "@/hooks/useAutosave";
import { scanAllSkills, type SkillInfo } from "@/services/skill-scanner";
import { getApiKey, generateText } from "@/services/claude-api";
import { toast } from "@/components/common/Toast";
import type { NodeKind, AuiNode, NodeVariable } from "@/types/aui-node";
import { VariableEditor } from "./VariableEditor";

const kindColors: Record<NodeKind, string> = {
  human: "#d29922",
  agent: "#f0883e",
  skill: "#3fb950",
  context: "#8b5cf6",
  settings: "#6e7681",
  group: "#4a9eff",
  pipeline: "#d946ef",
  note: "#d29922",
};

const badgeStyle = (kind: NodeKind): CSSProperties => ({
  display: "inline-block",
  padding: "2px 8px",
  borderRadius: 10,
  fontSize: 11,
  fontWeight: 600,
  textTransform: "uppercase",
  letterSpacing: "0.5px",
  color: "white",
  background: kindColors[kind],
});

export function InspectorPanel() {
  const selectedNodeId = useUiStore((s) => s.selectedNodeId);
  const selectNode = useUiStore((s) => s.selectNode);
  const toggleInspector = useUiStore((s) => s.toggleInspector);
  const node = useTreeStore((s) =>
    selectedNodeId ? s.nodes.get(selectedNodeId) ?? null : null,
  );

  const updateNode = useTreeStore((s) => s.updateNode);

  const [contextEditing, setContextEditing] = useState(false);
  const [copiedPath, setCopiedPath] = useState(false);

  if (!node) {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          color: "var(--text-secondary)",
          fontSize: 14,
          position: "relative",
        }}
      >
        <button
          onClick={toggleInspector}
          style={{
            position: "absolute",
            top: 8,
            right: 8,
            background: "transparent",
            border: "none",
            color: "var(--text-secondary)",
            cursor: "pointer",
            fontSize: 18,
            padding: "0 4px",
            lineHeight: 1,
          }}
          title="Close panel"
        >
          x
        </button>
        Select a node
      </div>
    );
  }

  const handleCopyPath = () => {
    if (node.sourcePath) {
      navigator.clipboard.writeText(node.sourcePath);
      setCopiedPath(true);
      setTimeout(() => setCopiedPath(false), 2000);
    }
  };

  const handleDelete = () => {
    (useUiStore.getState() as any).openDeleteDialog(node.id);
  };

  const renderEditor = () => {
    switch (node.kind) {
      case "agent":
        return <AgentEditor key={node.id} node={node} />;
      case "skill":
        return <SkillEditor key={node.id} node={node} />;
      case "group":
        return <GroupEditor key={node.id} node={node} />;
      case "pipeline":
        return <PipelineEditor key={node.id} node={node} />;
      case "settings":
        return <SettingsEditor key={node.id} node={node} />;
      case "context":
        return (
          <div>
            <div
              style={{
                display: "flex",
                justifyContent: "flex-end",
                marginBottom: 8,
              }}
            >
              <button
                onClick={() => setContextEditing(!contextEditing)}
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
                {contextEditing ? "Read Only" : "Edit"}
              </button>
            </div>
            <MarkdownEditor
              value={node.promptBody}
              readOnly={!contextEditing}
              height={500}
              onChange={
                contextEditing
                  ? (val) =>
                      updateNode(node.id, {
                        promptBody: val,
                        lastModified: Date.now(),
                      })
                  : undefined
              }
            />
          </div>
        );
      case "human":
        return <RootEditor node={node} />;
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      {/* Sticky Header */}
      <div
        style={{
          position: "sticky",
          top: 0,
          zIndex: 10,
          background: "var(--bg-secondary)",
          paddingBottom: 12,
          marginBottom: 8,
          borderBottom: "1px solid var(--border-color)",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            marginBottom: 6,
          }}
        >
          <span style={{ fontWeight: 700, fontSize: 18, color: "var(--text-primary)" }}>
            {node.name}
          </span>
          <span style={badgeStyle(node.kind)}>{node.kind === "pipeline" ? "project mgr" : node.kind}</span>
          <div style={{ marginLeft: "auto", display: "flex", gap: 6, alignItems: "center" }}>
            {node.kind !== "human" && (
              <button
                onClick={handleDelete}
                style={{
                  background: "transparent",
                  border: "1px solid rgba(248,81,73,0.5)",
                  color: "#f85149",
                  borderRadius: 4,
                  cursor: "pointer",
                  padding: "2px 8px",
                  fontSize: 11,
                  fontWeight: 600,
                }}
              >
                Delete
              </button>
            )}
            <button
              onClick={() => {
                selectNode(null);
                toggleInspector();
              }}
              style={{
                background: "transparent",
                border: "none",
                color: "var(--text-secondary)",
                cursor: "pointer",
                fontSize: 18,
                padding: "0 4px",
                lineHeight: 1,
              }}
              title="Close panel"
            >
              ×
            </button>
          </div>
        </div>
        {node.sourcePath && (
          <div
            onClick={handleCopyPath}
            style={{
              fontSize: 11,
              color: copiedPath ? "var(--accent-green)" : "var(--text-secondary)",
              cursor: "pointer",
              wordBreak: "break-all",
              transition: "color 0.2s",
            }}
            title="Click to copy path"
          >
            {copiedPath ? "Copied!" : node.sourcePath}
          </div>
        )}
      </div>

      {/* Scrollable Editor Content */}
      <div style={{ flex: 1, overflowY: "auto", minHeight: 0 }}>
        {renderEditor()}
      </div>
    </div>
  );
}

// ── Root/Owner Editor ──────────────────────────────────

const rootLabelStyle: CSSProperties = {
  fontSize: 12,
  textTransform: "uppercase",
  color: "var(--text-secondary)",
  marginBottom: 4,
  display: "block",
  letterSpacing: "0.5px",
};

const rootInputStyle: CSSProperties = {
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

const rootSectionStyle: CSSProperties = {
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

function CollapsibleSection({
  title,
  count,
  defaultOpen = true,
  children,
}: {
  title: string;
  count?: number;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{ marginBottom: 4 }}>
      <div
        onClick={() => setOpen(!open)}
        style={{
          ...rootSectionStyle,
          cursor: "pointer",
          userSelect: "none",
          display: "flex",
          alignItems: "center",
          gap: 6,
        }}
      >
        <span style={{ fontSize: 10, transition: "transform 0.15s", display: "inline-block", transform: open ? "rotate(90deg)" : "rotate(0)" }}>
          {"\u25B6"}
        </span>
        {title}{count !== undefined ? ` (${count})` : ""}
      </div>
      {open && <div style={{ paddingTop: 4 }}>{children}</div>}
    </div>
  );
}

function RootEditor({ node }: { node: AuiNode }) {
  const updateNode = useTreeStore((s) => s.updateNode);
  const nodes = useTreeStore((s) => s.nodes);
  const projectPath = useTreeStore((s) => s.projectPath);
  const cacheSkillName = useTreeStore((s) => s.cacheSkillName);
  const assignSkillToNode = useTreeStore((s) => s.assignSkillToNode);
  const removeSkillFromNode = useTreeStore((s) => s.removeSkillFromNode);
  const saveTreeMetadata = useTreeStore((s) => s.saveTreeMetadata);
  const selectNode = useUiStore((s) => s.selectNode);
  const openCreateDialog = useUiStore((s) => s.openCreateDialog);

  const [ownerName, setOwnerName] = useState(node.name);
  const [description, setDescription] = useState(node.promptBody);
  const [variables, setVariables] = useState<NodeVariable[]>(node.variables);
  const [addSkillId, setAddSkillId] = useState("");
  const [teamCount, setTeamCount] = useState(3);
  const [agentsPer, setAgentsPer] = useState(3);
  const [generatingGoals, setGeneratingGoals] = useState(false);

  // Filesystem-scanned skills
  const [fsSkills, setFsSkills] = useState<SkillInfo[]>([]);

  useEffect(() => {
    setOwnerName(node.name);
    setDescription(node.promptBody);
    setVariables(node.variables);
  }, [node.id, node.name, node.promptBody, node.variables]);

  useEffect(() => {
    if (!projectPath) return;
    let cancelled = false;
    scanAllSkills(projectPath).then((skills) => {
      if (!cancelled) setFsSkills(skills);
    });
    return () => { cancelled = true; };
  }, [projectPath, nodes]);

  // All skill nodes
  const treeSkills = useMemo(() => {
    const skills: AuiNode[] = [];
    for (const n of nodes.values()) {
      if (n.kind === "skill") skills.push(n);
    }
    return skills;
  }, [nodes]);

  // Merged skills list
  const allSkills = useMemo(() => {
    const treeIds = new Set(treeSkills.map((s) => s.id));
    const merged: Array<{ id: string; name: string; description: string }> = treeSkills.map((s) => ({
      id: s.id,
      name: s.name,
      description: "",
    }));
    for (const fs of fsSkills) {
      if (!treeIds.has(fs.id)) {
        merged.push({ id: fs.id, name: fs.name, description: fs.description });
      }
    }
    return merged.sort((a, b) => a.name.localeCompare(b.name));
  }, [treeSkills, fsSkills]);

  // Assigned skills
  const assignedSkills = useMemo(() => {
    return node.assignedSkills
      .map((id) => {
        const treeNode = nodes.get(id);
        if (treeNode) return { id: treeNode.id, name: treeNode.name };
        const fsMatch = fsSkills.find((f) => f.id === id);
        if (fsMatch) return { id: fsMatch.id, name: fsMatch.name };
        return null;
      })
      .filter((n): n is { id: string; name: string } => n !== null);
  }, [node.assignedSkills, nodes, fsSkills]);

  // Available (not assigned yet)
  const availableSkills = useMemo(() => {
    const assigned = new Set(node.assignedSkills);
    return allSkills.filter((s) => !assigned.has(s.id));
  }, [allSkills, node.assignedSkills]);

  // Direct children (top-level teams)
  const children = useMemo(() => {
    const result: AuiNode[] = [];
    for (const n of nodes.values()) {
      if (n.parentId === node.id) result.push(n);
    }
    return result;
  }, [nodes, node.id]);

  const handleGenerateFromGoals = useCallback(async () => {
    if (!projectPath || !description.trim()) return;
    setGeneratingGoals(true);
    try {
      const apiKey = await getApiKey(projectPath);
      if (!apiKey) {
        toast("No API key configured. Go to Settings to add one.", "error");
        setGeneratingGoals(false);
        return;
      }

      const globalSkillNames = node.assignedSkills
        .map((id) => nodes.get(id)?.name ?? id)
        .filter(Boolean);

      const prompt = `You are designing an AI agent team structure for a company/project.

Company/Project Description: "${description}"
${globalSkillNames.length > 0 ? `Global skills available: ${globalSkillNames.join(", ")}` : ""}

STRICT REQUIREMENTS:
- Generate EXACTLY ${teamCount} teams. Not fewer, not more.
- Each team MUST have EXACTLY ${agentsPer} agents. Not fewer, not more.
- Every team must have a clear purpose that contributes to achieving the stated goals.
- Agent roles must be specific and complementary within their team.

Return ONLY valid JSON in this exact format (no markdown, no explanation):
{
  "teams": [
    {
      "name": "Team Name",
      "description": "How this team helps achieve the goals",
      "agents": [
        { "name": "Agent Name", "description": "Specific role and responsibilities" }
      ]
    }
  ]
}

IMPORTANT: The JSON must contain exactly ${teamCount} objects in the "teams" array, and each team must contain exactly ${agentsPer} objects in its "agents" array. Make team and agent names descriptive and specific. Use title case for names. Each team should address a different aspect of the goals.`;

      const result = await generateText(apiKey, prompt, { maxTokens: 2048 });

      const jsonMatch = result.match(/\{[\s\S]*\}/);
      if (!jsonMatch) throw new Error("No valid JSON in response");
      const parsed = JSON.parse(jsonMatch[0]);

      if (!Array.isArray(parsed.teams)) throw new Error("Invalid response format");

      const { createGroupNode: createGroup } = useTreeStore.getState();
      for (const team of parsed.teams) {
        createGroup(team.name, team.description, "root");
        const { nodes: currentNodes } = useTreeStore.getState();
        let teamId: string | null = null;
        for (const [id, n] of currentNodes) {
          if (n.kind === "group" && n.name === team.name && n.parentId === "root") {
            teamId = id;
            break;
          }
        }
        if (teamId && Array.isArray(team.agents)) {
          for (const agent of team.agents) {
            createGroup(agent.name, agent.description, teamId);
          }
        }
      }

      toast(`Created ${parsed.teams.length} teams designed for your goals`, "success");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Generation failed", "error");
    }
    setGeneratingGoals(false);
  }, [projectPath, description, teamCount, agentsPer, node.assignedSkills, nodes]);

  const handleSave = useCallback(() => {
    updateNode(node.id, {
      name: ownerName,
      promptBody: description,
      variables: variables.filter((v) => v.name.trim()),
      lastModified: Date.now(),
    });
    saveTreeMetadata();
  }, [ownerName, description, variables, node.id, updateNode, saveTreeMetadata]);

  // Autosave on changes
  useAutosave(handleSave, [ownerName, description, variables], node.id);

  const handleAddSkill = () => {
    if (!addSkillId) return;
    // Cache the skill name so OrgNode can display it (without adding a visible node)
    const match = allSkills.find((s) => s.id === addSkillId);
    if (match) {
      cacheSkillName(addSkillId, match.name);
    }
    assignSkillToNode(node.id, addSkillId);
    setAddSkillId("");
  };

  const teamChildren = children.filter((c) => c.kind === "group");

  return (
    <div>
      {/* Company / Project Info */}
      <div style={{ marginBottom: 16 }}>
        <label style={rootLabelStyle}>Company / Project Name</label>
        <input
          style={rootInputStyle}
          value={ownerName}
          onChange={(e) => setOwnerName(e.target.value)}
          placeholder="e.g. Acme Corp, My SaaS Project"
        />
      </div>

      <div style={{ marginBottom: 16 }}>
        <label style={rootLabelStyle}>Description</label>
        <textarea
          rows={3}
          style={{ ...rootInputStyle, resize: "vertical" }}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Describe your company, project goals, or the work being done..."
        />
      </div>

      {/* Global Skills — collapsible */}
      <CollapsibleSection title="Global Skills" count={assignedSkills.length} defaultOpen={assignedSkills.length > 0}>
        <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 8, lineHeight: 1.4 }}>
          Skills assigned here are visible to every team and agent.
        </div>

        {assignedSkills.map((skill) => (
          <div
            key={skill.id}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "6px 8px",
              background: "var(--tint-green)",
              border: "1px solid var(--border-color)",
              borderRadius: 4,
              marginBottom: 4,
            }}
          >
            <span style={{ fontSize: 13, color: "var(--text-primary)" }}>{skill.name}</span>
            <button
              type="button"
              onClick={() => removeSkillFromNode(node.id, skill.id)}
              style={{
                background: "none",
                border: "none",
                color: "var(--text-secondary)",
                cursor: "pointer",
                padding: "0 4px",
                fontSize: 14,
                lineHeight: 1,
              }}
              title="Remove skill"
            >
              x
            </button>
          </div>
        ))}

        <div style={{ display: "flex", gap: 6, marginTop: 6 }}>
          <select
            style={{ ...rootInputStyle, flex: 1 }}
            value={addSkillId}
            onChange={(e) => setAddSkillId(e.target.value)}
          >
            <option value="">Add a skill...</option>
            {availableSkills.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>
          <button
            onClick={handleAddSkill}
            disabled={!addSkillId}
            style={{
              padding: "8px 12px",
              background: addSkillId ? "var(--accent-green)" : "var(--border-color)",
              color: "white",
              border: "none",
              borderRadius: 4,
              cursor: addSkillId ? "pointer" : "default",
              fontSize: 12,
              fontWeight: 600,
              whiteSpace: "nowrap",
              opacity: addSkillId ? 1 : 0.5,
            }}
          >
            Add
          </button>
        </div>
      </CollapsibleSection>

      {/* Global Variables — collapsible */}
      <CollapsibleSection title="Global Variables" count={variables.filter((v) => v.name.trim()).length} defaultOpen={variables.length > 0}>
        <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 10, lineHeight: 1.4 }}>
          API keys, passwords, and config values shared with every team during deployment.
        </div>
        <VariableEditor variables={variables} onChange={setVariables} accentColor="#d29922" />
      </CollapsibleSection>

      {/* Teams — collapsible */}
      <CollapsibleSection title="Teams" count={teamChildren.length}>
        {/* Generate with AI */}
        <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 8, lineHeight: 1.4 }}>
          Generate teams with AI or add them manually.
        </div>
        <div style={{ display: "flex", gap: 10, marginBottom: 10, alignItems: "center" }}>
          <div style={{ flex: 1 }}>
            <label style={{ ...rootLabelStyle, fontSize: 10 }}>Teams</label>
            <input
              type="number"
              min={1}
              max={10}
              value={teamCount}
              onChange={(e) => setTeamCount(Math.max(1, Math.min(10, Number(e.target.value))))}
              style={{ ...rootInputStyle, textAlign: "center" }}
            />
          </div>
          <div style={{ flex: 1 }}>
            <label style={{ ...rootLabelStyle, fontSize: 10 }}>Agents per team</label>
            <input
              type="number"
              min={1}
              max={10}
              value={agentsPer}
              onChange={(e) => setAgentsPer(Math.max(1, Math.min(10, Number(e.target.value))))}
              style={{ ...rootInputStyle, textAlign: "center" }}
            />
          </div>
        </div>
        <button
          onClick={handleGenerateFromGoals}
          disabled={generatingGoals || !description.trim()}
          style={{
            width: "100%",
            padding: "9px 16px",
            marginBottom: 8,
            background: generatingGoals || !description.trim() ? "var(--border-color)" : "var(--accent-blue)",
            color: "white",
            border: "none",
            borderRadius: 6,
            cursor: generatingGoals || !description.trim() ? "default" : "pointer",
            fontSize: 13,
            fontWeight: 600,
            opacity: !description.trim() ? 0.5 : 1,
            transition: "opacity 0.15s",
          }}
          title={!description.trim() ? "Add a description above to generate teams" : ""}
        >
          {generatingGoals ? "Generating..." : `Generate ${teamCount} x ${agentsPer} Teams`}
        </button>

        {/* Team list */}
        {teamChildren.length > 0 && (
          <div style={{ marginTop: 8 }}>
            {teamChildren.map((child) => (
              <div
                key={child.id}
                onClick={() => selectNode(child.id)}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  padding: "6px 8px",
                  background: "var(--tint-blue)",
                  border: "1px solid var(--border-color)",
                  borderRadius: 4,
                  marginBottom: 4,
                  cursor: "pointer",
                  transition: "background 0.15s",
                }}
                onMouseEnter={(e) => { e.currentTarget.style.background = "var(--tint-blue-hover)"; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = "var(--tint-blue)"; }}
              >
                <span style={{
                  display: "inline-block",
                  padding: "1px 6px",
                  borderRadius: 8,
                  fontSize: 10,
                  fontWeight: 600,
                  textTransform: "uppercase",
                  color: "white",
                  background: "var(--accent-blue)",
                }}>
                  team
                </span>
                <span style={{ fontSize: 13, color: "var(--text-primary)" }}>{child.name}</span>
              </div>
            ))}
          </div>
        )}

        <button
          onClick={() => openCreateDialog(node.id)}
          style={{
            width: "100%",
            padding: "8px 12px",
            marginTop: 6,
            background: "transparent",
            color: "var(--accent-blue)",
            border: "1px dashed var(--accent-blue)",
            borderRadius: 4,
            cursor: "pointer",
            fontSize: 12,
            fontWeight: 600,
          }}
        >
          + Add Team
        </button>
      </CollapsibleSection>

    </div>
  );
}
