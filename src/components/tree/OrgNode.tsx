import React, { memo, useMemo, useState } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import type { AuiNode, NodeKind } from "@/types/aui-node";
import { useUiStore } from "@/store/ui-store";
import { useTreeStore } from "@/store/tree-store";
import { toast } from "@/components/common/Toast";
import { getTeamColor } from "@/utils/grouping";

const KIND_COLORS: Record<NodeKind, string> = {
  agent: "#f0883e",
  skill: "#3fb950",
  settings: "#6e7681",
  human: "#d29922",
  context: "#8b5cf6",
  group: "#4a9eff",
  pipeline: "#d946ef",
  note: "#d29922",
};

function OrgNodeInner({ data, selected }: NodeProps) {
  const [hovered, setHovered] = useState(false);
  const node = data.auiNode as AuiNode;
  const hasErrors = node.validationErrors.length > 0;
  const isRoot = node.kind === "human";
  const isGroup = node.kind === "group";
  const isPipeline = node.kind === "pipeline";

  const description = isGroup || isPipeline
    ? node.promptBody
    : ((node.config as any)?.description ?? "");

  // Count children for group nodes, step count for pipelines
  const allNodes = useTreeStore((s) => s.nodes);
  const childCount = isGroup
    ? Array.from(allNodes.values()).filter((n) => n.parentId === node.id).length
    : 0;
  const stepCount = isPipeline ? node.pipelineSteps.length : 0;

  const collapsed = useUiStore((s) => s.collapsedGroups.has(node.id));
  const isMultiSelected = useUiStore((s) => s.multiSelectedNodeIds.has(node.id));

  // Determine if this group is an "agent" (nested inside another group/team)
  const parentNode = node.parentId ? allNodes.get(node.parentId) : null;
  const isMember = isGroup && parentNode?.kind === "group";

  // Determine if this is a sub-agent (parent is an agent, not a team)
  // A sub-agent's parent is either a file-based agent (kind === "agent")
  // or a member-agent (group whose parent is also a group)
  const parentIsMemberAgent = parentNode?.kind === "group" && parentNode.parentId
    ? allNodes.get(parentNode.parentId)?.kind === "group"
    : false;
  const isSubAgent = isGroup && (parentNode?.kind === "agent" || parentIsMemberAgent);

  // Team = blue, sub-agent = lighter blue, agent-in-team = orange, pipeline = magenta
  const color = isPipeline ? "#d946ef" : isSubAgent ? "#a5d6ff" : isMember ? "#f0883e" : KIND_COLORS[node.kind];

  // Build comprehensive skill ID → name map from all sources
  const skillNameCache = useTreeStore((s) => s.skillNameCache);
  const skillIdToName = useMemo(() => {
    const map = new Map<string, string>();
    // Source 1: live skill nodes in the store (most authoritative)
    for (const [id, n] of allNodes) {
      if (n.kind === "skill" && n.name) {
        map.set(id, n.name);
      }
    }
    // Source 2: persisted skillNameCache (covers skills not loaded as nodes)
    for (const [id, name] of skillNameCache) {
      if (!map.has(id)) {
        map.set(id, name);
      }
    }
    return map;
  }, [allNodes, skillNameCache]);

  // Resolve assigned skill names using the comprehensive map
  const skillNames: string[] = [];
  if (node.assignedSkills.length > 0) {
    for (const skillId of node.assignedSkills) {
      const name = skillIdToName.get(skillId);
      if (name) {
        skillNames.push(name);
      } else {
        console.warn(`[ATM] Skill ID "${skillId}" not resolved for group "${node.name}"`);
        skillNames.push(skillId);
      }
    }
  }

  const nodeWidth = isGroup || isPipeline ? 280 : isRoot ? 260 : 240;
  const glowStrength = selected ? "0 0 12px" : isMultiSelected ? "0 0 10px" : hovered ? "0 0 8px" : "none";
  const borderOpacity = selected ? 1 : 0.7;

  const handleContextMenu = (e: React.MouseEvent) => {
    e.preventDefault();
    useUiStore.getState().openContextMenu(e.clientX, e.clientY, node.id);
  };

  const handleDoubleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    const { inspectorOpen, toggleInspector, selectNode } = useUiStore.getState();
    selectNode(node.id);
    if (!inspectorOpen) toggleInspector();
  };

  const handleAddChild = (e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    useUiStore.getState().openCreateDialog(node.id);
  };

  const handleRemove = (e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    const name = useTreeStore.getState().removeNodeFromCanvas(node.id);
    if (name) toast(`Removed ${name} from canvas`, "info");
  };

  const currentHandleStyle = hovered ? handleHoverStyle : handleBaseStyle;

  const background = isPipeline
    ? "var(--tint-purple)"
    : isGroup
      ? isSubAgent
        ? "var(--tint-subagent)"
        : isMember
          ? "var(--tint-orange)"
          : "var(--tint-blue)"
      : isRoot
        ? "var(--tint-gold)"
        : "var(--bg-surface, #1c2333)";

  const borderLeftStyle = isGroup || isPipeline
    ? `4px dashed rgba(${hexToRgb(color)}, ${borderOpacity})`
    : `4px solid rgba(${hexToRgb(color)}, ${borderOpacity})`;

  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onContextMenu={handleContextMenu}
      onDoubleClick={handleDoubleClick}
      style={{
        width: nodeWidth,
        padding: 12,
        background,
        border: isMultiSelected ? "1px solid #8b5cf6" : "1px solid transparent",
        borderLeft: borderLeftStyle,
        borderRadius: 8,
        boxShadow: glowStrength !== "none" ? `${glowStrength} ${color}` : "none",
        position: "relative",
        cursor: "pointer",
        transition: "box-shadow 0.2s ease, border-color 0.2s ease",
      }}
    >
      <Handle type="target" position={Position.Top} style={currentHandleStyle} />

      {/* Validation error dot */}
      {hasErrors && (
        <div
          style={{
            position: "absolute",
            top: 6,
            left: 10,
            width: 8,
            height: 8,
            borderRadius: "50%",
            background: "#f85149",
          }}
        />
      )}

      {/* Kind badge */}
      <div
        style={{
          position: "absolute",
          top: 6,
          right: 8,
          fontSize: 9,
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: "0.05em",
          background: color,
          color: "#fff",
          padding: "1px 6px",
          borderRadius: 10,
        }}
      >
        {isRoot ? "YOU" : isPipeline ? "PROJECT MGR" : isSubAgent ? "SUB-AGENT" : isMember ? "AGENT" : isGroup ? "TEAM" : node.kind}
      </div>

      {/* Name */}
      <div
        style={{
          fontWeight: 700,
          fontSize: 14,
          color: "var(--text-primary)",
          marginTop: 4,
          marginBottom: 4,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          paddingRight: 50,
        }}
      >
        {node.name}
      </div>

      {/* Description - 2-line clamp */}
      <div
        style={{
          fontSize: 12,
          color: "var(--text-secondary)",
          lineHeight: "1.3",
          overflow: "hidden",
          display: "-webkit-box",
          WebkitLineClamp: 2,
          WebkitBoxOrient: "vertical",
        }}
      >
        {description || "\u00A0"}
      </div>

      {/* Group child count with collapse toggle */}
      {isGroup && (
        <div
          onClick={(e) => {
            e.stopPropagation();
            useUiStore.getState().toggleCollapse(node.id);
          }}
          onMouseDown={(e) => e.stopPropagation()}
          style={{
            fontSize: 11,
            color: isSubAgent ? "#a5d6ff" : isMember ? "#f0883e" : "#4a9eff",
            marginTop: 4,
            display: "flex",
            alignItems: "center",
            gap: 4,
            cursor: "pointer",
            userSelect: "none",
            padding: "2px 0",
            borderRadius: 4,
          }}
          title={collapsed ? "Expand group" : "Collapse group"}
        >
          <span>{collapsed ? "\u25B8" : "\u25BE"}</span>
          {childCount} {isMember
            ? (childCount === 1 ? "sub-agent" : "sub-agents")
            : (childCount === 1 ? "agent" : "agents")}
          {collapsed && (
            <span style={{ color: "#a0a0a0", fontSize: 10 }}>(collapsed)</span>
          )}
        </div>
      )}

      {/* Pipeline step count */}
      {isPipeline && (
        <div
          style={{
            fontSize: 11,
            color: "#d946ef",
            marginTop: 4,
            display: "flex",
            alignItems: "center",
            gap: 4,
          }}
        >
          {stepCount} {stepCount === 1 ? "step" : "steps"}
        </div>
      )}

      {/* Team indicator */}
      {node.team && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 4,
            marginTop: 4,
          }}
        >
          <div
            style={{
              width: 6,
              height: 6,
              borderRadius: "50%",
              background: getTeamColor(node.team),
              flexShrink: 0,
            }}
          />
          <span
            style={{
              fontSize: 10,
              color: "var(--text-tertiary)",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {node.team}
          </span>
        </div>
      )}

      {/* Assigned skill badges */}
      {skillNames.length > 0 && (
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 3,
            marginTop: 4,
          }}
        >
          {skillNames.map((name) => (
            <span
              key={name}
              style={{
                fontSize: 9,
                fontWeight: 600,
                color: "#3fb950",
                background: "var(--tint-green)",
                padding: "1px 5px",
                borderRadius: 8,
                whiteSpace: "nowrap",
              }}
            >
              {name}
            </span>
          ))}
        </div>
      )}

      {/* Hover action buttons */}
      {hovered && (
        <>
          {/* Delete button — all nodes except root */}
          {!isRoot && (
            <button
              onClick={handleRemove}
              onMouseDown={(e) => e.stopPropagation()}
              style={{
                position: "absolute",
                top: 6,
                left: -8,
                width: 16,
                height: 16,
                borderRadius: "50%",
                border: "none",
                background: "rgba(120, 120, 120, 0.6)",
                color: "#ddd",
                fontSize: 10,
                lineHeight: "14px",
                textAlign: "center",
                cursor: "pointer",
                padding: 0,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                transition: "background 0.15s, color 0.15s",
                zIndex: 10,
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = "rgba(248, 81, 73, 0.8)";
                e.currentTarget.style.color = "#fff";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = "rgba(120, 120, 120, 0.6)";
                e.currentTarget.style.color = "#ddd";
              }}
              title="Remove from canvas"
            >
              x
            </button>
          )}

          {/* Add child button */}
          <button
            onClick={handleAddChild}
            onMouseDown={(e) => e.stopPropagation()}
            style={{
              position: "absolute",
              bottom: 6,
              right: 6,
              width: 20,
              height: 20,
              borderRadius: "50%",
              border: "1px solid #4a9eff",
              background: "rgba(74, 158, 255, 0.15)",
              color: "#4a9eff",
              fontSize: 14,
              lineHeight: "18px",
              textAlign: "center",
              cursor: "pointer",
              padding: 0,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
            title="Add child node"
          >
            +
          </button>
        </>
      )}

      <Handle type="source" position={Position.Bottom} style={currentHandleStyle} />
    </div>
  );
}

const handleBaseStyle: React.CSSProperties = {
  width: 8,
  height: 8,
  background: "#4a9eff",
  border: "2px solid var(--bg-surface, #1c2333)",
  transition: "width 0.15s ease, height 0.15s ease",
};

const handleHoverStyle: React.CSSProperties = {
  ...handleBaseStyle,
  width: 12,
  height: 12,
};

function hexToRgb(hex: string): string {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `${r}, ${g}, ${b}`;
}

export const OrgNode = memo(OrgNodeInner);
