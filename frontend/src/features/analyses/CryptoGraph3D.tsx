/**
 * CryptoGraph3D.tsx — Feature 1
 *
 * Interactive 3D IKE SA / cryptographic handshake visualizer.
 * Uses @react-three/fiber + @react-three/drei.
 *
 * Renders the IKEv2 negotiation as an orbiting 3D node graph:
 *   - Initiator ↔ Responder endpoint spheres
 *   - Accepted proposal nodes (green = strong, amber = moderate)
 *   - Rejected/not-selected proposals (red, below center plane)
 *   - Child SA / ESP node (blue)
 *   - Animated glowing edges
 *
 * Click a node to open its detail panel.
 * The camera orbits continuously; the user can drag/rotate/zoom.
 */
import type { ReactNode, MutableRefObject } from "react";
import { Suspense, useRef, useState, useMemo } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { OrbitControls, Text, Sphere, Line } from "@react-three/drei";
import type * as THREE from "three";

import type { AnalysisDetail } from "@/api/client";
import { buildHandshakeGraph } from "./graphUtils";
import type { GraphNode, GraphEdge } from "./graphUtils";

// ─── Color mapping ────────────────────────────────────────────────────────────
const KIND_COLOR: Record<string, string> = {
  initiator: "#af50ff",   // Signal Violet
  responder: "#af50ff",   // Signal Violet
  proposal: "#4ade80",    // Green (overridden per-node for weak)
  child_sa: "#60a5fa",    // Blue
};

const EDGE_COLOR: Record<string, string> = {
  accepted: "#4ade80",
  rejected: "#f87171",
  weak: "#fbbf24",
  unknown: "#828384",
};

// ─── Sub-components ───────────────────────────────────────────────────────────

function NodeMesh({
  node,
  isSelected,
  onClick,
}: {
  node: GraphNode;
  isSelected: boolean;
  onClick: () => void;
}): ReactNode {
  const meshRef = useRef<THREE.Mesh>(null!);

  const isWeak = node.detail?.startsWith("⚠");
  const color =
    node.kind === "proposal"
      ? isWeak
        ? "#fbbf24"
        : "#4ade80"
      : KIND_COLOR[node.kind] ?? "#af50ff";

  const size =
    node.kind === "initiator" || node.kind === "responder"
      ? 0.38
      : node.kind === "child_sa"
        ? 0.3
        : 0.22;

  // Gentle float animation
  useFrame((state) => {
    if (meshRef.current) {
      meshRef.current.position.y =
        node.position[1] + Math.sin(state.clock.elapsedTime * 0.6 + node.position[0]) * 0.06;
    }
  });

  return (
    <group position={node.position}>
      {/* Outer glow sphere */}
      <Sphere ref={meshRef} args={[size * 1.4, 12, 12]}>
        <meshBasicMaterial
          color={color}
          transparent
          opacity={isSelected ? 0.25 : 0.08}
        />
      </Sphere>

      {/* Core sphere */}
      <Sphere
        args={[size, 16, 16]}
        onClick={(e) => { e.stopPropagation(); onClick(); }}
      >
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={isSelected ? 0.8 : 0.3}
          metalness={0.3}
          roughness={0.4}
        />
      </Sphere>

      {/* Label */}
      <Text
        position={[0, size + 0.25, 0]}
        fontSize={0.18}
        color={color}
        anchorX="center"
        anchorY="bottom"
        maxWidth={2.4}
      >
        {node.label}
      </Text>
    </group>
  );
}

function EdgeLine({
  from,
  to,
  kind,
}: {
  from: [number, number, number];
  to: [number, number, number];
  kind: GraphEdge["kind"];
}): ReactNode {
  const color = EDGE_COLOR[kind] ?? "#828384";
  const lineRef = useRef<THREE.Line>(null!);

  // Subtle pulse on accepted edges
  useFrame((state) => {
    if (lineRef.current && kind === "accepted") {
      (lineRef.current.material as THREE.LineBasicMaterial).opacity =
        0.5 + Math.sin(state.clock.elapsedTime * 1.5) * 0.2;
    }
  });

  const points: [number, number, number][] = [from, to];

  return (
    <Line
      ref={lineRef as MutableRefObject<never>}
      points={points}
      color={color}
      lineWidth={kind === "accepted" ? 1.5 : 0.8}
      transparent
      opacity={kind === "rejected" ? 0.35 : 0.65}
      dashed={kind === "rejected"}
      dashSize={0.15}
      gapSize={0.08}
    />
  );
}

function Scene({
  nodes,
  edges,
  selectedId,
  onSelect,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}): ReactNode {
  const nodeMap = useMemo(() => {
    const m = new Map<string, GraphNode>();
    for (const n of nodes) m.set(n.id, n);
    return m;
  }, [nodes]);

  return (
    <>
      <ambientLight intensity={0.4} />
      <pointLight position={[5, 5, 5]} intensity={1.2} color="#af50ff" />
      <pointLight position={[-5, -5, -3]} intensity={0.6} color="#60a5fa" />

      {edges.map((edge) => {
        const fromNode = nodeMap.get(edge.from);
        const toNode = nodeMap.get(edge.to);
        if (!fromNode || !toNode) return null;
        return (
          <EdgeLine
            key={edge.id}
            from={fromNode.position}
            to={toNode.position}
            kind={edge.kind}
          />
        );
      })}

      {nodes.map((node) => (
        <NodeMesh
          key={node.id}
          node={node}
          isSelected={selectedId === node.id}
          onClick={() => onSelect(node.id)}
        />
      ))}

      <OrbitControls
        autoRotate
        autoRotateSpeed={0.4}
        enableDamping
        dampingFactor={0.08}
        minDistance={4}
        maxDistance={16}
      />
    </>
  );
}

// ─── Main export ──────────────────────────────────────────────────────────────

export default function CryptoGraph3D({
  detail,
}: {
  detail: AnalysisDetail;
}): ReactNode {
  const graph = useMemo(() => buildHandshakeGraph(detail), [detail]);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const selectedNode = graph.nodes.find((n) => n.id === selectedId) ?? null;

  const isWeak = (node: GraphNode) =>
    node.kind === "proposal" && node.detail?.startsWith("⚠");

  return (
    <div
      role="region"
      aria-label="3D IKE cryptographic handshake visualizer"
      className="space-y-3"
    >
      <div className="flex flex-wrap items-center gap-3">
        <h3 className="font-medium">IKE SA Crypto Negotiation Graph</h3>
        {graph.ikeVersion !== null && (
          <span className="mono rounded border border-line px-2 py-0.5 text-xs text-ink-muted">
            {graph.ikeVersion}
          </span>
        )}
        {graph.transforms !== null && (
          <span className="mono rounded border border-prov-observed px-2 py-0.5 text-xs text-prov-observed">
            {graph.transforms}
          </span>
        )}
      </div>

      <p className="max-w-xl text-sm text-ink-muted">
        Drag to rotate · Scroll to zoom · Click a node to inspect.
        Dashed red edges = offered but not selected. Amber nodes = weak algorithms.
      </p>

      {/* 3D Canvas */}
      <div
        className="overflow-hidden rounded border border-line"
        style={{ height: 420, background: "#090909" }}
      >
        <Canvas
          camera={{ position: [0, 1.5, 9], fov: 50 }}
          gl={{ antialias: true, alpha: true }}
        >
          <Suspense fallback={null}>
            <Scene
              nodes={graph.nodes}
              edges={graph.edges}
              selectedId={selectedId}
              onSelect={(id) =>
                setSelectedId((prev) => (prev === id ? null : id))
              }
            />
          </Suspense>
        </Canvas>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-4 text-xs" aria-label="Graph legend">
        {[
          { color: "#af50ff", label: "IKE Endpoint" },
          { color: "#4ade80", label: "Accepted algorithm" },
          { color: "#fbbf24", label: "Weak / deprecated algorithm" },
          { color: "#f87171", label: "Rejected proposal" },
          { color: "#60a5fa", label: "Child SA / ESP" },
        ].map(({ color, label }) => (
          <span key={label} className="flex items-center gap-1.5">
            <span
              aria-hidden="true"
              className="inline-block h-2 w-2 rounded-full"
              style={{ background: color }}
            />
            <span style={{ color }}>{label}</span>
          </span>
        ))}
      </div>

      {/* Node detail panel */}
      {selectedNode !== null && (
        <div
          className="rounded border border-line bg-surface-raised p-3"
          role="region"
          aria-label={`Node detail: ${selectedNode.label}`}
        >
          <p className="font-medium mono text-sm">{selectedNode.label}</p>
          <p className="text-xs text-ink-muted">
            Type: <strong>{selectedNode.kind.replace(/_/g, " ")}</strong>
          </p>
          {selectedNode.detail !== undefined && (
            <p
              className="mt-1 text-sm"
              style={{
                color: isWeak(selectedNode)
                  ? "#fbbf24"
                  : selectedNode.detail.startsWith("✗")
                    ? "#f87171"
                    : "#4ade80",
              }}
            >
              {selectedNode.detail}
            </p>
          )}
        </div>
      )}

      {graph.nodes.length <= 2 && (
        <p className="text-sm text-ink-muted" role="note">
          Insufficient IKE transform evidence in this capture to build a full graph.
          The graph shows only the observed endpoints.
        </p>
      )}
    </div>
  );
}
