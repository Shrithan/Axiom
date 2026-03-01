// src/App.tsx
// Axiom v2 — Local-first Data Leakage Prevention (VLM edition)
//
// Detection is now fully done server-side in Rust:
//   screenshot → base64 → Ollama VLM → JSON detections → overlay
//
// This frontend only:
//   1. Starts/stops scanning via Tauri commands
//   2. Listens for "scan_result" events and renders detection cards
//   3. Renders the transparent overlay canvas in the overlay window
//
// No AI inference happens in the browser.

import { useEffect, useRef, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";

// ---------------------------------------------------------------------------
// Types — mirror Rust structs exactly
// ---------------------------------------------------------------------------

type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
type DetectionSource = "screen" | "clipboard";

interface BoundingBox {
  x: number; y: number;
  width: number; height: number;
  screen_width: number; screen_height: number;
}

interface Detection {
  id: string;
  pattern_name: string;
  matched_text: string;
  severity: Severity;
  source: DetectionSource;
  bbox: BoundingBox | null;
  timestamp_ms: number;
}

interface ScanResult {
  detections: Detection[];
  raw_text_snippet: string;
}

interface ModelInfo {
  model: string;
  ollama_url: string;
}

// ---------------------------------------------------------------------------
// Constants / theme
// ---------------------------------------------------------------------------

const SEV_COLOR: Record<Severity, string> = {
  LOW:      "rgba(59,130,246,0.25)",
  MEDIUM:   "rgba(234,179,8,0.35)",
  HIGH:     "rgba(249,115,22,0.45)",
  CRITICAL: "rgba(239,68,68,0.55)",
};
const SEV_BORDER: Record<Severity, string> = {
  LOW: "#3b82f6", MEDIUM: "#eab308", HIGH: "#f97316", CRITICAL: "#ef4444",
};
const SEV_ORDER: Record<Severity, number> = {
  CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1,
};
const SEV_LABEL: Record<Severity, string> = {
  LOW: "Low", MEDIUM: "Med", HIGH: "High", CRITICAL: "CRIT",
};

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

const IS_OVERLAY = window.location.pathname === "/overlay";

// ---------------------------------------------------------------------------
// OVERLAY PAGE
// Transparent full-screen canvas with highlight boxes.
// ---------------------------------------------------------------------------

function OverlayPage() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const draw = useCallback((detections: Detection[]) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    canvas.width  = window.screen.width;
    canvas.height = window.screen.height;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const hits = detections
      .filter(d => d.source === "screen" && d.bbox)
      .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);

    for (const d of hits) {
      const bbox = d.bbox!;
      const sev  = d.severity;

      // bbox coords are already in pixels (set by Rust from normalised VLM output)
      const scaleX = canvas.width  / bbox.screen_width;
      const scaleY = canvas.height / bbox.screen_height;
      const pad = 6;
      const rx = bbox.x * scaleX - pad;
      const ry = bbox.y * scaleY - pad;
      const rw = bbox.width  * scaleX + pad * 2;
      const rh = bbox.height * scaleY + pad * 2;

      // Glow
      ctx.shadowColor = SEV_BORDER[sev];
      ctx.shadowBlur  = sev === "CRITICAL" ? 14 : 7;

      // Fill
      ctx.fillStyle = SEV_COLOR[sev];
      ctx.beginPath();
      ctx.roundRect(rx, ry, rw, rh, 5);
      ctx.fill();

      // Border
      ctx.shadowBlur  = 0;
      ctx.strokeStyle = SEV_BORDER[sev];
      ctx.lineWidth   = sev === "CRITICAL" ? 2.5 : 1.5;
      ctx.beginPath();
      ctx.roundRect(rx, ry, rw, rh, 5);
      ctx.stroke();

      // Label badge
      const label = `${SEV_LABEL[sev]}: ${d.pattern_name.replace(/_/g, " ")}`;
      ctx.font = "bold 11px 'SF Mono', 'Fira Code', monospace";
      const tw = ctx.measureText(label).width;
      const bw = tw + 12, bh = 20;
      const bx = rx, by = Math.max(0, ry - bh - 3);

      ctx.fillStyle = SEV_BORDER[sev];
      ctx.beginPath();
      ctx.roundRect(bx, by, bw, bh, 3);
      ctx.fill();
      ctx.fillStyle = "#ffffff";
      ctx.fillText(label, bx + 6, by + 14);
    }
  }, []);

  useEffect(() => {
    const unsubs: UnlistenFn[] = [];
    (async () => {
      const win = getCurrentWebviewWindow();
      unsubs.push(await win.listen<ScanResult>("scan_result", e => draw(e.payload.detections)));
      unsubs.push(await win.listen("clear_overlay", () => {
        const canvas = canvasRef.current;
        if (canvas) {
          const ctx = canvas.getContext("2d");
          ctx?.clearRect(0, 0, canvas.width, canvas.height);
        }
      }));
    })();
    return () => unsubs.forEach(u => u());
  }, [draw]);

  return (
    <canvas
      ref={canvasRef}
      style={{ position: "fixed", inset: 0, pointerEvents: "none", background: "transparent" }}
    />
  );
}

// ---------------------------------------------------------------------------
// Detection card
// ---------------------------------------------------------------------------

function DetectionCard({ d }: { d: Detection }) {
  const sev = d.severity;
  const age = Math.round((Date.now() - d.timestamp_ms) / 1000);

  return (
    <div style={{
      background: "#111827",
      border: `1px solid ${SEV_BORDER[sev]}33`,
      borderLeft: `3px solid ${SEV_BORDER[sev]}`,
      borderRadius: 7,
      padding: "9px 11px",
      marginBottom: 6,
      animation: "fadeIn 0.2s ease",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
        <span style={{ fontSize: 11, fontWeight: 700, color: SEV_BORDER[sev], fontFamily: "monospace", letterSpacing: "0.04em" }}>
          {d.pattern_name.replace(/_/g, " ")}
        </span>
        <span style={{
          fontSize: 9, fontWeight: 700, padding: "1px 5px", borderRadius: 99,
          background: SEV_BORDER[sev] + "22", color: SEV_BORDER[sev],
        }}>
          {SEV_LABEL[sev]}
        </span>
      </div>
      <div style={{ fontSize: 12, fontFamily: "monospace", color: "#cbd5e1", marginBottom: 4 }}>
        {d.matched_text}
      </div>
      <div style={{ display: "flex", gap: 8, fontSize: 9, color: "#475569" }}>
        <span>{d.source === "screen" ? "🖥 Screen" : "📋 Clipboard"}</span>
        {d.bbox && <span>📍 {Math.round(d.bbox.x)},{Math.round(d.bbox.y)}</span>}
        <span>{age < 5 ? "just now" : `${age}s ago`}</span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// CONTROL PANEL PAGE
// ---------------------------------------------------------------------------

function ControlPanel() {
  const [scanning,    setScanning]    = useState(false);
  const [overlayOn,   setOverlayOn]   = useState(false);
  const [detections,  setDetections]  = useState<Detection[]>([]);
  const [status,      setStatus]      = useState("Ready — click Start Scanning");
  const [modelInfo,   setModelInfo]   = useState<ModelInfo | null>(null);
  const [ollamaOk,    setOllamaOk]    = useState<boolean | null>(null);

  const unlistenRef   = useRef<UnlistenFn | null>(null);
  const processedIds  = useRef<Set<string>>(new Set());

  // Load model info and probe Ollama on mount
  useEffect(() => {
    invoke<ModelInfo>("get_model_info").then(info => {
      setModelInfo(info);
      // Quick connectivity check
      fetch(`${info.ollama_url}/api/tags`, { signal: AbortSignal.timeout(3000) })
        .then(r => setOllamaOk(r.ok))
        .catch(() => setOllamaOk(false));
    });
    invoke<boolean>("get_overlay_active").then(setOverlayOn);
  }, []);

  const handleScanResult = useCallback((payload: ScanResult) => {
    const fresh = payload.detections.filter(d => !processedIds.current.has(d.id));
    if (!fresh.length) return;
    fresh.forEach(d => processedIds.current.add(d.id));
    setDetections(prev => [...fresh, ...prev].slice(0, 100));
  }, []);

  const toggleScan = useCallback(async () => {
    if (!scanning) {
      try {
        await invoke("start_scanning");
        setScanning(true);
        setStatus(`Scanning · ${modelInfo?.model ?? "VLM"} · every 3s`);
        const ul = await listen<ScanResult>("scan_result", e => handleScanResult(e.payload));
        unlistenRef.current = ul;
      } catch (err) { setStatus(`Error: ${err}`); }
    } else {
      await invoke("stop_scanning");
      setScanning(false);
      setStatus("Paused");
      unlistenRef.current?.();
      unlistenRef.current = null;
    }
  }, [scanning, handleScanResult, modelInfo]);

  const toggleOverlay = useCallback(async () => {
    const next = !overlayOn;
    await invoke("set_overlay_visible", { visible: next });
    setOverlayOn(next);
    setStatus(next ? "Overlay active" : "Overlay hidden");
  }, [overlayOn]);

  const scanClipboard = useCallback(async () => {
    try {
      const found = await invoke<Detection[]>("scan_clipboard_now");
      if (!found.length) { setStatus("Clipboard: clean ✓"); return; }
      handleScanResult({ detections: found, raw_text_snippet: "" });
      setStatus(`Clipboard: ${found.length} item(s) flagged`);
    } catch (err) { setStatus(`Clipboard error: ${err}`); }
  }, [handleScanResult]);

  useEffect(() => () => { unlistenRef.current?.(); }, []);

  const critical = detections.filter(d => d.severity === "CRITICAL").length;
  const high     = detections.filter(d => d.severity === "HIGH").length;

  return (
    <div style={{
      width: "100vw", height: "100vh",
      background: "#0a0f1e",
      color: "#e2e8f0",
      fontFamily: "'SF Pro Display', 'Segoe UI', system-ui, sans-serif",
      display: "flex", flexDirection: "column",
      overflow: "hidden",
    }}>
      <style>{`
        @keyframes fadeIn { from { opacity:0; transform:translateY(-4px); } to { opacity:1; transform:none; } }
        @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:0.4; } }
        ::-webkit-scrollbar { width:4px; }
        ::-webkit-scrollbar-track { background:#0f172a; }
        ::-webkit-scrollbar-thumb { background:#1e293b; border-radius:2px; }
      `}</style>

      {/* Header */}
      <div style={{ padding: "14px 16px 10px", borderBottom: "1px solid #1e293b", background: "#070d1a" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{
              width: 30, height: 30,
              background: "linear-gradient(135deg, #1d4ed8, #7c3aed)",
              borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 15, boxShadow: "0 0 12px #7c3aed55",
            }}>
              🛡
            </div>
            <div>
              <div style={{ fontSize: 13, fontWeight: 800, letterSpacing: "0.12em", color: "#f8fafc", fontFamily: "monospace" }}>
                AXIOM
              </div>
              <div style={{ fontSize: 8, color: "#475569", letterSpacing: "0.1em" }}>
                DATA LEAKAGE PREVENTION · VLM EDITION
              </div>
            </div>
          </div>
          <div style={{ display: "flex", gap: 4 }}>
            {critical > 0 && (
              <span style={{ background: "#dc2626", color: "#fff", fontSize: 9, fontWeight: 700, padding: "2px 7px", borderRadius: 99, animation: "pulse 2s infinite" }}>
                {critical} CRIT
              </span>
            )}
            {high > 0 && (
              <span style={{ background: "#ea580c", color: "#fff", fontSize: 9, fontWeight: 700, padding: "2px 7px", borderRadius: 99 }}>
                {high} HIGH
              </span>
            )}
          </div>
        </div>

        {/* Status strip */}
        <div style={{
          marginTop: 8, padding: "5px 8px",
          background: "#0f172a", borderRadius: 5,
          fontSize: 10, color: "#64748b",
          display: "flex", alignItems: "center", gap: 6,
        }}>
          <span style={{
            width: 7, height: 7, borderRadius: "50%",
            background: scanning ? "#22c55e" : "#334155",
            display: "inline-block",
            boxShadow: scanning ? "0 0 6px #22c55e" : "none",
            animation: scanning ? "pulse 1.5s infinite" : "none",
          }} />
          {status}
        </div>
      </div>

      {/* Model info badge */}
      {modelInfo && (
        <div style={{
          margin: "8px 14px 0",
          padding: "6px 10px",
          background: "#0f172a",
          border: `1px solid ${ollamaOk === false ? "#7f1d1d" : ollamaOk ? "#14532d" : "#1e293b"}`,
          borderRadius: 6,
          display: "flex", alignItems: "center", gap: 8, fontSize: 10,
        }}>
          <span style={{ fontSize: 14 }}>{ollamaOk === false ? "⚠️" : ollamaOk ? "🤖" : "⏳"}</span>
          <div style={{ flex: 1 }}>
            <div style={{ color: "#94a3b8", fontFamily: "monospace" }}>
              <strong style={{ color: "#c084fc" }}>{modelInfo.model}</strong>
              {" · "}
              <span style={{ color: "#64748b" }}>{modelInfo.ollama_url}</span>
            </div>
            <div style={{ color: ollamaOk === false ? "#ef4444" : ollamaOk ? "#4ade80" : "#64748b", fontSize: 9, marginTop: 1 }}>
              {ollamaOk === null ? "Checking Ollama…" : ollamaOk ? "Ollama reachable · VLM ready" : "Ollama not found — run: ollama serve"}
            </div>
          </div>
        </div>
      )}

      {/* Controls */}
      <div style={{ padding: "10px 14px", borderBottom: "1px solid #1e293b", display: "flex", flexDirection: "column", gap: 7, marginTop: 4 }}>
        <button
          onClick={toggleScan}
          disabled={ollamaOk === false}
          style={{
            width: "100%", padding: "9px 0",
            fontSize: 12, fontWeight: 700,
            borderRadius: 6, border: "none",
            background: ollamaOk === false ? "#1e293b" : scanning ? "#991b1b" : "#065f46",
            color: ollamaOk === false ? "#475569" : "#fff",
            cursor: ollamaOk === false ? "not-allowed" : "pointer",
            letterSpacing: "0.04em",
            transition: "background 0.2s",
          }}
        >
          {scanning ? "⏹  Stop Scanning" : "▶  Start Scanning"}
        </button>

        <div style={{ display: "flex", gap: 7 }}>
          <button onClick={scanClipboard} style={{
            flex: 1, padding: "7px 0", fontSize: 11, fontWeight: 600,
            borderRadius: 6, border: "none",
            background: "#1e293b", color: "#94a3b8", cursor: "pointer",
          }}>
            📋 Scan Clipboard
          </button>
          <button onClick={toggleOverlay} style={{
            flex: 1, padding: "7px 0", fontSize: 11, fontWeight: 600,
            borderRadius: 6, border: "none",
            background: overlayOn ? "#451a03" : "#1e293b",
            color: overlayOn ? "#fcd34d" : "#94a3b8",
            cursor: "pointer",
            transition: "background 0.2s",
          }}>
            {overlayOn ? "🔲 Hide Overlay" : "🔳 Show Overlay"}
          </button>
        </div>

        {detections.length > 0 && (
          <button
            onClick={() => { setDetections([]); processedIds.current.clear(); }}
            style={{ fontSize: 9, color: "#334155", background: "none", border: "none", cursor: "pointer", padding: "1px 0" }}
          >
            Clear {detections.length} result(s)
          </button>
        )}
      </div>

      {/* Detection list */}
      <div style={{ flex: 1, overflowY: "auto", padding: "10px 14px" }}>
        {detections.length === 0 ? (
          <div style={{ textAlign: "center", padding: "40px 20px", color: "#1e293b" }}>
            <div style={{ fontSize: 36, marginBottom: 10, opacity: 0.4 }}>🔍</div>
            <p style={{ fontSize: 11, lineHeight: 1.7, color: "#334155" }}>
              No sensitive data detected.
              <br />Start scanning to monitor your screen with {modelInfo?.model ?? "the VLM"}.
            </p>
          </div>
        ) : detections.map(d => <DetectionCard key={d.id} d={d} />)}
      </div>

      {/* Footer */}
      <div style={{
        padding: "7px 14px",
        borderTop: "1px solid #0f172a",
        fontSize: 8, color: "#1e293b",
        textAlign: "center", letterSpacing: "0.06em",
      }}>
        100% LOCAL · NO DATA LEAVES THIS DEVICE · OLLAMA + {modelInfo?.model?.toUpperCase() ?? "VLM"}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Root
// ---------------------------------------------------------------------------

export default function App() {
  return IS_OVERLAY ? <OverlayPage /> : <ControlPanel />;
}
