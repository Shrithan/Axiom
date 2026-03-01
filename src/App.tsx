// src/App.tsx
// Axiom v4 — Preview PDF Data Leakage Prevention

import { useEffect, useRef, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
type DetectionSource = "pdf" | "clipboard";

interface Detection {
  id: string;
  pattern_name: string;
  matched_text: string;
  severity: Severity;
  source: DetectionSource;
  page: number | null;
  timestamp_ms: number;
  detection_layer: "gemma";
  confidence?: string;
}

interface GemmaPageLog {
  page:         number;
  chunks:       number;
  raw_findings: number;
  kept:         number;
  duration_ms:  number;
  status:       "ok" | "empty" | "parse_error" | "blank";
}

interface ScanResult {
  detections:       Detection[];
  raw_text_snippet: string;
  pdf_path:         string | null;
  gemma_log:        GemmaPageLog[];
  model_id?:        string;
  device?:          string;
}

function fileIcon(path: string | null): string {
  if (!path) return '📄';
  const ext = path.split('.').pop()?.toLowerCase();
  if (ext === 'pdf')  return '📕';
  if (ext === 'docx' || ext === 'doc')  return '📝';
  if (ext === 'xlsx' || ext === 'xls')  return '📊';
  if (ext === 'pptx' || ext === 'ppt')  return '📑';
  return '📄';
}


interface PreviewStatus {
  status: "waiting" | "scanning" | "done";
  message: string;
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

const SEV_BORDER: Record<Severity, string> = {
  LOW: "#3b82f6", MEDIUM: "#eab308", HIGH: "#f97316", CRITICAL: "#ef4444",
};
const SEV_LABEL: Record<Severity, string> = { LOW:"Low", MEDIUM:"Med", HIGH:"High", CRITICAL:"CRIT" };

const IS_OVERLAY = getCurrentWebviewWindow().label === "overlay";

// ---------------------------------------------------------------------------
// Overlay — shows a warning badge when PII is found in the open PDF
// ---------------------------------------------------------------------------

function OverlayPage() {
  const [detectionCount, setDetectionCount] = useState(0);
  const [criticalCount,  setCriticalCount]  = useState(0);
  const [pdfName,        setPdfName]        = useState<string | null>(null);
  const [visible,        setVisible]        = useState(false);

  useEffect(() => {
    const win = getCurrentWebviewWindow();
    const unsubs: UnlistenFn[] = [];
    (async () => {
      unsubs.push(await win.listen<ScanResult>("scan_result", e => {
        const dets = e.payload.detections;
        const crits = dets.filter(d => d.severity === "CRITICAL").length;
        setDetectionCount(dets.length);
        setCriticalCount(crits);
        setPdfName(e.payload.pdf_path?.split("/").pop() ?? null);
        setVisible(dets.length > 0);
      }));
      unsubs.push(await win.listen("clear_overlay", () => {
        setVisible(false);
        setDetectionCount(0);
      }));
    })();
    return () => unsubs.forEach(u => u());
  }, []);

  if (!visible) return null;

  return (
    <div style={{
      position: "fixed", top: 20, right: 20,
      pointerEvents: "none",
      display: "flex", flexDirection: "column", gap: 8, alignItems: "flex-end",
    }}>
      {/* Main badge */}
      <div style={{
        background: criticalCount > 0 ? "rgba(127,29,29,0.95)" : "rgba(120,53,15,0.95)",
        border: `2px solid ${criticalCount > 0 ? "#ef4444" : "#f97316"}`,
        borderRadius: 10, padding: "10px 14px",
        display: "flex", alignItems: "center", gap: 10,
        boxShadow: `0 0 20px ${criticalCount > 0 ? "#ef444466" : "#f9731666"}`,
        backdropFilter: "blur(8px)",
      }}>
        <span style={{ fontSize: 22 }}>{criticalCount > 0 ? "🚨" : "⚠️"}</span>
        <div>
          <div style={{
            fontSize: 13, fontWeight: 800, color: "#fff",
            fontFamily: "monospace", letterSpacing: "0.05em",
          }}>
            {detectionCount} PII ITEM{detectionCount !== 1 ? "S" : ""} DETECTED
          </div>
          {pdfName && (
            <div style={{ fontSize: 10, color: "#fca5a5", marginTop: 2 }}>
              in {pdfName}
            </div>
          )}
        </div>
      </div>

      {/* Severity breakdown */}
      {criticalCount > 0 && (
        <div style={{
          background: "rgba(0,0,0,0.8)", border: "1px solid #991b1b",
          borderRadius: 6, padding: "4px 10px",
          fontSize: 10, color: "#fca5a5", fontFamily: "monospace",
        }}>
          ⚡ {criticalCount} CRITICAL — check Axiom panel
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Detection card
// ---------------------------------------------------------------------------

function DetectionCard({ d }: { d: Detection }) {
  const sev = d.severity;
  return (
    <div style={{
      background: "#111827",
      border: `1px solid ${SEV_BORDER[sev]}33`,
      borderLeft: `3px solid ${SEV_BORDER[sev]}`,
      borderRadius: 7, padding: "9px 11px", marginBottom: 6,
      animation: "fadeIn 0.2s ease",
    }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:4 }}>
        <span style={{ fontSize:11, fontWeight:700, color:SEV_BORDER[sev], fontFamily:"monospace", letterSpacing:"0.04em" }}>
          {d.pattern_name.replace(/_/g," ")}
        </span>
        <div style={{ display:"flex", gap:5, alignItems:"center" }}>
          {d.page && (
            <span style={{ fontSize:9, color:"#475569", fontFamily:"monospace" }}>p.{d.page}</span>
          )}
          <span style={{ fontSize:9, fontWeight:700, padding:"1px 5px", borderRadius:99,
            background: SEV_BORDER[sev]+"22", color: SEV_BORDER[sev] }}>
            {SEV_LABEL[sev]}
          </span>
        </div>
      </div>
      <div style={{ fontSize:12, fontFamily:"monospace", color:"#cbd5e1", marginBottom:4 }}>
        {d.matched_text}
      </div>
      <div style={{ display:"flex", gap:6, alignItems:"center" }}>
        <span style={{ fontSize:9, color:"#475569" }}>
          {d.source === "pdf" ? "📄 PDF" : "📋 Clipboard"}
        </span>
        <span style={{
          fontSize:8, fontWeight:700, padding:"1px 5px", borderRadius:99, fontFamily:"monospace",
          background: d.source === "pdf" ? "#1e1b4b" : "#1e293b",
          color:      d.source === "pdf" ? "#a78bfa" : "#475569",
        }}>
          {d.source === "pdf" ? "✦ gemma" : "· regex"}
        </span>
        {d.confidence && d.confidence !== "medium" && (
          <span style={{
            fontSize:8, padding:"1px 5px", borderRadius:99, fontFamily:"monospace",
            background:
              d.confidence === "high" ? "#14532d44" :
              d.confidence === "low"  ? "#44403c44" : "transparent",
            color:
              d.confidence === "high" ? "#4ade80" :
              d.confidence === "low"  ? "#a8a29e" : "#475569",
          }}>
            {d.confidence}
          </span>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Control panel
// ---------------------------------------------------------------------------

type ModelState = "idle" | "loading" | "ready" | "error";

function ControlPanel() {
  const [scanning,       setScanning]       = useState(false);
  const [overlayOn,      setOverlayOn]      = useState(false);
  const [detections,     setDetections]     = useState<Detection[]>([]);
  const [status,         setStatus]         = useState("Ready");
  const [modelState,     setModelState]     = useState<ModelState>("idle");
  const [modelError,     setModelError]     = useState<string | null>(null);
  const [currentPdf,     setCurrentPdf]     = useState<string | null>(null);
  const [previewWaiting, setPreviewWaiting] = useState(false);
  const [gemmaLog,       setGemmaLog]       = useState<GemmaPageLog[]>([]);
  const [modelDevice,    setModelDevice]    = useState<string | null>(null);
  const [modelName,      setModelName]      = useState<string>("google/gemma-3-4b-it");
  const [redacting,      setRedacting]      = useState(false);
  const [redactedPath,   setRedactedPath]   = useState<string | null>(null);

  const unlistenRef  = useRef<UnlistenFn | null>(null);
  const processedIds = useRef<Set<string>>(new Set());

  useEffect(() => {
    invoke<boolean>("get_overlay_active").then(setOverlayOn);

    const unsubs: Array<() => void> = [];

    listen("paligemma_ready", () => {
      setModelState("ready");
      setStatus("Scanner ready — watching Preview");
    }).then(u => unsubs.push(u));

    listen<string>("paligemma_error", e => {
      setModelState("error");
      setModelError(e.payload);
      setScanning(false);
      setStatus("⚠ Scanner error");
    }).then(u => unsubs.push(u));

    listen<PreviewStatus>("preview_status", e => {
      setPreviewWaiting(e.payload.status === "waiting");
      setStatus(e.payload.message);
      if (e.payload.status === "scanning") {
        setCurrentPdf(e.payload.message.replace("Scanning: ", ""));
      }
    }).then(u => unsubs.push(u));

    return () => unsubs.forEach(u => u());
  }, []);

  const handleScanResult = useCallback((payload: ScanResult) => {
    if (payload.pdf_path) setCurrentPdf(payload.pdf_path.split("/").pop() ?? null);
    if (payload.gemma_log?.length) setGemmaLog(payload.gemma_log);
    if (payload.model_id)  setModelName(payload.model_id);
    if (payload.device)    setModelDevice(payload.device);
    const fresh = payload.detections.filter(d => !processedIds.current.has(d.id));
    if (!fresh.length) {
      setStatus("Gemma scanned — no PII found");
      return;
    }
    fresh.forEach(d => processedIds.current.add(d.id));
    setDetections(prev => [...fresh, ...prev].slice(0, 200));
    const crits = fresh.filter(d => d.severity === "CRITICAL").length;
    setStatus(crits > 0
      ? `🚨 ${crits} critical finding${crits > 1 ? "s" : ""} in PDF`
      : `Found ${fresh.length} item${fresh.length > 1 ? "s" : ""} in PDF`
    );
  }, []);

  const toggleScan = useCallback(async () => {
    if (!scanning) {
      try {
        setModelState("loading");
        setModelError(null);
        setStatus("Starting PDF scanner…");
        await invoke("start_scanning");
        setScanning(true);
        const ul = await listen<ScanResult>("scan_result", e => handleScanResult(e.payload));
        unlistenRef.current = ul;
      } catch (err) {
        setModelState("error");
        setModelError(String(err));
        setScanning(false);
        setStatus(`Error: ${err}`);
      }
    } else {
      await invoke("stop_scanning");
      setScanning(false);
      setModelState("idle");
      setStatus("Stopped");
      setCurrentPdf(null);
      setPreviewWaiting(false);
      unlistenRef.current?.();
      unlistenRef.current = null;
    }
  }, [scanning, handleScanResult]);

  const toggleOverlay = useCallback(async () => {
    const next = !overlayOn;
    await invoke("set_overlay_visible", { visible: next });
    setOverlayOn(next);
  }, [overlayOn]);

  const scanClipboard = useCallback(async () => {
    try {
      const found = await invoke<Detection[]>("scan_clipboard_now");
      if (!found.length) { setStatus("Clipboard: clean ✓"); return; }
      handleScanResult({ detections: found, raw_text_snippet: "", pdf_path: null, gemma_log: [] });
      setStatus(`Clipboard: ${found.length} item(s) flagged`);
    } catch (err) { setStatus(`Clipboard error: ${err}`); }
  }, [handleScanResult]);

  const redactDocument = useCallback(async () => {
    if (!detections.length) return;
    try {
      setRedacting(true);
      setStatus("Creating redacted copy…");
      const path = await invoke<string>("redact_document");
      setRedactedPath(path);
      setStatus("✓ Redacted preview opened in Preview");
    } catch (err) {
      setStatus(`Redact error: ${err}`);
    } finally {
      setRedacting(false);
    }
  }, [detections]);

  useEffect(() => () => { unlistenRef.current?.(); }, []);

  const critical = detections.filter(d => d.severity === "CRITICAL").length;
  const high     = detections.filter(d => d.severity === "HIGH").length;

  return (
    <div style={{
      width:"100vw", height:"100vh", background:"#0a0f1e", color:"#e2e8f0",
      fontFamily:"'SF Pro Display','Segoe UI',system-ui,sans-serif",
      display:"flex", flexDirection:"column", overflow:"hidden",
    }}>
      <style>{`
        @keyframes fadeIn { from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none} }
        @keyframes pulse  { 0%,100%{opacity:1}50%{opacity:0.3} }
        @keyframes spin   { from{transform:rotate(0deg)}to{transform:rotate(360deg)} }
        ::-webkit-scrollbar{width:4px}
        ::-webkit-scrollbar-track{background:#0f172a}
        ::-webkit-scrollbar-thumb{background:#1e293b;border-radius:2px}
      `}</style>

      {/* Header */}
      <div style={{ padding:"14px 16px 10px", borderBottom:"1px solid #1e293b", background:"#070d1a" }}>
        <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between" }}>
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <div style={{
              width:30, height:30,
              background:"linear-gradient(135deg,#1d4ed8,#7c3aed)",
              borderRadius:8, display:"flex", alignItems:"center", justifyContent:"center",
              fontSize:15, boxShadow:"0 0 12px #7c3aed55",
            }}>🛡</div>
            <div>
              <div style={{ fontSize:13, fontWeight:800, letterSpacing:"0.12em", color:"#f8fafc", fontFamily:"monospace" }}>
                AXIOM
              </div>
              <div style={{ fontSize:8, color:"#475569", letterSpacing:"0.1em" }}>
                DATA LEAKAGE PREVENTION
              </div>
            </div>
          </div>
          <div style={{ display:"flex", gap:4 }}>
            {critical > 0 && (
              <span style={{ background:"#dc2626", color:"#fff", fontSize:9, fontWeight:700, padding:"2px 7px", borderRadius:99, animation:"pulse 2s infinite" }}>
                {critical} CRIT
              </span>
            )}
            {high > 0 && (
              <span style={{ background:"#ea580c", color:"#fff", fontSize:9, fontWeight:700, padding:"2px 7px", borderRadius:99 }}>
                {high} HIGH
              </span>
            )}
          </div>
        </div>

        {/* Status bar */}
        <div style={{
          marginTop:8, padding:"5px 8px", background:"#0f172a", borderRadius:5,
          fontSize:10, color:"#64748b", display:"flex", alignItems:"center", gap:6,
        }}>
          <span style={{
            width:7, height:7, borderRadius:"50%",
            background: scanning ? (previewWaiting ? "#f97316" : "#22c55e") : "#334155",
            display:"inline-block",
            boxShadow: scanning ? "0 0 6px #22c55e" : "none",
            animation: scanning ? "pulse 1.5s infinite" : "none",
          }}/>
          {status}
        </div>
      </div>

      {/* Current PDF indicator */}
      {currentPdf && (
        <div style={{
          margin:"8px 14px 0", padding:"8px 10px",
          background:"#0f172a", border:"1px solid #1e3a5f",
          borderRadius:6, display:"flex", alignItems:"center", gap:8,
        }}>
          <span style={{ fontSize:16 }}>{fileIcon(currentPdf)}</span>
          <div style={{ flex:1, minWidth:0 }}>
            <div style={{ fontSize:9, color:"#475569", marginBottom:2 }}>SCANNING</div>
            <div style={{ fontSize:11, color:"#93c5fd", fontFamily:"monospace", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
              {currentPdf}
            </div>
          </div>
        </div>
      )}

      {/* Waiting for Preview indicator */}
      {scanning && previewWaiting && !currentPdf && (
        <div style={{
          margin:"8px 14px 0", padding:"12px",
          background:"#0f172a", border:"1px solid #1e293b",
          borderRadius:6, textAlign:"center",
        }}>
          <div style={{ fontSize:24, marginBottom:6 }}>📂</div>
          <div style={{ fontSize:11, color:"#64748b" }}>
            Open a PDF, DOCX, XLSX, or PPTX to begin scanning
          </div>
        </div>
      )}

      {/* Gemma engine badge */}
      <div style={{
        margin:"8px 14px 0", padding:"8px 10px",
        background:"#0f172a",
        border:`1px solid ${modelState === "ready" ? "#4c1d95" : modelState === "error" ? "#7f1d1d" : modelState === "loading" ? "#1e3a5f" : "#1e293b"}`,
        borderRadius:6,
      }}>
        <div style={{ display:"flex", alignItems:"center", gap:8 }}>
          <span style={{ fontSize:16, color:"#a78bfa" }}>✦</span>
          <div style={{ flex:1 }}>
            <div style={{ fontSize:10, fontFamily:"monospace", display:"flex", alignItems:"center", gap:6 }}>
              <strong style={{ color:"#a78bfa" }}>{modelName}</strong>
              {modelDevice && (
                <span style={{ fontSize:8, padding:"1px 5px", borderRadius:99,
                  background:"#312e81", color:"#a5b4fc" }}>
                  {modelDevice}
                </span>
              )}
            </div>
            <div style={{ fontSize:9, marginTop:1,
              color: modelState==="ready" ? "#a78bfa" : modelState==="error" ? "#ef4444" : modelState==="loading" ? "#60a5fa" : "#64748b"
            }}>
              {modelState === "idle"      ? "Click Start to load Gemma"
               : modelState === "loading" ? "Loading Gemma 3 4B model…"
               : modelState === "ready"   ? "Gemma 4B active · regex + semantic PII scan"
               : modelError?.split("\n")[0] ?? "Error"}
            </div>
          </div>
        </div>
        {modelState === "error" && modelError && (
          <div style={{ marginTop:6, fontFamily:"monospace", fontSize:9, color:"#f87171",
            background:"#1e0f0f", padding:"5px 8px", borderRadius:4, whiteSpace:"pre-wrap" }}>
            {modelError}
          </div>
        )}
      </div>

      {/* Gemma activity log */}
      {gemmaLog.length > 0 && (
        <div style={{
          margin:"8px 14px 0", padding:"8px 10px",
          background:"#0a0e1f", border:"1px solid #1e1b4b",
          borderRadius:6,
        }}>
          <div style={{ fontSize:9, color:"#6366f1", fontFamily:"monospace",
            fontWeight:700, marginBottom:5, letterSpacing:"0.06em" }}>
            ✦ GEMMA ACTIVITY LOG
          </div>
          <div style={{ display:"flex", flexDirection:"column", gap:3 }}>
            {gemmaLog.map(entry => (
              <div key={entry.page} style={{
                display:"flex", alignItems:"center", gap:6,
                fontSize:9, fontFamily:"monospace",
              }}>
                <span style={{ color:"#475569", minWidth:28 }}>p{entry.page}</span>
                <span style={{
                  width:6, height:6, borderRadius:"50%", flexShrink:0,
                  background:
                    entry.status === "ok"          ? "#22c55e" :
                    entry.status === "parse_error" ? "#ef4444" :
                    entry.status === "blank"        ? "#334155" :
                                                     "#64748b",
                }}/>
                <span style={{ color:"#64748b", flex:1 }}>
                  {entry.status === "blank"        ? "blank page" :
                   entry.status === "parse_error"  ? `parse error (${entry.chunks} chunk${entry.chunks!==1?"s":""})` :
                   entry.status === "empty"         ? `${entry.chunks} chunk${entry.chunks!==1?"s":""} · no PII found` :
                   `${entry.chunks} chunk${entry.chunks!==1?"s":""} · ${entry.raw_findings} raw · ${entry.kept} kept`}
                </span>
                <span style={{ color:"#334155" }}>{entry.duration_ms}ms</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Controls */}
      <div style={{ padding:"10px 14px", borderBottom:"1px solid #1e293b", display:"flex", flexDirection:"column", gap:7, marginTop:8 }}>
        <button
          onClick={toggleScan}
          disabled={modelState === "loading"}
          style={{
            width:"100%", padding:"9px 0", fontSize:12, fontWeight:700,
            borderRadius:6, border:"none",
            background: modelState==="loading" ? "#1e3a5f" : scanning ? "#991b1b" : "#065f46",
            color:"#fff",
            cursor: modelState==="loading" ? "wait" : "pointer",
            letterSpacing:"0.04em",
          }}
        >
          {modelState === "loading" ? "⏳ Starting…"
           : scanning ? "⏹  Stop Watching"
           : "▶  Watch Preview"}
        </button>

        <div style={{ display:"flex", gap:7 }}>
          <button onClick={scanClipboard} style={{
            flex:1, padding:"7px 0", fontSize:11, fontWeight:600,
            borderRadius:6, border:"none", background:"#1e293b", color:"#94a3b8", cursor:"pointer",
          }}>📋 Scan Clipboard</button>
          <button onClick={toggleOverlay} style={{
            flex:1, padding:"7px 0", fontSize:11, fontWeight:600,
            borderRadius:6, border:"none",
            background: overlayOn ? "#451a03" : "#1e293b",
            color: overlayOn ? "#fcd34d" : "#94a3b8",
            cursor:"pointer",
          }}>
            {overlayOn ? "🔲 Hide Overlay" : "🔳 Show Overlay"}
          </button>
        </div>

        {detections.length > 0 && (
          <>
            <button
              onClick={redactDocument}
              disabled={redacting}
              style={{
                width:"100%", padding:"8px 0", fontSize:11, fontWeight:700,
                borderRadius:6, border:"none", cursor: redacting ? "wait" : "pointer",
                background: redacting ? "#1e3a5f" : "#7c3aed",
                color:"#fff", letterSpacing:"0.04em",
                opacity: redacting ? 0.7 : 1,
              }}
            >
              {redacting ? "⏳ Redacting…" : "🔏 Preview Redacted Copy"}
            </button>
            {redactedPath && (
              <div style={{
                fontSize:9, color:"#a78bfa", fontFamily:"monospace",
                background:"#1e1b4b", borderRadius:4, padding:"4px 8px",
                overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap",
              }}>
                ✓ {redactedPath.split("/").pop()}
              </div>
            )}
            <button
              onClick={() => { setDetections([]); setGemmaLog([]); setRedactedPath(null); processedIds.current.clear(); setStatus("Cleared"); }}
              style={{ fontSize:9, color:"#334155", background:"none", border:"none", cursor:"pointer", padding:"1px 0" }}
            >
              Clear {detections.length} result(s)
            </button>
          </>
        )}
      </div>

      {/* Detection list */}
      <div style={{ flex:1, overflowY:"auto", padding:"10px 14px" }}>
        {detections.length === 0 ? (
          <div style={{ textAlign:"center", padding:"40px 20px" }}>
            <div style={{ fontSize:36, marginBottom:10, opacity:0.3 }}>📄</div>
            <p style={{ fontSize:11, lineHeight:1.7, color:"#334155" }}>
              No sensitive data detected yet.<br/>
              Open a PDF, DOCX, XLSX, or PPTX and click Watch.
            </p>
          </div>
        ) : detections.map(d => <DetectionCard key={d.id} d={d} />)}
      </div>

      {/* Footer */}
      <div style={{
        padding:"7px 14px", borderTop:"1px solid #0f172a",
        fontSize:8, color:"#1e293b", textAlign:"center", letterSpacing:"0.06em",
      }}>
        100% LOCAL · NO SCREEN RECORDING · NO DATA LEAVES THIS DEVICE
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
