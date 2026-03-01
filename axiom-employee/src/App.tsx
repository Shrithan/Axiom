import React, { useState, useEffect, useRef, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow';
import { sendNotification, onAction } from '@tauri-apps/plugin-notification';
import { open, save } from '@tauri-apps/plugin-dialog';
import './app.css';

// ── Ripple keyframe injected once ────────────────────────────────────────────
const RIPPLE_STYLE = `
@keyframes axiom-ripple {
  to { transform: scale(4); opacity: 0; }
}
@keyframes axiom-press {
  0%   { transform: scale(1); }
  40%  { transform: scale(0.94); }
  100% { transform: scale(1); }
}
@keyframes axiom-glow-pulse {
  0%, 100% { box-shadow: 0 0 0 0 var(--glow-color, rgba(184,127,255,0)); }
  50%       { box-shadow: 0 0 18px 4px var(--glow-color, rgba(184,127,255,.3)); }
}
`;
if (typeof document !== 'undefined' && !document.getElementById('axiom-btn-styles')) {
  const s = document.createElement('style');
  s.id = 'axiom-btn-styles';
  s.textContent = RIPPLE_STYLE;
  document.head.appendChild(s);
}

// ── Types ─────────────────────────────────────────────────────────────────────
type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
type Page = 'home' | 'logs' | 'about';

interface AuthUser {
  id: string;
  name: string;
  department: string;
}

interface Detection {
  id: string;
  pattern_name: string;
  matched_text: string;
  severity: Severity;
  source: 'Pdf' | 'Clipboard';
  page: number | null;
  detection_layer: string;
  confidence: string;
  raw_value: string;
  timestamp_ms: number;
}

interface ScanResultPayload {
  detections: Detection[];
  pdf_path: string | null;
  model_id?: string | null;
  device?: string | null;
}

interface FileLog {
  fileName: string;
  fullPath: string;
  scannedAt: number;
  byType: Record<string, Detection[]>;
  totalCount: number;
  highestSeverity: Severity;
  redactedPath: string | null;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
const SEV_RANK: Record<Severity, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

function maxSeverity(dets: Detection[]): Severity {
  return dets.reduce<Severity>(
    (best, d) => SEV_RANK[d.severity] > SEV_RANK[best] ? d.severity : best, 'LOW'
  );
}
function fmtPath(p: string | null): string {
  if (!p || p === 'clipboard') return 'Clipboard';
  return p.split('/').pop() ?? p;
}
function fmtTime(ms: number): string {
  return new Date(ms).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
function fmtDate(ms: number): string {
  return new Date(ms).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false });
}

const SEV_PILL_CLS: Record<Severity, string> = {
  LOW: 'pill-ok', MEDIUM: 'pill-accent', HIGH: 'pill-high', CRITICAL: 'pill-danger',
};

// ── Pure SVG icon set (no emojis) ─────────────────────────────────────────────
const Icons = {
  File: () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
      <polyline points="14 2 14 8 20 8"/>
    </svg>
  ),
  Clipboard: () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="9" y="2" width="6" height="4" rx="1"/>
      <path d="M9 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2h-3"/>
    </svg>
  ),
  Shield: () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  ),
  Eye: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
      <circle cx="12" cy="12" r="3"/>
    </svg>
  ),
  Download: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
      <polyline points="7 10 12 15 17 10"/>
      <line x1="12" y1="15" x2="12" y2="3"/>
    </svg>
  ),
  Redact: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="18" height="18" rx="2"/>
      <line x1="9" y1="9" x2="15" y2="15"/>
      <line x1="15" y1="9" x2="9" y2="15"/>
    </svg>
  ),
  Play: () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" stroke="none">
      <polygon points="5 3 19 12 5 21 5 3"/>
    </svg>
  ),
  Stop: () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" stroke="none">
      <rect x="3" y="3" width="18" height="18" rx="2"/>
    </svg>
  ),
  Upload: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
      <polyline points="17 8 12 3 7 8"/>
      <line x1="12" y1="3" x2="12" y2="15"/>
    </svg>
  ),
  ClipboardScan: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
    </svg>
  ),
  Home: () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
      <polyline points="9 22 9 12 15 12 15 22"/>
    </svg>
  ),
  Logs: () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
      <polyline points="14 2 14 8 20 8"/>
      <line x1="16" y1="13" x2="8" y2="13"/>
      <line x1="16" y1="17" x2="8" y2="17"/>
    </svg>
  ),
  Cpu: () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="4" width="16" height="16" rx="2"/>
      <rect x="9" y="9" width="6" height="6"/>
      <line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/>
      <line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/>
      <line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/>
      <line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/>
    </svg>
  ),
  SSN: () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="5" width="20" height="14" rx="2"/>
      <line x1="2" y1="10" x2="22" y2="10"/>
    </svg>
  ),
  Email: () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
      <polyline points="22,6 12,13 2,6"/>
    </svg>
  ),
  Phone: () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07A19.5 19.5 0 0 1 4.69 12 19.79 19.79 0 0 1 1.61 3.35 2 2 0 0 1 3.59 1h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L7.91 8.96a16 16 0 0 0 6.29 6.29l1.46-1.46a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/>
    </svg>
  ),
  Key: () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/>
    </svg>
  ),
  Lock: () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
      <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </svg>
  ),
  Warning: () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z"/>
      <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  ),
  CreditCard: () => (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="1" y="4" width="22" height="16" rx="2" ry="2"/>
      <line x1="1" y1="10" x2="23" y2="10"/>
    </svg>
  ),
  Info: () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <line x1="12" y1="16" x2="12" y2="12"/>
      <line x1="12" y1="8" x2="12.01" y2="8"/>
    </svg>
  ),
  GemmaLogo: () => (
    <svg width="22" height="22" viewBox="0 0 60 60" fill="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="g1" x1="0" y1="0" x2="60" y2="60" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#8B5CF6"/>
          <stop offset="50%" stopColor="#6366F1"/>
          <stop offset="100%" stopColor="#3B82F6"/>
        </linearGradient>
        <linearGradient id="g2" x1="60" y1="0" x2="0" y2="60" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#A78BFA" stopOpacity="0.9"/>
          <stop offset="100%" stopColor="#60A5FA" stopOpacity="0.7"/>
        </linearGradient>
      </defs>
      <path d="M30 4 L52 18 L52 42 L30 56 L8 42 L8 18 Z" fill="url(#g1)" opacity="0.15" stroke="url(#g1)" strokeWidth="1.5"/>
      <path d="M30 12 L46 22 L46 38 L30 48 L14 38 L14 22 Z" fill="url(#g2)" opacity="0.2" stroke="url(#g2)" strokeWidth="1"/>
      <path d="M36 24 C36 24 32 22 28 24 C24 26 22 30 22 30 C22 30 22 34 26 36 C30 38 34 37 36 35 L36 30 L30 30"
        stroke="url(#g1)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
      <circle cx="30" cy="9" r="2" fill="#A78BFA" opacity="0.9"/>
      <circle cx="9" cy="19" r="1.5" fill="#818CF8" opacity="0.7"/>
      <circle cx="51" cy="19" r="1.5" fill="#818CF8" opacity="0.7"/>
      <circle cx="9" cy="41" r="1.5" fill="#818CF8" opacity="0.7"/>
      <circle cx="51" cy="41" r="1.5" fill="#818CF8" opacity="0.7"/>
      <circle cx="30" cy="51" r="2" fill="#60A5FA" opacity="0.8"/>
    </svg>
  ),
};

function patternIconEl(name: string): React.ReactElement {
  const n = name.toUpperCase();
  if (n === 'SSN') return <Icons.SSN />;
  if (n === 'CREDIT_CARD') return <Icons.CreditCard />;
  if (n === 'EMAIL') return <Icons.Email />;
  if (n === 'PHONE') return <Icons.Phone />;
  if (n === 'AWS_KEY' || n === 'JWT' || n === 'PRIVATE_KEY') return <Icons.Key />;
  if (n === 'PASSWORD') return <Icons.Lock />;
  return <Icons.Warning />;
}

// ── ActionBtn — ripple + press animation, no emojis ──────────────────────────
interface ActionBtnProps {
  onClick: () => void;
  disabled?: boolean;
  variant?: 'primary' | 'danger' | 'ghost' | 'success' | 'subtle';
  size?: 'lg' | 'md' | 'sm';
  icon?: React.ReactElement;
  fullWidth?: boolean;
  children: React.ReactNode;
  glowOnHover?: boolean;
}

function ActionBtn({ onClick, disabled, variant = 'primary', size = 'md', icon, fullWidth, children, glowOnHover }: ActionBtnProps) {
  const btnRef = useRef<HTMLButtonElement>(null);
  const [pressing, setPressing] = useState(false);

  const handleClick = (e: React.MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    if (disabled) return;

    // Ripple
    const btn = btnRef.current;
    if (btn) {
      const rect = btn.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const ripple = document.createElement('span');
      const rippleSize = Math.max(rect.width, rect.height);
      const rippleColor = variant === 'danger' ? 'rgba(255,100,120,0.35)'
        : variant === 'success' ? 'rgba(74,222,128,0.35)'
        : variant === 'subtle'  ? 'rgba(120,150,255,0.35)'
        : 'rgba(200,160,255,0.35)';
      ripple.style.cssText = `
        position:absolute; border-radius:50%; pointer-events:none;
        width:${rippleSize}px; height:${rippleSize}px;
        left:${x - rippleSize / 2}px; top:${y - rippleSize / 2}px;
        background: ${rippleColor};
        transform: scale(0); animation: axiom-ripple 480ms cubic-bezier(.2,.8,.3,1) forwards;
      `;
      btn.appendChild(ripple);
      setTimeout(() => ripple.remove(), 600);
    }

    // Press bounce
    setPressing(true);
    setTimeout(() => setPressing(false), 280);

    onClick();
  };

  const variantStyles: Record<string, React.CSSProperties> = {
    primary: { background: 'var(--neon-dim)', borderColor: 'rgba(184,127,255,.4)', color: 'var(--neon)', '--glow-color': 'rgba(184,127,255,.35)' } as React.CSSProperties,
    danger:  { background: 'rgba(255,61,90,.1)', borderColor: 'rgba(255,61,90,.4)', color: 'var(--danger)', '--glow-color': 'rgba(255,61,90,.3)' } as React.CSSProperties,
    ghost:   { background: 'rgba(255,255,255,.05)', borderColor: 'rgba(255,255,255,.1)', color: 'rgba(255,255,255,.65)' } as React.CSSProperties,
    success: { background: 'rgba(34,197,94,.1)', borderColor: 'rgba(34,197,94,.35)', color: '#4ade80', '--glow-color': 'rgba(34,197,94,.3)' } as React.CSSProperties,
    subtle:  { background: 'rgba(78,124,255,.1)', borderColor: 'rgba(78,124,255,.3)', color: 'var(--accent)', '--glow-color': 'rgba(78,124,255,.3)' } as React.CSSProperties,
  };

  const sizeStyles: Record<string, React.CSSProperties> = {
    lg: { padding: '13px 22px', fontSize: 13.5, borderRadius: 12, gap: 9,  letterSpacing: '.03em', textTransform: 'uppercase' as const },
    md: { padding: '11px 18px', fontSize: 12.5, borderRadius: 11, gap: 8 },
    sm: { padding: '9px 15px',  fontSize: 11.5, borderRadius: 10, gap: 7 },
  };

  return (
    <button
      ref={btnRef}
      onClick={handleClick}
      disabled={disabled}
      style={{
        position: 'relative', overflow: 'hidden',
        display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
        fontFamily: 'var(--sans)', fontWeight: 600, letterSpacing: '.01em',
        border: '1px solid', cursor: disabled ? 'not-allowed' : 'pointer',
        whiteSpace: 'nowrap', userSelect: 'none',
        width: fullWidth ? '100%' : undefined,
        opacity: disabled ? 0.42 : 1,
        transition: 'background 130ms, border-color 130ms, box-shadow 130ms, opacity 130ms',
        transform: pressing ? 'scale(0.95)' : 'scale(1)',
        ...sizeStyles[size],
        ...variantStyles[variant],
      }}
      onMouseEnter={e => {
        if (disabled || !glowOnHover) return;
        const c = variantStyles[variant]['--glow-color' as keyof React.CSSProperties] as string;
        if (c) (e.currentTarget as HTMLButtonElement).style.boxShadow = `0 0 24px 6px ${c}, 0 0 8px 1px ${c}`;
        (e.currentTarget as HTMLButtonElement).style.filter = 'brightness(1.12)';
      }}
      onMouseLeave={e => {
        (e.currentTarget as HTMLButtonElement).style.boxShadow = '';
        (e.currentTarget as HTMLButtonElement).style.filter = '';
      }}
    >
      {icon && <span style={{ display: 'flex', alignItems: 'center', flexShrink: 0 }}>{icon}</span>}
      {children}
    </button>
  );
}

// ── Particle Canvas ───────────────────────────────────────────────────────────
function ParticleCanvas() {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = ref.current; if (!c) return;
    const ctx = c.getContext('2d')!;
    let W = 0, H = 0, raf = 0;
    const pts = Array.from({ length: 60 }, () => ({
      x: Math.random(), y: Math.random(),
      vx: (Math.random() - .5) * .0003, vy: (Math.random() - .5) * .0003,
      r: Math.random() * 1.5 + .4, a: Math.random() * .5 + .1,
    }));
    const resize = () => { W = c.width = c.offsetWidth || 800; H = c.height = c.offsetHeight || 600; };
    window.addEventListener('resize', resize); resize();
    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      for (const p of pts) {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0) p.x = 1; if (p.x > 1) p.x = 0;
        if (p.y < 0) p.y = 1; if (p.y > 1) p.y = 0;
        ctx.beginPath(); ctx.arc(p.x * W, p.y * H, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(184,127,255,${p.a})`; ctx.fill();
      }
      raf = requestAnimationFrame(draw);
    };
    draw();
    return () => { window.removeEventListener('resize', resize); cancelAnimationFrame(raf); };
  }, []);
  return <canvas ref={ref} className="hero-canvas" />;
}

// ── SevPill ───────────────────────────────────────────────────────────────────
function SevPill({ sev }: { sev: Severity }) {
  return <span className={`pill ${SEV_PILL_CLS[sev]}`}>{sev}</span>;
}

// ── Model Badge with loading bar ─────────────────────────────────────────────
interface ModelBadgeProps { modelId: string | null; device: string | null; status: 'idle' | 'loading' | 'ready' | 'error'; }

const LOAD_PHASES = [
  { pct: 8,  text: 'Initializing runtime…' },
  { pct: 18, text: 'Loading tokenizer…' },
  { pct: 32, text: 'Allocating model weights…' },
  { pct: 48, text: 'Loading Gemma 3 4B…' },
  { pct: 63, text: 'Moving to device…' },
  { pct: 78, text: 'Warming up inference…' },
  { pct: 90, text: 'Running first pass…' },
  { pct: 97, text: 'Almost ready…' },
];

function ModelBadge({ modelId, device, status }: ModelBadgeProps) {
  const [loadPct, setLoadPct] = useState(0);
  const [phaseIdx, setPhaseIdx] = useState(0);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (status === 'loading') {
      setLoadPct(0); setPhaseIdx(0);
      let currentPhase = 0;
      intervalRef.current = setInterval(() => {
        currentPhase = Math.min(currentPhase + 1, LOAD_PHASES.length - 1);
        setPhaseIdx(currentPhase);
        setLoadPct(LOAD_PHASES[currentPhase].pct);
      }, 1800);
    } else if (status === 'ready') {
      if (intervalRef.current) clearInterval(intervalRef.current);
      setLoadPct(100);
    } else {
      if (intervalRef.current) clearInterval(intervalRef.current);
      setLoadPct(0); setPhaseIdx(0);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [status]);

  const statusColor = { idle: 'var(--muted2)', loading: 'var(--accent)', ready: '#a3e635', error: 'var(--danger)' }[status];
  const glowColor   = { idle: 'transparent', loading: 'rgba(78,124,255,.15)', ready: 'rgba(163,230,53,.12)', error: 'rgba(255,61,90,.15)' }[status];
  const borderColor = { idle: 'rgba(255,255,255,.08)', loading: 'rgba(78,124,255,.35)', ready: 'rgba(163,230,53,.4)', error: 'rgba(255,61,90,.4)' }[status];

  const displayName = modelId ?? (status === 'loading' || status === 'ready' ? 'Gemma 3 4B' : 'No model loaded');
  const loadingText = status === 'loading' ? LOAD_PHASES[phaseIdx].text : status === 'ready' ? 'Online · ' + (device ?? '') : status === 'idle' ? 'Not loaded' : 'Load failed';
  const barColor = status === 'ready' ? '#a3e635' : status === 'loading' ? 'var(--accent)' : 'var(--muted2)';

  return (
    <div style={{
      borderRadius: 11, overflow: 'hidden',
      background: `linear-gradient(135deg, rgba(255,255,255,.04), ${glowColor})`,
      border: `1px solid ${borderColor}`,
      transition: 'all 400ms ease',
      boxShadow: status === 'ready' ? '0 0 12px 0 rgba(163,230,53,.1)' : 'none',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '11px 13px 8px' }}>
        <div style={{
          width: 34, height: 34, borderRadius: 8, flexShrink: 0,
          background: 'linear-gradient(135deg, rgba(139,92,246,.15), rgba(99,102,241,.1))',
          border: `1px solid ${status === 'ready' ? 'rgba(163,230,53,.3)' : 'rgba(139,92,246,.25)'}`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          transition: 'all 400ms',
        }}>
          <Icons.GemmaLogo />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 11, fontWeight: 700, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginBottom: 3 }}>
            {displayName}
          </div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: statusColor, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', transition: 'color 400ms' }}>
            {loadingText}
          </div>
        </div>
      </div>
      {(status === 'loading' || status === 'ready') && (
        <div style={{ height: 3, background: 'rgba(255,255,255,.06)', margin: '0 13px 10px' }}>
          <div style={{
            height: '100%', borderRadius: 99,
            width: `${loadPct}%`,
            background: barColor,
            transition: status === 'ready' ? 'width 300ms ease' : 'width 1600ms cubic-bezier(.4,0,.2,1)',
            boxShadow: `0 0 6px ${barColor}`,
          }} />
        </div>
      )}
    </div>
  );
}

// ── FileLogCard ───────────────────────────────────────────────────────────────
interface FileLogCardProps {
  log: FileLog;
  defaultOpen?: boolean;
  onRedact: (fullPath: string) => Promise<void>;
  onPreview: (redactedPath: string) => void;
  onSave: (redactedPath: string) => Promise<void>;
  redacting: boolean;
}

function FileLogCard({ log, defaultOpen = false, onRedact, onPreview, onSave, redacting }: FileLogCardProps) {
  const [expanded, setExpanded] = useState(defaultOpen);
  const [expandedTypes, setExpandedTypes] = useState<Set<string>>(new Set());

  const toggleType = (type: string) =>
    setExpandedTypes(prev => { const n = new Set(prev); n.has(type) ? n.delete(type) : n.add(type); return n; });

  const sortedTypes = Object.entries(log.byType).sort(
    ([, a], [, b]) => SEV_RANK[maxSeverity(b)] - SEV_RANK[maxSeverity(a)] || b.length - a.length
  );

  const isClipboard = log.fullPath === 'clipboard';

  return (
    <div className="findings-card" style={{ marginBottom: 0 }}>
      {/* File header row */}
      <div
        className="findings-card-head"
        style={{ cursor: 'pointer', userSelect: 'none', gap: 10 }}
        onClick={() => setExpanded(o => !o)}
      >
        {/* Icon + name */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1, minWidth: 0 }}>
          <span style={{ color: isClipboard ? 'var(--accent)' : 'var(--neon)', flexShrink: 0 }}>
            {isClipboard ? <Icons.Clipboard /> : <Icons.File />}
          </span>
          <div style={{ minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span className="findings-card-title"
                style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 180 }}>
                {log.fileName}
              </span>
              <SevPill sev={log.highestSeverity} />
            </div>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--muted2)', marginTop: 2 }}>
              {fmtDate(log.scannedAt)} · {log.totalCount} flag{log.totalCount !== 1 ? 's' : ''} · {sortedTypes.length} type{sortedTypes.length !== 1 ? 's' : ''}
            </div>
          </div>
        </div>

        {/* Type chips */}
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', justifyContent: 'flex-end', maxWidth: 150 }}>
          {sortedTypes.slice(0, 3).map(([type, dets]) => (
            <span key={type} className={`pill ${SEV_PILL_CLS[maxSeverity(dets)]}`} style={{ fontSize: 8, padding: '2px 6px' }}>
              {type.replace(/_/g, '\u00A0')} {dets.length}
            </span>
          ))}
          {sortedTypes.length > 3 && (
            <span className="pill pill-muted" style={{ fontSize: 8, padding: '2px 6px' }}>+{sortedTypes.length - 3}</span>
          )}
        </div>

        {/* Action buttons — stopPropagation so they don't toggle accordion */}
        <div style={{ display: 'flex', gap: 6, flexShrink: 0 }} onClick={e => e.stopPropagation()}>
          {!isClipboard && !log.redactedPath && (
            <ActionBtn variant="danger" size="sm" icon={<Icons.Redact />}
              onClick={() => onRedact(log.fullPath)} disabled={redacting} glowOnHover>
              {redacting ? 'Redacting…' : 'Redact'}
            </ActionBtn>
          )}
          {log.redactedPath && (
            <>
              <ActionBtn variant="subtle" size="sm" icon={<Icons.Eye />}
                onClick={() => onPreview(log.redactedPath!)} glowOnHover>
                Preview
              </ActionBtn>
              <ActionBtn variant="success" size="sm" icon={<Icons.Download />}
                onClick={() => onSave(log.redactedPath!)} glowOnHover>
                Download
              </ActionBtn>
            </>
          )}
        </div>

        <span style={{ color: 'var(--muted2)', fontFamily: 'var(--mono)', fontSize: 10, flexShrink: 0 }}>
          {expanded ? '▲' : '▼'}
        </span>
      </div>

      {/* Expanded body: pattern-type groups */}
      {expanded && (
        <div>
          {sortedTypes.map(([type, dets]) => {
            const isTypeOpen = expandedTypes.has(type);
            const topSev = maxSeverity(dets);
            return (
              <div key={type}>
                <div
                  style={{
                    cursor: 'pointer', display: 'flex', alignItems: 'center',
                    justifyContent: 'space-between', padding: '9px 18px',
                    borderTop: '1px solid rgba(255,255,255,.04)',
                    background: 'rgba(255,255,255,.015)',
                  }}
                  onClick={() => toggleType(type)}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ color: 'var(--muted)', display: 'flex' }}>{patternIconEl(type)}</span>
                    <span style={{ fontFamily: 'var(--mono)', fontSize: 10, fontWeight: 700, letterSpacing: '.08em', textTransform: 'uppercase', color: 'var(--text)' }}>
                      {type.replace(/_/g, ' ')}
                    </span>
                    <SevPill sev={topSev} />
                    <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--muted2)' }}>
                      {dets.length} instance{dets.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                  <span style={{ color: 'var(--muted2)', fontSize: 10 }}>{isTypeOpen ? '▲' : '▼'}</span>
                </div>

                {isTypeOpen && dets.map(d => (
                  <div key={d.id} className="finding-row" style={{ paddingLeft: 40 }}>
                    <div className="f-info">
                      <div className="f-value" style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{d.matched_text}</div>
                      <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--muted2)', marginTop: 3, display: 'flex', gap: 10 }}>
                        {d.source === 'Pdf' && d.page != null && <span>p.{d.page}</span>}
                        {d.source === 'Clipboard' && <span>clipboard</span>}
                        {d.detection_layer && <span>{d.detection_layer}</span>}
                        {d.confidence && <span>{d.confidence} conf.</span>}
                        <span>{fmtTime(d.timestamp_ms)}</span>
                      </div>
                    </div>
                    <SevPill sev={d.severity} />
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── LogsPage ──────────────────────────────────────────────────────────────────
interface LogsPageProps {
  fileLogs: FileLog[];
  totalFlags: number;
  onRedact: (fullPath: string) => Promise<void>;
  onPreview: (redactedPath: string) => void;
  onSave: (redactedPath: string) => Promise<void>;
  redacting: boolean;
}

function LogsPage({ fileLogs, totalFlags, onRedact, onPreview, onSave, redacting }: LogsPageProps) {
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState<Severity | 'ALL'>('ALL');

  const filtered = fileLogs
    .map(log => {
      const byType: Record<string, Detection[]> = {};
      for (const [type, dets] of Object.entries(log.byType)) {
        const matching = dets.filter(d => {
          const matchesSev = sevFilter === 'ALL' || d.severity === sevFilter;
          const matchesSearch = !search
            || d.matched_text.toLowerCase().includes(search.toLowerCase())
            || d.pattern_name.toLowerCase().includes(search.toLowerCase())
            || log.fileName.toLowerCase().includes(search.toLowerCase());
          return matchesSev && matchesSearch;
        });
        if (matching.length) byType[type] = matching;
      }
      if (!Object.keys(byType).length) return null;
      const allDets = Object.values(byType).flat();
      return { ...log, byType, totalCount: allDets.length, highestSeverity: maxSeverity(allDets) } as FileLog;
    })
    .filter((l): l is FileLog => l !== null);

  const criticalTotal = fileLogs.reduce(
    (n, l) => n + Object.values(l.byType).flat().filter(d => d.severity === 'CRITICAL').length, 0
  );

  const sevBtns: (Severity | 'ALL')[] = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const sevBtnColor: Partial<Record<string, string>> = { CRITICAL: 'danger', HIGH: 'warn', MEDIUM: 'accent' };

  return (
    <div className="page-view" style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div className="log-stats-bar">
        <div className="log-stat-chip"><span style={{ color: 'var(--neon)' }}>●</span> Files <strong>{fileLogs.length}</strong></div>
        <div className="log-stat-sep" />
        <div className="log-stat-chip"><span style={{ color: 'var(--accent)' }}>●</span> Flags <strong>{totalFlags}</strong></div>
        <div className="log-stat-sep" />
        <div className="log-stat-chip"><span style={{ color: 'var(--danger)' }}>●</span> Critical <strong>{criticalTotal}</strong></div>
      </div>

      <div className="logs-toolbar">
        {sevBtns.map(s => (
          <button key={s} className={`log-filter-btn ${sevFilter === s ? 'active' : ''} ${sevBtnColor[s] ?? ''}`} onClick={() => setSevFilter(s)}>
            {s}
          </button>
        ))}
        <div className="logs-search">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
          </svg>
          <input placeholder="Search files, types, values…" value={search} onChange={e => setSearch(e.target.value)} />
        </div>
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 10, scrollbarWidth: 'thin' }}>
        {filtered.length === 0 ? (
          <div className="log-empty">
            <div className="log-empty-icon" style={{ display: 'flex', justifyContent: 'center', opacity: .4 }}><Icons.Shield /></div>
            <div className="log-empty-txt">
              {fileLogs.length === 0 ? 'No scans yet — run the detection algorithm or upload a file.' : 'No results match your filter.'}
            </div>
          </div>
        ) : (
          filtered.map((log, i) => (
            <FileLogCard
              key={log.fullPath + log.scannedAt}
              log={log}
              defaultOpen={i === 0}
              onRedact={onRedact}
              onPreview={onPreview}
              onSave={onSave}
              redacting={redacting}
            />
          ))
        )}
      </div>
    </div>
  );
}

// ── HomeDashboard ─────────────────────────────────────────────────────────────
interface HomeDashboardProps {
  fileLogs: FileLog[];
  totalFlags: number;
  scanning: boolean;
  onNavigate: (page: Page) => void;
  onRedact: (path: string) => Promise<void>;
  redacting: boolean;
}

function HomeDashboard({ fileLogs, totalFlags, scanning, onNavigate, onRedact, redacting }: HomeDashboardProps) {
  const allDets = fileLogs.flatMap(l => Object.values(l.byType).flat());
  const criticalCount = allDets.filter(d => d.severity === 'CRITICAL').length;
  const highCount     = allDets.filter(d => d.severity === 'HIGH').length;
  const filesScanned  = fileLogs.filter(l => l.fullPath !== 'clipboard').length;
  const redactedCount = fileLogs.filter(l => l.redactedPath).length;

  // Exposure score: weighted 0-100 — critical*10 + high*4 + medium*1, capped at 100
  const rawScore = Math.min(100, criticalCount * 10 + highCount * 4 + allDets.filter(d => d.severity === 'MEDIUM').length);
  const exposureScore = totalFlags === 0 ? 0 : rawScore;
  const scoreColor = exposureScore >= 70 ? 'var(--danger)' : exposureScore >= 35 ? '#f97316' : exposureScore > 0 ? 'var(--accent)' : '#4ade80';
  const scoreLabel = exposureScore >= 70 ? 'Critical Risk' : exposureScore >= 35 ? 'Elevated Risk' : exposureScore > 0 ? 'Moderate Risk' : 'Clean';

  // Files needing action: have CRITICAL or HIGH detections and not yet redacted
  const needsAction = fileLogs.filter(l =>
    l.fullPath !== 'clipboard' && !l.redactedPath &&
    Object.values(l.byType).flat().some(d => d.severity === 'CRITICAL' || d.severity === 'HIGH')
  );

  // Redaction coverage
  const coveragePct = filesScanned === 0 ? 0 : Math.round((redactedCount / filesScanned) * 100);

  // Detection source breakdown (regex vs gemma)
  const regexCount = allDets.filter(d => d.detection_layer === 'regex').length;
  const gemmaCount = allDets.filter(d => d.detection_layer !== 'regex').length;

  // PII type breakdown
  const typeCounts: Record<string, number> = {};
  for (const d of allDets) {
    const k = d.pattern_name.toUpperCase();
    typeCounts[k] = (typeCounts[k] ?? 0) + 1;
  }
  const topTypes = Object.entries(typeCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);

  const Card = ({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) => (
    <div style={{
      background: 'rgba(255,255,255,.04)', border: '1px solid rgba(255,255,255,.08)',
      borderRadius: 14, padding: '16px 18px', position: 'relative', overflow: 'hidden',
      ...style,
    }}>{children}</div>
  );

  const CardLabel = ({ children }: { children: React.ReactNode }) => (
    <div style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '.1em', textTransform: 'uppercase', color: 'var(--muted2)', marginBottom: 10 }}>
      {children}
    </div>
  );

  return (
    <div style={{
      position: 'relative', zIndex: 2,
      padding: '0 28px 28px',
      display: 'flex', flexDirection: 'column', gap: 12,
      maxWidth: 820, width: '100%', margin: '0 auto',
    }}>

      {/* Row 1: Exposure Score (wide) + 3 action cards */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr 1fr', gap: 10 }}>

        {/* Exposure Score */}
        <Card>
          <CardLabel>Exposure Score</CardLabel>
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: 10 }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 42, fontWeight: 900, color: scoreColor, lineHeight: 1 }}>
              {exposureScore}
            </div>
            <div style={{ marginBottom: 4 }}>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: scoreColor, fontWeight: 700 }}>{scoreLabel}</div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'var(--muted2)' }}>out of 100</div>
            </div>
          </div>
          {/* Score bar */}
          <div style={{ marginTop: 10, height: 4, borderRadius: 99, background: 'rgba(255,255,255,.06)' }}>
            <div style={{ height: '100%', borderRadius: 99, width: `${exposureScore}%`, background: scoreColor, transition: 'width 800ms ease', boxShadow: `0 0 8px ${scoreColor}66` }} />
          </div>
          <div style={{ position: 'absolute', bottom: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, ${scoreColor}55, transparent)` }} />
        </Card>

        {/* Files Needing Action */}
        <Card style={{ borderColor: needsAction.length > 0 ? 'rgba(255,61,90,.3)' : 'rgba(255,255,255,.08)' }}>
          <CardLabel>Needs Action</CardLabel>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 32, fontWeight: 900, color: needsAction.length > 0 ? 'var(--danger)' : '#4ade80', lineHeight: 1 }}>
            {needsAction.length}
          </div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--muted2)', marginTop: 4 }}>
            {needsAction.length === 0 ? 'all files redacted' : `file${needsAction.length !== 1 ? 's' : ''} unredacted`}
          </div>
          {needsAction.length > 0 && (
            <button onClick={() => onNavigate('logs')} style={{
              marginTop: 10, fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--danger)',
              background: 'rgba(255,61,90,.08)', border: '1px solid rgba(255,61,90,.25)',
              borderRadius: 6, padding: '4px 8px', cursor: 'pointer', letterSpacing: '.04em',
            }}>View in Logs →</button>
          )}
        </Card>

        {/* Redaction Coverage */}
        <Card>
          <CardLabel>Redaction Coverage</CardLabel>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 32, fontWeight: 900, color: coveragePct === 100 && filesScanned > 0 ? '#4ade80' : 'var(--neon)', lineHeight: 1 }}>
            {filesScanned === 0 ? '—' : `${coveragePct}%`}
          </div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--muted2)', marginTop: 4 }}>
            {redactedCount} of {filesScanned} files
          </div>
          <div style={{ marginTop: 10, height: 4, borderRadius: 99, background: 'rgba(255,255,255,.06)' }}>
            <div style={{ height: '100%', borderRadius: 99, width: `${coveragePct}%`, background: coveragePct === 100 && filesScanned > 0 ? '#4ade80' : 'var(--neon)', transition: 'width 800ms ease' }} />
          </div>
        </Card>

        {/* Critical + High */}
        <Card style={{ borderColor: criticalCount > 0 ? 'rgba(255,61,90,.25)' : 'rgba(255,255,255,.08)' }}>
          <CardLabel>Critical / High</CardLabel>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 32, fontWeight: 900, color: 'var(--danger)', lineHeight: 1 }}>{criticalCount}</span>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 18, color: 'rgba(255,255,255,.2)' }}>/</span>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 22, fontWeight: 700, color: '#f97316', lineHeight: 1 }}>{highCount}</span>
          </div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--muted2)', marginTop: 4 }}>
            critical · high severity
          </div>
        </Card>
      </div>

      {/* Row 2: Files at Risk list + Top PII Types */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>

        {/* Files at Risk */}
        <Card style={{ padding: '14px 16px' }}>
          <CardLabel>Files at Risk</CardLabel>
          {fileLogs.filter(l => l.fullPath !== 'clipboard').length === 0 ? (
            <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--muted2)', padding: '8px 0' }}>
              {scanning ? 'Monitoring open documents…' : 'No files scanned yet'}
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {fileLogs.filter(l => l.fullPath !== 'clipboard').slice(0, 5).map(log => {
                const criticals = Object.values(log.byType).flat().filter(d => d.severity === 'CRITICAL').length;
                const highs     = Object.values(log.byType).flat().filter(d => d.severity === 'HIGH').length;
                const riskColor = criticals > 0 ? 'var(--danger)' : highs > 0 ? '#f97316' : 'var(--accent)';
                return (
                  <div key={log.fullPath} style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '7px 10px', borderRadius: 8,
                    background: log.redactedPath ? 'rgba(74,222,128,.04)' : 'rgba(255,255,255,.03)',
                    border: `1px solid ${log.redactedPath ? 'rgba(74,222,128,.15)' : 'rgba(255,255,255,.06)'}`,
                  }}>
                    {/* Risk dot */}
                    <span style={{ width: 7, height: 7, borderRadius: '50%', background: log.redactedPath ? '#4ade80' : riskColor, flexShrink: 0, boxShadow: `0 0 5px ${log.redactedPath ? '#4ade8088' : riskColor + '88'}` }} />
                    <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {log.fileName}
                    </span>
                    <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--muted2)', flexShrink: 0 }}>{log.totalCount} flags</span>
                    {log.redactedPath ? (
                      <span style={{ fontFamily: 'var(--mono)', fontSize: 8, color: '#4ade80', padding: '2px 5px', borderRadius: 4, background: 'rgba(74,222,128,.1)', flexShrink: 0 }}>REDACTED</span>
                    ) : (
                      <button
                        disabled={redacting}
                        onClick={() => onRedact(log.fullPath)}
                        style={{
                          fontFamily: 'var(--mono)', fontSize: 8, color: riskColor,
                          background: `${riskColor}18`, border: `1px solid ${riskColor}44`,
                          borderRadius: 4, padding: '2px 6px', cursor: redacting ? 'not-allowed' : 'pointer',
                          flexShrink: 0, opacity: redacting ? 0.5 : 1,
                        }}>
                        Redact
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </Card>

        {/* Top PII Types + Detection Source */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <Card style={{ padding: '14px 16px', flex: 1 }}>
            <CardLabel>Top PII Types Detected</CardLabel>
            {topTypes.length === 0 ? (
              <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--muted2)' }}>
                {scanning ? 'Scanning…' : 'No detections yet'}
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {topTypes.map(([type, count]) => {
                  const pct = Math.round((count / totalFlags) * 100);
                  const sevColor = (() => {
                    const d = allDets.find(x => x.pattern_name.toUpperCase() === type);
                    if (!d) return 'var(--muted2)';
                    return { CRITICAL: 'var(--danger)', HIGH: '#f97316', MEDIUM: 'var(--accent)', LOW: 'var(--muted2)' }[d.severity];
                  })();
                  return (
                    <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ color: 'var(--muted)', flexShrink: 0 }}>{patternIconEl(type)}</span>
                      <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--text)', flex: 1 }}>{type.replace(/_/g, ' ')}</span>
                      <div style={{ width: 60, height: 3, borderRadius: 99, background: 'rgba(255,255,255,.07)', flexShrink: 0 }}>
                        <div style={{ height: '100%', borderRadius: 99, width: `${pct}%`, background: sevColor }} />
                      </div>
                      <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--muted2)', width: 18, textAlign: 'right', flexShrink: 0 }}>{count}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </Card>

          {/* Detection source: Gemma vs Regex */}
          <Card style={{ padding: '14px 16px' }}>
            <CardLabel>Detection Source</CardLabel>
            <div style={{ display: 'flex', gap: 14, alignItems: 'center' }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: '#a78bfa' }}>Gemma LLM</span>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--muted2)' }}>{gemmaCount}</span>
                </div>
                <div style={{ height: 4, borderRadius: 99, background: 'rgba(255,255,255,.07)' }}>
                  <div style={{ height: '100%', borderRadius: 99, width: totalFlags > 0 ? `${Math.round(gemmaCount/totalFlags*100)}%` : '0%', background: '#a78bfa', transition: 'width 600ms' }} />
                </div>
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--accent)' }}>Regex</span>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--muted2)' }}>{regexCount}</span>
                </div>
                <div style={{ height: 4, borderRadius: 99, background: 'rgba(255,255,255,.07)' }}>
                  <div style={{ height: '100%', borderRadius: 99, width: totalFlags > 0 ? `${Math.round(regexCount/totalFlags*100)}%` : '0%', background: 'var(--accent)', transition: 'width 600ms' }} />
                </div>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

// ── AboutPage ─────────────────────────────────────────────────────────────────
function AboutPage() {
  const steps = [
    {
      icon: <Icons.Eye />,
      title: 'Active App Monitor',
      color: 'var(--neon)',
      desc: `Axiom's background watcher uses macOS AppleScript to detect when you open a document in Preview, Excel, Word, Numbers, PowerPoint, Pages, or Keynote — no manual upload needed.`,
    },
    {
      icon: <Icons.Cpu />,
      title: 'Regex Pre-scan',
      color: 'var(--accent)',
      desc: 'A fast regex engine runs first, catching high-confidence patterns like SSNs, credit card numbers, emails, API keys, JWTs, and phone numbers with zero latency.',
    },
    {
      icon: <Icons.GemmaLogo />,
      title: 'Gemma 3 4B LLM',
      color: '#a78bfa',
      desc: `Google's Gemma 3 4B instruction-tuned model then reads every text chunk and extracts contextual PII — names, addresses, dates of birth, passport numbers, and more that regex alone misses.`,
    },
    {
      icon: <Icons.Redact />,
      title: 'Redaction Engine',
      color: '#f97316',
      desc: 'PDFs get visual block redaction via PyMuPDF with colored overlays. DOCX, XLSX, and PPTX are patched at the raw XML level inside the zip, preserving charts, formatting, and embedded objects.',
    },
    {
      icon: <Icons.Shield />,
      title: '100% Local',
      color: '#4ade80',
      desc: 'Every byte stays on your machine. No cloud API calls, no telemetry, no network requests. Gemma runs on-device via CPU, Metal (Apple Silicon), or CUDA — your documents never leave.',
    },
  ];

  const privacyPoints = [
    'No document content ever leaves your device',
    'No cloud inference — Gemma runs entirely on-device',
    'No analytics, telemetry, or usage tracking',
    'Redacted files written to a local temp directory only',
    'Clipboard scanning is on-demand only, never background',
    'Open source — inspect every line of the detection pipeline',
  ];

  return (
    <div className="page-view" style={{ height: '100%', overflowY: 'auto', scrollbarWidth: 'thin' }}>
      <div style={{ maxWidth: 680, margin: '0 auto', padding: '32px 28px 48px' }}>

        {/* Hero */}
        <div style={{ marginBottom: 36, textAlign: 'center' }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: 10, marginBottom: 16,
            padding: '6px 16px', borderRadius: 99,
            background: 'rgba(184,127,255,.08)', border: '1px solid rgba(184,127,255,.2)',
          }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#4ade80', boxShadow: '0 0 6px #4ade80' }} />
            <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--neon)', letterSpacing: '.1em', textTransform: 'uppercase' }}>
              Fully Local · Zero Cloud
            </span>
          </div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 26, fontWeight: 800, color: 'var(--text)', marginBottom: 10, letterSpacing: '-.01em' }}>
            How Axiom Works
          </div>
          <div style={{ fontFamily: 'var(--sans)', fontSize: 13, color: 'var(--muted)', lineHeight: 1.7, maxWidth: 480, margin: '0 auto' }}>
            Axiom is a privacy-first PII detection and redaction engine that runs entirely on your machine.
            No data ever leaves your device — not even a single byte.
          </div>
        </div>

        {/* Pipeline steps */}
        <div style={{ marginBottom: 32 }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '.12em', textTransform: 'uppercase', color: 'var(--muted2)', marginBottom: 14 }}>
            Detection Pipeline
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            {steps.map((step, i) => (
              <div key={i} style={{ display: 'flex', gap: 0 }}>
                {/* Step connector */}
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 40, flexShrink: 0 }}>
                  <div style={{
                    width: 32, height: 32, borderRadius: 10, flexShrink: 0,
                    background: `linear-gradient(135deg, ${step.color}22, ${step.color}0a)`,
                    border: `1px solid ${step.color}44`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    color: step.color, zIndex: 1,
                  }}>
                    {step.icon}
                  </div>
                  {i < steps.length - 1 && (
                    <div style={{ width: 1, flex: 1, minHeight: 12, background: `linear-gradient(to bottom, ${step.color}44, rgba(255,255,255,.06))`, margin: '2px 0' }} />
                  )}
                </div>
                {/* Content */}
                <div style={{ padding: '4px 0 20px 14px', flex: 1 }}>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: 11, fontWeight: 700, color: step.color, marginBottom: 4, letterSpacing: '.02em' }}>
                    {String(i + 1).padStart(2, '0')} · {step.title}
                  </div>
                  <div style={{ fontFamily: 'var(--sans)', fontSize: 12, color: 'var(--muted)', lineHeight: 1.65 }}>
                    {step.desc}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Privacy guarantee */}
        <div style={{
          borderRadius: 14, padding: '18px 20px',
          background: 'linear-gradient(135deg, rgba(74,222,128,.06), rgba(74,222,128,.02))',
          border: '1px solid rgba(74,222,128,.2)',
          marginBottom: 28,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <span style={{ color: '#4ade80' }}><Icons.Shield /></span>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 10, fontWeight: 700, color: '#4ade80', letterSpacing: '.08em', textTransform: 'uppercase' }}>
              Privacy Guarantee
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
            {privacyPoints.map((p, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                <span style={{ color: '#4ade80', fontSize: 10, marginTop: 2, flexShrink: 0 }}>✓</span>
                <span style={{ fontFamily: 'var(--sans)', fontSize: 12, color: 'var(--muted)', lineHeight: 1.5 }}>{p}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Supported apps */}
        <div style={{ marginBottom: 28 }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '.12em', textTransform: 'uppercase', color: 'var(--muted2)', marginBottom: 12 }}>
            Auto-detected Applications
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
            {[
              { app: 'Preview', fmt: 'PDF' },
              { app: 'Microsoft Excel', fmt: 'XLSX / XLS' },
              { app: 'Microsoft Word', fmt: 'DOCX / DOC' },
              { app: 'Microsoft PowerPoint', fmt: 'PPTX / PPT' },
              { app: 'Apple Numbers', fmt: 'XLSX-compatible' },
              { app: 'Apple Pages', fmt: 'DOCX-compatible' },
              { app: 'Apple Keynote', fmt: 'PPTX-compatible' },
            ].map(({ app, fmt }) => (
              <div key={app} style={{
                padding: '10px 12px', borderRadius: 10,
                background: 'rgba(255,255,255,.03)', border: '1px solid rgba(255,255,255,.07)',
              }}>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 10, fontWeight: 700, color: 'var(--text)', marginBottom: 2 }}>{app}</div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'var(--muted2)', letterSpacing: '.06em' }}>{fmt}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Tech stack */}
        <div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: '.12em', textTransform: 'uppercase', color: 'var(--muted2)', marginBottom: 12 }}>
            Tech Stack
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {['Tauri 2', 'Rust', 'React + TypeScript', 'Gemma 3 4B', 'PyMuPDF', 'python-docx', 'openpyxl', 'python-pptx', 'pdfminer.six', 'transformers', 'PyTorch'].map(t => (
              <span key={t} style={{
                fontFamily: 'var(--mono)', fontSize: 9, fontWeight: 600,
                padding: '3px 8px', borderRadius: 6,
                background: 'rgba(184,127,255,.07)', border: '1px solid rgba(184,127,255,.18)',
                color: '#c4b5fd', letterSpacing: '.04em',
              }}>{t}</span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── LoginPage ─────────────────────────────────────────────────────────────────
function LoginPage({ onLogin }: { onLogin: (u: AuthUser) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const user = await invoke<AuthUser>('login', { username, pass: password });
      onLogin(user);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg)', color: 'var(--text)' }}>
      <form onSubmit={handleLogin} style={{ background: 'var(--surface)', padding: 40, borderRadius: 16, border: '1px solid var(--border)', width: 340, display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div style={{ textAlign: 'center', marginBottom: 10 }}>
          <div style={{ fontFamily: 'var(--display)', fontSize: 24, fontWeight: 900, color: 'var(--neon)' }}>AXIOM</div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--muted2)', marginTop: 4, textTransform: 'uppercase', letterSpacing: '.1em' }}>Secure Employee Portal</div>
        </div>
        
        {error && <div style={{ color: 'var(--danger)', fontSize: 12, background: 'var(--danger-bg)', padding: '8px 12px', borderRadius: 8, border: '1px solid rgba(255,61,90,.3)' }}>{error}</div>}
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <label style={{ fontSize: 11, fontFamily: 'var(--mono)', color: 'var(--muted)' }}>Username</label>
          <input type="text" value={username} onChange={e => setUsername(e.target.value)} style={{ padding: 12, borderRadius: 10, border: '1px solid var(--border)', background: 'rgba(255,255,255,.02)', color: 'white', outline: 'none' }} required />
        </div>
        
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 10 }}>
          <label style={{ fontSize: 11, fontFamily: 'var(--mono)', color: 'var(--muted)' }}>Password</label>
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} style={{ padding: 12, borderRadius: 10, border: '1px solid var(--border)', background: 'rgba(255,255,255,.02)', color: 'white', outline: 'none' }} required />
        </div>
        
        <button type="submit" disabled={loading} style={{
          padding: '12px', borderRadius: 10, border: '1px solid rgba(184,127,255,.4)',
          background: 'var(--neon-dim)', color: 'var(--neon)', fontFamily: 'var(--sans)',
          fontWeight: 600, fontSize: 14, cursor: loading ? 'not-allowed' : 'pointer',
          transition: 'all 130ms', opacity: loading ? 0.6 : 1,
        }}>
          {loading ? 'Authenticating…' : 'Authenticate'}
        </button>
      </form>
    </div>
  );
}

export default function App() {
  const [authUser, setAuthUser] = useState<AuthUser | null>(null);

  const [page, setPage] = useState<Page>('home');
  const [scanning, setScanning] = useState(false);
  const [statusTxt, setStatusTxt] = useState('Ready');
  const [redacting, setRedacting] = useState(false);
  const [fileLogs, setFileLogs] = useState<FileLog[]>([]);
  const [modelId, setModelId] = useState<string | null>(null);
  const [device, setDevice] = useState<string | null>(null);
  const [modelStatus, setModelStatus] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle');
  const [detectedFile, setDetectedFile] = useState<{ path: string; fileName: string } | null>(null);

  const processedIds = useRef<Set<string>>(new Set());
  const totalFlags = fileLogs.reduce((n, l) => n + l.totalCount, 0);

  const handleScanResult = useCallback((payload: ScanResultPayload) => {
    const fresh = payload.detections.filter(d => !processedIds.current.has(d.id));
    if (!fresh.length) return;
    fresh.forEach(d => processedIds.current.add(d.id));

    if (payload.model_id) setModelId(payload.model_id);
    if (payload.device)   setDevice(payload.device);

    const fullPath = payload.pdf_path ?? 'clipboard';
    const fileName = fmtPath(payload.pdf_path);
    const now = Date.now();

    const byType: Record<string, Detection[]> = {};
    for (const d of fresh) {
      const key = d.pattern_name.toUpperCase();
      (byType[key] ??= []).push({ ...d, timestamp_ms: d.timestamp_ms || now });
    }

    setFileLogs(prev => {
      const idx = prev.findIndex(l => l.fullPath === fullPath);
      if (idx === -1) {
        return [{ fileName, fullPath, scannedAt: now, byType, totalCount: fresh.length, highestSeverity: maxSeverity(fresh), redactedPath: null }, ...prev];
      }
      const existing = prev[idx];
      const merged: Record<string, Detection[]> = { ...existing.byType };
      for (const [type, dets] of Object.entries(byType)) merged[type] = [...(merged[type] ?? []), ...dets];
      const allDets = Object.values(merged).flat();
      const updated: FileLog = { ...existing, scannedAt: now, byType: merged, totalCount: allDets.length, highestSeverity: maxSeverity(allDets) };
      const next = [...prev]; next.splice(idx, 1);
      return [updated, ...next];
    });

    sendNotification({ title: 'PII Detected', body: `${fresh.length} flag${fresh.length > 1 ? 's' : ''} in ${fileName}` });
    setDetectedFile(prev => (prev && prev.path === fullPath ? null : prev));
  }, []);

  useEffect(() => {
    const unsubs: (() => void)[] = [];

    onAction(() => {
      const win = getCurrentWebviewWindow();
      win.unminimize(); win.show(); win.setFocus();
    }).then((l: any) => unsubs.push(typeof l === 'function' ? l : () => l.unregister()));

    listen('paligemma_ready', (e: any) => {
      setModelStatus('ready');
      setStatusTxt('Detection algorithm ready');
      if (e.payload?.model_id) setModelId(e.payload.model_id);
      if (e.payload?.device)   setDevice(e.payload.device);
    }).then(u => unsubs.push(u));

    listen<ScanResultPayload>('scan_result', e => handleScanResult(e.payload)).then(u => unsubs.push(u));
    listen<{ message: string }>('preview_status', e => setStatusTxt(e.payload.message)).then(u => unsubs.push(u));

    listen<{ path: string; file_name: string }>('file_detected', e => {
      setDetectedFile({ path: e.payload.path, fileName: e.payload.file_name });
    }).then(u => unsubs.push(u));

    return () => unsubs.forEach(u => u());
  }, [handleScanResult]);

  const handleRedact = useCallback(async (fullPath: string) => {
    setRedacting(true);
    try {
      const log = fileLogs.find(l => l.fullPath === fullPath);
      const detections = log ? Object.values(log.byType).flat() : [];
      const path = await invoke<string>('redact_document', { sourcePath: fullPath, detections });
      setFileLogs(prev => prev.map(l => l.fullPath === fullPath ? { ...l, redactedPath: path } : l));
      setStatusTxt('Redaction complete');
    } catch (err) {
      console.error('[Axiom] redact_document error:', err);
      setStatusTxt(`Redaction error: ${String(err)}`);
    } finally {
      setRedacting(false);
    }
  }, [fileLogs]);

  const handlePreview = useCallback((redactedPath: string) => {
    invoke('open_in_preview', { path: redactedPath })
      .catch(err => console.error('[Axiom] open_in_preview error:', err));
  }, []);

  const handleSave = useCallback(async (redactedPath: string) => {
    try {
      const fileName = redactedPath.split('/').pop() ?? 'redacted';
      const ext = fileName.split('.').pop()?.toLowerCase() ?? 'pdf';
      const extFilters: Record<string, string[]> = {
        pdf: ['pdf'], docx: ['docx'], doc: ['doc'],
        xlsx: ['xlsx'], xls: ['xls'], pptx: ['pptx'], ppt: ['ppt'],
      };
      const dest = await save({
        defaultPath: fileName,
        filters: [{ name: ext.toUpperCase(), extensions: extFilters[ext] ?? [ext] }],
      });
      if (!dest) return;
      await invoke('save_redacted_document', { tempPath: redactedPath, destPath: dest });
      setStatusTxt('File saved');
    } catch (err) {
      console.error('[Axiom] save_redacted_document error:', err);
      setStatusTxt(`Save error: ${String(err)}`);
    }
  }, []);

  const latestPdfLog = fileLogs.find(l => l.fullPath !== 'clipboard');

  // Require login before rendering the main dashboard
  if (!authUser) {
    return <LoginPage onLogin={setAuthUser} />;
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-logo">AXIOM</div>
          <div className="brand-tag"><span>●</span> Privacy Guard</div>
        </div>

        <nav className="nav-section">
          <div className="nav-label">Navigation</div>
          <button className={`nav-btn ${page === 'home' ? 'active' : ''}`} onClick={() => setPage('home')}>
            <span className="nav-icon"><Icons.Home /></span>
            Home
          </button>
          <button className={`nav-btn ${page === 'logs' ? 'active' : ''}`} onClick={() => setPage('logs')}>
            <span className="nav-icon"><Icons.Logs /></span>
            Detection Logs
            {totalFlags > 0 && <span className="nav-badge">{totalFlags}</span>}
          </button>
          <button className={`nav-btn ${page === 'about' ? 'active' : ''}`} onClick={() => setPage('about')}>
            <span className="nav-icon"><Icons.Shield /></span>
            How It Works
          </button>
        </nav>

        {/* Supported formats */}
        <div style={{ padding: '0 14px' }}>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 8, letterSpacing: '.1em', textTransform: 'uppercase', color: 'var(--muted2)', marginBottom: 6 }}>Supported Formats</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {['PDF', 'DOCX', 'XLSX', 'PPTX', 'DOC', 'XLS', 'PPT'].map(fmt => (
              <span key={fmt} style={{
                fontFamily: 'var(--mono)', fontSize: 8, fontWeight: 700,
                padding: '2px 6px', borderRadius: 5,
                background: 'rgba(184,127,255,.08)', border: '1px solid rgba(184,127,255,.2)',
                color: 'var(--neon)', letterSpacing: '.06em',
              }}>{fmt}</span>
            ))}
          </div>
        </div>

        <div className="sidebar-footer" style={{ gap: '10px' }}>
          {/* User Profile Info */}
          <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)', background: 'rgba(255,255,255,.02)', borderRadius: 8 }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--muted2)', textTransform: 'uppercase', letterSpacing: '.05em' }}>Logged in as</div>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--neon)', marginTop: 2 }}>{authUser.name}</div>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--muted)', marginTop: 2 }}>{authUser.department}</div>
          </div>

          <ModelBadge modelId={modelId} device={device} status={modelStatus} />

          {/* Detected-file banner */}
          {detectedFile && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '9px 12px', borderRadius: 10,
              background: 'rgba(78,124,255,.10)',
              border: '1px solid rgba(78,124,255,.35)',
              animation: 'axiom-glow-pulse 2s ease-in-out infinite',
              '--glow-color': 'rgba(78,124,255,.25)',
            } as React.CSSProperties}>
              <span style={{ flexShrink: 0, color: 'var(--accent)', display: 'flex' }}><Icons.File /></span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{
                  fontFamily: 'var(--mono)', fontSize: 10, fontWeight: 700,
                  color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                  {detectedFile.fileName}
                </div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 8, color: 'var(--accent)', letterSpacing: '.06em', marginTop: 2 }}>
                  Detected · scanning…
                </div>
                <div style={{
                  fontFamily: 'var(--mono)', fontSize: 7, color: 'var(--muted2)',
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 2,
                }} title={detectedFile.path}>
                  {detectedFile.path}
                </div>
              </div>
              <span style={{
                width: 7, height: 7, borderRadius: '50%', flexShrink: 0,
                background: 'var(--accent)',
                boxShadow: '0 0 6px 2px rgba(78,124,255,.6)',
                animation: 'axiom-glow-pulse 1.2s ease-in-out infinite',
              }} />
            </div>
          )}

          <div className="status-strip">
            <span className={`s-dot ${scanning ? 'scanning' : 'idle'}`} />
            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 11 }}>{statusTxt}</span>
          </div>

          <ActionBtn
            variant={scanning ? 'danger' : 'primary'}
            size="lg"
            icon={scanning ? <Icons.Stop /> : <Icons.Play />}
            fullWidth
            glowOnHover
            onClick={async () => {
              if (!scanning) {
                setModelStatus('loading');
                await invoke('start_scanning', { empId: authUser.id, empName: authUser.name, empDept: authUser.department });
                setScanning(true);
                setStatusTxt('Running detection algorithm…');
              } else {
                await invoke('stop_scanning');
                setScanning(false);
                setModelStatus('idle');
                setStatusTxt('Stopped');
              }
            }}
          >
            {scanning ? 'Stop Algorithm' : 'Run Detection Alg'}
          </ActionBtn>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 7 }}>
            <ActionBtn variant="ghost" size="md" icon={<Icons.Upload />} glowOnHover
              onClick={async () => {
                const p = await open({ multiple: false });
                if (p && typeof p === 'string') await invoke('scan_manual_file', { path: p });
              }}>
              Upload
            </ActionBtn>
            <ActionBtn variant="ghost" size="md" icon={<Icons.ClipboardScan />} glowOnHover
              onClick={() => invoke('scan_clipboard_now')}>
              Clipboard
            </ActionBtn>
          </div>

          {latestPdfLog && !latestPdfLog.redactedPath && (
            <div style={{ borderTop: '1px solid var(--border)', paddingTop: 10 }}>
              <ActionBtn variant="danger" size="md" icon={<Icons.Redact />} fullWidth glowOnHover
                onClick={() => handleRedact(latestPdfLog.fullPath)} disabled={redacting}>
                {redacting ? 'Redacting…' : 'Redact'}
              </ActionBtn>
            </div>
          )}

          {latestPdfLog?.redactedPath && (
            <div style={{ borderTop: '1px solid var(--border)', paddingTop: 10, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 7 }}>
              <ActionBtn variant="subtle" size="md" icon={<Icons.Eye />} glowOnHover
                onClick={() => handlePreview(latestPdfLog.redactedPath!)}>
                Preview
              </ActionBtn>
              <ActionBtn variant="success" size="md" icon={<Icons.Download />} glowOnHover
                onClick={() => handleSave(latestPdfLog.redactedPath!)}>
                Download
              </ActionBtn>
            </div>
          )}
        </div>
      </aside>

      <main className="main">
        {page === 'home' && (
          <div className="home-page page-view">
            <ParticleCanvas />
            <div className="home-hero">
              <div className="hero-wordmark">AXIOM</div>
              <div className="hero-tagline">Real-time local detection of PII. Fully local.</div>
            </div>
            <HomeDashboard fileLogs={fileLogs} totalFlags={totalFlags} scanning={scanning} onNavigate={setPage} onRedact={handleRedact} redacting={redacting} />
          </div>
        )}
        {page === 'logs' && (
          <LogsPage
            fileLogs={fileLogs}
            totalFlags={totalFlags}
            onRedact={handleRedact}
            onPreview={handlePreview}
            onSave={handleSave}
            redacting={redacting}
          />
        )}
        {page === 'about' && <AboutPage />}
      </main>
    </div>
  );
}