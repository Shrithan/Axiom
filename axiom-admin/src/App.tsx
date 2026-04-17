import React, { useState, useEffect, useCallback, useRef } from 'react';
import { invoke } from "@tauri-apps/api/core";
import './App.css'; // Connects to the unified Gold theme

// ── Ripple / animation injection (Updated for Gold Theme) ─────────────────────
const ANIM_STYLE = `
@import url('https://fonts.googleapis.com/css2?family=Unbounded:wght@400;500;600;700;800;900&family=DM+Sans:ital,wght@0,300;0,400;0,500;0,600;1,400&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
@keyframes axiom-ripple { to { transform: scale(4); opacity: 0; } }
@keyframes axiom-press { 0%{transform:scale(1)}40%{transform:scale(0.94)}100%{transform:scale(1)} }
@keyframes axiom-glow-pulse { 0%,100%{box-shadow:0 0 0 0 rgba(234,179,8,0)}50%{box-shadow:0 0 18px 4px rgba(234,179,8,.3)} }
@keyframes blink { 0%,100%{opacity:1}50%{opacity:.3} }
@keyframes slide-in { from{transform:translateX(20px);opacity:0}to{transform:translateX(0);opacity:1} }
@keyframes spin { to{transform:rotate(360deg)} }
@keyframes fade-in { from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)} }
@keyframes shrink { from{width:100%}to{width:0} }
`;

if (typeof document !== 'undefined' && !document.getElementById('axiom-admin-anim')) {
  const s = document.createElement('style');
  s.id = 'axiom-admin-anim';
  s.textContent = ANIM_STYLE;
  document.head.appendChild(s);
}

// ── Types (Synced with Rust structs) ──────────────────────────────────────────
type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
type AdminPage = 'dashboard' | 'activity' | 'users' | 'policies' | 'reports';
type UserStatus = 'active' | 'inactive' | 'suspended';
type RuleCategory = 'PII' | 'FINANCIAL' | 'HEALTH' | 'CREDENTIALS' | 'CUSTOM';

interface Employee {
  id: string;
  name: string;
  email: string; // Acts as 'username' in the backend DB
  department: string;
  status: UserStatus;
  lastSeen: number; 
  totalScans: number; 
  totalDetections: number; 
  riskScore: number; 
  avatarInitials: string; 
}

interface ActivityLog {
  id: string;
  employeeId: string;
  employeeName: string;
  department: string;
  fileName: string;
  detectionCount: number;
  highestSeverity: Severity;
  timestamp: number;
  redacted: boolean;
  piiTypes: string[];
}

interface PolicyRule {
  id: string;
  name: string;
  category: RuleCategory;
  pattern: string;
  severity: Severity;
  enabled: boolean;
  detectionCount: number;
  description: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
const SEV_COLOR: Record<Severity, string> = { LOW:'var(--muted)', MEDIUM:'var(--accent)', HIGH:'#ff7c3d', CRITICAL:'var(--danger)' };
const SEV_BG: Record<Severity, string> = { LOW:'rgba(255,255,255,.06)', MEDIUM:'var(--accent-bg)', HIGH:'rgba(255,124,61,.1)', CRITICAL:'var(--danger-bg)' };
const SEV_BORDER: Record<Severity, string> = { LOW:'rgba(255,255,255,.1)', MEDIUM:'rgba(78,124,255,.3)', HIGH:'rgba(255,124,61,.3)', CRITICAL:'rgba(255,61,90,.3)' };
const CAT_COLOR: Record<RuleCategory, string> = { PII:'var(--neon)', FINANCIAL:'var(--warn)', HEALTH:'#34d399', CREDENTIALS:'#ff7c3d', CUSTOM:'var(--accent)' };
const CAT_BG: Record<RuleCategory, string> = { PII:'var(--neon-dim)', FINANCIAL:'var(--warn-bg)', HEALTH:'rgba(52,211,153,.1)', CREDENTIALS:'rgba(255,124,61,.1)', CUSTOM:'var(--accent-bg)' };

function fmtRelative(ms: number): string {
  const d = Date.now() - ms;
  if (d < 60000) return 'Just now';
  if (d < 3600000) return `${Math.floor(d/60000)}m ago`;
  if (d < 86400000) return `${Math.floor(d/3600000)}h ago`;
  return `${Math.floor(d/86400000)}d ago`;
}

function fmtDate(ms: number): string {
  if (ms === 0) return 'Never';
  return new Date(ms).toLocaleDateString('en-US', { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit', hour12:false });
}

function riskColor(score: number): string {
  if (score >= 85) return 'var(--danger)';
  if (score >= 65) return '#ff7c3d';
  if (score >= 40) return 'var(--warn)';
  return '#34d399';
}

// ── SVG Icons ─────────────────────────────────────────────────────────────────
const Icons = {
  Dashboard: () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>,
  Activity: () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>,
  Users: () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>,
  Policies: () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  Reports: () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>,
  Alert: () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
  Check: () => <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>,
  Edit: () => <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>,
  Trash: () => <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>,
  Plus: () => <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>,
  Download: () => <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>,
  Search: () => <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>,
  Shield: () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  Ban: () => <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>,
  Clock: () => <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>,
  File: () => <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>,
  Eye: () => <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>,
  Toggle: (p:{on:boolean}) => p.on
    ? <svg width="36" height="20" viewBox="0 0 36 20"><rect width="36" height="20" rx="10" fill="rgba(234,179,8,.9)"/><circle cx="26" cy="10" r="8" fill="#111"/></svg>
    : <svg width="36" height="20" viewBox="0 0 36 20"><rect width="36" height="20" rx="10" fill="rgba(255,255,255,.12)"/><circle cx="10" cy="10" r="8" fill="rgba(255,255,255,.4)"/></svg>,
};

// ── Micro Components ──────────────────────────────────────────────────────────
function SparkBar({ data, color = 'var(--neon)', height = 36 }: { data: number[]; color?: string; height?: number }) {
  const max = Math.max(...data, 1);
  return (
    <div style={{ display:'flex', alignItems:'flex-end', gap:2, height }}>
      {data.map((v, i) => (
        <div key={i} style={{
          flex:1, borderRadius:2, background:color,
          height:`${(v/max)*100}%`, minHeight:2,
          opacity: i === data.length-1 ? 1 : 0.35 + (i/data.length)*0.5,
          transition:'height 400ms var(--ease)',
        }}/>
      ))}
    </div>
  );
}

function StatCard({ label, value, sub, color = 'var(--neon)', spark, trend }: {
  label: string; value: string | number; sub?: string; color?: string;
  spark?: number[]; trend?: { val: string; up: boolean };
}) {
  return (
    <div style={{
      padding:'18px 20px', borderRadius:14, background:'var(--surface)',
      border:'1px solid var(--border)', display:'flex', flexDirection:'column', gap:10,
      transition:'border-color 200ms',
    }}
      onMouseEnter={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,.14)')}
      onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border)')}
    >
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start' }}>
        <div>
          <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--muted2)', letterSpacing:'.12em', textTransform:'uppercase', marginBottom:8 }}>{label}</div>
          <div style={{ fontFamily:'var(--display)', fontSize:28, fontWeight:800, color, lineHeight:1 }}>{value}</div>
          {sub && <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--muted2)', marginTop:5 }}>{sub}</div>}
        </div>
        {trend && (
          <div style={{
            fontFamily:'var(--mono)', fontSize:10, fontWeight:700,
            color: trend.up ? 'var(--danger)' : '#34d399',
            padding:'3px 8px', borderRadius:99,
            background: trend.up ? 'var(--danger-bg)' : 'rgba(52,211,153,.1)',
            border: `1px solid ${trend.up ? 'rgba(255,61,90,.2)' : 'rgba(52,211,153,.2)'}`,
          }}>
            {trend.up ? '↑' : '↓'} {trend.val}
          </div>
        )}
      </div>
      {spark && <SparkBar data={spark} color={color} />}
    </div>
  );
}

function SevPill({ sev }: { sev: Severity }) {
  return (
    <span style={{
      fontFamily:'var(--mono)', fontSize:9, fontWeight:700, letterSpacing:'.07em',
      padding:'3px 8px', borderRadius:99, textTransform:'uppercase',
      color:SEV_COLOR[sev], background:SEV_BG[sev], border:`1px solid ${SEV_BORDER[sev]}`,
    }}>{sev}</span>
  );
}

function Avatar({ initials, size = 32, risk }: { initials: string; size?: number; risk?: number }) {
  const c = risk != null ? riskColor(risk) : 'var(--neon)';
  return (
    <div style={{
      width:size, height:size, borderRadius:'50%', display:'grid', placeItems:'center',
      background:`linear-gradient(135deg, ${c}22, ${c}44)`,
      border:`1.5px solid ${c}55`, flexShrink:0,
      fontFamily:'var(--display)', fontSize:size*0.3, fontWeight:800, color:c,
    }}>{initials}</div>
  );
}

function ActionBtn({ children, onClick, variant='primary', size='md', icon, disabled=false, fullWidth=false, style={} }: {
  children?: React.ReactNode; onClick?: () => void; variant?: string;
  size?: 'sm'|'md'|'lg'; icon?: React.ReactNode; disabled?: boolean;
  fullWidth?: boolean; style?: React.CSSProperties;
}) {
  const pad = size === 'sm' ? '5px 10px' : size === 'lg' ? '11px 18px' : '8px 14px';
  const fs = size === 'sm' ? 11 : size === 'lg' ? 13 : 12;
  const styles: Record<string, React.CSSProperties> = {
    primary: { background:'var(--neon-dim)', border:'1px solid var(--neon-mid)', color:'var(--neon)' },
    danger:  { background:'var(--danger-bg)', border:'1px solid rgba(255,61,90,.3)', color:'var(--danger)' },
    ghost:   { background:'transparent', border:'1px solid var(--border)', color:'var(--muted)' },
    success: { background:'rgba(52,211,153,.1)', border:'1px solid rgba(52,211,153,.3)', color:'#34d399' },
    warn:    { background:'var(--warn-bg)', border:'1px solid rgba(255,190,11,.3)', color:'var(--warn)' },
    accent:  { background:'var(--accent-bg)', border:'1px solid rgba(78,124,255,.3)', color:'var(--accent)' },
  };
  return (
    <button onClick={onClick} disabled={disabled}
      style={{
        display:'inline-flex', alignItems:'center', gap:6,
        padding:pad, borderRadius:9, cursor:disabled?'not-allowed':'pointer',
        fontFamily:'var(--sans)', fontSize:fs, fontWeight:600,
        transition:'all 130ms var(--ease)', whiteSpace:'nowrap',
        opacity:disabled?0.5:1, width:fullWidth?'100%':undefined,
        justifyContent:fullWidth?'center':undefined,
        ...styles[variant], ...style,
      }}
    >{icon}{children}</button>
  );
}

function SearchInput({ value, onChange, placeholder = 'Search…' }: { value: string; onChange: (v:string)=>void; placeholder?: string }) {
  return (
    <div style={{ display:'flex', alignItems:'center', gap:8, background:'rgba(255,255,255,.04)', border:'1px solid var(--border)', borderRadius:9, padding:'7px 12px' }}>
      <span style={{ color:'var(--muted2)', display:'flex' }}><Icons.Search /></span>
      <input
        value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
        style={{ background:'none', border:'none', outline:'none', color:'var(--text)', fontFamily:'var(--mono)', fontSize:11, width:180 }}
      />
    </div>
  );
}

// ── Pages ─────────────────────────────────────────────────────────────────────

function DashboardPage({ employees, activity, onNav }: { employees: Employee[]; activity: ActivityLog[]; onNav: (p:AdminPage)=>void }) {
  const totalScans = employees.reduce((s,e) => s + e.totalScans, 0);
  const totalDetections = employees.reduce((s,e) => s + e.totalDetections, 0);
  const criticalCount = activity.filter(a => a.highestSeverity === 'CRITICAL').length;
  const unreacted = activity.filter(a => !a.redacted && a.highestSeverity !== 'LOW').length;
  const highRisk = employees.filter(e => e.riskScore >= 75);

  const sparkScans = [42,55,38,71,63,88,95,101,89,115,142,totalScans];
  const sparkDetect = [18,24,15,31,28,41,38,55,49,62,78,totalDetections];

  const recentActivity = [...activity].sort((a,b) => b.timestamp - a.timestamp).slice(0,5);

  return (
    <div style={{ padding:'28px 28px 40px', display:'flex', flexDirection:'column', gap:28, animation:'fade-in 300ms var(--ease)' }}>
      {/* Header */}
      <div>
        <div style={{ fontFamily:'var(--display)', fontSize:11, letterSpacing:'.12em', textTransform:'uppercase', color:'var(--muted2)', marginBottom:6 }}>Overview</div>
        <div style={{ fontFamily:'var(--display)', fontSize:22, fontWeight:800, letterSpacing:'.02em', background:'linear-gradient(135deg,#fff,var(--neon))', WebkitBackgroundClip:'text', WebkitTextFillColor:'transparent' }}>
          Admin Dashboard
        </div>
        <div style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--muted2)', marginTop:4 }}>
          {new Date().toLocaleDateString('en-US', { weekday:'long', month:'long', day:'numeric', year:'numeric' })}
        </div>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:14 }}>
        <StatCard label="Total Scans" value={totalScans} sub="All employees" color="var(--neon)" spark={sparkScans} trend={{ val:'18%', up:false }}/>
        <StatCard label="Total Detections" value={totalDetections} sub="PII instances found" color="var(--accent)" spark={sparkDetect} trend={{ val:'12%', up:true }}/>
        <StatCard label="Critical Events" value={criticalCount} sub="Unacknowledged" color="var(--danger)" spark={[2,1,3,0,4,2,5,3,6,4,7,criticalCount]} trend={{ val:'3 today', up:true }}/>
        <StatCard label="Unredacted Files" value={unreacted} sub="Require attention" color="var(--warn)" spark={[1,2,1,3,2,4,3,5,4,6,5,unreacted]}/>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'1fr 340px', gap:20 }}>
        {/* Recent Activity */}
        <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:14, overflow:'hidden' }}>
          <div style={{ padding:'16px 20px', borderBottom:'1px solid var(--border)', display:'flex', justifyContent:'space-between', alignItems:'center' }}>
            <div>
              <div style={{ fontFamily:'var(--display)', fontSize:12, fontWeight:700, letterSpacing:'.04em' }}>Recent Activity</div>
              <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--muted2)', marginTop:3 }}>Latest document scans across all employees</div>
            </div>
            <ActionBtn variant="ghost" size="sm" onClick={() => onNav('activity')}>View all</ActionBtn>
          </div>
          <div>
            {recentActivity.length === 0 ? (
                <div style={{ padding:'24px', textAlign:'center', fontFamily:'var(--mono)', fontSize:11, color:'var(--muted2)' }}>No activity yet.</div>
            ) : recentActivity.map((a, i) => (
              <div key={a.id} style={{
                padding:'12px 20px', borderBottom: i < recentActivity.length-1 ? '1px solid rgba(255,255,255,.04)' : 'none',
                display:'grid', gridTemplateColumns:'32px 1fr auto', gap:12, alignItems:'center',
                transition:'background 120ms',
              }}
                onMouseEnter={e => (e.currentTarget.style.background='rgba(255,255,255,.02)')}
                onMouseLeave={e => (e.currentTarget.style.background='transparent')}
              >
                <Avatar initials={a.employeeName.split(' ').map(p=>p[0]).join('')} size={32} />
                <div>
                  <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:3 }}>
                    <span style={{ fontFamily:'var(--sans)', fontSize:12, fontWeight:600 }}>{a.employeeName}</span>
                    <SevPill sev={a.highestSeverity} />
                    {!a.redacted && a.highestSeverity !== 'LOW' && (
                      <span style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--warn)', background:'var(--warn-bg)', border:'1px solid rgba(255,190,11,.2)', padding:'2px 6px', borderRadius:99 }}>Unredacted</span>
                    )}
                  </div>
                  <div style={{ display:'flex', gap:8, alignItems:'center' }}>
                    <span style={{ color:'var(--muted2)', display:'flex', alignItems:'center', gap:4 }}><Icons.File /><span style={{ fontFamily:'var(--mono)', fontSize:10 }}>{a.fileName}</span></span>
                    <span style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--muted2)' }}>·</span>
                    <span style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--muted2)' }}>{a.detectionCount} detections</span>
                  </div>
                </div>
                <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--muted2)', textAlign:'right', display:'flex', alignItems:'center', gap:4 }}>
                  <Icons.Clock />{fmtRelative(a.timestamp)}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* High Risk Employees */}
        <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:14, overflow:'hidden' }}>
          <div style={{ padding:'16px 20px', borderBottom:'1px solid var(--border)' }}>
            <div style={{ fontFamily:'var(--display)', fontSize:12, fontWeight:700, letterSpacing:'.04em' }}>High Risk Employees</div>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--muted2)', marginTop:3 }}>Risk score ≥ 75</div>
          </div>
          <div style={{ padding:'12px 16px', display:'flex', flexDirection:'column', gap:10 }}>
            {highRisk.map(e => (
              <div key={e.id} style={{ display:'flex', alignItems:'center', gap:12, padding:'10px 12px', borderRadius:10, background:'rgba(255,255,255,.02)', border:'1px solid var(--border)' }}>
                <Avatar initials={e.avatarInitials} size={34} risk={e.riskScore} />
                <div style={{ flex:1, minWidth:0 }}>
                  <div style={{ fontFamily:'var(--sans)', fontSize:12, fontWeight:600, marginBottom:3 }}>{e.name}</div>
                  <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--muted2)' }}>{e.department}</div>
                  <div style={{ marginTop:5, height:3, background:'rgba(255,255,255,.06)', borderRadius:99, overflow:'hidden' }}>
                    <div style={{ height:'100%', width:`${e.riskScore}%`, background:riskColor(e.riskScore), borderRadius:99, transition:'width 600ms var(--ease)' }}/>
                  </div>
                </div>
                <div style={{ fontFamily:'var(--display)', fontSize:16, fontWeight:800, color:riskColor(e.riskScore), flexShrink:0 }}>{e.riskScore}</div>
              </div>
            ))}
            {highRisk.length === 0 && (
              <div style={{ padding:'24px', textAlign:'center', fontFamily:'var(--mono)', fontSize:11, color:'var(--muted2)' }}>No high-risk employees</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function ActivityPage({ activity }: { activity: ActivityLog[] }) {
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState<Severity | 'ALL'>('ALL');
  const [deptFilter, setDeptFilter] = useState('ALL');
  const [selectedLog, setSelectedLog] = useState<ActivityLog | null>(null);

  const depts = ['ALL', ...Array.from(new Set(activity.map(a => a.department)))];
  const filtered = activity.filter(a => {
    const matchSearch = !search || a.employeeName.toLowerCase().includes(search.toLowerCase()) || a.fileName.toLowerCase().includes(search.toLowerCase());
    const matchSev = sevFilter === 'ALL' || a.highestSeverity === sevFilter;
    const matchDept = deptFilter === 'ALL' || a.department === deptFilter;
    return matchSearch && matchSev && matchDept;
  }).sort((a,b) => b.timestamp - a.timestamp);

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', animation:'fade-in 300ms var(--ease)' }}>
      {/* Toolbar */}
      <div style={{ padding:'14px 22px', borderBottom:'1px solid var(--border)', display:'flex', gap:10, alignItems:'center', flexWrap:'wrap', background:'rgba(255,255,255,.01)', flexShrink:0 }}>
        <span style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--muted2)', letterSpacing:'.1em', textTransform:'uppercase', marginRight:4 }}>Severity</span>
        {(['ALL','CRITICAL','HIGH','MEDIUM','LOW'] as const).map(s => (
          <button key={s} onClick={() => setSevFilter(s)} style={{
            padding:'4px 12px', borderRadius:99, border:'1px solid var(--border)', cursor:'pointer',
            fontFamily:'var(--mono)', fontSize:10, fontWeight:600, textTransform:'uppercase', letterSpacing:'.05em',
            background: sevFilter===s ? (s==='ALL'?'var(--neon-dim)':SEV_BG[s as Severity]) : 'transparent',
            color: sevFilter===s ? (s==='ALL'?'var(--neon)':SEV_COLOR[s as Severity]) : 'var(--muted)',
            borderColor: sevFilter===s ? (s==='ALL'?'rgba(234,179,8,.3)':SEV_BORDER[s as Severity]) : 'var(--border)',
            transition:'all 130ms',
          }}>{s}</button>
        ))}
        <div style={{ width:1, height:20, background:'var(--border)' }}/>
        <span style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--muted2)', letterSpacing:'.1em', textTransform:'uppercase' }}>Dept</span>
        <select value={deptFilter} onChange={e => setDeptFilter(e.target.value)} style={{
          background:'var(--surface)', border:'1px solid var(--border)', borderRadius:8,
          color:'var(--text)', fontFamily:'var(--mono)', fontSize:11, padding:'5px 10px', outline:'none', cursor:'pointer',
        }}>
          {depts.map(d => <option key={d} value={d} style={{color: 'black'}}>{d}</option>)}
        </select>
        <div style={{ marginLeft:'auto' }}><SearchInput value={search} onChange={setSearch} placeholder="Search employee, file…"/></div>
      </div>

      {/* Log entries */}
      <div style={{ flex:1, overflowY:'auto' }}>
        <div style={{ display:'grid', gridTemplateColumns:'200px 120px 1fr 100px 90px 80px', gap:12, padding:'8px 22px', borderBottom:'1px solid var(--border)', background:'rgba(255,255,255,.01)' }}>
          {['Employee','Department','File','Severity','Time','Redacted'].map(h => (
            <div key={h} style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--muted2)', letterSpacing:'.1em', textTransform:'uppercase' }}>{h}</div>
          ))}
        </div>

        {filtered.length === 0 && (
          <div style={{ padding:'64px', textAlign:'center', fontFamily:'var(--mono)', fontSize:12, color:'var(--muted2)' }}>No activity matching filters</div>
        )}

        {filtered.map(a => (
          <div key={a.id} onClick={() => setSelectedLog(selectedLog?.id===a.id ? null : a)}
            style={{
              display:'grid', gridTemplateColumns:'200px 120px 1fr 100px 90px 80px',
              gap:12, padding:'12px 22px', borderBottom:'1px solid rgba(255,255,255,.03)',
              cursor:'pointer', transition:'background 120ms',
              background: selectedLog?.id===a.id ? 'rgba(234,179,8,.05)' : 'transparent',
              borderLeft: selectedLog?.id===a.id ? '2px solid var(--neon)' : '2px solid transparent',
            }}
            onMouseEnter={e => { if(selectedLog?.id!==a.id) e.currentTarget.style.background='rgba(255,255,255,.02)'; }}
            onMouseLeave={e => { if(selectedLog?.id!==a.id) e.currentTarget.style.background='transparent'; }}
          >
            <div style={{ display:'flex', alignItems:'center', gap:8 }}>
              <Avatar initials={a.employeeName.split(' ').map(p=>p[0]).join('')} size={26} />
              <span style={{ fontFamily:'var(--sans)', fontSize:12, fontWeight:500 }}>{a.employeeName}</span>
            </div>
            <div style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--muted2)', alignSelf:'center' }}>{a.department}</div>
            <div style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--text)', alignSelf:'center', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', display:'flex', alignItems:'center', gap:6 }}>
              <span style={{ color:'var(--muted2)', flexShrink:0 }}><Icons.File /></span>{a.fileName}
            </div>
            <div style={{ alignSelf:'center' }}><SevPill sev={a.highestSeverity}/></div>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--muted2)', alignSelf:'center', display:'flex', alignItems:'center', gap:4 }}>
              <Icons.Clock />{fmtRelative(a.timestamp)}
            </div>
            <div style={{ alignSelf:'center' }}>
              {a.redacted
                ? <span style={{ display:'flex', alignItems:'center', gap:4, fontFamily:'var(--mono)', fontSize:10, color:'#34d399' }}><Icons.Check/>Yes</span>
                : <span style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--warn)' }}>No</span>
              }
            </div>
          </div>
        ))}
      </div>

      {/* Detail panel */}
      {selectedLog && (
        <div style={{ borderTop:'1px solid var(--border)', padding:'20px 22px', background:'rgba(234,179,8,.03)', flexShrink:0, animation:'slide-in 200ms var(--ease)' }}>
          <div style={{ display:'flex', gap:20, flexWrap:'wrap' }}>
            <div>
              <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--muted2)', letterSpacing:'.1em', textTransform:'uppercase', marginBottom:6 }}>PII Types Detected</div>
              <div style={{ display:'flex', gap:6, flexWrap:'wrap' }}>
                {selectedLog.piiTypes.map(t => (
                  <span key={t} style={{ fontFamily:'var(--mono)', fontSize:10, fontWeight:700, padding:'3px 10px', borderRadius:99, background:'var(--neon-dim)', border:'1px solid rgba(234,179,8,.25)', color:'var(--neon)' }}>{t}</span>
                ))}
              </div>
            </div>
            <div>
              <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--muted2)', letterSpacing:'.1em', textTransform:'uppercase', marginBottom:6 }}>Total Detections</div>
              <div style={{ fontFamily:'var(--display)', fontSize:22, fontWeight:800, color:SEV_COLOR[selectedLog.highestSeverity] }}>{selectedLog.detectionCount}</div>
            </div>
            <div>
              <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--muted2)', letterSpacing:'.1em', textTransform:'uppercase', marginBottom:6 }}>Timestamp</div>
              <div style={{ fontFamily:'var(--mono)', fontSize:12, color:'var(--text)' }}>{fmtDate(selectedLog.timestamp)}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function UsersPage({ employees, onUpdate, refreshData }: { employees: Employee[]; onUpdate: (id:string, patch:Partial<Employee>)=>void; refreshData: ()=>void }) {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<UserStatus|'ALL'>('ALL');
  const [selectedUser, setSelectedUser] = useState<Employee|null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [newForm, setNewForm] = useState({ name:'', username:'', pass:'', dept:'Engineering' });

  const filtered = employees.filter(e => {
    const ms = !search || e.name.toLowerCase().includes(search.toLowerCase()) || e.email.toLowerCase().includes(search.toLowerCase()) || e.department.toLowerCase().includes(search.toLowerCase());
    const mst = statusFilter === 'ALL' || e.status === statusFilter;
    return ms && mst;
  }).sort((a,b) => b.riskScore - a.riskScore);

  const statusStyle: Record<UserStatus, React.CSSProperties> = {
    active:    { color:'#34d399', background:'rgba(52,211,153,.1)', border:'1px solid rgba(52,211,153,.2)' },
    inactive:  { color:'var(--muted)', background:'var(--surface)', border:'1px solid var(--border)' },
    suspended: { color:'var(--danger)', background:'var(--danger-bg)', border:'1px solid rgba(255,61,90,.2)' },
  };

  const handleAddSubmit = async () => {
    console.log("1. Save button clicked! Form data:", newForm);
    
    if (!newForm.name || !newForm.username || !newForm.pass) {
      console.warn("2. Missing fields");
      alert("Please fill in all fields (Name, Username, and Password).");
      return;
    }
    
    try {
      console.log("3. Sending data to Rust...");
      // Explicitly mapping the payload to match Rust exactly
      await invoke('add_employee', { 
        name: newForm.name, 
        username: newForm.username, 
        pass: newForm.pass, 
        dept: newForm.dept 
      });
      
      console.log("4. User successfully added to SQLite!");
      setShowAdd(false);
      setNewForm({ name:'', username:'', pass:'', dept:'Engineering' });
      refreshData(); // Refreshes the list to show the new user
      
    } catch (e) {
      console.error("5. Rust threw an error:", e);
      alert(`Database Error: ${String(e)}`);
    }
  };

  return (
    <div style={{ display:'flex', height:'100%', animation:'fade-in 300ms var(--ease)' }}>
      {/* List */}
      <div style={{ flex:1, display:'flex', flexDirection:'column', borderRight:selectedUser?'1px solid var(--border)':'none' }}>
        {/* Toolbar */}
        <div style={{ padding:'14px 22px', borderBottom:'1px solid var(--border)', display:'flex', gap:10, alignItems:'center', flexShrink:0, flexWrap:'wrap' }}>
          {(['ALL','active','inactive','suspended'] as const).map(s => (
            <button key={s} onClick={() => setStatusFilter(s)} style={{
              padding:'4px 12px', borderRadius:99, border:'1px solid var(--border)', cursor:'pointer',
              fontFamily:'var(--mono)', fontSize:10, fontWeight:600, textTransform:'capitalize', letterSpacing:'.05em',
              background: statusFilter===s ? (s==='ALL'?'var(--neon-dim)':statusStyle[s as UserStatus].background) : 'transparent',
              color: statusFilter===s ? (s==='ALL'?'var(--neon)':(statusStyle[s as UserStatus].color as string)) : 'var(--muted)',
              borderColor: statusFilter===s ? (s==='ALL'?'rgba(234,179,8,.3)':'') : 'var(--border)',
              transition:'all 130ms',
            }}>{s === 'ALL' ? 'All' : s.charAt(0).toUpperCase()+s.slice(1)}</button>
          ))}
          <div style={{ marginLeft:'auto' }}><SearchInput value={search} onChange={setSearch} placeholder="Search name, user, dept…"/></div>
          <ActionBtn variant="primary" size="sm" icon={<Icons.Plus />} onClick={() => setShowAdd(!showAdd)}>Add Employee</ActionBtn>
        </div>

        {/* Add Form */}
        {showAdd && (
          <div style={{ padding: '16px 22px', background: 'var(--surface)', borderBottom: '1px solid var(--border)', display: 'flex', gap: 10, alignItems: 'center' }}>
            <input placeholder="Full Name" value={newForm.name} onChange={e=>setNewForm({...newForm, name:e.target.value})} style={{ padding:'8px 12px', borderRadius:8, border:'1px solid var(--border)', background:'rgba(255,255,255,.03)', color:'white', fontSize:12, flex: 1, outline:'none' }} />
            <input placeholder="Username" value={newForm.username} onChange={e=>setNewForm({...newForm, username:e.target.value})} style={{ padding:'8px 12px', borderRadius:8, border:'1px solid var(--border)', background:'rgba(255,255,255,.03)', color:'white', fontSize:12, flex: 1, outline:'none' }} />
            <input placeholder="Password" type="password" value={newForm.pass} onChange={e=>setNewForm({...newForm, pass:e.target.value})} style={{ padding:'8px 12px', borderRadius:8, border:'1px solid var(--border)', background:'rgba(255,255,255,.03)', color:'white', fontSize:12, flex: 1, outline:'none' }} />
            <select value={newForm.dept} onChange={e=>setNewForm({...newForm, dept:e.target.value})} style={{ padding:'8px 12px', borderRadius:8, border:'1px solid var(--border)', background:'rgba(255,255,255,.03)', color:'white', fontSize:12, outline: 'none' }}>
              <option value="Engineering" style={{color: 'black'}}>Engineering</option>
              <option value="HR" style={{color: 'black'}}>HR</option>
              <option value="Finance" style={{color: 'black'}}>Finance</option>
              <option value="Sales" style={{color: 'black'}}>Sales</option>
              <option value="IT" style={{color: 'black'}}>IT</option>
            </select>
            <ActionBtn variant="success" size="sm" onClick={handleAddSubmit}>Save User</ActionBtn>
          </div>
        )}

        <div style={{ display:'grid', gridTemplateColumns:'1fr 120px 100px 80px 70px 80px', gap:12, padding:'8px 22px', borderBottom:'1px solid var(--border)', background:'rgba(255,255,255,.01)' }}>
          {['Employee','Department','Status','Scans','Risk',''].map(h => (
            <div key={h} style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--muted2)', letterSpacing:'.1em', textTransform:'uppercase' }}>{h}</div>
          ))}
        </div>

        <div style={{ flex:1, overflowY:'auto' }}>
          {filtered.map(e => (
            <div key={e.id} onClick={() => setSelectedUser(selectedUser?.id===e.id ? null : e)}
              style={{
                display:'grid', gridTemplateColumns:'1fr 120px 100px 80px 70px 80px',
                gap:12, padding:'14px 22px', borderBottom:'1px solid rgba(255,255,255,.03)',
                cursor:'pointer', transition:'background 120ms',
                background: selectedUser?.id===e.id ? 'rgba(234,179,8,.05)' : 'transparent',
                borderLeft: selectedUser?.id===e.id ? '2px solid var(--neon)' : '2px solid transparent',
              }}
              onMouseEnter={ev => { if(selectedUser?.id!==e.id) ev.currentTarget.style.background='rgba(255,255,255,.02)'; }}
              onMouseLeave={ev => { if(selectedUser?.id!==e.id) ev.currentTarget.style.background='transparent'; }}
            >
              <div style={{ display:'flex', alignItems:'center', gap:10 }}>
                <Avatar initials={e.avatarInitials} size={34} risk={e.riskScore} />
                <div>
                  <div style={{ fontFamily:'var(--sans)', fontSize:13, fontWeight:600, marginBottom:2 }}>{e.name}</div>
                  <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--muted2)' }}>@{e.email}</div>
                </div>
              </div>
              <div style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--muted2)', alignSelf:'center' }}>{e.department}</div>
              <div style={{ alignSelf:'center' }}>
                <span style={{ fontFamily:'var(--mono)', fontSize:10, fontWeight:700, padding:'3px 8px', borderRadius:99, textTransform:'capitalize', ...statusStyle[e.status] }}>
                  {e.status}
                </span>
              </div>
              <div style={{ fontFamily:'var(--mono)', fontSize:12, color:'var(--text)', alignSelf:'center', fontWeight:600 }}>{e.totalScans}</div>
              <div style={{ alignSelf:'center' }}>
                <div style={{ fontFamily:'var(--display)', fontSize:15, fontWeight:800, color:riskColor(e.riskScore) }}>{e.riskScore}</div>
                <div style={{ height:2, width:40, background:'rgba(255,255,255,.06)', borderRadius:99, marginTop:3 }}>
                  <div style={{ height:'100%', width:`${e.riskScore}%`, background:riskColor(e.riskScore), borderRadius:99 }}/>
                </div>
              </div>
              <div style={{ alignSelf:'center', display:'flex', gap:6 }}>
                <button onClick={ev => { ev.stopPropagation(); setSelectedUser(e); }} style={{ background:'transparent', border:'1px solid var(--border)', borderRadius:7, padding:'4px 6px', cursor:'pointer', color:'var(--muted)', transition:'all 120ms' }}
                  onMouseEnter={ev => { ev.currentTarget.style.borderColor='var(--border2)'; ev.currentTarget.style.color='var(--text)'; }}
                  onMouseLeave={ev => { ev.currentTarget.style.borderColor='var(--border)'; ev.currentTarget.style.color='var(--muted)'; }}
                ><Icons.Edit /></button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {selectedUser && (
        <div style={{ width:300, flexShrink:0, padding:'24px 20px', overflowY:'auto', animation:'slide-in 200ms var(--ease)' }}>
          <div style={{ textAlign:'center', marginBottom:20 }}>
            <Avatar initials={selectedUser.avatarInitials} size={56} risk={selectedUser.riskScore} />
            <div style={{ fontFamily:'var(--display)', fontSize:15, fontWeight:800, marginTop:12 }}>{selectedUser.name}</div>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--muted2)', marginTop:4 }}>@{selectedUser.email}</div>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--muted)', marginTop:2 }}>{selectedUser.department}</div>
          </div>

          <div style={{ marginBottom:20, padding:'14px 16px', background:'var(--surface)', border:'1px solid var(--border)', borderRadius:12 }}>
            <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8 }}>
              <span style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--muted2)', letterSpacing:'.1em', textTransform:'uppercase' }}>Risk Score</span>
              <span style={{ fontFamily:'var(--display)', fontSize:20, fontWeight:800, color:riskColor(selectedUser.riskScore) }}>{selectedUser.riskScore}</span>
            </div>
            <div style={{ height:4, background:'rgba(255,255,255,.06)', borderRadius:99, overflow:'hidden' }}>
              <div style={{ height:'100%', width:`${selectedUser.riskScore}%`, background:`linear-gradient(90deg,#34d399,${riskColor(selectedUser.riskScore)})`, borderRadius:99, transition:'width 600ms var(--ease)' }}/>
            </div>
          </div>

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:10, marginBottom:20 }}>
            {[
              { label:'Total Scans', val:selectedUser.totalScans, color:'var(--neon)' },
              { label:'Detections', val:selectedUser.totalDetections, color:'var(--accent)' },
            ].map(s => (
              <div key={s.label} style={{ padding:'12px 14px', background:'var(--surface)', border:'1px solid var(--border)', borderRadius:10 }}>
                <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--muted2)', letterSpacing:'.1em', textTransform:'uppercase', marginBottom:4 }}>{s.label}</div>
                <div style={{ fontFamily:'var(--display)', fontSize:20, fontWeight:800, color:s.color }}>{s.val}</div>
              </div>
            ))}
          </div>

          <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--muted2)', letterSpacing:'.1em', textTransform:'uppercase', marginBottom:6 }}>Last Active</div>
          <div style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--text)', marginBottom:20 }}>{fmtDate(selectedUser.lastSeen)}</div>

          <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
            {selectedUser.status !== 'active' && (
              <ActionBtn variant="success" fullWidth size="sm" icon={<Icons.Check />} onClick={() => onUpdate(selectedUser.id, { status:'active' })}>Reactivate</ActionBtn>
            )}
            {selectedUser.status === 'active' && (
              <ActionBtn variant="warn" fullWidth size="sm" icon={<Icons.Ban />} onClick={() => onUpdate(selectedUser.id, { status:'suspended' })}>Suspend Access</ActionBtn>
            )}
            <ActionBtn variant="ghost" fullWidth size="sm" icon={<Icons.Download />}>Export Activity</ActionBtn>
          </div>
        </div>
      )}
    </div>
  );
}

function PoliciesPage({ rules, onToggle, onSeverityChange }: { rules: PolicyRule[]; onToggle: (id:string)=>void; onSeverityChange: (id:string, sev:Severity)=>void; }) {
  const [search, setSearch] = useState('');
  const [catFilter, setCatFilter] = useState<RuleCategory|'ALL'>('ALL');
  const cats: Array<RuleCategory|'ALL'> = ['ALL','PII','FINANCIAL','HEALTH','CREDENTIALS','CUSTOM'];

  const filtered = rules.filter(r => {
    const ms = !search || r.name.toLowerCase().includes(search.toLowerCase());
    const mc = catFilter === 'ALL' || r.category === catFilter;
    return ms && mc;
  });

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', animation:'fade-in 300ms var(--ease)' }}>
      <div style={{ padding:'14px 22px', borderBottom:'1px solid var(--border)', display:'flex', gap:10, alignItems:'center', flexWrap:'wrap', flexShrink:0 }}>
        {cats.map(c => (
          <button key={c} onClick={() => setCatFilter(c)} style={{
            padding:'4px 12px', borderRadius:99, border:'1px solid var(--border)', cursor:'pointer',
            fontFamily:'var(--mono)', fontSize:10, fontWeight:600, textTransform:'uppercase', letterSpacing:'.05em',
            background: catFilter===c ? (c==='ALL'?'var(--neon-dim)':`${CAT_BG[c as RuleCategory]}`) : 'transparent',
            color: catFilter===c ? (c==='ALL'?'var(--neon)':CAT_COLOR[c as RuleCategory]) : 'var(--muted)',
            borderColor: catFilter===c ? (c==='ALL'?'rgba(234,179,8,.3)':'') : 'var(--border)',
            transition:'all 130ms',
          }}>{c}</button>
        ))}
        <div style={{ marginLeft:'auto' }}><SearchInput value={search} onChange={setSearch} placeholder="Search rules…"/></div>
        <ActionBtn variant="primary" size="sm" icon={<Icons.Plus />}>Add Rule</ActionBtn>
      </div>

      <div style={{ flex:1, overflowY:'auto' }}>
        <div style={{ display:'grid', gridTemplateColumns:'1fr 100px 100px 100px 80px 60px', gap:12, padding:'8px 22px', borderBottom:'1px solid var(--border)', background:'rgba(255,255,255,.01)' }}>
          {['Rule','Category','Severity','Detections','Status',''].map(h => (
            <div key={h} style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--muted2)', letterSpacing:'.1em', textTransform:'uppercase' }}>{h}</div>
          ))}
        </div>

        {filtered.map(r => (
          <div key={r.id} style={{
            display:'grid', gridTemplateColumns:'1fr 100px 100px 100px 80px 60px',
            gap:12, padding:'14px 22px', borderBottom:'1px solid rgba(255,255,255,.03)',
            transition:'background 120ms', opacity:r.enabled ? 1 : 0.55,
          }}
            onMouseEnter={e => (e.currentTarget.style.background='rgba(255,255,255,.02)')}
            onMouseLeave={e => (e.currentTarget.style.background='transparent')}
          >
            <div>
              <div style={{ fontFamily:'var(--sans)', fontSize:13, fontWeight:600, marginBottom:3 }}>{r.name}</div>
              <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--muted2)', marginBottom:4 }}>{r.description}</div>
              <code style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--muted)', background:'rgba(255,255,255,.04)', padding:'2px 6px', borderRadius:4 }}>{r.pattern}</code>
            </div>
            <div style={{ alignSelf:'center' }}>
              <span style={{ fontFamily:'var(--mono)', fontSize:9, fontWeight:700, padding:'3px 8px', borderRadius:99, textTransform:'uppercase', letterSpacing:'.07em', color:CAT_COLOR[r.category], background:CAT_BG[r.category], border:`1px solid ${CAT_COLOR[r.category]}33` }}>{r.category}</span>
            </div>
            <div style={{ alignSelf:'center' }}>
              <select value={r.severity} onChange={e => onSeverityChange(r.id, e.target.value as Severity)} onClick={e => e.stopPropagation()} style={{
                background:SEV_BG[r.severity], border:`1px solid ${SEV_BORDER[r.severity]}`, borderRadius:7,
                color:SEV_COLOR[r.severity], fontFamily:'var(--mono)', fontSize:10, fontWeight:700,
                padding:'3px 6px', outline:'none', cursor:'pointer', textTransform:'uppercase',
              }}>
                {(['LOW','MEDIUM','HIGH','CRITICAL'] as Severity[]).map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div style={{ fontFamily:'var(--display)', fontSize:16, fontWeight:800, color:'var(--neon)', alignSelf:'center' }}>
              {r.detectionCount.toLocaleString()}
            </div>
            <div style={{ alignSelf:'center', display:'flex', alignItems:'center', gap:6 }}>
              <span style={{ fontFamily:'var(--mono)', fontSize:9, color:r.enabled?'#34d399':'var(--muted2)' }}>{r.enabled?'On':'Off'}</span>
            </div>
            <div style={{ alignSelf:'center', display:'flex', gap:6 }}>
              <button onClick={() => onToggle(r.id)} style={{ background:'none', border:'none', cursor:'pointer', padding:0, display:'flex' }}>
                <Icons.Toggle on={r.enabled} />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ReportsPage({ employees, activity }: { employees: Employee[]; activity: ActivityLog[] }) {
  // Use the variables to calculate real reporting data
  const totalScans = employees.reduce((s, e) => s + e.totalScans, 0);
  const totalDetections = employees.reduce((s, e) => s + e.totalDetections, 0);
  const redactedCount = activity.filter(a => a.redacted).length;
  
  // Calculate compliance score based on redacted vs total unredacted critical logs
  const complianceScore = activity.length === 0 ? 100 : Math.round((redactedCount / activity.length) * 100);

  return (
    <div style={{ padding: '28px', display: 'flex', flexDirection: 'column', gap: 24, overflowY: 'auto', height: '100%', animation: 'fade-in 300ms var(--ease)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontFamily: 'var(--display)', fontSize: 11, letterSpacing: '.12em', textTransform: 'uppercase', color: 'var(--muted2)', marginBottom: 6 }}>Compliance & Analytics</div>
          <div style={{ fontFamily: 'var(--display)', fontSize: 22, fontWeight: 800, letterSpacing: '.02em', background: 'linear-gradient(135deg,#fff,var(--neon))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Reports</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <ActionBtn variant="ghost" size="sm" icon={<Icons.Download />}>Export PDF</ActionBtn>
          <ActionBtn variant="primary" size="sm" icon={<Icons.Download />}>Export CSV</ActionBtn>
        </div>
      </div>

      {/* Real Data Visualization */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
        <StatCard label="Compliance Score" value={`${complianceScore}%`} sub="Target: 95%+" color="var(--neon)" spark={[80, 85, 90, complianceScore]} />
        <StatCard label="Total scans" value={totalScans} sub="Across organization" color="var(--accent)" />
        <StatCard label="Total Detections" value={totalDetections} sub="Total PII flags" color="var(--danger)" />
      </div>

      <div style={{ padding: '24px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 14, textAlign: 'center', color: 'var(--muted)' }}>
        <div style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>
          Detailed audit logs for {employees.length} employees and {activity.length} activity records loaded.
        </div>
      </div>
    </div>
  );
}
// ── Main Admin App ────────────────────────────────────────────────────────────
let _toastId = 0;
type Toast = { id: number; msg: string; type: 'ok'|'danger'|'warn' };

export default function AdminApp() {
  const [page, setPage] = useState<AdminPage>('dashboard');
  
  // State definitions
  const [employees, setEmployees] = useState<any[]>([]);
  const [activity, setActivity] = useState<any[]>([]);
  const [rules, setRules] = useState<PolicyRule[]>([]);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [loading, setLoading] = useState(true);

  const addToast = useCallback((msg: string, type: Toast['type'] = 'ok') => {
    const id = ++_toastId;
    setToasts(prev => [...prev, { id, msg, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 3500);
  }, []);

  // CONSOLIDATED DATA LOADER
  // This maps the Rust snake_case to your React camelCase
  const loadData = useCallback(async () => {
    try {
      const [empRes, actRes, ruleRes] = await Promise.all([
        invoke<any[]>('list_employees'),
        invoke<any[]>('list_activity', { employeeId: null }),
        invoke<any[]>('list_rules')
      ]);

      setEmployees(empRes.map(e => ({
        ...e,
        lastSeen: e.last_seen,
        totalScans: e.total_scans,
        totalDetections: e.total_detections,
        riskScore: e.risk_score,
        avatarInitials: e.avatar_initials,
      })));

      setActivity(actRes.map(a => ({
        ...a,
        employeeId: a.employee_id,
        employeeName: a.employee_name,
        detectionCount: a.detection_count,
        highestSeverity: a.highest_severity,
        piiTypes: a.pii_types
      })));

      setRules(ruleRes.map(r => ({
        ...r,
        detectionCount: r.detection_count
      })));
      
      setLoading(false);
    } catch (err) {
      console.error("Axiom Sync Error:", err);
      // Only show toast if it's the first failure to avoid spamming the user
      if (loading) addToast("Failed to sync with backend", "danger");
    }
  }, [addToast, loading]);

  // SINGLE HEARTBEAT EFFECT
  useEffect(() => {
    // Initial fetch
    loadData(); 
    
    // Auto-refresh every 3 seconds
    const intervalId = setInterval(() => {
      loadData();
    }, 3000); 

    return () => clearInterval(intervalId);
  }, [loadData]);

  const handleEmployeeUpdate = useCallback(async (id: string, patch: any) => {
    try {
      const updated = await invoke<any>('update_employee', { id, patch });
      // Refresh all data after an update to stay in sync
      loadData();
      addToast(`Employee status: ${updated.status}`, 'ok');
    } catch (err) {
      addToast("Failed to update employee", "danger");
    }
  }, [addToast, loadData]);

  const handleRuleToggle = useCallback(async (id: string) => {
    try {
      await invoke<any>('toggle_rule', { id });
      loadData();
      addToast(`Policy Updated`, 'ok');
    } catch (err) {
      addToast("Failed to toggle rule", "danger");
    }
  }, [addToast, loadData]);

  const handleSeverityChange = useCallback(async (id: string, severity: Severity) => {
    try {
      await invoke<any>('set_rule_severity', { id, severity });
      loadData();
      addToast(`Severity updated to ${severity}`, 'ok');
    } catch (err) {
      addToast("Failed to update severity", "danger");
    }
  }, [addToast, loadData]);

  if (loading) {
    return (
      <div style={{ height: '100vh', display: 'grid', placeItems: 'center', background: 'var(--bg)', color: 'var(--neon)' }}>
        <div style={{ animation: 'spin 1s linear infinite' }}><Icons.Shield /></div>
      </div>
    );
  }

  const activeEmployees = employees.filter(e => e.status === 'active').length;

  return (
    <div style={{
      position:'relative', zIndex:1,
      height:'100vh', display:'grid', gridTemplateColumns:'240px 1fr',
      fontFamily:'var(--sans)', color:'var(--text)', background:'var(--bg)',
    }}>
      <aside style={{ height:'100%', display:'flex', flexDirection:'column', borderRight:'1px solid var(--border)', background:'rgba(8,11,15,.85)', backdropFilter:'blur(20px)' }}>
        <div style={{ padding:'20px 20px 18px', borderBottom:'1px solid var(--border)' }}>
          <div style={{ fontFamily:'var(--display)', fontWeight:900, fontSize:22, letterSpacing:'.06em', background:'linear-gradient(135deg, #fff 0%, var(--neon) 100%)', WebkitBackgroundClip:'text', WebkitTextFillColor:'transparent', backgroundClip:'text', lineHeight:1, marginBottom:4 }}>AXIOM</div>
          <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'rgba(234,179,8,.5)', letterSpacing:'.18em', textTransform:'uppercase' }}>
            <span style={{ color:'var(--neon)', opacity:.7 }}>▲</span> Admin Console
          </div>
        </div>

        <nav style={{ padding:'16px 12px 8px', flex:1, display:'flex', flexDirection:'column', gap:3 }}>
          <div style={{ fontFamily:'var(--mono)', fontSize:9, letterSpacing:'.15em', textTransform:'uppercase', color:'var(--muted2)', padding:'0 8px', marginBottom:6, marginTop:4 }}>Navigation</div>
          {[
            { id:'dashboard', label:'Dashboard', icon:<Icons.Dashboard /> },
            { id:'activity',  label:'Activity Log', icon:<Icons.Activity />, badge: activity.filter(a=>!a.redacted && a.highestSeverity==='CRITICAL').length || undefined },
            { id:'users',     label:'Users', icon:<Icons.Users />, badge: employees.filter(e=>e.riskScore>=85).length || undefined },
            { id:'policies',  label:'Detection Policies', icon:<Icons.Policies /> },
            { id:'reports',   label:'Reports', icon:<Icons.Reports /> },
          ].map(item => (
            <button key={item.id} onClick={() => setPage(item.id as AdminPage)} style={{
              width:'100%', background: page===item.id ? 'var(--neon-dim)' : 'transparent',
              border: `1px solid ${page===item.id ? 'rgba(234,179,8,.2)' : 'transparent'}`,
              color: page===item.id ? 'var(--neon)' : 'var(--muted)',
              padding:'10px 12px', borderRadius:10,
              display:'flex', alignItems:'center', gap:10,
              cursor:'pointer', fontFamily:'var(--sans)', fontSize:13, fontWeight: page===item.id ? 600 : 500,
              transition:'all 130ms var(--ease)', textAlign:'left', position:'relative',
            }}
              onMouseEnter={e => { if(page!==item.id) { e.currentTarget.style.background='var(--surface)'; e.currentTarget.style.color='rgba(255,255,255,.8)'; e.currentTarget.style.borderColor='var(--border)'; } }}
              onMouseLeave={e => { if(page!==item.id) { e.currentTarget.style.background='transparent'; e.currentTarget.style.color='var(--muted)'; e.currentTarget.style.borderColor='transparent'; } }}
            >
              <span style={{
                width:28, height:28, borderRadius:8, display:'grid', placeItems:'center', flexShrink:0,
                border: page===item.id ? '1px solid rgba(234,179,8,.3)' : '1px solid rgba(255,255,255,.06)',
                background: page===item.id ? 'rgba(234,179,8,.08)' : 'rgba(255,255,255,.03)',
              }}>{item.icon}</span>
              {item.label}
              {item.badge != null && (
                <span style={{ marginLeft:'auto', fontFamily:'var(--mono)', fontSize:9, fontWeight:700, padding:'2px 7px', borderRadius:99, background:'rgba(255,61,90,.15)', color:'var(--danger)', border:'1px solid rgba(255,61,90,.3)' }}>{item.badge}</span>
              )}
            </button>
          ))}
        </nav>

        <div style={{ padding:'12px 14px', borderTop:'1px solid var(--border)', display:'flex', flexDirection:'column', gap:10 }}>
          <div style={{ padding:'10px 12px', background:'var(--surface)', border:'1px solid var(--border)', borderRadius:10 }}>
            <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--muted2)', letterSpacing:'.1em', textTransform:'uppercase', marginBottom:6 }}>Organisation</div>
            <div style={{ fontFamily:'var(--sans)', fontSize:12, fontWeight:600, marginBottom:2 }}>Acme Corp</div>
            <div style={{ display:'flex', alignItems:'center', gap:6, fontFamily:'var(--mono)', fontSize:10, color:'var(--muted2)' }}>
              <span style={{ width:6, height:6, borderRadius:'50%', background:'#34d399', boxShadow:'0 0 6px 2px rgba(52,211,153,.4)', animation:'blink 2.5s infinite' }}/>
              {activeEmployees} active employee{activeEmployees!==1?'s':''}
            </div>
          </div>
        </div>
      </aside>

      <main style={{ height:'100%', display:'flex', flexDirection:'column', overflow:'hidden' }}>
        <div style={{
          position:'sticky', top:0, zIndex:20, padding:'14px 24px 12px',
          borderBottom:'1px solid var(--border)', backdropFilter:'blur(20px)',
          background:'linear-gradient(180deg, rgba(8,11,15,.9), rgba(8,11,15,.5))',
          display:'flex', alignItems:'center', justifyContent:'space-between', gap:12, flexShrink:0,
        }}>
          <div>
            <div style={{ fontFamily:'var(--display)', fontSize:13, fontWeight:700, letterSpacing:'.04em' }}>Admin Console</div>
            <div style={{ color:'var(--muted2)', fontSize:11, marginTop:3, fontFamily:'var(--mono)' }}>Organization Data Overview</div>
          </div>
          <div style={{ display:'flex', gap:8, alignItems:'center' }}>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--muted2)' }}>{new Date().toLocaleTimeString('en-US', { hour12:false })}</div>
            <div style={{ width:1, height:16, background:'var(--border)' }}/>
            <Avatar initials="AD" size={28} />
            <span style={{ fontFamily:'var(--sans)', fontSize:12, fontWeight:500 }}>Admin</span>
          </div>
        </div>

        <div style={{ flex:1, overflowY: page==='activity'||page==='users'||page==='policies' ? 'hidden' : 'auto', display:'flex', flexDirection:'column' }}>
          {page === 'dashboard' && <DashboardPage employees={employees} activity={activity} onNav={setPage} />}
          {page === 'activity' && <ActivityPage activity={activity} />}
          {page === 'users' && <UsersPage employees={employees} onUpdate={handleEmployeeUpdate} refreshData={loadData} />}
          {page === 'policies' && <PoliciesPage rules={rules} onToggle={handleRuleToggle} onSeverityChange={handleSeverityChange} />}
          {page === 'reports' && <ReportsPage employees={employees} activity={activity} />}
        </div>
      </main>

      <div style={{ position:'fixed', top:16, right:16, zIndex:9999, display:'flex', flexDirection:'column', gap:8, maxWidth:320, pointerEvents:'none' }}>
        {toasts.map(t => (
          <div key={t.id} style={{
            borderRadius:12, overflow:'hidden', pointerEvents:'all',
            border:`1px solid ${t.type==='ok'?'rgba(234,179,8,.2)':'rgba(255,61,90,.25)'}`,
            background:'rgba(14,18,26,.97)', backdropFilter:'blur(16px)',
            boxShadow:'0 8px 32px rgba(0,0,0,.5)', animation:'slide-in 250ms var(--ease) both',
          }}>
            <div style={{ display:'flex', alignItems:'center', gap:10, padding:'12px 14px' }}>
              <div style={{
                width:28, height:28, borderRadius:8, display:'grid', placeItems:'center', flexShrink:0,
                background:t.type==='ok'?'var(--neon-dim)':'var(--danger-bg)',
                border:`1px solid ${t.type==='ok'?'rgba(234,179,8,.25)':'rgba(255,61,90,.3)'}`,
                color:t.type==='ok'?'var(--neon)':'var(--danger)',
              }}>{t.type==='ok'?<Icons.Check />:<Icons.Alert />}</div>
              <span style={{ fontFamily:'var(--sans)', fontSize:12, fontWeight:500, flex:1 }}>{t.msg}</span>
            </div>
            <div style={{ height:3, background:'rgba(255,255,255,.05)' }}>
              <div style={{ height:'100%', width:'100%', background:t.type==='ok'?'var(--neon)':'var(--danger)', animation:'shrink 3.5s linear forwards' }}/>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}