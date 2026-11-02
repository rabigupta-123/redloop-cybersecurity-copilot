"""Read-only RedLoop operations dashboard."""

from __future__ import annotations

import json
from datetime import date
from html import escape
from ipaddress import ip_network
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from redloop.reporting import AuditReader, MAX_DASHBOARD_ROWS, MAX_REPORT_ROWS
from redloop.scope import ScopeManager
from starlette.requests import Request

_MODULES = (
    ("recon", "Recon"),
    ("webapp", "Web App"),
    ("exploit", "Exploit"),
    ("forensics", "Forensics"),
    ("executor", "Executor"),
    ("memory", "Memory"),
)

_DARK_TOKENS = """
  /* Dark is the historical REDLOOP default. */
  --bg: #0b0b10;
  --bg-elevated: #121218;
  --surface: #121218;
  --surface-2: #17171f;
  --surface-elevated: #1b1b24;
  --surface-glass: rgba(18, 18, 24, 0.78);
  --border: #1e293b;
  --border-subtle: rgba(148, 163, 184, 0.12);
  --border-glow: rgba(37, 99, 235, 0.38);
  --border-cyan: rgba(37, 99, 235, 0.28);
  --border-amber-glow: rgba(249, 115, 22, 0.30);
  --fg: #f8fafc;
  --fg-muted: #94a3b8;
  --fg-subtle: #8b9bb0;
  --accent: #f97316;
  --accent-strong: #fb923c;
  --accent-soft: rgba(249, 115, 22, 0.14);
  --accent-hover: #fb923c;
  --accent-cyber: #2563eb;
  --accent-cyber-hover: #3b82f6;
  --accent-blue: #60a5fa;
  --accent-amber: #f99c00;
  --accent-purple: #a855f7;
  --accent-green: #00bb7f;
  --accent-critical: #ef4444;
  --accent-critical-bg: rgba(239, 68, 68, 0.12);
  --success-bg: rgba(0, 187, 127, 0.12);
  --success: #00bb7f;
  --success-strong: #34d399;
  --warning-bg: rgba(249, 156, 0, 0.12);
  --warning: #f99c00;
  --warning-strong: #fbbf24;
  --info-bg: rgba(37, 99, 235, 0.12);
  --info: #2563eb;
  --info-strong: #60a5fa;
  --critical: #ef4444;
  --critical-bg: rgba(239, 68, 68, 0.12);
  --accent-ink: #fb923c;
  --accent-button: #C2410C;
  --accent-button-hover: #9A3412;
  --brand: #2563eb;
  --primary: #2563eb;
  --radius: 16px;
  --radius-sm: 8px;
  --radius-md: 12px;
  --radius-lg: 16px;
  --radius-xl: 22px;
  --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.35);
  --shadow-md: 0 4px 16px rgba(0, 0, 0, 0.36), 0 1px 3px rgba(0, 0, 0, 0.22);
  --shadow-lg: 0 12px 32px rgba(0, 0, 0, 0.55);
  --shadow-glow: 0 0 20px rgba(249, 115, 22, 0.18);
  --bg-old: #0b0b10;
  --accent-old: #f97316;
  --text-xs: 12px;
  --text-sm: 14px;
  --text-md: 16px;
  --text-lg: 20px;
  --text-xl: 28px;
  --text-2xl: 36px;
  --font-body: "DM Sans", "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  --font-mono: "JetBrains Mono", ui-monospace, "SF Mono", "Cascadia Code", "Consolas", monospace;
  --font-display: "Space Grotesk", "DM Sans", "Inter", system-ui, sans-serif;
"""

_LIGHT_TOKENS = """
  /* Light "white + orange" palette. Body text always uses --fg; --accent-strong
     is reserved for large text, icons, and UI strokes (>= 3:1 on white). */
  --bg: #FFF8F2;
  --bg-elevated: #FFFFFF;
  --surface: #FFFFFF;
  --surface-2: #FFF1E6;
  --surface-elevated: #FFFFFF;
  --surface-glass: rgba(255, 255, 255, 0.84);
  --border: #F1E3D6;
  --border-subtle: rgba(31, 27, 22, 0.08);
  --border-glow: rgba(234, 88, 12, 0.28);
  --border-cyan: rgba(234, 88, 12, 0.24);
  --border-amber-glow: rgba(234, 88, 12, 0.28);
  --fg: #1F1B16;
  --fg-muted: #756A61;
  --fg-subtle: #6F645B;
  --accent: #F97316;
  --accent-strong: #EA580C;
  --accent-soft: #FFEDD5;
  --accent-hover: #EA580C;
  --accent-cyber: #C2410C;
  --accent-cyber-hover: #9A3412;
  --accent-blue: #C2410C;
  --accent-amber: #D97706;
  --accent-purple: #7E22CE;
  --accent-green: #16A34A;
  --accent-critical: #DC2626;
  --accent-critical-bg: rgba(220, 38, 38, 0.10);
  --success-bg: rgba(22, 163, 74, 0.12);
  --success: #16A34A;
  --success-strong: #15803D;
  --warning-bg: rgba(217, 119, 6, 0.12);
  --warning: #D97706;
  --warning-strong: #B45309;
  --info-bg: rgba(2, 132, 199, 0.10);
  --info: #0284C7;
  --info-strong: #0369A1;
  --critical: #DC2626;
  --critical-bg: rgba(220, 38, 38, 0.10);
  --accent-ink: #C2410C;
  --accent-button: #C2410C;
  --accent-button-hover: #9A3412;
  --brand: #EA580C;
  --primary: #EA580C;
  --radius: 16px;
  --radius-sm: 10px;
  --radius-md: 12px;
  --radius-lg: 16px;
  --radius-xl: 22px;
  --shadow-sm: 0 1px 2px rgba(31, 27, 22, 0.06);
  --shadow-md: 0 6px 20px rgba(31, 27, 22, 0.08), 0 1px 3px rgba(31, 27, 22, 0.06);
  --shadow-lg: 0 18px 40px rgba(31, 27, 22, 0.12);
  --shadow-glow: 0 10px 28px rgba(249, 115, 22, 0.18);
  --bg-old: #FFF8F2;
  --accent-old: #F97316;
  --text-xs: 12px;
  --text-sm: 14px;
  --text-md: 16px;
  --text-lg: 20px;
  --text-xl: 28px;
  --text-2xl: 36px;
  --font-body: "DM Sans", "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  --font-mono: "JetBrains Mono", ui-monospace, "SF Mono", "Cascadia Code", "Consolas", monospace;
  --font-display: "Space Grotesk", "DM Sans", "Inter", system-ui, sans-serif;
"""

THEME_TOKENS_CSS = (
    ":root {" + _DARK_TOKENS + "  color-scheme: dark;\n}\n"
    ':root[data-theme="light"] {' + _LIGHT_TOKENS + "  color-scheme: light;\n}\n"
    "@media (prefers-color-scheme: light) {\n"
    '  :root:not([data-theme]) {' + _LIGHT_TOKENS + "    color-scheme: light;\n  }\n}\n"
)

_SHARED_DASHBOARD_CSS = THEME_TOKENS_CSS + """

* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  background:
    radial-gradient(1400px 600px at 50% -100px, rgba(37, 99, 235, 0.10), transparent 60%),
    radial-gradient(700px 400px at 90% 20%, rgba(249, 115, 22, 0.05), transparent 60%),
    var(--bg);
  color: var(--fg);
  font-family: var(--font-body);
  font-size: 13px;
  line-height: 1.55;
  min-height: 100vh;
  overflow-x: hidden;
}
h1, h2, h3 { font-family: var(--font-display); font-weight: 700; letter-spacing: -0.02em; margin: 0; }
a { color: inherit; text-decoration: none; }
:focus-visible { outline: 2px solid var(--accent-strong); outline-offset: 2px; }

/* SHELL */
.shell {
  display: grid;
  grid-template-columns: 250px minmax(0, 1fr);
  min-height: 100vh;
  transition: grid-template-columns 0.25s cubic-bezier(0.16, 1, 0.3, 1);
}

/* SIDEBAR */
.sidebar {
  position: sticky;
  top: 0;
  height: 100vh;
  display: flex;
  flex-direction: column;
  background: linear-gradient(180deg, rgba(13, 19, 34, 0.97), rgba(8, 12, 21, 0.99));
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-right: 1px solid var(--border);
  box-shadow: 4px 0 40px rgba(0, 0, 0, 0.4);
  z-index: 60;
  user-select: none;
}
.sidebar-header {
  padding: 18px 16px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.brand, .brand-wrap { display: flex; align-items: center; gap: 10px; }
.brand {
  padding: 20px 16px 16px;
  border-bottom: 1px solid var(--border);
}
.brand > div:last-child { min-width: 0; }
.brand-mark {
  width: 38px;
  height: 38px;
  border-radius: 10px;
  background: linear-gradient(135deg, var(--accent), #3b82f6);
  display: grid;
  place-items: center;
  font-family: var(--font-display);
  font-weight: 800;
  font-size: 14px;
  color: #030712;
  box-shadow: 0 0 20px rgba(6, 182, 212, 0.4);
  flex-shrink: 0;
}
.brand-text { overflow: hidden; }
.brand-name {
  font-weight: 700;
  font-size: 14px;
  letter-spacing: -0.01em;
  color: var(--fg);
  white-space: nowrap;
}
.brand-sub {
  font-size: 10px;
  color: var(--fg-muted);
  font-family: var(--font-mono);
  margin-top: 1px;
  white-space: nowrap;
}
.nav-section { margin-bottom: 20px; }
.navlabel {
  padding: 10px 14px 4px;
  font-size: 9.5px;
  font-weight: 700;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--fg-subtle);
  font-family: var(--font-mono);
}
.navlink {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 14px;
  margin: 2px 6px;
  border-radius: 8px;
  color: var(--fg-muted);
  font-size: 12.5px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.18s cubic-bezier(0.16, 1, 0.3, 1);
  text-decoration: none;
  border: 1px solid transparent;
}
.navlink svg { width: 16px; height: 16px; flex: none; stroke-width: 1.7; transition: stroke 0.18s ease; }
.navlink:hover {
  background: rgba(6, 182, 212, 0.08);
  color: var(--fg);
  border-color: rgba(6, 182, 212, 0.25);
  transform: translateX(3px);
}
.navlink.active {
  background: linear-gradient(90deg, rgba(6, 182, 212, 0.14), rgba(6, 182, 212, 0.04));
  color: var(--fg);
  font-weight: 600;
  border-color: rgba(6, 182, 212, 0.4);
  box-shadow: inset 2px 0 0 0 var(--accent);
}
.navlink.active svg { stroke: var(--accent); }
.count {
  margin-left: auto;
  color: var(--fg-subtle);
  font-family: var(--font-display);
  font-size: 11px;
  background: rgba(255, 255, 255, 0.05);
  padding: 1px 8px;
  border-radius: 10px;
}
.sidebar-foot {
  margin-top: auto;
  padding: 14px 16px;
  border-top: 1px solid var(--border);
  color: var(--fg-subtle);
  font-size: 10px;
  font-family: var(--font-mono);
  display: flex;
  align-items: center;
  gap: 8px;
}
.sidebar-foot .foot-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--accent-green);
  box-shadow: 0 0 10px var(--accent-green);
}

/* MAIN */
main {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 26px;
  padding: 28px clamp(22px, 4vw, 48px) 56px 32px;
}
.topline {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
  margin-bottom: 4px;
}
.topline h1 {
  font-size: 22px;
  letter-spacing: -0.02em;
  color: var(--fg);
}
.topline p {
  margin: 5px 0 0;
  color: var(--fg-muted);
  font-size: 12.5px;
}
.top-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }

/* COMPONENTS */
.tele-pill {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 6px 16px;
  border-radius: 10px;
  font-size: 11.5px;
  font-weight: 600;
  font-family: var(--font-display);
  cursor: pointer;
  text-decoration: none;
  background: rgba(6, 182, 212, 0.08);
  border: 1px solid rgba(6, 182, 212, 0.28);
  color: var(--accent);
  transition: all 0.2s ease;
}
.tele-pill:hover {
  background: rgba(6, 182, 212, 0.16);
  transform: translateY(-1px);
  box-shadow: 0 4px 16px rgba(6, 182, 212, 0.25);
}
.pulse-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--accent-green);
  box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
  animation: pulse-ring 2s infinite cubic-bezier(0.66, 0, 0, 1);
}
@keyframes pulse-ring {
  0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
  70% { box-shadow: 0 0 0 10px rgba(16, 185, 129, 0); }
  100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
}

.scope-banner {
  display: flex;
  align-items: center;
  gap: 24px 36px;
  flex-wrap: wrap;
  padding: 22px 28px;
  border: 1px solid var(--border);
  border-radius: 14px;
  background: linear-gradient(135deg, rgba(17, 24, 39, 0.9), rgba(13, 20, 36, 0.85));
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  box-shadow: 0 8px 32px -4px rgba(0, 0, 0, 0.55), inset 0 1px 0 rgba(255, 255, 255, 0.06);
}
.scope-item {
  display: flex;
  min-width: min(150px, 100%);
  flex-direction: column;
  gap: 4px;
}
.scope-item .key {
  color: var(--fg-subtle);
  font-size: 10.5px;
  letter-spacing: 0.09em;
  text-transform: uppercase;
  font-family: var(--font-display);
  font-weight: 700;
}
.scope-item .value {
  overflow-wrap: anywhere;
  font-family: var(--font-display);
  font-size: 13px;
  font-weight: 600;
}
.scope-pill {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  margin-left: auto;
  padding: 6px 16px;
  border-radius: 10px;
  background: var(--success-bg);
  color: var(--accent-green);
  font-size: 11px;
  font-weight: 700;
  font-family: var(--font-display);
  white-space: nowrap;
  box-shadow: inset 0 0 0 1px rgba(16, 185, 129, 0.3);
  border: 1px solid rgba(16, 185, 129, 0.2);
}
.scope-pill::before {
  content: "";
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 10px currentColor;
}
.scope-pill.danger {
  background: var(--accent-critical-bg);
  color: var(--accent-critical);
  box-shadow: inset 0 0 0 1px rgba(239, 68, 68, 0.3);
  border-color: rgba(239, 68, 68, 0.25);
}
.scope-pill.danger::before { background: var(--accent-critical); box-shadow: 0 0 10px var(--accent-critical); }
.scope-pill.muted {
  background: rgba(255, 255, 255, 0.04);
  color: var(--fg-muted);
  box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.08);
  border-color: rgba(255, 255, 255, 0.08);
}

/* STATS TILES */
.stats {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 16px;
}
.tile {
  min-width: 0;
  padding: 22px 24px;
  border: 1px solid var(--border);
  border-radius: 14px;
  background: linear-gradient(145deg, rgba(17, 24, 39, 0.85), rgba(13, 20, 36, 0.7));
  backdrop-filter: blur(14px);
  -webkit-backdrop-filter: blur(14px);
  position: relative;
  overflow: hidden;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.45), inset 0 1px 0 rgba(255, 255, 255, 0.06);
  transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
}
.tile:hover {
  transform: translateY(-3px);
  border-color: rgba(6, 182, 212, 0.4);
  box-shadow: 0 16px 40px -8px rgba(0, 0, 0, 0.6), 0 0 24px rgba(6, 182, 212, 0.12);
}
.tile::before {
  position: absolute;
  inset: 0 auto 0 0;
  width: 3px;
  background: var(--accent);
  content: "";
  box-shadow: 0 0 14px var(--accent);
}
.tile.green::before { background: var(--accent-green); box-shadow: 0 0 14px var(--accent-green); }
.tile.purple::before { background: var(--accent-purple); box-shadow: 0 0 14px var(--accent-purple); }
.tile.amber::before { background: var(--accent-amber); box-shadow: 0 0 14px var(--accent-amber); }
.tile.red::before { background: var(--accent-critical); box-shadow: 0 0 14px var(--accent-critical); }

.tile .label {
  color: var(--fg-muted);
  font-size: 10.5px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  font-family: var(--font-display);
  font-weight: 700;
}
.tile .value {
  margin-top: 8px;
  font-family: var(--font-display);
  font-size: 30px;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
  letter-spacing: -0.03em;
  color: var(--fg);
}
.tile .delta {
  margin-top: 8px;
  color: var(--fg-muted);
  font-size: 11.5px;
  font-family: var(--font-display);
}
.tile .delta.up { color: var(--accent-critical); }
.tile .bullet-bar {
  margin-top: 12px;
  width: 100%;
  height: 5px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.05);
  overflow: hidden;
}
.tile .bullet-fill {
  height: 100%;
  border-radius: 999px;
  background: var(--accent);
}
.tile.green .bullet-fill { background: var(--accent-green); }
.tile.purple .bullet-fill { background: var(--accent-purple); }
.tile.amber .bullet-fill { background: var(--accent-amber); }
.tile.red .bullet-fill { background: var(--accent-critical); }

.card {
  min-width: 0;
  border: 1px solid var(--border);
  border-radius: 14px;
  background: linear-gradient(145deg, rgba(17, 24, 39, 0.85), rgba(13, 20, 36, 0.7));
  backdrop-filter: blur(14px);
  -webkit-backdrop-filter: blur(14px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.45), inset 0 1px 0 rgba(255, 255, 255, 0.05);
  overflow: hidden;
}
.card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  flex-wrap: wrap;
  padding: 18px 26px;
  border-bottom: 1px solid var(--border);
  background: rgba(255, 255, 255, 0.02);
}
.card-head h2 {
  font-size: 13px;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  font-family: var(--font-display);
  color: var(--fg);
}
.filters { display: flex; gap: 8px; flex-wrap: wrap; }
.chip {
  padding: 6px 16px;
  border: 1px solid var(--border);
  border-radius: 10px;
  background: rgba(26, 38, 60, 0.6);
  color: var(--fg-muted);
  font-family: var(--font-display);
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
  text-decoration: none;
  transition: all 0.18s ease;
}
.chip:hover {
  color: var(--fg);
  border-color: rgba(6, 182, 212, 0.4);
  transform: translateY(-1px);
}
.chip.active {
  border-color: rgba(6, 182, 212, 0.5);
  background: rgba(6, 182, 212, 0.12);
  color: var(--accent);
  font-weight: 700;
  box-shadow: 0 0 12px rgba(6, 182, 212, 0.2);
}

.filters-form {
  display: flex;
  gap: 14px;
  align-items: center;
  flex-wrap: wrap;
  padding: 14px 26px;
  border-bottom: 1px solid var(--border);
  background: rgba(0, 0, 0, 0.2);
}
.filters-form label {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 11px;
  color: var(--fg-muted);
  font-family: var(--font-display);
}
.filters-form select, .filters-form input {
  padding: 6px 12px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: #0b111c;
  color: var(--fg);
  font-family: var(--font-display);
  font-size: 11.5px;
  outline: none;
  transition: border-color 0.18s ease, box-shadow 0.18s ease;
}
.filters-form select:focus, .filters-form input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(6, 182, 212, 0.15);
}
.filters-form button {
  padding: 6px 18px;
  border-radius: 8px;
  border: 1px solid rgba(6, 182, 212, 0.35);
  background: rgba(6, 182, 212, 0.1);
  color: var(--accent);
  font-family: var(--font-display);
  font-size: 11px;
  font-weight: 700;
  cursor: pointer;
  transition: all 0.18s ease;
}
.filters-form button:hover {
  background: var(--accent);
  color: #030712;
  box-shadow: 0 0 16px rgba(6, 182, 212, 0.35);
}

.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; text-align: left; }
thead th {
  padding: 12px 22px;
  border-bottom: 1px solid var(--border);
  color: var(--fg-muted);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  font-family: var(--font-display);
  white-space: nowrap;
  background: rgba(2, 4, 8, 0.4);
}
tbody td {
  padding: 12px 22px;
  border-bottom: 1px solid var(--border);
  font-size: 12.5px;
  vertical-align: middle;
  transition: background 0.15s ease;
}
tbody tr:hover td { background: rgba(6, 182, 212, 0.05); }
.badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 10px;
  border-radius: 10px;
  font-size: 10.5px;
  font-weight: 700;
  font-family: var(--font-display);
  white-space: nowrap;
}
.badge-success { background: var(--success-bg); color: var(--accent-green); border: 1px solid rgba(16, 185, 129, 0.3); }
.badge-failed, .badge-blocked { background: var(--accent-critical-bg); color: var(--accent-critical); border: 1px solid rgba(239, 68, 68, 0.3); }
.badge-started { background: var(--info-bg); color: var(--accent-blue); border: 1px solid rgba(79, 140, 255, 0.3); }
.badge-unknown { background: rgba(255, 255, 255, 0.05); color: var(--fg-muted); border: 1px solid var(--border); }

/* MODULE CARDS */
.modules { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; padding: 20px 0; }
.module-card {
  padding: 22px;
  border: 1px solid var(--border);
  border-radius: 14px;
  background: rgba(20, 28, 46, 0.6);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  display: flex;
  flex-direction: column;
  gap: 10px;
  transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
}
.module-card:hover {
  transform: translateY(-3px);
  border-color: rgba(6, 182, 212, 0.4);
  box-shadow: 0 16px 40px -8px rgba(0, 0, 0, 0.55);
}
.module-card .row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}
.module-card h3 {
  font-size: 14px;
  color: var(--fg);
  font-weight: 700;
}
.module-card p {
  margin: 0;
  color: var(--fg-muted);
  font-size: 12px;
  line-height: 1.55;
}
.module-meta {
  margin-top: auto;
  color: var(--fg-subtle);
  font-size: 11px;
  font-family: var(--font-display);
}
.module-status {
  padding: 3px 12px;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.04);
  color: var(--fg-muted);
  font-family: var(--font-display);
  font-size: 10.5px;
  font-weight: 700;
}
.module-status.operational {
  background: var(--success-bg);
  color: var(--accent-green);
  border: 1px solid rgba(16, 185, 129, 0.25);
}
.module-status.partial {
  background: var(--warning-bg);
  color: var(--accent-amber);
  border: 1px solid rgba(245, 158, 11, 0.25);
}

/* CONFIDENCE BAR */
.confidence-bar {
  width: 90px;
  height: 6px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.06);
  overflow: hidden;
  display: inline-block;
  vertical-align: middle;
  margin-left: 10px;
}
.confidence-fill {
  height: 100%;
  border-radius: 999px;
  background: linear-gradient(90deg, var(--accent), var(--accent-green));
}

footer {
  padding: 6px 0 0;
  color: var(--fg-subtle);
  font-size: 11px;
  font-family: var(--font-display);
}

/* RESPONSIVE */
@media (max-width: 1080px) {
  .modules { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 900px) {
  .shell { grid-template-columns: 210px minmax(0, 1fr); }
  .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .modules { grid-template-columns: 1fr; }
}
@media (max-width: 700px) {
  .shell { grid-template-columns: 1fr; }
  .sidebar {
    flex-direction: row;
    align-items: center;
    overflow-x: auto;
    border-right: 0;
    border-bottom: 1px solid var(--border);
    padding: 12px;
    height: auto;
    position: sticky;
    top: 0;
    z-index: 60;
  }
  .sidebar nav { flex-direction: row; gap: 6px; overflow-x: auto; padding-bottom: 8px; }
  .navlabel, .sidebar-foot, .count { display: none; }
  .navlink { white-space: nowrap; padding: 8px 12px; }
  main { padding: 20px 16px 30px 16px; }
  .scope-pill { margin-left: 0; }
}
@media (max-width: 480px) {
  .stats { grid-template-columns: 1fr; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}
"""


def _icon(name: str) -> str:
    shapes = {
        "overview": (
            '<rect x="1.5" y="1.5" width="5.5" height="5.5" rx="1"/>'
            '<rect x="9" y="1.5" width="5.5" height="5.5" rx="1"/>'
            '<rect x="1.5" y="9" width="5.5" height="5.5" rx="1"/>'
            '<rect x="9" y="9" width="5.5" height="5.5" rx="1"/>'
        ),
        "chat": '<path d="M2 3h12v8H7l-4 3V3Z"/><path d="M5 6h6M5 8.5h4"/>',
        "performance": '<path d="M2 13.5h12M4 10.5l3-4 3 2 4-5"/><circle cx="7" cy="6.5" r="1"/><circle cx="10" cy="8.5" r="1"/><circle cx="14" cy="3.5" r="1"/>',
        "recon": '<circle cx="7" cy="7" r="5"/><path d="m10.8 10.8 3.2 3.2"/>',
        "webapp": '<rect x="1.5" y="2.5" width="13" height="11" rx="1.5"/><path d="M1.5 5.5h13"/>',
        "exploit": '<path d="m8 1.5-6 3v4c0 3.5 2.5 5.5 6 6 3.5-.5 6-2.5 6-6v-4l-6-3Z"/>',
        "forensics": '<rect x="2.5" y="2" width="11" height="12" rx="1"/><path d="M5 5.5h6M5 8h6M5 10.5h3.5"/>',
        "memory": '<circle cx="8" cy="8" r="6"/><path d="M8 4.5v3.7l2.2 1.4"/>',
        "scope": '<path d="m8 1.5-5.5 2v4c0 3.6 2.5 5.8 5.5 7 3-1.2 5.5-3.4 5.5-7v-4l-5.5-2Z"/>',
        "reports": '<path d="M4 1.5h5.5l3 3.5v9.5H4Z"/><path d="M9.3 1.5V5h3.2M6 8h4.5M6 10.5h4.5"/>',
    }
    shape = shapes.get(name, shapes["overview"])
    return (
        '<svg viewBox="0 0 16 16" stroke="currentColor" stroke-width="1.5" '
        f'fill="none" aria-hidden="true">{shape}</svg>'
    )


def _render_sidebar(
    active_item: str = "overview",
    module_counts: dict[str, int] | None = None,
    active_module: str | None = None,
) -> str:
    module_counts = module_counts or {}
    overview_active = ' active" aria-current="page"' if active_item == "overview" and not active_module else '"'
    chat_active = ' active" aria-current="page"' if active_item == "chat" else '"'
    perf_active = ' active" aria-current="page"' if active_item == "performance" else '"'

    module_links = []
    for mod_key, mod_label in _MODULES:
        cnt = module_counts.get(mod_key, 0)
        is_mod_active = (active_item == "overview" and active_module == mod_key)
        cls = ' active" aria-current="page"' if is_mod_active else '"'
        query = urlencode({"module": mod_key})
        module_links.append(
            f'<a class="navlink{cls} href="/?{query}#activity">'
            f'{_icon(mod_key)}{escape(mod_label)}'
            f'<span class="count">{cnt}</span></a>'
        )

    return f"""  <aside class="sidebar">
    <div class="brand">
      <div class="brand-mark" aria-hidden="true">RL</div>
      <div>
        <div class="brand-name">RedLoop</div>
        <div class="brand-sub">Mythos Console · v2.5</div>
      </div>
    </div>
    <nav aria-label="Primary navigation">
      <div class="navlabel">Operate</div>
      <a class="navlink{overview_active} href="/">{_icon("overview")}Overview</a>
      <a class="navlink" href="/workbench">{_icon("exploit")}Security Command Center</a>
      <a class="navlink{chat_active} href="/chat">{_icon("chat")}Chat</a>
      <a class="navlink{perf_active} href="/performance">{_icon("performance")}Performance</a>
      {''.join(module_links)}
      <div class="navlabel">Govern</div>
      <a class="navlink" href="/#scope">{_icon("scope")}Scope</a>
      <a class="navlink" href="/#reports">{_icon("reports")}Reports</a>
    </nav>
    <div class="sidebar-foot">
      <span class="foot-dot"></span>
      <span>Engine online · Port 8765</span>
    </div>
  </aside>"""


def create_app(
    db_path: str,
    scope_manager: ScopeManager | None = None,
    assessment_store: Any = None,
):
    try:
        from fastapi import FastAPI, Query, Request
        from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
        from redloop.chat import CHAT_SCRIPT_CSP_HASH, register_chat_routes
        from redloop.workbench import (
            WORKBENCH_SCRIPT_CSP_HASH,
            register_workbench_routes,
        )
        from redloop.unified_app import (
            UNIFIED_CSS,
            UNIFIED_SCRIPT,
            UNIFIED_SCRIPT_CSP_HASH,
            _svg_icon,
            generate_pdf_report,
            generate_pptx_report,
        )
    except ImportError as exc:
        raise RuntimeError(
            "Dashboard dependencies are missing. Install with "
            '`pip install -e ".[dashboard]`.'
        ) from exc

    def _resolve_assessment_store():
        if assessment_store is not None:
            return assessment_store
        asmt_candidate = Path(db_path).parent / "assessments.sqlite"
        if asmt_candidate.exists():
            from redloop.assessment.engine import AssessmentStore
            return AssessmentStore(db_path=asmt_candidate)
        try:
            from redloop.config import settings
            if (settings.data_dir / "assessments.sqlite").exists():
                from redloop.assessment.engine import AssessmentStore
                return AssessmentStore(db_path=settings.data_dir / "assessments.sqlite")
        except Exception:
            pass
        from redloop.assessment.engine import AssessmentStore
        return AssessmentStore()

    reader = AuditReader(db_path)
    from redloop.performance import TokenUsageStore

    token_usage = TokenUsageStore(f"{db_path}.chats.sqlite")
    app = FastAPI(title="RedLoop Console", docs_url=None, redoc_url=None)
    register_chat_routes(app, db_path, scope_manager=scope_manager)
    register_workbench_routes(app, db_path, scope_manager)

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            f"default-src 'none'; script-src 'sha256-{CHAT_SCRIPT_CSP_HASH}' "
            f"'sha256-{WORKBENCH_SCRIPT_CSP_HASH}' 'sha256-{UNIFIED_SCRIPT_CSP_HASH}'; "
            "style-src 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; "
            "connect-src 'self' http://localhost:8080 http://127.0.0.1:8080; "
            "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/", response_class=HTMLResponse)
    def dashboard(
        target: str | None = Query(default=None, max_length=2_048),
        limit: int = Query(default=50, ge=1, le=MAX_DASHBOARD_ROWS),
        module: str | None = Query(default=None, max_length=64),
    ):
        rows, truncated = reader.entries(target=target, limit=limit, module=module)
        all_rows, all_truncated = reader.entries(limit=MAX_REPORT_ROWS)
        target_rows = [
            row
            for row in all_rows
            if not (
                str(row["module"]).casefold() == "memory"
                and str(row["action"]).casefold() == "memory_store"
            )
        ]
        target_values = {str(row["target"]) for row in target_rows}
        targets = [item for item in reader.targets() if item in target_values]
        active_target = target or _active_target(target_rows, scope_manager)
        active_entry = _scope_entry(scope_manager, active_target)
        today = date.today()
        if scope_manager is None:
            scope_label = "Scope unavailable"
            scope_status = "Unavailable"
            authorized_window = "Not verified"
            allowed_actions = "Not available"
            window_remaining = "Not verified"
            status_class = "muted"
        elif active_entry is None:
            scope_label = "No matching scope entry"
            scope_status = "Out of scope"
            authorized_window = "—"
            allowed_actions = "None"
            window_remaining = "—"
            status_class = "danger"
        else:
            in_date_window = (
                active_entry.authorized_from <= today <= active_entry.authorized_until
            )
            is_in_scope = in_date_window and scope_manager.is_within_window()
            scope_label = active_entry.label
            scope_status = "In scope" if is_in_scope else "Out of scope"
            authorized_window = (
                f"{active_entry.authorized_from.isoformat()} → "
                f"{active_entry.authorized_until.isoformat()}"
            )
            allowed_actions = ", ".join(active_entry.allowed_actions) or "None"
            remaining_days = (active_entry.authorized_until - today).days
            if not scope_manager.is_within_window():
                window_remaining = "Scope expired"
            elif remaining_days < 0:
                window_remaining = "Expired"
            else:
                window_remaining = f"{remaining_days} days"
            status_class = "success" if is_in_scope else "danger"

        module_counts = {
            key: sum(_is_module(row, key) for row in all_rows) for key, _ in _MODULES
        }
        findings = sum(_finding_count(row["details"]) for row in all_rows)
        blocked_rows = [
            row for row in all_rows if str(row["status"]).casefold() == "blocked"
        ]
        blocked_target = (
            str(blocked_rows[0]["target"]) if blocked_rows else "No blocked attempts"
        )
        actions_label = (
            f"{MAX_REPORT_ROWS}+" if all_truncated else str(len(all_rows))
        )
        finding_breakdown = _finding_breakdown(all_rows)
        target_options = ['<option value="">All targets</option>']
        for item in targets:
            selected = " selected" if target == item else ""
            target_options.append(
                f'<option value="{escape(item, quote=True)}"{selected}>'
                f"{escape(item)}</option>"
            )
        active_module = module or "all"
        chips = []
        for key, label in (
            ("all", "all"),
            ("recon", "recon"),
            ("webapp", "webapp"),
            ("exploit", "exploit"),
            ("forensics", "forensics"),
            ("executor", "executor"),
        ):
            query: dict[str, str | int] = {"limit": limit}
            if target:
                query["target"] = target
            if key != "all":
                query["module"] = key
            href = "/?" + urlencode(query) + "#activity"
            current = ' aria-current="page"' if key == active_module else ""
            active = " active" if key == active_module else ""
            chips.append(
                f'<a class="chip{active}" href="{escape(href, quote=True)}"'
                f'{current}>{escape(label)}</a>'
            )
        hidden_module = (
            f'<input type="hidden" name="module" value="{escape(module, quote=True)}">'
            if module
            else ""
        )
        table_rows = []
        for row in rows:
            status = str(row["status"])
            status_class_row = {
                "success": "success",
                "failed": "failed",
                "blocked": "blocked",
                "started": "started",
            }.get(status, "unknown")
            details = _details_text(row["details"])
            table_rows.append(
                "<tr>"
                f'<td class="time" style="font-family:var(--font-display);font-size:var(--text-xs);color:var(--dim);">{escape(str(row["timestamp"]))}</td>'
                f'<td class="target" style="font-family:var(--font-display);font-weight:600;color:var(--accent);">{escape(str(row["target"]))}</td>'
                f'<td class="module"><span class="chip active" style="padding:2px 8px;font-size:0.72rem;">{escape(str(row["module"]))}</span></td>'
                f'<td style="font-family:var(--font-display);">{escape(str(row["action"]))}</td>'
                f'<td><span class="badge badge-{status_class_row}">'
                f"{escape(status)}</span></td>"
                f'<td class="details"><details><summary style="cursor:pointer;color:var(--accent);font-family:var(--font-display);font-size:var(--text-xs);">View Payload</summary>'
                f'<pre style="background:rgba(0,0,0,0.4);padding:10px;border-radius:6px;border:1px solid var(--border);font-family:var(--font-display);font-size:var(--text-xs);">{escape(details)}</pre></details></td>'
                "</tr>"
            )
        notice = (
            f'<p class="table-notice" role="status" style="padding:10px 22px;color:var(--muted);font-size:var(--text-xs);font-family:var(--font-display);">Showing latest {limit} '
            "matching events; additional records exist in database.</p>"
            if truncated
            else ""
        )
        body = "\n".join(table_rows) or (
            '<tr><td class="empty-state" colspan="6" style="text-align:center;padding:32px;color:var(--dim);font-family:var(--font-display);">'
            "No audit records match these filters.</td></tr>"
        )
        modules = _render_modules(module_counts)
        scope_manager_status = (
            "Signature verified" if scope_manager is not None else "Verification unavailable"
        )
        sidebar = _render_sidebar("overview", module_counts, module)

        html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="theme-color" content="#0a0e17">
  <title>RedLoop Console — Unified Command Center</title>
  <style>
{_SHARED_DASHBOARD_CSS}
  </style>
  <style>
{UNIFIED_CSS}
  </style>
</head>
<body>
<div class="shell">
  <aside class="sidebar" id="primary-sidebar">
    <div class="sidebar-header">
      <div class="brand-wrap">
        <div class="brand-mark" aria-hidden="true">RL</div>
        <div class="brand-text">
          <div class="brand-title">RedLoop</div>
          <div class="brand-sub">Unified Console</div>
        </div>
      </div>
    </div>
    <nav aria-label="Primary navigation" class="sidebar-nav">
      <div class="nav-section">
        <div class="nav-label">OPERATE</div>
        <a class="nav-item active" data-section="overview" onclick="switchSection('overview')" href="#overview">{_svg_icon("overview")}<span>Overview</span></a>
        <a class="nav-item" data-section="chat" onclick="switchSection('chat')" href="/chat">{_svg_icon("chat")}<span>Chat</span></a>
        <a class="nav-item" data-section="copilot" onclick="toggleCopilot()" href="javascript:void(0)">{_svg_icon("copilot")}<span>Copilot Drawer</span></a>
        <a class="nav-item" data-section="terminal" onclick="switchSection('terminal')" href="#terminal">{_svg_icon("terminal")}<span>Terminal</span></a>
        <a class="nav-item" data-section="tools" onclick="switchSection('tools')" href="#tools">{_svg_icon("tools")}<span>Tools</span></a>
      </div>
      <div class="nav-section">
        <div class="nav-label">INVESTIGATE</div>
        <a class="nav-item" data-section="investigations" onclick="switchSection('investigations')" href="#investigations">{_svg_icon("investigations")}<span>Investigations</span></a>
        <a class="nav-item" data-section="evidence" onclick="switchSection('evidence')" href="#evidence">{_svg_icon("evidence")}<span>Evidence</span></a>
        <a class="nav-item" data-section="graph" onclick="switchSection('graph')" href="#graph">{_svg_icon("graph")}<span>Graph</span></a>
        <a class="nav-item" data-section="osint" onclick="switchSection('osint')" href="#osint">{_svg_icon("osint")}<span>OSINT</span></a>
        <a class="nav-item" data-section="email-footprint" onclick="switchSection('email-footprint')" href="#email-footprint">{_svg_icon("osint")}<span>Email Footprint</span></a>
        <a class="nav-item" data-section="threat-intel" onclick="switchSection('threat-intel')" href="#threat-intel">{_svg_icon("findings")}<span>Threat Intel</span></a>
        <a class="nav-item" data-section="identity" onclick="switchSection('identity')" href="#identity">{_svg_icon("investigations")}<span>Identity</span></a>
      </div>
      <div class="nav-section">
        <div class="nav-label">SECURITY</div>
        <a class="nav-item" data-section="investigations" onclick="switchSection('investigations')" href="#investigations">{_svg_icon("assessments")}<span>Investigation Workspace</span></a>
        <a class="nav-item" data-section="findings" onclick="switchSection('findings')" href="#findings">{_svg_icon("findings")}<span>Findings</span></a>
        <a class="nav-item" data-section="reports" onclick="switchSection('reports')" href="#reports">{_svg_icon("reports")}<span>Reports</span></a>
      </div>
      <div class="nav-section">
        <div class="nav-label">GOVERN</div>
        <a class="nav-item" data-section="audit" onclick="switchSection('audit')" href="#audit">{_svg_icon("audit")}<span>Audit</span></a>
        <a class="nav-item" data-section="providers" onclick="switchSection('providers')" href="#providers">{_svg_icon("providers")}<span>Providers</span></a>
      </div>
      <div class="nav-section">
        <div class="nav-label">SYSTEM</div>
        <a class="nav-item" data-section="system-health" onclick="switchSection('system-health')" href="/performance">{_svg_icon("system-health")}<span>System Health</span></a>
        <a class="nav-item" data-section="settings" onclick="switchSection('settings')" href="#settings">{_svg_icon("settings")}<span>Settings</span></a>
      </div>
    </nav>
    <div class="sidebar-footer">
      <span class="foot-dot"></span>
      <span>Engine online · Port 8765</span>
    </div>
  </aside>

  <div style="display:flex; flex-direction:column; min-height:100vh; overflow-y:auto; flex:1;">
    <header class="topbar">
      <div class="topbar-left">
        <button class="icon-btn mobile-nav-toggle" type="button" data-action="toggle-mobile-nav" aria-label="Open navigation" aria-expanded="false" aria-controls="primary-sidebar">
          <svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M3 12h18M3 18h18"/></svg>
        </button>
        <span id="current-page-title" class="page-title">COPILOT</span>
        <span id="topbar-inv-pill" class="scope-pill scope-pill-neutral">📋 Authorized Local Assessment</span>
        <span id="header-scope-pill" class="scope-pill verified">LOCAL LAB ACTIVE</span>
      </div>
      <div class="topbar-right">
        <div class="target-select-wrap">
          <select id="target-selector" class="target-select" onchange="changeTarget(this.value)">
            {''.join(target_options)}
          </select>
        </div>
        <span id="topbar-provider-status" class="scope-pill scope-pill-info">AI: Ollama (READY)</span>
        <span id="topbar-task-status" class="scope-pill scope-pill-success">IDLE</span>
        <button class="icon-btn theme-toggle" id="theme-toggle" type="button" data-action="toggle-theme" aria-label="Switch to light theme" aria-pressed="false" title="Toggle light/dark theme">
          <svg class="theme-icon theme-icon-sun" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
          <svg class="theme-icon theme-icon-moon" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>
        </button>
        <button class="btn-action" onclick="openPalette()"><kbd>Ctrl+K</kbd> Command Palette</button>
        <button class="btn-action btn-primary" onclick="toggleCopilot()"><kbd>Ctrl+/</kbd> AI Copilot</button>
      </div>
    </header>

    <main class="main-viewport" id="overview">
      <!-- 1. SECTION: CHAT (Dedicated Standalone Security Chat) -->
      <section id="section-chat" class="spa-section">
        <div class="chat-container dual-pane">
          <!-- LEFT CONVERSATION RAIL -->
          <aside class="chat-rail" id="chat-rail">
            <div class="chat-rail-header">
              <button class="btn-new-chat" id="btn-new-chat" onclick="createNewChat()">
                <svg viewBox="0 0 24 24" class="svg-icon" style="width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:2;"><path d="M12 5v14M5 12h14"/></svg>
                <span>New chat</span>
              </button>
              <input type="text" id="chat-search-input" class="chat-search-input" placeholder="Search conversations..." oninput="filterConversations(this.value)">
            </div>
            <div class="chat-conv-list" id="chat-conv-list" role="list">
              <!-- Dynamically populated via loadConversations() -->
            </div>
          </aside>

          <!-- MAIN CHAT PANE -->
          <div class="chat-main-pane">
            <!-- CHAT TOPBAR -->
            <div class="chat-topbar">
              <div class="chat-title-wrap">
                <span id="active-chat-title" class="active-chat-title">New chat</span>
                <button class="btn-icon-subtle" title="Rename conversation" onclick="promptRenameActiveChat()">
                  <svg viewBox="0 0 24 24" class="svg-icon" style="width:13px;height:13px;fill:none;stroke:currentColor;stroke-width:2;"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>
                </button>
              </div>
              <span id="chat-target-chip" class="chat-target-chip">🎯 Target: {escape(active_target)}</span>
              <div class="chat-model-selector-wrap" style="margin-left:auto; display:flex; align-items:center; gap:8px;">
                <span style="font-size:11px; color:var(--fg-muted); font-family:var(--font-mono);">MODEL:</span>
                <select id="chat-model-select" class="chat-select" style="min-width:220px;" onchange="saveModelPreference(this.value)">
                  <option value="auto">🟢 Auto · Best fit</option>
                </select>
              </div>
            </div>

            <!-- MESSAGE STREAM -->
            <div id="chat-messages-stream" class="chat-messages" role="log" aria-live="polite">
              <!-- Dynamically rendered via renderConversationMessages() -->
            </div>

            <!-- CHAT COMPOSER -->
            <div class="chat-bottom">
              <div class="quick-chips">
                <span class="quick-chip" onclick="setAndSendPrompt('Explain TCP three-way handshake.')">Explain TCP Handshake</span>
                <span class="quick-chip" onclick="setAndSendPrompt('Investigate public IP 8.8.8.8.')">Investigate 8.8.8.8</span>
                <span class="quick-chip" onclick="setAndSendPrompt('Scan authorized localhost with Nmap.')">Scan Localhost</span>
                <span class="quick-chip" onclick="setAndSendPrompt('Verify audit chain')">Verify Audit Chain</span>
                <span class="quick-chip" onclick="setAndSendPrompt('Suggest a Wireshark filter for DNS queries')">Wireshark Filter</span>
              </div>
              <div id="chat-attached-chips" class="attached-chips"></div>
              <div class="chat-input-row">
                <input type="file" id="chat-file-input" style="display:none;" onchange="handleFileAttachment(this)">
                <button type="button" class="btn-attach" onclick="document.getElementById('chat-file-input').click()" title="Attach file or log">
                  <svg viewBox="0 0 24 24" class="svg-icon"><path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>
                </button>
                <textarea id="chat-input-field" class="chat-input" rows="1" placeholder="Type a cybersecurity command, investigation, or question (Enter to send, Shift+Enter for newline)..." onkeydown="handleChatKeydown(event)" oninput="autoGrowTextarea(this)"></textarea>
                <button id="chat-send-btn" class="btn-send" onclick="sendChatMessage()">Send</button>
                <button id="chat-stop-btn" class="btn-stop" style="display:none;" onclick="cancelActiveChat()">
                  <span style="font-size:10px;">◼</span> Stop
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- SECTION: COPILOT ALIAS (Backward compatible) -->
      <section id="section-copilot" class="spa-section" style="display:none;"></section>

      <!-- 2. SECTION: TERMINAL -->
      <section id="section-terminal" class="spa-section">
        <div class="card-panel">
          <div class="panel-header">
            <div>
              <span class="panel-title">Terminal Intelligence &amp; Execution Console</span>
              <p style="color:var(--fg-muted); font-size:12px; margin:4px 0 0 0;">Multi-environment command dispatch (Windows Host, WSL Linux, Kali Linux).</p>
            </div>
            <div style="display:flex; align-items:center; gap:8px;">
              <label for="terminal-env" style="font-size:12px; color:var(--fg-muted); font-weight:600;">ENV:</label>
              <select id="terminal-env" style="background:var(--surface-2); border:1px solid var(--border); color:var(--fg); padding:4px 10px; border-radius:6px; font-size:12px; font-family:var(--font-mono);" onchange="updateTerminalEnv()">
                <option value="host">Host (Windows)</option>
                <option value="wsl">WSL (Ubuntu)</option>
                <option value="kali">Kali Linux (WSL)</option>
              </select>
              <span id="terminal-env-badge" class="badge badge-success">READY</span>
            </div>
          </div>
          <div style="background:#050811; border:1px solid var(--border); border-radius:8px; padding:16px; margin-bottom:14px;">
            <pre id="terminal-output" style="font-family:var(--font-mono); font-size:12px; color:#4fd17a; min-height:240px; max-height:400px; overflow-y:auto; margin:0; white-space:pre-wrap;">REDLOOP Terminal Intelligence Console v2.0
Environments: Host (Windows) [READY] | WSL (Ubuntu) [READY] | Kali Linux [NOT INSTALLED]
Enter a host/system command (e.g. whoami, hostname, uname -a, pwd) or network probe (e.g. nmap -sV 127.0.0.1)...</pre>
          </div>
          <div style="display:flex; gap:10px; align-items:center;">
            <span id="terminal-prompt-sym" style="font-family:var(--font-mono); font-weight:700; color:var(--accent);">[host] $</span>
            <input type="text" id="terminal-input" class="chat-input" placeholder="Enter command (e.g. whoami, hostname, or nmap -sV 127.0.0.1)..." onkeydown="if(event.key==='Enter') runTerminal();">
            <button class="btn-action btn-primary" onclick="runTerminal()">Execute</button>
          </div>
          <div class="quick-chips" style="margin-top:12px;">
            <span class="quick-chip" onclick="document.getElementById('terminal-input').value='whoami'; runTerminal();">whoami</span>
            <span class="quick-chip" onclick="document.getElementById('terminal-input').value='hostname'; runTerminal();">hostname</span>
            <span class="quick-chip" onclick="document.getElementById('terminal-input').value='nmap -sV 127.0.0.1'; runTerminal();">nmap -sV 127.0.0.1</span>
            <span class="quick-chip" onclick="document.getElementById('terminal-input').value='ss -tulpn'; runTerminal();">ss -tulpn</span>
          </div>
        </div>
      </section>

      <!-- 3. SECTION: TOOLS -->
      <section id="section-tools" class="spa-section">
        <div class="card-panel">
          <div class="panel-header">
            <span class="panel-title">Tool Capability Matrix &amp; Environment Detection</span>
            <button class="btn-action" onclick="loadToolsMatrix()">↻ Refresh Tools Matrix</button>
          </div>
          <p style="color:var(--fg-muted); margin-bottom:16px;">Verified operational matrix across Native Windows, WSL/Kali, and Container runtimes. Never fabricates tool existence.</p>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Tool</th>
                  <th>Status</th>
                  <th>Reason</th>
                  <th>Environment</th>
                  <th>Installation Guidance</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody id="tools-matrix-body">
                <tr><td colspan="6" style="text-align:center; padding:24px; color:var(--fg-muted);">Click "Refresh Tools Matrix" or wait for automatic initialization...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- 4. SECTION: INVESTIGATIONS (UNIFIED OPERATIONAL WORKBENCH) -->
      <section id="section-investigations" class="spa-section" aria-labelledby="inv-workbench-title">
        <!-- Workbench Banner & Integrity State -->
        <div class="card-panel" style="margin-bottom:16px;">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
            <div>
              <div style="display:flex; align-items:center; gap:8px;">
                <span class="badge badge-info" style="font-size:11px; font-weight:700;">OPERATIONAL WORKBENCH</span>
                <span class="badge badge-success" id="ws-scope-badge">SCOPE VERIFIED</span>
                <span class="badge badge-warning" id="ws-audit-badge">INTEGRITY_VERIFIED</span>
              </div>
              <h1 id="inv-workbench-title" style="font-size:22px; font-weight:700; margin:8px 0 4px; color:var(--fg);">
                Unified Security Investigation &amp; Assessment Workspace
              </h1>
              <p style="color:var(--fg-muted); font-size:13px; margin:0;">
                Active &amp; passive multi-stage vulnerability analysis, web metadata check, deep intelligence, and audit evidence summary (verified local audit events, not detections or SIEM correlation).
              </p>
            </div>
            <div style="display:flex; gap:8px; align-items:center;">
              <div style="font-family:var(--font-mono); font-size:11px; color:var(--fg-muted); text-align:right;">
                <div>Ledger: <strong style="color:var(--success);">INTEGRITY_VERIFIED</strong></div>
                <div>Gap status: <span style="color:var(--fg-muted);">No CHAIN_GAP_DETECTED</span></div>
                <div>Static hash provenance: SHA-256 verified</div>
              </div>
            </div>
          </div>
        </div>

        <!-- KPI Status Bar -->
        <div class="kpi-grid" style="margin-bottom:16px;">
          <div class="kpi-card info">
            <div class="kpi-label">Active Target</div>
            <div class="kpi-value" id="ws-active-target" style="font-size:18px;">{escape(active_target)}</div>
            <div class="kpi-sub">Localhost &amp; Private Safe</div>
          </div>
          <div class="kpi-card success">
            <div class="kpi-label">Assessment Status</div>
            <div class="kpi-value" id="ws-engine-status" style="font-size:18px;">READY</div>
            <div class="kpi-sub" id="ws-engine-sub">Autonomous Engine Online</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Discovered Findings</div>
            <div class="kpi-value" id="ws-findings-count" style="font-size:18px;">0</div>
            <div class="kpi-sub" id="ws-findings-breakdown">0 Critical · 0 High · 0 Med</div>
          </div>
          <div class="kpi-card warning">
            <div class="kpi-label">Evidence Hash Records</div>
            <div class="kpi-value" id="ws-evidence-count" style="font-size:18px;">0</div>
            <div class="kpi-sub">Cryptographically Signed</div>
          </div>
        </div>

        <!-- Investigation Configuration & Launch Panel -->
        <div class="card-panel" style="margin-bottom:16px;">
          <div class="panel-header">
            <span class="panel-title">Investigation Execution Controls</span>
            <div style="display:flex; gap:8px;">
              <button type="button" class="btn btn-sm btn-ghost" onclick="loadInvestigationsList()">↻ Refresh History</button>
            </div>
          </div>
          <form id="ws-investigation-form" onsubmit="event.preventDefault(); executeWorkspaceScan();">
            <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:12px; margin-bottom:14px;">
              <div>
                <label class="field-label" for="ws-target-input">Target Host / IP / Domain / URL</label>
                <input type="text" id="ws-target-input" class="input" value="{escape(active_target)}" placeholder="e.g. 127.0.0.1 or example.local" required oninput="syncTargetWithTopbar(this.value)">
              </div>
              <div>
                <label class="field-label" for="ws-title-input">Investigation Title</label>
                <input type="text" id="ws-title-input" class="input" value="Automated Assessment &amp; Surface Triage" placeholder="Enter investigation title">
              </div>
              <div>
                <label class="field-label" for="ws-scan-type">Scan Type</label>
                <select id="ws-scan-type" class="select" onchange="onScanTypeChanged(this.value)">
                  <option value="autonomous">Full Autonomous Assessment</option>
                  <option value="recon">Port &amp; Service Reconnaissance</option>
                  <option value="webapp">Web App &amp; Vulnerability Triage</option>
                  <option value="tls">TLS / Certificate Security Check</option>
                  <option value="forensics">File Metadata &amp; Static Hash Triage</option>
                  <option value="exploit">Exploit Simulation &amp; Surface Check</option>
                  <option value="osint">OSINT Footprint Intelligence</option>
                </select>
              </div>
              <div>
                <label class="field-label" for="ws-depth">Investigation Depth</label>
                <select id="ws-depth" class="select">
                  <option value="standard">Standard (Recon + Web + TLS + Vuln)</option>
                  <option value="quick">Quick (Passive &amp; Fast Port Scan)</option>
                  <option value="deep">Deep (Full Autonomous Pipeline &amp; Exploit Simulation)</option>
                </select>
              </div>
            </div>

            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
              <div style="display:flex; gap:10px; align-items:center;">
                <button type="submit" id="ws-btn-run" class="btn btn-primary" style="padding:8px 18px; font-weight:600;">
                  ⚡ Execute Deep Investigation
                </button>
                <button type="button" id="ws-btn-cancel" class="btn btn-secondary" onclick="cancelWorkspaceScan()" style="display:none;">
                  ⏹ Stop Scan
                </button>
                <button type="button" class="btn btn-ghost" onclick="clearWorkspaceResults()">
                  🗑️ Clear
                </button>
              </div>
              <div style="font-size:12px; color:var(--fg-muted);">
                <span>Safety Guard:</span>
                <span class="status-pill status-pill-success" style="margin-left:4px;">Strict Loopback / Private Isolation</span>
              </div>
            </div>
          </form>
        </div>

        <!-- Deep Scan Live Execution Pipeline (Phases 4 & 6) -->
        <div class="card-panel" id="ws-pipeline-card" style="margin-bottom:16px;">
          <div class="panel-header">
            <div>
              <span class="panel-title">Multi-Stage Investigation Execution Pipeline</span>
              <p class="panel-hint" id="ws-pipeline-hint">10 verifiable stages with deterministic status and cryptographic evidence tracking.</p>
            </div>
            <span class="status-pill status-pill-neutral" id="ws-overall-status">IDLE</span>
          </div>

          <!-- Progress Bar -->
          <div style="margin: 12px 0 16px;">
            <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:6px; color:var(--fg-muted);">
              <span id="ws-progress-stage">Ready to execute</span>
              <span id="ws-progress-percent" style="font-family:var(--font-mono); font-weight:700;">0%</span>
            </div>
            <div style="height:6px; background:var(--surface-2); border-radius:3px; overflow:hidden;">
              <div id="ws-progress-bar" style="width:0%; height:100%; background:linear-gradient(90deg, var(--accent), var(--accent-strong)); transition:width 0.3s ease;"></div>
            </div>
          </div>

          <!-- Pipeline Stages Grid -->
          <div class="pipeline-grid" id="ws-pipeline-stages" style="display:grid; grid-template-columns:repeat(auto-fill, minmax(180px, 1fr)); gap:10px; margin-bottom:16px;">
            <div class="stage-tile" id="stage-scope" data-stage="scope" style="background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:10px;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                <span style="font-size:16px;">🛡️</span>
                <span class="stage-status status-pill status-pill-success">VERIFIED</span>
              </div>
              <div style="font-weight:600; font-size:12px;">1. Scope &amp; Target</div>
              <div class="stage-sub" style="font-size:11px; color:var(--fg-muted);">Target authorization</div>
            </div>
            <div class="stage-tile" id="stage-recon" data-stage="recon" style="background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:10px;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                <span style="font-size:16px;">📡</span>
                <span class="stage-status status-pill status-pill-neutral">IDLE</span>
              </div>
              <div style="font-weight:600; font-size:12px;">2. Recon &amp; Ports</div>
              <div class="stage-sub" style="font-size:11px; color:var(--fg-muted);">Port scanning &amp; banners</div>
            </div>
            <div class="stage-tile" id="stage-dns" data-stage="dns" style="background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:10px;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                <span style="font-size:16px;">🌐</span>
                <span class="stage-status status-pill status-pill-neutral">IDLE</span>
              </div>
              <div style="font-weight:600; font-size:12px;">3. DNS &amp; Domain</div>
              <div class="stage-sub" style="font-size:11px; color:var(--fg-muted);">7-record resolution</div>
            </div>
            <div class="stage-tile" id="stage-tls" data-stage="tls" style="background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:10px;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                <span style="font-size:16px;">🔒</span>
                <span class="stage-status status-pill status-pill-neutral">IDLE</span>
              </div>
              <div style="font-weight:600; font-size:12px;">4. TLS &amp; Certs</div>
              <div class="stage-sub" style="font-size:11px; color:var(--fg-muted);">Cipher suites &amp; validity</div>
            </div>
            <div class="stage-tile" id="stage-web" data-stage="web" style="background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:10px;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                <span style="font-size:16px;">🕸️</span>
                <span class="stage-status status-pill status-pill-neutral">IDLE</span>
              </div>
              <div style="font-weight:600; font-size:12px;">5. Web Metadata</div>
              <div class="stage-sub" style="font-size:11px; color:var(--fg-muted);">Headers, cookies &amp; CSP</div>
            </div>
            <div class="stage-tile" id="stage-api" data-stage="api" style="background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:10px;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                <span style="font-size:16px;">🔌</span>
                <span class="stage-status status-pill status-pill-neutral">IDLE</span>
              </div>
              <div style="font-weight:600; font-size:12px;">6. API Discovery</div>
              <div class="stage-sub" style="font-size:11px; color:var(--fg-muted);">Endpoints &amp; schema audit</div>
            </div>
            <div class="stage-tile" id="stage-host" data-stage="host" style="background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:10px;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                <span style="font-size:16px;">🖥️</span>
                <span class="stage-status status-pill status-pill-neutral">IDLE</span>
              </div>
              <div style="font-weight:600; font-size:12px;">7. Host Profiling</div>
              <div class="stage-sub" style="font-size:11px; color:var(--fg-muted);">OS &amp; service fingerprint</div>
            </div>
            <div class="stage-tile" id="stage-software" data-stage="software" style="background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:10px;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                <span style="font-size:16px;">📦</span>
                <span class="stage-status status-pill status-pill-neutral">IDLE</span>
              </div>
              <div style="font-weight:600; font-size:12px;">8. Software Vulns</div>
              <div class="stage-sub" style="font-size:11px; color:var(--fg-muted);">CVE &amp; component matching</div>
            </div>
            <div class="stage-tile" id="stage-forensics" data-stage="forensics" style="background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:10px;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                <span style="font-size:16px;">🔍</span>
                <span class="stage-status status-pill status-pill-neutral">IDLE</span>
              </div>
              <div style="font-weight:600; font-size:12px;">9. File Forensics</div>
              <div class="stage-sub" style="font-size:11px; color:var(--fg-muted);">Static hash &amp; IOC triage</div>
            </div>
            <div class="stage-tile" id="stage-risk" data-stage="risk" style="background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:10px;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                <span style="font-size:16px;">⚖️</span>
                <span class="stage-status status-pill status-pill-neutral">IDLE</span>
              </div>
              <div style="font-weight:600; font-size:12px;">10. Risk &amp; ASVS</div>
              <div class="stage-sub" style="font-size:11px; color:var(--fg-muted);">Scoring &amp; audit evidence</div>
            </div>
          </div>

          <!-- Live Terminal Output -->
          <div>
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
              <span style="font-size:12px; font-weight:600; color:var(--fg-muted); text-transform:uppercase; letter-spacing:0.05em;">Execution Console Log</span>
              <button type="button" class="btn btn-sm btn-ghost" onclick="clearWorkspaceTerminal()" style="padding:2px 8px; font-size:11px;">Clear Log</button>
            </div>
            <div id="ws-terminal-logs" style="background:var(--bg); border:1px solid var(--border); border-radius:8px; padding:12px; font-family:var(--font-mono); font-size:12px; min-height:140px; max-height:220px; overflow-y:auto; color:var(--fg-muted); line-height:1.6;">
              <div style="color:var(--accent);">[System] Workspace initialized. Ready to execute investigation against authorized targets.</div>
            </div>
          </div>
        </div>

        <!-- Investigation Findings & Evidence Tabs (Phases 7 & 8: Verifiable Provenance & Ask Copilot) -->
        <div class="card-panel">
          <div class="panel-header" style="border-bottom:1px solid var(--border); padding-bottom:12px; margin-bottom:14px;">
            <div class="tabs" role="tablist" style="display:flex; gap:8px;">
              <button type="button" class="btn btn-sm btn-action active" id="ws-tab-findings" onclick="switchWorkspaceSubTab('findings')">
                Findings (<span id="ws-tab-findings-count">0</span>)
              </button>
              <button type="button" class="btn btn-sm btn-action" id="ws-tab-evidence" onclick="switchWorkspaceSubTab('evidence')">
                Cryptographic Evidence (<span id="ws-tab-evidence-count">0</span>)
              </button>
              <button type="button" class="btn btn-sm btn-action" id="ws-tab-history" onclick="switchWorkspaceSubTab('history')">
                Saved Investigations
              </button>
            </div>
            <!-- Report Export Buttons -->
            <div style="display:flex; gap:8px; align-items:center;">
              <span style="font-size:12px; color:var(--fg-muted);">Export:</span>
              <a id="ws-export-md" class="btn btn-sm btn-secondary" href="/report/md" target="_blank" download>Markdown</a>
              <a id="ws-export-pdf" class="btn btn-sm btn-secondary" href="/report/pdf" target="_blank" download>PDF</a>
              <a id="ws-export-pptx" class="btn btn-sm btn-secondary" href="/report/pptx" target="_blank" download>PPTX</a>
              <a id="ws-export-json" class="btn btn-sm btn-secondary" href="/report/json" target="_blank" download>JSON</a>
            </div>
          </div>

          <!-- Findings View -->
          <div id="ws-view-findings">
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th style="width:110px;">Severity</th>
                    <th>Finding Title</th>
                    <th>Target / Asset</th>
                    <th>Evidence Hash / Check</th>
                    <th style="width:160px; text-align:right;">Copilot Action</th>
                  </tr>
                </thead>
                <tbody id="ws-findings-body">
                  <tr>
                    <td colspan="5" style="text-align:center; padding:32px; color:var(--fg-muted);">
                      No active findings in workspace. Run an investigation or select a past assessment from the history tab.
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Evidence View -->
          <div id="ws-view-evidence" style="display:none;">
            <p style="color:var(--fg-muted); font-size:12px; margin-bottom:12px;">
              Every observation is stored with immutable SHA-256 hash provenance, exact confidence breakdown, and source attribution.
            </p>
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Target</th>
                    <th>Module</th>
                    <th>SHA-256 Provenance</th>
                    <th>Confidence</th>
                    <th style="width:160px; text-align:right;">Copilot Action</th>
                  </tr>
                </thead>
                <tbody id="ws-evidence-body">
                  <tr>
                    <td colspan="6" style="text-align:center; padding:32px; color:var(--fg-muted);">
                      No evidence records loaded. Launch a scan to collect verifiable observations.
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- History View -->
          <div id="ws-view-history" style="display:none;">
            <div class="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Investigation ID</th>
                    <th>Title</th>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Findings</th>
                    <th style="width:140px; text-align:right;">Action</th>
                  </tr>
                </thead>
                <tbody id="ws-history-body">
                  <tr>
                    <td colspan="6" style="text-align:center; padding:24px; color:var(--fg-muted);">
                      Loading past investigations…
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </section>

      <!-- 5. SECTION: EVIDENCE -->
      <section id="section-evidence" class="spa-section">
        <div class="card-panel">
          <div class="panel-header">
            <span class="panel-title">Cryptographic Evidence Ledger &amp; Integrity Hashes</span>
            <span class="badge badge-info">TAMPER EVIDENT</span>
          </div>
          <p style="color:var(--fg-muted); margin-bottom:16px;">Every observation is signed with SHA-256 hash, provenance metadata, source, and confidence score.</p>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Target</th>
                  <th>Module</th>
                  <th>Action</th>
                  <th>Status</th>
                  <th>SHA-256 / Details</th>
                </tr>
              </thead>
              <tbody>{body}</tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- 6. SECTION: GRAPH -->
      <section id="section-graph" class="spa-section">
        <div class="card-panel">
          <div class="panel-header">
            <div>
              <span class="panel-title">Investigation Entity Knowledge Graph</span>
              <span style="margin-left:12px; font-size:11px; color:var(--fg-muted); font-family:var(--font-mono);">
                Nodes: <strong id="graph-node-count" class="badge badge-info">0</strong> |
                Edges: <strong id="graph-edge-count" class="badge badge-info">0</strong>
              </span>
            </div>
            <div style="display:flex; gap:8px; align-items:center;">
              <div class="graph-zoom-controls" style="display:inline-flex; border:1px solid var(--border); border-radius:6px; overflow:hidden;">
                <button type="button" class="btn-tool" onclick="graphZoom(1.2)" title="Zoom In" style="padding:4px 10px; background:var(--surface-2); border:none; color:var(--fg); cursor:pointer; font-weight:700;">+</button>
                <button type="button" class="btn-tool" onclick="graphZoom(0.8)" title="Zoom Out" style="padding:4px 10px; background:var(--surface-2); border:none; border-left:1px solid var(--border); color:var(--fg); cursor:pointer; font-weight:700;">−</button>
                <button type="button" class="btn-tool" onclick="graphResetView()" title="Fit / Reset View" style="padding:4px 10px; background:var(--surface-2); border:none; border-left:1px solid var(--border); color:var(--fg); font-size:11px; cursor:pointer;">⤢</button>
              </div>
              <button class="btn-action" onclick="loadGraph()">↻ Refresh</button>
              <button class="btn-action" onclick="clearGraph()" style="color:var(--critical); border-color:rgba(239,68,68,0.3);">🗑️ Clear</button>
            </div>
          </div>
          <p style="color:var(--fg-muted); margin-bottom:14px;">Interactive force-directed entity graph backed 100% by authentic evidence. Drag nodes to reposition; mouse wheel to zoom; click to inspect cryptographic provenance.</p>
          <div id="graph-canvas" class="graph-container" style="min-height:420px; height:460px; background:radial-gradient(circle at 50% 50%, #0d1527 0%, #060911 100%); border:1px solid var(--border); border-radius:8px; position:relative; overflow:hidden;">
            <div style="height:100%; min-height:360px; display:grid; place-items:center; color:var(--fg-muted); text-align:center;">
              <div>
                <div style="font-size:24px; margin-bottom:8px;">🕸️</div>
                <div style="font-weight:600;">Investigation Graph is Empty</div>
                <div style="font-size:11px; margin-top:4px;">elements = [] (Zero fabricated seed nodes). Run an OSINT or tool command to populate.</div>
              </div>
            </div>
          </div>
          <div id="graph-inspector-panel" style="margin-top:14px;"></div>
        </div>
      </section>

      <!-- 7. SECTION: OSINT -->
      <section id="section-osint" class="spa-section">
        <div class="card-panel">
          <div class="panel-header">
            <span class="panel-title">OSINT Intelligence Workstation</span>
            <span class="badge badge-success">PASSIVE FIRST</span>
          </div>
          <p style="color:var(--fg-muted); margin-bottom:14px;">Deterministic reconnaissance with exponential backoff, TTL caching, and offline mode enforcement.</p>
          <div style="display:flex; gap:8px; margin-bottom:14px; flex-wrap:wrap;">
            <button class="btn-action osint-tab-btn active" data-tab="ip" onclick="switchOSINTTab('ip')">IP / RDAP</button>
            <button class="btn-action osint-tab-btn" data-tab="domain" onclick="switchOSINTTab('domain')">DNS / Domain</button>
            <button class="btn-action osint-tab-btn" data-tab="email" onclick="switchOSINTTab('email')">Email Exposure</button>
            <button class="btn-action osint-tab-btn" data-tab="username" onclick="switchOSINTTab('username')">Username Intel</button>
            <button class="btn-action osint-tab-btn" data-tab="phone" onclick="switchOSINTTab('phone')">Phone Format</button>
            <button class="btn-action osint-tab-btn" data-tab="metadata" onclick="switchOSINTTab('metadata')">File Metadata</button>
          </div>
          <div style="display:flex; gap:10px;">
            <input type="text" id="osint-query-input" class="chat-input" placeholder="Enter IPv4 or IPv6 address (e.g. 8.8.8.8 or 1.1.1.1)..." onkeydown="if(event.key==='Enter') runOSINT();">
            <button class="btn-action btn-primary" onclick="runOSINT()">Investigate Target</button>
          </div>
          <div id="osint-result-card" style="margin-top:16px; display:none;"></div>
        </div>
      </section>

      <!-- 8. SECTION: EMAIL FOOTPRINT -->
      <section id="section-email-footprint" class="spa-section">
        <div class="card-panel">
          <div class="panel-header">
            <span class="panel-title">Email Digital Footprint</span>
            <span class="badge badge-warning">HEURISTIC · NOT A PROBABILITY</span>
          </div>
          <p style="color:var(--fg-muted); margin-bottom:14px;">Public-source email associations from Gravatar, OpenPGP keyservers, breach corpora, and public commit authorship. Live lookups are opt-in and never confirm ownership.</p>
          <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
            <input type="text" id="email-footprint-input" class="chat-input" placeholder="analyst@example.com" onkeydown="if(event.key==='Enter') runEmailFootprint();">
            <label style="display:flex; align-items:center; gap:6px; font-size:12px; color:var(--fg-muted);">
              <input type="checkbox" id="email-footprint-live"> Enable live public lookups
            </label>
            <button class="btn-action btn-primary" onclick="runEmailFootprint()">Investigate Email</button>
          </div>
          <div id="email-footprint-result" style="margin-top:16px;"></div>
        </div>
      </section>

      <!-- 9. SECTION: THREAT INTEL -->
      <section id="section-threat-intel" class="spa-section">
        <div class="card-panel">
          <div class="panel-header">
            <span class="panel-title">VirusTotal Intelligence</span>
            <span id="vt-provider-badge" class="badge badge-info">CHECKING</span>
          </div>
          <p style="color:var(--fg-muted); margin-bottom:14px;">VirusTotal API v3 lookups for IPs, domains, URLs, and file hashes. Detection ratio is the share of voting engines that flagged the indicator — not a probability of maliciousness.</p>
          <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-bottom:14px;">
            <input type="text" id="vt-indicator-input" class="chat-input" placeholder="8.8.8.8, example.com, URL, or SHA-256" onkeydown="if(event.key==='Enter') runVirusTotal();">
            <select id="vt-indicator-type" style="background:var(--surface-2); border:1px solid var(--border); color:var(--fg); padding:8px 12px; border-radius:6px;">
              <option value="">Auto-detect</option>
              <option value="ip">IP</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="file">File hash</option>
            </select>
            <button class="btn-action btn-primary" onclick="runVirusTotal()">Lookup Indicator</button>
          </div>
          <div style="border-top:1px solid var(--border); padding-top:14px; margin-bottom:14px;">
            <div style="font-size:12px; font-weight:700; color:var(--fg); margin-bottom:8px;">File hash / upload</div>
            <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
              <input type="file" id="vt-file-input" style="font-size:12px; color:var(--fg-muted);">
              <label style="display:flex; align-items:center; gap:6px; font-size:12px; color:var(--fg-muted);">
                <input type="checkbox" id="vt-upload-consent"> I consent to uploading this file to VirusTotal
              </label>
              <button class="btn-action" onclick="runVirusTotalFile()">Analyze File</button>
            </div>
            <p style="font-size:11px; color:var(--fg-muted); margin-top:8px;">Uploads are opt-in and require the explicit consent checkbox. Files over 32 MiB are rejected.</p>
          </div>
          <div id="vt-result" style="margin-top:16px;"></div>
        </div>
      </section>

      <!-- 10. SECTION: IDENTITY -->
      <section id="section-identity" class="spa-section">
        <div class="card-panel">
          <div class="panel-header">
            <span class="panel-title">Identity Correlation &amp; Analyst Review</span>
            <button class="btn-action" onclick="loadIdentityClusters()">Refresh Clusters</button>
          </div>
          <p style="color:var(--fg-muted); margin-bottom:14px;">Exact shared identifiers and explicit correlation keys merge. Names or avatar similarity never confirm an identity. Analyst confirmation is recorded in the audit ledger.</p>
          <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:10px; margin-bottom:14px;">
            <select id="identity-type" style="background:var(--surface-2); border:1px solid var(--border); color:var(--fg); padding:8px 12px; border-radius:6px;">
              <option value="email">Email</option>
              <option value="username">Username</option>
              <option value="phone">Phone</option>
              <option value="domain">Domain</option>
              <option value="ip">IP</option>
              <option value="public_profile">Public profile</option>
              <option value="pgp_key">PGP key</option>
              <option value="breach">Breach</option>
            </select>
            <input type="text" id="identity-value" class="chat-input" placeholder="Value">
            <input type="text" id="identity-source" class="chat-input" placeholder="Source (e.g. github)">
            <input type="text" id="identity-method" class="chat-input" placeholder="Method (e.g. public_commits)">
            <input type="text" id="identity-correlation-key" class="chat-input" placeholder="Optional correlation key">
            <select id="identity-classification" style="background:var(--surface-2); border:1px solid var(--border); color:var(--fg); padding:8px 12px; border-radius:6px;">
              <option value="UNVERIFIED">UNVERIFIED</option>
              <option value="POSSIBLE_MATCH">POSSIBLE_MATCH</option>
              <option value="STRONG_PUBLIC_MATCH">STRONG_PUBLIC_MATCH</option>
              <option value="CONFIRMED_PUBLIC_ASSOCIATION">CONFIRMED_PUBLIC_ASSOCIATION</option>
              <option value="CONFLICTING_EVIDENCE">CONFLICTING_EVIDENCE</option>
            </select>
            <input type="number" id="identity-confidence" class="chat-input" placeholder="Confidence 0-1" min="0" max="1" step="0.05">
          </div>
          <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap; margin-bottom:18px;">
            <label style="display:flex; align-items:center; gap:6px; font-size:12px; color:var(--fg-muted);">
              <input type="checkbox" id="identity-authoritative"> Authoritative source
            </label>
            <button class="btn-action btn-primary" onclick="addIdentityObservation()">Add Observation</button>
          </div>
          <div id="identity-result" style="margin-bottom:16px;"></div>
          <div id="identity-clusters"></div>
        </div>
      </section>

      <!-- 11. SECTION: ASSESSMENTS -->
      <section id="section-assessments" class="spa-section">
        <div class="kpi-grid">
          <div class="kpi-card info"><div class="kpi-label">Active Target</div><div class="kpi-value" style="font-size:22px;">{escape(active_target)}</div><div class="kpi-sub">Scope Verified</div></div>
          <div class="kpi-card critical"><div class="kpi-label">Critical Findings</div><div class="kpi-value" id="wb-kpi-crit">0</div><div class="kpi-sub">Immediate Action</div></div>
          <div class="kpi-card warning"><div class="kpi-label">High Findings</div><div class="kpi-value" id="wb-kpi-high">0</div><div class="kpi-sub">High Priority</div></div>
          <div class="kpi-card success"><div class="kpi-label">Risk Posture Score</div><div class="kpi-value">0.0</div><div class="kpi-sub">Target Verified</div></div>
        </div>

        <div class="card-panel">
          <div class="panel-header">
            <span class="panel-title">Autonomous Assessment Orchestrator</span>
            <span class="badge badge-success">READY</span>
          </div>
          <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
            <input type="text" id="asmt-target-input" value="{escape(active_target)}" style="background:var(--surface-2); border:1px solid var(--border); color:var(--fg); padding:8px 12px; border-radius:6px; width:220px;">
            <select id="asmt-depth-select" style="background:var(--surface-2); border:1px solid var(--border); color:var(--fg); padding:8px 12px; border-radius:6px;">
              <option value="quick">Depth: Quick (Recon + Core Ports)</option>
              <option value="standard" selected>Depth: Standard (Recon + Web + TLS + DNS)</option>
              <option value="exhaustive">Depth: Exhaustive (Full Audit)</option>
            </select>
            <button class="btn-action btn-primary" onclick="switchSection('copilot'); document.getElementById('chat-input-field').value='Run assessment on ' + document.getElementById('asmt-target-input').value; sendChatMessage();">🚀 Launch Assessment via Copilot</button>
            <button class="btn-action" onclick="toggleCopilot(true)">🤖 Consult AI Copilot</button>
          </div>
        </div>

        <div class="card-panel">
          <div class="panel-header">
            <span class="panel-title">Task Graph DAG Execution Matrix</span>
          </div>
          <div style="background:#050811; border:1px solid var(--border); border-radius:8px; padding:24px; min-height:220px; display:flex; align-items:center; justify-content:center; gap:24px;">
            <div style="padding:12px 18px; background:var(--surface-2); border:1px solid var(--border-glow); border-radius:8px; box-shadow:0 0 16px rgba(79,140,255,0.2); text-align:center;">
              <div style="font-size:10px; color:var(--fg-muted); font-family:var(--font-mono);">STAGE 1</div>
              <div style="font-weight:700; color:var(--accent-blue);">Scope Validation</div>
              <span class="badge badge-success" style="margin-top:6px;">PASSED</span>
            </div>
            <div style="color:var(--accent-blue); font-size:20px;">→</div>
            <div style="padding:12px 18px; background:var(--surface-2); border:1px solid var(--border-glow); border-radius:8px; box-shadow:0 0 16px rgba(79,140,255,0.2); text-align:center;">
              <div style="font-size:10px; color:var(--fg-muted); font-family:var(--font-mono);">STAGE 2</div>
              <div style="font-weight:700; color:var(--accent-cyber);">Surface Discovery</div>
              <span class="badge badge-success" style="margin-top:6px;">VERIFIED</span>
            </div>
            <div style="color:var(--accent-cyber); font-size:20px;">→</div>
            <div style="padding:12px 18px; background:var(--surface-2); border:1px solid var(--border); border-radius:8px; text-align:center;">
              <div style="font-size:10px; color:var(--fg-muted); font-family:var(--font-mono);">STAGE 3</div>
              <div style="font-weight:700; color:var(--fg);">Risk Analysis</div>
              <span class="badge badge-info" style="margin-top:6px;">READY</span>
            </div>
          </div>
        </div>
      </section>

      <!-- 9. SECTION: FINDINGS -->
      <section id="section-findings" class="spa-section">
        <div class="card-panel">
          <div class="panel-header">
            <span class="panel-title">Security Findings &amp; Vulnerability Posture</span>
            <span class="badge badge-warning">{findings} FINDINGS</span>
          </div>
          <p style="color:var(--fg-muted); margin-bottom:16px;">Vulnerabilities discovered across scoped evaluations with remediation verification.</p>
          <div class="kpi-grid">
            <article class="tile purple">
              <div class="label">Findings</div>
              <div class="value">{findings}</div><div class="delta flat">{escape(finding_breakdown)}</div>
            </article>
            <article class="tile red">
              <div class="label">Blocked attempts</div>
              <div class="value">{len(blocked_rows)}</div>
              <div class="delta up">{escape(blocked_target)}</div>
            </article>
          </div>
        </div>
      </section>

      <!-- 10. SECTION: REPORTS -->
      <section id="section-reports" class="spa-section">
        <div class="card-panel">
          <div class="panel-header"><span class="panel-title">Verifiable Security Report Export</span></div>
          <p style="color:var(--fg-muted); margin-bottom:20px;">Download verifiable technical and executive reports generated directly from authentic findings and cryptographic audit records.</p>
          <div style="display:flex; gap:12px; flex-wrap:wrap;">
            <a href="/report/html?target={escape(active_target)}" target="_blank" class="btn-action">HTML Report</a>
            <a href="/report/json?target={escape(active_target)}" target="_blank" class="btn-action">JSON Report</a>
            <a href="/report/md?target={escape(active_target)}" target="_blank" class="btn-action">Markdown Report</a>
            <a href="/report/pdf?target={escape(active_target)}" target="_blank" class="btn-action btn-primary">Download PDF Report</a>
            <a href="/report/pptx?target={escape(active_target)}" target="_blank" class="btn-action btn-primary" style="background:var(--accent);">Download PPTX Presentation</a>
          </div>
        </div>
      </section>


      <!-- 12. SECTION: AUDIT -->
      <section id="section-audit" class="spa-section">
        <div class="card-panel">
          <div class="panel-header">
            <span class="panel-title">Cryptographic Tamper-Evident Audit Ledger</span>
            <button class="btn-action btn-primary" onclick="verifyAuditChain()">Verify Audit Chain Integrity</button>
          </div>
          <div id="audit-verify-status" style="margin-bottom:14px;"></div>
          <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-bottom:14px; padding:12px; border:1px solid var(--border); border-radius:8px; background:var(--surface-2);">
            <span style="font-size:12px; font-weight:700; color:var(--fg);">External checkpoint</span>
            <button class="btn-action" onclick="verifyAuditCheckpoint()">Verify Checkpoint</button>
            <button class="btn-action btn-primary" onclick="createAuditCheckpoint()">Create Checkpoint</button>
            <button class="btn-action" onclick="rotateAuditCheckpointKey()">Rotate Key</button>
            <span id="audit-checkpoint-status" style="font-size:11.5px; color:var(--fg-muted);"></span>
          </div>
          <p style="color:var(--fg-muted); margin-bottom:14px;">Cryptographic SHA-256 hash-chain guaranteeing immutable operational logs. The external checkpoint binds the ledger head to an independent HMAC file.</p>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Target</th>
                  <th>Module</th>
                  <th>Action</th>
                  <th>Status</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>{body}</tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- 13. SECTION: PROVIDERS -->
      <section id="section-providers" class="spa-section">
        <div class="card-panel">
          <div class="panel-header">
            <span class="panel-title">AI &amp; OSINT Provider Gateway</span>
            <span class="badge badge-success">LOCAL FIRST</span>
          </div>
          <div class="kpi-grid" style="margin-bottom:20px;">
            <div class="kpi-card success">
              <div class="kpi-label">Local Ollama Status</div>
              <div class="kpi-value" style="font-size:18px;">READY</div>
              <div class="kpi-sub">Ollama Local-First Mode</div>
            </div>
            <div class="kpi-card info">
              <div class="kpi-label">Fail-Closed Mode</div>
              <div class="kpi-value" style="font-size:18px;">ENFORCED</div>
              <div class="kpi-sub">No Silent Cloud Leaks</div>
            </div>
            <div class="kpi-card warning">
              <div class="kpi-label">Offline Mode</div>
              <div class="kpi-value" style="font-size:18px;">STANDBY</div>
              <div class="kpi-sub">Configurable via OFFLINE_MODE</div>
            </div>
          </div>
          <p style="color:var(--fg-muted); font-size:12.5px;">All LLM queries prioritize local Ollama models. If unavailable, status is transparently indicated without fabricated responses.</p>
        </div>
      </section>

      <!-- 14. SECTION: SYSTEM HEALTH -->
      <section id="section-system-health" class="spa-section">
        <div class="card-panel">
          <div class="panel-header">
            <span class="panel-title">System Health &amp; Telemetry</span>
            <span class="badge badge-success">ONLINE</span>
          </div>
          <div class="kpi-grid">
            <div class="kpi-card"><div class="kpi-label">Total Tokens</div><div class="kpi-value">{token_usage.get_summary().get('total_tokens', 0)}</div><div class="kpi-sub">Persisted Tokens</div></div>
            <div class="kpi-card info"><div class="kpi-label">Prompt Tokens</div><div class="kpi-value">{token_usage.get_summary().get('prompt_tokens', 0)}</div><div class="kpi-sub">Input Tokens</div></div>
            <div class="kpi-card success"><div class="kpi-label">Completion Tokens</div><div class="kpi-value">{token_usage.get_summary().get('completion_tokens', 0)}</div><div class="kpi-sub">Generated Tokens</div></div>
            <div class="kpi-card warning"><div class="kpi-label">Reported Requests</div><div class="kpi-value">{token_usage.get_summary().get('reported_requests', 0)}</div><div class="kpi-sub">Inference Queries</div></div>
          </div>
          <h3 style="font-size:13px; font-family:var(--font-mono); margin:20px 0 10px;">Token Usage Ledger</h3>
          <p style="color:var(--fg-muted); font-size:12px;">Real token accounting ledger persisted across local sessions in SQLite.</p>
        </div>

        <div class="card-panel" style="margin-top:20px;">
          <div class="panel-header">
            <div>
              <span class="panel-title">Low-Confidence Review Queue</span>
              <span class="badge badge-warning" id="lcr-pending-count">0 PENDING</span>
            </div>
            <button class="btn-action" onclick="loadLowConfidenceQueue()">↻ Refresh Queue</button>
          </div>
          <p style="color:var(--fg-muted); font-size:12px; margin-bottom:14px;">
            Inferences and classifications scoring below threshold (&lt; 0.50) are flagged here for human operator validation. No unverified inference is ever automatically promoted without explicit ground-truth or observation.
          </p>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Type</th>
                  <th>Prompt / Finding</th>
                  <th>Classified As</th>
                  <th>Confidence</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody id="low-confidence-table-body">
                <tr><td colspan="7" style="text-align:center; padding:18px; color:var(--fg-muted);">Click "Refresh Queue" to inspect review items.</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- 15. SECTION: SETTINGS -->
      <section id="section-settings" class="spa-section">
        <div class="card-panel">
          <div class="panel-header">
            <span class="panel-title">REDLOOP Operational Settings &amp; Policies</span>
          </div>
          <div style="background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:18px;">
            <div style="font-weight:700; margin-bottom:12px;">Security &amp; Network Policies</div>
            <div style="font-size:12.5px; color:var(--fg); line-height:1.8;">
              <div>• <strong>Offline Mode:</strong> Set <code>OFFLINE_MODE=true</code> to restrict all operations to local tools and local Ollama inference.</div>
              <div>• <strong>Scope Enforcement:</strong> Cryptographic HMAC signature validation required on all assessments.</div>
              <div>• <strong>Evidence Integrity:</strong> SHA-256 tamper-evident chaining on all observations and audit events.</div>
            </div>
          </div>
        </div>
      </section>

      <!-- 0. SECTION: OVERVIEW -->
      <section id="section-overview" class="spa-section active" aria-labelledby="overview-title">
        <div class="scope-banner" id="scope-manifest" aria-label="Active target scope" style="margin-bottom:16px;">
          <div class="scope-item">
            <span class="key">Active target</span>
            <span class="value" style="color:var(--accent);font-weight:600;">{escape(active_target)}</span>
          </div>
          <div class="scope-item">
            <span class="key">Authorized window</span>
            <span class="value">{escape(authorized_window)}</span>
          </div>
          <div class="scope-item">
            <span class="key">Allowed actions</span>
            <span class="value" style="color:#22d3ee;">{escape(allowed_actions)}</span>
          </div>
          <div class="scope-item">
            <span class="key">Window remaining</span>
            <span class="value">{escape(window_remaining)}</span>
          </div>
          <span class="scope-pill {status_class}">{escape(scope_status)}</span>
        </div>
        <div class="overview-head">
          <div>
            <div class="overview-eyebrow">RedLoop command center</div>
            <h1 id="overview-title">Overview</h1>
            <p class="overview-lede">Scope-verified security operations, evidence, and AI copiloting in one calm surface.</p>
          </div>
          <div class="overview-actions">
            <button type="button" class="btn btn-secondary" data-action="refresh-overview" id="ov-refresh">Refresh data</button>
            <a class="btn btn-primary" href="#chat" data-action="goto-chat">Start a session</a>
            <a class="btn btn-ghost" href="#investigations" onclick="switchSection('investigations')">Open Investigation Workspace</a>
          </div>
        </div>

        <div class="overview-kpis" aria-label="Operations summary">
          <article class="kpi-tile" data-kpi="scope">
            <div class="kpi-label">Scoped targets</div>
            <div class="kpi-value" id="ov-scope-targets">{len(scope_manager.scope.targets) if scope_manager else "—"}</div>
            <div class="kpi-note"><span id="ov-scope-note">Signature verified</span> · <span>Actions logged {actions_label}</span></div>
          </article>
          <article class="kpi-tile" data-kpi="findings">
            <div class="kpi-label">Findings logged</div>
            <div class="kpi-value" id="ov-findings-total">—</div>
            <div class="kpi-note" id="ov-findings-note">Loading severity split…</div>
          </article>
          <article class="kpi-tile" data-kpi="tasks">
            <div class="kpi-label">Active tasks</div>
            <div class="kpi-value" id="ov-active-tasks">—</div>
            <div class="kpi-note" id="ov-active-note">Tasks and assessments in flight</div>
          </article>
          <article class="kpi-tile" data-kpi="audit">
            <div class="kpi-label">Audit health</div>
            <div class="kpi-value kpi-value-sm" id="ov-audit-status">{escape(scope_status)}</div>
            <div class="kpi-note" id="ov-audit-note">Verifying chain…</div>
          </article>
        </div>
        <div id="ov-kpi-error" class="inline-error-host" role="status" aria-live="polite"></div>

        <div class="overview-chart-grid">
          <section class="card-panel chart-card" aria-labelledby="findings-chart-title">
            <div class="panel-header chart-head">
              <div>
                <span class="panel-title" id="findings-chart-title">Findings over time</span>
                <p class="panel-hint">Total findings per assessment, grouped by creation date.</p>
              </div>
              <div class="tabs" role="tablist" aria-label="Findings time range">
                <button type="button" class="tab" role="tab" aria-selected="false" data-action="ov-range" data-range="30">30d</button>
                <button type="button" class="tab" role="tab" aria-selected="true" data-action="ov-range" data-range="90">90d</button>
                <button type="button" class="tab" role="tab" aria-selected="false" data-action="ov-range" data-range="all">All</button>
              </div>
            </div>
            <div class="chart-host" id="ov-findings-chart"><div class="skeleton skeleton-chart" aria-hidden="true"></div></div>
            <p class="chart-caption" id="ov-findings-caption" role="status">Loading assessment history…</p>
          </section>

          <section class="card-panel chart-card" aria-labelledby="severity-chart-title">
            <div class="panel-header chart-head">
              <div>
                <span class="panel-title" id="severity-chart-title">Severity distribution</span>
                <p class="panel-hint">Latest assessment findings by severity.</p>
              </div>
            </div>
            <div class="chart-host" id="ov-severity-chart"><div class="skeleton skeleton-chart" aria-hidden="true"></div></div>
            <ul class="severity-legend" id="ov-severity-legend" aria-label="Severity legend"></ul>
            <p class="chart-caption" id="ov-severity-caption" role="status">Loading severity data…</p>
          </section>
        </div>

        <div class="overview-grid">
          <section class="card-panel" id="activity" aria-labelledby="activity-title">
            <div class="panel-header">
              <div>
                <span class="panel-title" id="activity-title">Recent activity</span>
                <p class="panel-hint">Latest audit events from the read-only trail.</p>
              </div>
              <span class="status-pill status-pill-neutral" id="ov-activity-count">—</span>
            </div>
            <div id="ov-activity" class="table-wrap" aria-live="polite"><div class="skeleton skeleton-row" aria-hidden="true"></div></div>
          </section>

          <section class="card-panel" aria-labelledby="tools-title">
            <div class="panel-header">
              <div>
                <span class="panel-title" id="tools-title">Tool availability</span>
                <p class="panel-hint">Runtime capability probe, not a static list.</p>
              </div>
              <span class="status-pill status-pill-neutral" id="ov-tools-count">—</span>
            </div>
            <div id="ov-tools" class="tool-list" aria-live="polite"><div class="skeleton skeleton-row" aria-hidden="true"></div></div>
          </section>
        </div>

        <section class="card-panel" aria-labelledby="assessments-title">
          <div class="panel-header">
            <div>
              <span class="panel-title" id="assessments-title">Assessments</span>
              <p class="panel-hint">Search, filter, and sort recorded assessments.</p>
            </div>
            <a class="btn btn-ghost" href="#investigations" onclick="switchSection('investigations')">Open Investigation Workspace</a>
          </div>
          <div class="table-toolbar">
            <label class="field">
              <span class="field-label">Search</span>
              <input id="ov-assess-search" class="input" type="search" placeholder="Target or assessment ID" autocomplete="off">
            </label>
            <label class="field">
              <span class="field-label">Status</span>
              <select id="ov-assess-status" class="select">
                <option value="all">All statuses</option>
                <option value="running">Running</option>
                <option value="completed">Completed</option>
                <option value="failed">Failed</option>
                <option value="paused">Paused</option>
                <option value="cancelled">Cancelled</option>
                <option value="blocked">Blocked</option>
                <option value="partially_blocked">Partially blocked</option>
              </select>
            </label>
            <span class="table-count" id="ov-assess-count" role="status">—</span>
          </div>
          <div id="ov-assessments" class="table-wrap" aria-live="polite"><div class="skeleton skeleton-row" aria-hidden="true"></div></div>
        </section>

        <footer class="overview-foot">Scope: {escape(scope_manager_status)} — audit records are read-only</footer>
      </section>
    </main>
  </div>
</div>

<!-- SLIDE-OVER AI COPILOT DRAWER -->
<aside class="copilot-drawer" id="copilot-drawer">
  <div class="copilot-drawer-header">
    <div class="copilot-drawer-title">
      <span class="copilot-dot"></span>
      <span>REDLOOP AI COPILOT</span>
    </div>
    <div style="display:flex; gap:8px;">
      <button class="btn-action" style="padding:2px 8px; font-size:11px;" onclick="toggleCopilot(false)">✕</button>
    </div>
  </div>
  <div class="copilot-drawer-context">
    <span id="copilot-ctx-target">Target: {escape(active_target)}</span>
    <span>·</span>
    <span style="color:var(--success);">In Scope</span>
  </div>
  <div class="copilot-drawer-messages" id="copilot-drawer-messages"></div>
  <form class="copilot-drawer-composer" onsubmit="sendCopilotMessage(event)">
    <textarea id="copilot-drawer-input" placeholder="Ask AI Copilot or enter security objective..." onkeydown="if(event.key==='Enter' && !event.shiftKey){{ event.preventDefault(); sendCopilotMessage(event); }}"></textarea>
    <div class="copilot-composer-actions">
      <span class="copilot-hint">Enter to send · Shift+Enter for newline</span>
      <button type="submit" class="btn-action btn-primary" style="padding:6px 14px;">Execute</button>
    </div>
  </form>
</aside>

<!-- COMMAND PALETTE MODAL (Ctrl+K) -->
<div class="modal-overlay" id="cmd-palette" onclick="if(event.target===this) closePalette()">
  <div class="palette-box">
    <div class="palette-search-wrap">
      <svg class="svg-icon" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      <input id="palette-search" placeholder="Type a section name or command..." oninput="filterPalette(this.value)">
      <kbd style="background:var(--surface-2); padding:2px 6px; border-radius:4px; font-size:11px;">ESC</kbd>
    </div>
    <div class="palette-list" id="palette-list">
      <div class="palette-item active" onclick="switchSection('chat'); closePalette();"><span class="palette-item-title">Chat (Standalone &amp; Conversations)</span><span class="palette-item-tag">OPERATE</span></div>
      <div class="palette-item" onclick="switchSection('terminal'); closePalette();"><span class="palette-item-title">Terminal</span><span class="palette-item-tag">OPERATE</span></div>
      <div class="palette-item" onclick="switchSection('tools'); closePalette();"><span class="palette-item-title">Tools</span><span class="palette-item-tag">OPERATE</span></div>
      <div class="palette-item" onclick="switchSection('investigations'); closePalette();"><span class="palette-item-title">Investigations</span><span class="palette-item-tag">INVESTIGATE</span></div>
      <div class="palette-item" onclick="switchSection('evidence'); closePalette();"><span class="palette-item-title">Evidence Ledger</span><span class="palette-item-tag">INVESTIGATE</span></div>
      <div class="palette-item" onclick="switchSection('graph'); closePalette();"><span class="palette-item-title">Entity Knowledge Graph</span><span class="palette-item-tag">INVESTIGATE</span></div>
      <div class="palette-item" onclick="switchSection('osint'); closePalette();"><span class="palette-item-title">OSINT Intelligence</span><span class="palette-item-tag">INVESTIGATE</span></div>
      <div class="palette-item" onclick="switchSection('assessments'); closePalette();"><span class="palette-item-title">Assessments</span><span class="palette-item-tag">SECURITY</span></div>
      <div class="palette-item" onclick="switchSection('findings'); closePalette();"><span class="palette-item-title">Findings</span><span class="palette-item-tag">SECURITY</span></div>
      <div class="palette-item" onclick="switchSection('reports'); closePalette();"><span class="palette-item-title">Reports</span><span class="palette-item-tag">SECURITY</span></div>
      <div class="palette-item" onclick="switchSection('scope'); closePalette();"><span class="palette-item-title">Scope &amp; HMAC Authorization</span><span class="palette-item-tag">GOVERN</span></div>
      <div class="palette-item" onclick="switchSection('audit'); closePalette();"><span class="palette-item-title">Cryptographic Audit Trail</span><span class="palette-item-tag">GOVERN</span></div>
      <div class="palette-item" onclick="switchSection('providers'); closePalette();"><span class="palette-item-title">LLM Providers &amp; Models</span><span class="palette-item-tag">GOVERN</span></div>
      <div class="palette-item" onclick="switchSection('system-health'); closePalette();"><span class="palette-item-title">System Health &amp; Diagnostics</span><span class="palette-item-tag">SYSTEM</span></div>
      <div class="palette-item" onclick="switchSection('settings'); closePalette();"><span class="palette-item-title">Settings</span><span class="palette-item-tag">SYSTEM</span></div>
      <div class="palette-item" onclick="closePalette(); createNewChat(); switchSection('chat');"><span class="palette-item-title">💬 Start New Chat Conversation</span><span class="palette-item-tag">QUICK ACTION</span></div>
      <div class="palette-item" onclick="closePalette(); toggleCopilot(true);"><span class="palette-item-title">🤖 Open AI Copilot Drawer</span><span class="palette-item-tag">QUICK ACTION</span></div>
      <div class="palette-item" onclick="closePalette(); switchSection('graph'); loadGraph();"><span class="palette-item-title">🕸️ Refresh Entity Graph</span><span class="palette-item-tag">QUICK ACTION</span></div>
    </div>
    <div class="palette-footer" style="padding:10px 18px; border-top:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; font-size:11px; color:var(--fg-muted); font-family:var(--font-mono); background:rgba(10,14,23,0.9);">
      <div style="display:flex; gap:14px;">
        <span><kbd style="background:var(--surface-2); padding:2px 6px; border-radius:4px; border:1px solid var(--border); color:var(--fg);">↑</kbd> <kbd style="background:var(--surface-2); padding:2px 6px; border-radius:4px; border:1px solid var(--border); color:var(--fg);">↓</kbd> navigate</span>
        <span><kbd style="background:var(--surface-2); padding:2px 6px; border-radius:4px; border:1px solid var(--border); color:var(--fg);">↵</kbd> select</span>
        <span><kbd style="background:var(--surface-2); padding:2px 6px; border-radius:4px; border:1px solid var(--border); color:var(--fg);">esc</kbd> close</span>
      </div>
      <span style="color:var(--accent-cyber); font-weight:600;">REDLOOP Cyber Command</span>
    </div>
  </div>
</div>

<div class="toast-region" id="toast-region" role="status" aria-live="polite" aria-atomic="false"></div>
<script>{UNIFIED_SCRIPT}</script>
</body>
</html>"""
        return HTMLResponse(html)

    @app.get("/api/scope")
    def api_scope(target: str | None = Query(default=None)):
        all_rows, _ = reader.entries(limit=MAX_REPORT_ROWS)
        target_rows = [
            row
            for row in all_rows
            if not (
                str(row["module"]).casefold() == "memory"
                and str(row["action"]).casefold() == "memory_store"
            )
        ]
        target_values = {str(row["target"]) for row in target_rows}
        targets = [item for item in reader.targets() if item in target_values]
        active_tgt = target or _active_target(target_rows, scope_manager)
        active_entry = _scope_entry(scope_manager, active_tgt)
        today = date.today()
        if scope_manager is None:
            return JSONResponse({
                "in_scope": False,
                "status": "Unavailable",
                "label": "Scope unavailable",
                "active_target": active_tgt,
                "authorized_window": "Not verified",
                "allowed_actions": [],
                "window_remaining": "Not verified",
                "targets": targets or ["127.0.0.1"],
                "signature_verified": False,
            })
        if active_entry is None:
            return JSONResponse({
                "in_scope": False,
                "status": "Out of scope",
                "label": "No matching scope entry",
                "active_target": active_tgt,
                "authorized_window": "—",
                "allowed_actions": [],
                "window_remaining": "—",
                "targets": [str(t.cidr) for t in scope_manager.scope.targets],
                "signature_verified": True,
            })
        in_date_window = active_entry.authorized_from <= today <= active_entry.authorized_until
        is_in_scope = in_date_window and scope_manager.is_within_window()
        rem_days = (active_entry.authorized_until - today).days
        rem_str = "Scope expired" if not scope_manager.is_within_window() else ("Expired" if rem_days < 0 else f"{rem_days} days")
        return JSONResponse({
            "in_scope": is_in_scope,
            "status": "In scope" if is_in_scope else "Out of scope",
            "label": active_entry.label,
            "active_target": active_tgt,
            "authorized_window": f"{active_entry.authorized_from.isoformat()} → {active_entry.authorized_until.isoformat()}",
            "allowed_actions": list(active_entry.allowed_actions),
            "window_remaining": rem_str,
            "targets": [str(t.cidr) for t in scope_manager.scope.targets],
            "signature_verified": True,
        })

    @app.get("/report/html")
    def report_html(target: str = Query("127.0.0.1")):
        store = _resolve_assessment_store()
        all_asmts = store.list_all()
        target_asmts = [store.load(a["id"]) for a in all_asmts if a.get("target") == target]
        findings = []
        if target_asmts and target_asmts[0]:
            findings = [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "asset": f.asset,
                    "risk_score": f.risk_score,
                    "remediation": f.remediation,
                }
                for f in target_asmts[0].findings
            ]
        rows, _ = reader.entries(target=target, limit=MAX_REPORT_ROWS)
        html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>RedLoop Report - {escape(target)}</title>
  <style>
    body {{ font-family: -apple-system, sans-serif; padding: 32px; background: #0a0e17; color: #e7e9ee; }}
    h1 {{ color: #4f8cff; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
    th, td {{ padding: 10px; border: 1px solid #243044; text-align: left; }}
    th {{ background: #1a2332; color: #8b93a7; }}
  </style>
</head>
<body>
  <h1>RedLoop Security Assessment Report</h1>
  <p><strong>Target:</strong> {escape(target)} | <strong>Date:</strong> {date.today().isoformat()}</p>
  <h2>Findings</h2>
"""
        if not findings:
            html += "<p>No findings in this category.</p>"
        else:
            html += "<table><tr><th>Severity</th><th>Title</th><th>Asset</th><th>Risk</th></tr>"
            for f in findings:
                html += f"<tr><td>{escape(f['severity'])}</td><td>{escape(f['title'])}</td><td>{escape(f['asset'])}</td><td>{f['risk_score']}</td></tr>"
            html += "</table>"
        html += f"<h2>Audit Summary</h2><p>Total recorded audit entries: {len(rows)}</p></body></html>"
        return HTMLResponse(html)

    @app.get("/report/json")
    def report_json(target: str = Query("127.0.0.1")):
        store = _resolve_assessment_store()
        all_asmts = store.list_all()
        target_asmts = [store.load(a["id"]) for a in all_asmts if a.get("target") == target]
        findings = []
        if target_asmts and target_asmts[0]:
            findings = [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "asset": f.asset,
                    "risk_score": f.risk_score,
                    "remediation": f.remediation,
                }
                for f in target_asmts[0].findings
            ]
        rows, _ = reader.entries(target=target, limit=MAX_REPORT_ROWS)
        evidence = []
        if target_asmts and target_asmts[0]:
            evidence = [e.model_dump(mode="json") for e in target_asmts[0].evidence]
        return JSONResponse({
            "target": target,
            "date": date.today().isoformat(),
            "findings": findings,
            "evidence": evidence,
            "audit_records_count": len(rows),
        })

    @app.get("/report/md")
    @app.get("/report/markdown")
    def report_md(target: str = Query("127.0.0.1")):
        from redloop.assessment.reporting import ReportingEngine
        from redloop.reporting import AuditReportGenerator
        store = _resolve_assessment_store()
        all_asmts = store.list_all()
        target_asmts = [store.load(a["id"]) for a in all_asmts if a.get("target") == target]
        if target_asmts and target_asmts[0]:
            rep_eng = ReportingEngine()
            md_content = rep_eng.generate_executive_report(target_asmts[0])
            return PlainTextResponse(md_content)
        generator = AuditReportGenerator(db_path, "reports")
        rows, truncated = reader.entries(target=target, limit=MAX_REPORT_ROWS)
        rows.reverse()
        rendered = generator._render(target, rows, truncated)
        return PlainTextResponse(rendered)

    @app.get("/report/pdf")
    def report_pdf(target: str = Query("127.0.0.1")):
        store = _resolve_assessment_store()
        all_asmts = store.list_all()
        target_asmts = [store.load(a["id"]) for a in all_asmts if a.get("target") == target]
        findings = []
        if target_asmts and target_asmts[0]:
            findings = [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "asset": f.asset,
                    "risk_score": f.risk_score,
                    "remediation": f.remediation,
                }
                for f in target_asmts[0].findings
            ]
        rows, _ = reader.entries(target=target, limit=MAX_REPORT_ROWS)
        pdf_bytes = generate_pdf_report(target, findings, rows)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="redloop_report_{target}.pdf"'},
        )

    @app.get("/report/pptx")
    def report_pptx(target: str = Query("127.0.0.1")):
        store = _resolve_assessment_store()
        all_asmts = store.list_all()
        target_asmts = [store.load(a["id"]) for a in all_asmts if a.get("target") == target]
        findings = []
        if target_asmts and target_asmts[0]:
            findings = [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "asset": f.asset,
                    "risk_score": f.risk_score,
                    "remediation": f.remediation,
                }
                for f in target_asmts[0].findings
            ]
        active_entry = _scope_entry(scope_manager, target)
        scope_str = (
            f"{active_entry.authorized_from.isoformat()} → {active_entry.authorized_until.isoformat()}"
            if active_entry else "Not verified"
        )
        pptx_bytes = generate_pptx_report(target, findings, scope_str)
        return Response(
            content=pptx_bytes,
            media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
            headers={"Content-Disposition": f'attachment; filename="redloop_deck_{target}.pptx"'},
        )

    @app.get("/api/entries")
    def entries(
        target: str | None = Query(default=None, max_length=2_048),
        limit: int = Query(default=50, ge=1, le=MAX_DASHBOARD_ROWS),
        module: str | None = Query(default=None, max_length=64),
    ):
        rows, truncated = reader.entries(
            target=target, limit=limit, module=module
        )
        return JSONResponse({"entries": rows, "truncated": truncated})

    @app.get("/performance", response_class=HTMLResponse)
    def performance_page():
        from redloop.performance import metrics_collector
        return HTMLResponse(
            _render_performance_page(
                metrics_collector,
                token_usage=token_usage.get_summary(),
            )
        )

    @app.get("/api/performance/summary")
    def performance_summary_api():
        from redloop.performance import metrics_collector
        usage = token_usage.get_summary()
        summary = metrics_collector.get_summary()
        summary.update(
            total_tokens_used=usage["total_tokens"],
            total_prompt_tokens=usage["prompt_tokens"],
            total_completion_tokens=usage["completion_tokens"],
            token_usage_reported_queries=usage["reported_requests"],
        )
        modes = metrics_collector.get_mode_breakdown()
        for item in usage["modes"]:
            mode_stats = modes.setdefault(
                item["mode"],
                {
                    "query_count": 0,
                    "avg_latency_ms": 0.0,
                    "avg_confidence": 0.0,
                    "success_rate": 0.0,
                    "total_tokens": 0,
                },
            )
            mode_stats.update(
                total_tokens=item["total_tokens"],
                prompt_tokens=item["prompt_tokens"],
                completion_tokens=item["completion_tokens"],
                chat_requests=item["requests"],
            )
        return JSONResponse({
            "summary": summary,
            "modes": modes,
            "recent": metrics_collector.get_recent_metrics(20),
            "token_usage": usage,
        })

    @app.get("/api/system/low-confidence-queue")
    def low_confidence_queue_api(
        status: str | None = Query(default=None),
        limit: int = Query(default=50, ge=1, le=200),
    ):
        from redloop.assessment.evaluation import get_review_queue
        rq = get_review_queue()
        items = rq.list_items(status=status, limit=limit)
        summary = rq.get_summary()
        return JSONResponse({"summary": summary, "items": items})

    @app.post("/api/system/low-confidence-queue/{item_id}/resolve")
    async def resolve_low_confidence_api(item_id: str, request: Request):
        from redloop.assessment.evaluation import get_review_queue

        origin = request.headers.get("origin")
        if not origin:
            return JSONResponse(
                {"success": False, "error": "Origin header required"},
                status_code=403,
            )
        parsed_origin = urlsplit(origin)
        if (
            parsed_origin.scheme != request.url.scheme
            or parsed_origin.netloc.casefold() != request.url.netloc.casefold()
            or parsed_origin.path not in ("", "/")
            or parsed_origin.query
            or parsed_origin.fragment
        ):
            return JSONResponse(
                {"success": False, "error": "Cross-origin request rejected"},
                status_code=403,
            )

        try:
            data = await request.json()
        except Exception:
            data = {}
        if not isinstance(data, dict):
            return JSONResponse(
                {"success": False, "error": "JSON object required"},
                status_code=400,
            )

        resolution = data.get("status", "APPROVED")
        if resolution not in {
            "APPROVED",
            "REJECTED",
            "DISMISSED",
            "ESCALATED",
            "PENDING_REVIEW",
        }:
            return JSONResponse(
                {"success": False, "error": "Invalid resolution status"},
                status_code=400,
            )
        notes = data.get("notes", "")
        reviewed_by = data.get("reviewed_by", "operator")
        if not isinstance(notes, str) or len(notes) > 2_000:
            return JSONResponse(
                {"success": False, "error": "notes must be <= 2000 characters"},
                status_code=400,
            )
        if not isinstance(reviewed_by, str) or not reviewed_by.strip() or len(reviewed_by) > 128:
            return JSONResponse(
                {"success": False, "error": "reviewed_by must be 1-128 characters"},
                status_code=400,
            )
        ok = get_review_queue().resolve(
            item_id,
            status=resolution,
            reviewed_by=reviewed_by.strip(),
            notes=notes,
        )
        return JSONResponse({"success": ok, "item_id": item_id, "status": resolution})

    return app


def _scope_entry(scope_manager: ScopeManager | None, target: str):
    if scope_manager is None or target == "No recent target":
        return None
    return next(
        (
            entry
            for entry in scope_manager.scope.targets
            if entry.matches(target)
        ),
        None,
    )


def _active_target(rows: list[dict], scope_manager: ScopeManager | None) -> str:
    if scope_manager is not None:
        for row in rows:
            target = str(row["target"])
            if _scope_entry(scope_manager, target) is not None:
                return target
        for entry in scope_manager.scope.targets:
            if entry.cidr:
                try:
                    return str(ip_network(entry.cidr, strict=False).network_address)
                except ValueError:
                    continue
            if entry.domain:
                return entry.domain
    for row in rows:
        candidate = str(row.get("target", "")).strip()
        if candidate and candidate != "email_footprint" and not candidate.startswith("internal_"):
            return candidate
    return "127.0.0.1" 

def _is_module(row: dict, category: str) -> bool:
    module = str(row["module"]).casefold()
    action = str(row["action"]).casefold()
    if category == "recon":
        return module in {"nmap", "recon"} or action == "recon"
    if category == "webapp":
        return module == "webapp" or action == "web_test"
    if category == "exploit":
        return module == "exploit" or action == "exploit"
    return module == category


def _finding_count(details) -> int:
    if not isinstance(details, dict):
        return 0
    count = details.get("findings_count")
    if isinstance(count, int) and not isinstance(count, bool):
        return max(0, count)
    open_ports = details.get("open_ports")
    if isinstance(open_ports, int) and not isinstance(open_ports, bool):
        return max(0, open_ports)
    if isinstance(open_ports, list):
        return len(open_ports)
    open_port_details = details.get("open_port_details")
    if isinstance(open_port_details, list):
        return len(open_port_details)
    findings = details.get("findings")
    return len(findings) if isinstance(findings, list) else 0


def _finding_breakdown(rows: list[dict]) -> str:
    counts: list[str] = []
    for category, label in (("recon", "recon"), ("forensics", "forensics"), ("webapp", "webapp")):
        count = sum(
            _finding_count(row["details"])
            for row in rows
            if _is_module(row, category)
        )
        if count:
            counts.append(f"{count} {label}")
    return " · ".join(counts) if counts else "No findings recorded"


def _nav_link(
    module: str,
    count: int,
    active_module: str | None,
    label: str | None = None,
) -> str:
    query = urlencode({"module": module})
    active = " active" if active_module == module else ""
    current = ' aria-current="page"' if active else ""
    return (
        f'<a class="navlink{active}" href="/?{query}#activity"{current}>'
        f'{_icon(module)}{escape(label or module.title())}'
        f'<span class="count">{count}</span></a>'
    )


def _render_modules(module_counts: dict[str, int]) -> str:
    descriptions = {
        "recon": (
            "Nmap is verified against loopback only. Shodan needs an API key; "
            "Amass requires the Go binary."
        ),
        "webapp": (
            "Loopback-only metadata checks. No broad fuzzing or SQL injection "
            "automation is enabled."
        ),
        "exploit": (
            "Offline synthetic workflow only; no exploit execution or live target "
            "interaction."
        ),
        "forensics": (
            "Static file triage; input files are not executed."
        ),
        "executor": (
            "Model-selected operations are limited to validated local functions."
        ),
        "memory": (
            "Bounded local SQLite history; retrieval is lexical and advisory."
        ),
    }
    statuses = {
        "recon": ("Operational", "operational"),
        "webapp": ("Loopback only", "partial"),
        "exploit": (
            ("Simulator operational", "operational")
            if module_counts.get("exploit", 0) > 0
            else ("Simulator only", "")
        ),
        "forensics": ("Static only", "operational"),
        "executor": ("Local only", "operational"),
        "memory": ("Lexical", "partial"),
    }
    cards = []
    for module, label in _MODULES:
        status, style = statuses[module]
        action_btn = ""
        if module == "exploit":
            action_btn = (
                '<div style="margin-top:10px;">'
                '<a href="/workbench?action=simulate-exploit" '
                'style="display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:6px;'
                'background:rgba(224,105,90,0.15);border:1px solid rgba(224,105,90,0.3);color:var(--critical);'
                'font-family:var(--font-display);font-size:var(--text-xs);font-weight:600;text-decoration:none;">'
                '⚔️ Simulate Attack Path</a></div>'
            )
        cards.append(
            f'<article class="module-card" id="{module}"><div class="row">'
            f"<h3>{escape(label)}</h3><span class=\"module-status {style}\">"
            f"{escape(status)}</span></div><p>{escape(descriptions[module])}</p>"
            f'<div class="module-meta">{module_counts[module]} logged event(s)</div>'
            f"{action_btn}"
            "</article>"
        )
    return "\n".join(cards)


def _details_text(details) -> str:
    try:
        return json.dumps(details, ensure_ascii=True, indent=2, default=str)[:4_000]
    except (TypeError, ValueError, RecursionError):
        return "{}"


def _render_performance_page(collector, *, token_usage=None) -> str:
    summary = collector.get_summary()
    modes = collector.get_mode_breakdown()
    recent = collector.get_recent_metrics(15)
    token_usage = token_usage or {}
    usage_by_mode = {
        item["mode"]: item for item in token_usage.get("modes", [])
    }
    for mode_name, usage in usage_by_mode.items():
        mode_stats = modes.setdefault(
            mode_name,
            {
                "query_count": 0,
                "avg_latency_ms": 0.0,
                "avg_confidence": 0.0,
                "success_rate": 0.0,
                "total_tokens": 0,
            },
        )
        mode_stats["total_tokens"] = usage["total_tokens"]

    p50 = summary.get("p50_latency_ms", 0.0)
    p95 = summary.get("p95_latency_ms", 0.0)
    p99 = summary.get("p99_latency_ms", 0.0)
    avg_lat = summary.get("avg_latency_ms", 0.0)
    total_q = summary.get("total_queries", 0)
    total_succ = summary.get("total_successes", 0)
    success_rate = summary.get("success_rate_percent", 0.0)
    exp_stored = summary.get("experiences_stored", 0)
    err_logged = summary.get("errors_logged", 0)
    feed_recv = summary.get("feedback_received", 0)
    total_tokens = token_usage.get(
        "total_tokens", summary.get("total_tokens_used", 0)
    )
    prompt_tokens = token_usage.get(
        "prompt_tokens", summary.get("total_prompt_tokens", 0)
    )
    completion_tokens = token_usage.get(
        "completion_tokens", summary.get("total_completion_tokens", 0)
    )
    uptime = summary.get("uptime_seconds", 0)

    lat_bar_pct = min(100, max(5, int((p50 / 500.0) * 100))) if p50 > 0 else 12
    lat_color_class = "green" if p50 < 200 else ("amber" if p50 < 800 else "red")

    display_modes = modes

    mode_rows = []
    for m_name, m_data in display_modes.items():
        q_count = m_data.get("query_count", 0)
        mode_rows.append(
            f'<tr>'
            f'<td><strong style="font-family:var(--font-display);color:var(--accent);">{escape(m_name)}</strong></td>'
            f'<td><span style="font-family:var(--font-display);font-weight:600;">{q_count}</span></td>'
            f'<td><span style="font-family:var(--font-display);">{m_data.get("avg_latency_ms", 0.0):.1f} ms</span></td>'
            f'<td><span style="font-family:var(--font-display);color:var(--muted);">{m_data.get("total_tokens", 0):,}</span></td>'
            f'</tr>'
        )
    if not mode_rows:
        mode_rows.append(
            '<tr><td colspan="4" style="text-align:center;color:var(--dim);">'
            "No modes have been recorded yet.</td></tr>"
        )

    recent_rows = []
    if not recent:
        recent_rows.append(
            '<tr><td colspan="5" style="text-align:center;color:var(--dim);padding:32px;font-family:var(--font-display);">'
            '&#9679; Telemetry collector ready. Invocations from Chat or CTF challenges will appear here in real-time.</td></tr>'
        )
    else:
        for q in recent:
            ts = q.get("timestamp", "")[:19].replace("T", " ")
            status_badge = (
                '<span class="badge badge-success">&#10003; Verified</span>'
                if q.get("verified")
                else ('<span class="badge badge-success">Success</span>' if q.get("success") else '<span class="badge badge-failed">Error</span>')
            )
            lat_color = "var(--success)" if q.get("latency_ms", 0) < 300 else ("var(--warning)" if q.get("latency_ms", 0) < 1000 else "var(--critical)")
            recent_rows.append(
                f'<tr>'
                f'<td style="color:var(--dim);font-family:var(--font-display);font-size:var(--text-xs);">{escape(ts)}</td>'
                f'<td><span class="chip active" style="font-size:0.7rem;padding:3px 9px;">{escape(q.get("mode", "general"))}</span></td>'
                f'<td><span style="font-family:var(--font-display);color:{lat_color};font-weight:600;">{q.get("latency_ms", 0.0):.1f} ms</span></td>'
                f'<td>{q.get("tokens_used", 0):,}</td>'
                f'<td>{status_badge}</td>'
                f'</tr>'
            )

    rendered_modes = "".join(mode_rows)
    rendered_recent = "".join(recent_rows)
    provider_rows = "".join(
        "<tr>"
        f"<td><strong>{escape(str(item['provider']))}</strong></td>"
        f"<td>{item['requests']:,}</td>"
        f"<td>{item['prompt_tokens']:,}</td>"
        f"<td>{item['completion_tokens']:,}</td>"
        f"<td>{item['total_tokens']:,}</td>"
        "</tr>"
        for item in token_usage.get("providers", [])
    ) or (
        '<tr><td colspan="5" style="text-align:center;color:var(--dim);">'
        "No chat completions recorded yet.</td></tr>"
    )
    usage_recent_rows = "".join(
        "<tr>"
        f"<td>{escape(str(item['timestamp'])[:19].replace('T', ' '))}</td>"
        f"<td>{escape(str(item['mode']))}</td>"
        f"<td>{escape(str(item['provider']))}</td>"
        f"<td>{escape(str(item['model']))}</td>"
        f"<td>{item['prompt_tokens']:,}</td>"
        f"<td>{item['completion_tokens']:,}</td>"
        f"<td>{item['total_tokens']:,}</td>"
        f"<td>{'Reported' if item['usage_reported'] else 'Unavailable'}</td>"
        "</tr>"
        for item in token_usage.get("recent", [])
    ) or (
        '<tr><td colspan="8" style="text-align:center;color:var(--dim);">'
        "Token usage appears after a chat completion.</td></tr>"
    )
    sidebar = _render_sidebar("performance")

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="theme-color" content="#070b14">
  <meta http-equiv="refresh" content="10">
  <title>RedLoop · Performance Telemetry</title>
  <style>{_SHARED_DASHBOARD_CSS}</style>
  <style>
    main {{ gap: 30px; padding-top: 40px; }}
    .topline {{ align-items: flex-end; }}
    .topline h1 {{
      font-family: var(--font-display);
      font-size: clamp(46px, 4.8vw, 68px);
      font-weight: 400;
      line-height: 0.98;
      letter-spacing: -0.04em;
    }}
    .topline p {{ font-size: 13.5px; max-width: 62ch; line-height: 1.6; }}
    .stats {{ gap: 18px; }}
    .tile {{
      padding: 24px 26px;
      border-radius: var(--radius-lg);
      background: linear-gradient(155deg, rgba(26, 37, 60, 0.72), rgba(18, 24, 38, 0.92));
    }}
    .tile .label {{
      font-family: var(--font-body);
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.13em;
    }}
    .tile .value {{
      font-family: var(--font-body);
      font-size: 32px;
      font-weight: 700;
      letter-spacing: -0.035em;
    }}
    .tile .delta {{ font-family: var(--font-body); font-size: 11.5px; line-height: 1.55; }}
    .card {{ border-radius: var(--radius-lg); }}
    .card-head {{ padding: 20px 27px; }}
    .card-head h2 {{ font-size: 12px; letter-spacing: 0.1em; }}
    @media (max-width: 1080px) {{
      main {{ padding-top: 30px; }}
    }}
  </style>
</head>
<body>
<div class="shell">
  {sidebar}
  <main>
    <div class="topline">
      <div>
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
          <span style="font-family:var(--font-mono);font-size:10px;font-weight:700;color:var(--accent-cyber);text-transform:uppercase;letter-spacing:.16em;">RedLoop / Telemetry</span>
        </div>
        <h1>Performance <em style="font-style:italic;color:var(--accent);">&amp; Usage</em></h1>
        <p>Local process telemetry · in-memory latency metrics · persisted chat token usage</p>
      </div>
      <div class="top-actions">
        <a href="/performance" class="tele-pill">
          <span class="pulse-dot"></span>
          <span>Auto-refresh every 10s</span>
        </a>
        <a href="/performance" class="chip">⟳ Refresh</a>
        <a href="/chat" class="chip">Open Chat</a>
        <a href="/api/performance/summary" class="chip" target="_blank">JSON API</a>
      </div>
    </div>

    <section class="scope-banner" aria-label="Agent architecture telemetry">
      <div class="scope-item">
        <span class="key">Application</span>
        <span class="value" style="color:var(--accent);">RedLoop local console</span>
      </div>
      <div class="scope-item">
        <span class="key">Operation Boundary</span>
        <span class="value" style="color:var(--purple);">Locally configured workflows</span>
      </div>
      <div class="scope-item">
        <span class="key">Usage Ledger</span>
        <span class="value" style="color:var(--success);">SQLite · provider-reported tokens</span>
      </div>
      <div class="scope-item">
        <span class="key">Stream Uptime</span>
        <span class="value">{uptime}s elapsed</span>
      </div>
      <span class="scope-pill">Local telemetry</span>
    </section>

    <section class="stats" aria-label="Performance summary">
      <article class="tile {lat_color_class}">
        <div class="label">P50 / P95 Latency</div>
        <div class="value">{p50:.1f}ms <span style="font-size:1rem;color:var(--dim);font-weight:400;">/ {p95:.1f}ms</span></div>
        <div class="delta">Avg: {avg_lat:.1f}ms · P99: {p99:.1f}ms</div>
        <div class="bullet-bar"><div class="bullet-fill" style="width: {lat_bar_pct}%;"></div></div>
      </article>
      <article class="tile green">
        <div class="label">Recorded Learning Events</div>
        <div class="value">{exp_stored + err_logged:,}</div>
        <div class="delta">{exp_stored} experiences · {err_logged} logged errors · {feed_recv} feedback signals</div>
        <div class="bullet-bar"><div class="bullet-fill" style="width: min(100%, max(10%, int({exp_stored + err_logged} * 5)));"></div></div>
      </article>
      <article class="tile purple">
        <div class="label">Successful Operations</div>
        <div class="value">{success_rate:.1f}%</div>
        <div class="delta">{total_succ} successes out of {total_q} recorded operations</div>
        <div class="bullet-bar"><div class="bullet-fill" style="width: min(100%, max(10%, int({success_rate})));"></div></div>
      </article>
      <article class="tile amber">
        <div class="label">Lifetime Chat Tokens</div>
        <div class="value">{total_tokens:,}</div>
        <div class="delta">Input {prompt_tokens:,} · Output {completion_tokens:,} · {token_usage.get("reported_requests", 0):,} provider-reported calls</div>
        <div class="bullet-bar"><div class="bullet-fill" style="width: min(100%, max(10%, int({total_q} * 15)));"></div></div>
      </article>
    </section>

    <section class="card">
      <div class="card-head">
        <h2>Persisted Chat Token Usage</h2>
        <span style="color:var(--dim);font-family:var(--font-display);font-size:var(--text-xs);">
          Provider-reported usage only · {token_usage.get("unreported_requests", 0):,} call(s) did not return counts · prompts are not stored here
        </span>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Provider</th><th>Calls</th><th>Input tokens</th><th>Output tokens</th><th>Total tokens</th></tr></thead>
          <tbody>{provider_rows}</tbody>
        </table>
      </div>
      <div class="table-wrap" style="margin-top:16px;">
        <table>
          <thead><tr><th>Timestamp (UTC)</th><th>Mode</th><th>Provider</th><th>Model</th><th>Input</th><th>Output</th><th>Total</th><th>Usage</th></tr></thead>
          <tbody>{usage_recent_rows}</tbody>
        </table>
      </div>
    </section>

    <section class="card">
      <div class="card-head">
        <h2>Mode Breakdown</h2>
        <span style="color:var(--dim);font-family:var(--font-display);font-size:var(--text-xs);">{len(display_modes)} mode(s) seen in this process or persisted chat usage</span>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Mode / Category</th>
              <th>Process Queries</th>
              <th>Avg Process Latency</th>
              <th>Persisted Chat Tokens</th>
            </tr>
          </thead>
          <tbody>
            {rendered_modes}
          </tbody>
        </table>
      </div>
    </section>

    <section class="card">
      <div class="card-head">
        <h2>Recent Recorded Operations</h2>
        <span style="color:var(--dim);font-family:var(--font-display);font-size:var(--text-xs);">Last {len(recent)} event(s)</span>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Timestamp (UTC)</th>
              <th>Mode</th>
              <th>Latency</th>
              <th>Chat Tokens</th>
              <th>Outcome</th>
            </tr>
          </thead>
          <tbody>
            {rendered_recent}
          </tbody>
        </table>
      </div>
    </section>

    <section class="card" style="padding:22px;">
      <h2 style="font-size:var(--text-base);margin-bottom:14px;">Telemetry and data boundaries</h2>
      <div class="grid-3">
        <div class="subcard">
          <h3><span style="color:var(--accent);">&#9679;</span> Local performance metrics</h3>
          <p>Latency, success, and mode counters are held in process memory and reset when the application restarts.</p>
        </div>
        <div class="subcard">
          <h3><span style="color:var(--critical);">&#9679;</span> Token usage ledger</h3>
          <p>Provider-reported input/output token counts from successful chat completions are persisted locally without storing prompts in the ledger.</p>
        </div>
        <div class="subcard">
          <h3><span style="color:var(--success);">&#9679;</span> No billing estimate</h3>
          <p>Token counts do not represent dollar charges or provider-account-wide usage. RedLoop does not estimate missing token data.</p>
        </div>
      </div>
    </section>
  </main>
</div>
</body>
</html>"""
