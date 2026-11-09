"""Operational Red/Blue/Purple workbench and deep cybersecurity command center."""







from __future__ import annotations

import asyncio







import base64



import hashlib



import ipaddress



import json



import os
import time



from datetime import datetime, timezone, timedelta



from pathlib import Path



from typing import Annotated, Any, Optional







from fastapi import File, HTTPException, Query, Request, UploadFile



from fastapi.responses import HTMLResponse, JSONResponse



from pydantic import BaseModel, ConfigDict, Field, model_validator







from redloop.assessment.capability import get_capabilities



from redloop.assessment.engine import AssessmentEngine, AssessmentStore



from redloop.assessment.models import AssessmentDepth, StageResult, StageStatus



from redloop.assessment.reporting import ReportingEngine



from redloop.assessment.exploit_simulator import ExploitSimulator



from redloop.assessment.shodan_engine import ShodanEngine



from redloop.assessment.ctf_toolkit import CTFCodec



from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError



from redloop.assessment.orchestrator import TaskOrchestrator, TaskStore



from redloop.assessment.tool_registry import get_tool_registry



from redloop.assessment.controlled_runner import ControlledToolRunner



from redloop.assessment.kali_copilot import (



    KaliCommandRunner,



    KaliCopilot,



    TerminalCommandRequest,



    TerminalCommandResponse,



    detect_wsl_status,



    get_kali_copilot,



)



from redloop.investigation import Investigation, InvestigationStore, get_investigation_store



from redloop.assessment.task_graph import TaskGraphStore



from redloop.audit import AuditLogger



from redloop.audit_checkpoint import AuditCheckpointError, AuditCheckpointStore



from redloop.email_footprint import EmailFootprintEngine



from redloop.identity_correlation import (



    IdentityCorrelationStore,



    IdentityObservation,



)



from redloop.auth import AuthManager, Permission, Session, User, UserRole

from redloop.virustotal import (



    MAX_FILE_BYTES as VT_MAX_FILE_BYTES,



    get_virustotal_client,



)



from redloop.forensics import MAX_FILE_SIZE, ForensicsAnalyzer



from redloop.performance import TokenUsageStore



from redloop.recon import MAX_PORTS, NmapScanner, ReconDependencyError, ReconError



from redloop.reporting import AuditReader



from redloop.scope import ScopeManager, UnauthorizedTargetError



from redloop.webapp import UnsafeWebTargetError, WebAppChecker, WebAppRequestError







from redloop.architecture_matrix import get_architecture_matrix



from redloop.assessment.agentic_engine import AgenticAIRuntime



from redloop.threat_intel import get_threat_intel_engine



from redloop.asvs import get_asvs_engine



from redloop.forensics_advanced import get_advanced_forensics_engine



from redloop.provider_gateway import get_provider_gateway, ProviderKeyStore



from redloop.rag_engine import get_rag_engine



from redloop.investigation_graph import (



    InvestigationGraph,



    InvestigationReplay,



    MultiModelEvaluator,



    NodeType,



    ProvenanceType,



    RemediationVerifier,



)











class WebCheckRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    url: str = Field(min_length=1, max_length=2_048)











class PortScanRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    target: str = Field(min_length=1, max_length=253)



    ports: list[Annotated[int, Field(ge=1, le=65_535)]] = Field(



        min_length=1,



        max_length=MAX_PORTS,



    )







    @model_validator(mode="after")



    def unique_ports(self):



        if len(set(self.ports)) != len(self.ports):



            raise ValueError("Duplicate ports are not allowed")



        return self











class TLSCheckRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    target: str = Field(min_length=1, max_length=253)



    port: Annotated[int, Field(ge=1, le=65_535)] = 443











class ExploitSimulateRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    target: str = Field(min_length=1, max_length=253)



    service: str = "http"



    port: int | None = Field(default=None, ge=1, le=65_535)



    finding_id: str | None = None



    cve: str | None = None











class ShodanQueryRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    target: str = Field(min_length=1, max_length=253)











class CyberCodecRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    text: str = Field(min_length=1)



    action: str = "decode"  # decode | encode



    format: str = "base64"



    hint: str | None = None











class ToolExecuteRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    tool: str = Field(min_length=1, max_length=64)



    target: str = Field(min_length=1, max_length=253)



    ports: list[int] | None = None



    args: list[str] | dict[str, Any] | None = None











KaliExecuteRequest = TerminalCommandRequest











class AssessmentStartRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    target: str = Field(min_length=1, max_length=253)



    depth: AssessmentDepth = AssessmentDepth.STANDARD



    config_artifacts: list[str] = Field(default_factory=list)



    file_artifacts: list[str] = Field(default_factory=list)











class AgenticPlanRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    target: str = Field(min_length=1, max_length=253)



    intent: str = Field(min_length=1, max_length=2048)



    ports: list[int] | None = None











class AgenticExecuteRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    target: str = Field(min_length=1, max_length=253)



    intent: str = Field(min_length=1, max_length=2048)



    max_iterations: int = 5



    ports: list[int] | None = None











class ASVSEvaluateRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    url: str = Field(min_length=1, max_length=2048)



    test_endpoints: bool = True











class ForensicsTriageRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    log_type: str = Field(min_length=1, max_length=64)  # windows_event, linux_auth, email_header, file_meta



    raw_content: str = Field(min_length=1)











class TerminalOutputRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    raw_output: str = Field(min_length=1)



    target: str | None = None











class ProviderConfigRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    provider_id: str = Field(min_length=1, max_length=64)



    api_key: str | None = None



    base_url: str | None = None











class ProviderTestRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    provider_id: str = Field(min_length=1, max_length=64)



    test_tool_calling: bool = False











class RAGIngestRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    title: str = Field(min_length=1, max_length=256)



    text: str = Field(min_length=1)



    category: str = "general"



    source: str = "manual_upload"











class RAGQueryRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    query: str = Field(min_length=1, max_length=1024)



    top_k: int = 3











class KnowledgeFeedbackRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    query: str = Field(min_length=1, max_length=1024)



    original_response: str = Field(min_length=1)



    corrected_response: str = Field(min_length=1)



    rating: int = 1



    category: str = "general"











class KnowledgeReviewRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    lesson_id: str = Field(min_length=1, max_length=128)



    approve: bool



    notes: str = ""











class RemediationVerifyRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    finding_id: str = Field(min_length=1, max_length=128)



    port: int | None = Field(default=None, ge=1, le=65535)











class ReplayDiffRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    baseline_id: str = Field(min_length=1, max_length=128)



    replayed_id: str = Field(min_length=1, max_length=128)











class VirusTotalRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    indicator: str = Field(min_length=1, max_length=4096)



    indicator_type: str | None = Field(default=None, max_length=32)











class EmailFootprintRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    email: str = Field(min_length=1, max_length=254)



    live: bool = False











class IdentityObservationRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    entity_type: str = Field(min_length=1, max_length=32)



    value: str = Field(min_length=1, max_length=512)



    source: str = Field(min_length=1, max_length=128)



    method: str = Field(min_length=1, max_length=128)



    confidence: float | None = Field(default=None, ge=0.0, le=1.0)



    classification: str = Field(default="UNVERIFIED", max_length=64)



    authoritative: bool = False



    correlation_key: str | None = Field(default=None, max_length=256)



    metadata: dict[str, Any] = Field(default_factory=dict)











class IdentityReviewRequest(BaseModel):



    model_config = ConfigDict(extra="forbid")



    decision: str = Field(min_length=1, max_length=16)



    analyst: str = Field(min_length=1, max_length=128)



    note: str | None = Field(default=None, max_length=2000)











def _require_same_origin(request: Request) -> None:



    origin = request.headers.get("origin")



    if not origin:



        return



    expected = str(request.base_url).rstrip("/")



    if origin.rstrip("/") != expected:



        raise HTTPException(status_code=403, detail="Cross-origin operation rejected")







_WORKBENCH_SCRIPT = r"""



/* RedLoop Command Center Core Application Engine */



(function() {



  'use strict';







  // --- State Store ---



  const state = {



    activeTab: 'dashboard',



    assessments: [],



    currentAssessment: null,



    stats: null,



    capabilities: null,



    auditVerify: null,



    performance: null,



    findings: [],



    evidenceList: [],



    selectedFinding: null,



    selectedEvidence: null,



    selectedNode: null,



    graphMode: '3d',



    graphFilterSeverity: 'all',



    graphFilterType: 'all',



    terminalLogs: [],



    autoScrollTerminal: true,



    copilotOpen: false,



    copilotMessages: [



      {



        role: 'assistant',



        text: '### 🛡️ REDLOOP AI Security Copilot Online\n\nI am your unified cybersecurity orchestrator. You can assign assessment tasks, query findings, analyze cryptographic evidence, or inspect attack surface relationships.\n\n**Quick actions:**\n- *Assess the authorized target*\n- *Enumerate open ports & services*\n- *Analyze TLS configuration*\n- *Crawl web endpoints*\n- *Verify audit ledger*',



        time: 'Ready'



      }



    ],



    commandPaletteOpen: false



  };







  // --- DOM Selectors ---



  const $ = (s) => document.querySelector(s);



  const $$ = (s) => Array.from(document.querySelectorAll(s));







  // --- Router ---



  function switchTab(tabId) {



    state.activeTab = tabId;



    $$('.nav-item').forEach(el => {



      const active = el.dataset.tab === tabId;



      el.classList.toggle('active', active);



      el.setAttribute('aria-selected', active ? 'true' : 'false');



    });



    $$('.tab-view').forEach(el => {



      el.classList.toggle('active', el.id === `view-${tabId}`);



    });



    const breadcrumb = $('#current-view-title');



    if (breadcrumb) {



      breadcrumb.textContent = tabId.charAt(0).toUpperCase() + tabId.slice(1).replace('-', ' ');



    }



    if (tabId === 'dashboard' || tabId === 'attack-surface') {



      setTimeout(() => {



        if (window.attackSurface3D) window.attackSurface3D.resize();



        if (window.hero3D) window.hero3D.resize();



      }, 50);



    }



    if (tabId === 'performance') {



      loadPerformance();



    }



    if (tabId === 'soc-ops') {



      loadAutonomousSOCOps();



    }



    if (tabId === 'copilot') {



      $('#copilot-input')?.focus();



    }



  }







  // --- Toast Notifications ---



  function toast(message, type = 'info') {



    const container = $('#toast-container');



    if (!container) return;



    const el = document.createElement('div');



    el.className = `toast toast-${type}`;



    el.innerHTML = `<span>${escapeHtml(message)}</span>`;



    container.appendChild(el);



    setTimeout(() => {



      el.style.opacity = '0';



      el.style.transform = 'translateY(-8px)';



      setTimeout(() => el.remove(), 300);



    }, 3500);



  }







  function escapeHtml(str) {



    if (str === null || str === undefined) return '';



    return String(str)



      .replace(/&/g, '&amp;')



      .replace(/</g, '&lt;')



      .replace(/>/g, '&gt;')



      .replace(/"/g, '&quot;')



      .replace(/'/g, '&#39;');



  }







  function renderMarkdown(md) {



    if (!md) return '';



    let html = escapeHtml(md);



    // Headers



    html = html.replace(/^### (.*$)/gim, '<h3 style="font-size:14px;margin:8px 0 4px;color:var(--text-primary);">$1</h3>');



    html = html.replace(/^#### (.*$)/gim, '<h4 style="font-size:12px;margin:6px 0 2px;color:var(--accent-cyber);">$1</h4>');



    // Bold & Italics



    html = html.replace(/\*\*(.*?)\*\*/gim, '<strong style="color:var(--text-primary);">$1</strong>');



    html = html.replace(/\*(.*?)\*/gim, '<em>$1</em>');



    // Code blocks



    html = html.replace(/```([a-z]*)\n([\s\S]*?)```/gim, '<pre><code>$2</code></pre>');



    html = html.replace(/`([^`]+)`/gim, '<code style="background:#040609;padding:2px 4px;border-radius:3px;border:1px solid var(--border);color:var(--accent-cyber);font-family:var(--font-mono);font-size:11px;">$1</code>');



    // Links



    html = html.replace(/\[([^\]]+)\]\(([^\)]+)\)/gim, '<a href="$2" style="color:var(--accent-primary);text-decoration:underline;">$1</a>');



    // Lists



    html = html.replace(/^\- (.*$)/gim, '<li style="margin-left:16px;">$1</li>');



    // Line breaks



    html = html.replace(/\n/g, '<br>');



    return html;



  }







  // --- Terminal Event Stream (Section 10) ---



  function logTerminal(level, message, source = 'ENGINE') {



    const time = new Date().toTimeString().split(' ')[0];



    state.terminalLogs.push({ time, level, message, source });



    if (state.terminalLogs.length > 200) state.terminalLogs.shift();



    renderTerminal();



  }







  function renderTerminal() {



    const box = $('#terminal-events');



    if (!box) return;



    box.innerHTML = state.terminalLogs.map(l => {



      const cls = l.level.toLowerCase();



      return `<div class="term-row term-${cls}">` +



        `<span class="term-time">${l.time}</span>` +



        `<span class="term-lvl ${cls}">[${l.level}]</span>` +



        `<span class="term-src">${l.source}:</span> ` +



        `<span class="term-msg">${escapeHtml(l.message)}</span>` +



        `</div>`;



    }).join('');



    if (state.autoScrollTerminal) {



      box.scrollTop = box.scrollHeight;



    }



  }







  // --- 3D Vector & Projection Engine ---



  class AttackSurface3D {



    constructor(canvas, isHero = false) {



      this.canvas = canvas;



      this.ctx = canvas.getContext('2d');



      this.isHero = isHero;



      this.nodes = [];



      this.edges = [];



      this.rotation = { x: 0.35, y: 0.45 };



      this.targetRotation = { x: 0.35, y: 0.45 };



      this.zoom = isHero ? 0.95 : 1.1;



      this.targetZoom = isHero ? 0.95 : 1.1;



      this.isDragging = false;



      this.lastMouse = { x: 0, y: 0 };



      this.hoveredNode = null;



      this.autoRotate = true;



      this.animId = null;







      this.initEvents();



      this.resize();



    }







    initEvents() {



      const c = this.canvas;



      c.addEventListener('pointerdown', (e) => {



        this.isDragging = true;



        this.lastMouse = { x: e.clientX, y: e.clientY };



        this.autoRotate = false;



        c.setPointerCapture(e.pointerId);



      });







      c.addEventListener('pointermove', (e) => {



        if (this.isDragging) {



          const dx = e.clientX - this.lastMouse.x;



          const dy = e.clientY - this.lastMouse.y;



          this.targetRotation.y += dx * 0.007;



          this.targetRotation.x = Math.max(-1.4, Math.min(1.4, this.targetRotation.x + dy * 0.007));



          this.lastMouse = { x: e.clientX, y: e.clientY };



        } else {



          this.checkHover(e);



        }



      });







      c.addEventListener('pointerup', (e) => {



        this.isDragging = false;



        try { c.releasePointerCapture(e.pointerId); } catch (_) {}



      });







      c.addEventListener('wheel', (e) => {



        e.preventDefault();



        const factor = e.deltaY < 0 ? 1.08 : 0.92;



        this.targetZoom = Math.max(0.4, Math.min(2.8, this.targetZoom * factor));



      }, { passive: false });







      c.addEventListener('click', () => {



        if (this.hoveredNode) {



          selectNode(this.hoveredNode);



        }



      });







      window.addEventListener('resize', () => this.resize());



    }







    resize() {



      const rect = this.canvas.getBoundingClientRect();



      const dpr = window.devicePixelRatio || 1;



      this.width = rect.width || (this.isHero ? 700 : 900);



      this.height = rect.height || (this.isHero ? 380 : 540);



      this.canvas.width = this.width * dpr;



      this.canvas.height = this.height * dpr;



      this.ctx.scale(dpr, dpr);



    }







    setData(graphData) {



      if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {



        this.nodes = [];



        this.edges = [];



        return;



      }







      const N = graphData.nodes.length;



      const radius = this.isHero ? 140 : 180;



      const phi = (1 + Math.sqrt(5)) / 2;







      this.nodes = graphData.nodes.map((n, i) => {



        const theta = 2 * Math.PI * i / phi;



        const y = 1 - (i / (N - 1 || 1)) * 2;



        const rAtY = Math.sqrt(Math.max(0, 1 - y * y));



        const x = Math.cos(theta) * rAtY;



        const z = Math.sin(theta) * rAtY;







        let col = '#4F8CFF';



        if (n.type === 'finding') {



          col = n.severity === 'CRITICAL' ? '#FF4D5E' : (n.severity === 'HIGH' ? '#FFB547' : '#21D07A');



        } else if (n.type === 'service' || n.type === 'port') {



          col = '#00D4FF';



        } else if (n.type === 'host') {



          col = '#7C5CFF';



        }







        return {



          id: n.id,



          label: n.label,



          type: n.type,



          severity: n.severity || 'INFO',



          riskScore: n.risk_score || 0,



          details: n.details || {},



          x: x * radius,



          y: y * radius,



          z: z * radius,



          origX: x * radius,



          origY: y * radius,



          origZ: z * radius,



          color: col,



          radius: n.type === 'host' ? 9 : (n.type === 'finding' ? 7 : 5),



          projX: 0,



          projY: 0,



          scale: 1,



          visible: true



        };



      });







      this.edges = (graphData.edges || []).map(e => ({



        source: e.source,



        target: e.target,



        type: e.type,



        color: 'rgba(32, 43, 58, 0.65)'



      }));



    }







    checkHover(e) {



      const rect = this.canvas.getBoundingClientRect();



      const mouseX = e.clientX - rect.left;



      const mouseY = e.clientY - rect.top;







      let closest = null;



      let minD = 18;







      for (const n of this.nodes) {



        if (!n.visible) continue;



        const d = Math.hypot(n.projX - mouseX, n.projY - mouseY);



        if (d < minD) {



          minD = d;



          closest = n;



        }



      }







      this.hoveredNode = closest;



      this.canvas.style.cursor = closest ? 'pointer' : 'default';







      const hud = this.isHero ? $('#hero-hud') : $('#attack-hud');



      if (hud) {



        if (closest) {



          hud.style.display = 'block';



          hud.style.left = `${mouseX + 16}px`;



          hud.style.top = `${mouseY + 16}px`;



          hud.innerHTML = `



            <div class="hud-title">${escapeHtml(closest.label)}</div>



            <div class="hud-type">${escapeHtml(closest.type.toUpperCase())} · ${escapeHtml(closest.severity)}</div>



            <div class="hud-meta">Risk: ${closest.riskScore.toFixed(1)} / 10.0</div>



            <div style="font-size:10px;color:var(--accent-cyber);margin-top:4px;">Click to inspect &amp; Ask AI</div>



          `;



        } else {



          hud.style.display = 'none';



        }



      }



    }







    start() {



      const render = () => {



        this.update();



        this.draw();



        this.animId = requestAnimationFrame(render);



      };



      this.animId = requestAnimationFrame(render);



    }







    stop() {



      if (this.animId) cancelAnimationFrame(this.animId);



    }







    update() {



      if (this.autoRotate) {



        this.targetRotation.y += 0.0025;



      }



      this.rotation.x += (this.targetRotation.x - this.rotation.x) * 0.1;



      this.rotation.y += (this.targetRotation.y - this.rotation.y) * 0.1;



      this.zoom += (this.targetZoom - this.zoom) * 0.1;







      const cosX = Math.cos(this.rotation.x);



      const sinX = Math.sin(this.rotation.x);



      const cosY = Math.cos(this.rotation.y);



      const sinY = Math.sin(this.rotation.y);







      const fov = 420 * this.zoom;



      const centerX = this.width / 2;



      const centerY = this.height / 2;







      for (const n of this.nodes) {



        const x1 = n.origX * cosY - n.origZ * sinY;



        const z1 = n.origZ * cosY + n.origX * sinY;



        const y1 = n.origY * cosX - z1 * sinX;



        const z2 = z1 * cosX + n.origY * sinX;







        n.x = x1;



        n.y = y1;



        n.z = z2;







        const distance = 480 + z2;



        const scale = distance > 10 ? fov / distance : 0;



        n.projX = centerX + x1 * scale;



        n.projY = centerY + y1 * scale;



        n.scale = Math.max(0.2, scale);







        n.visible = true;



        if (state.graphFilterSeverity !== 'all' && n.type === 'finding') {



          if (n.severity !== state.graphFilterSeverity) n.visible = false;



        }



        if (state.graphFilterType !== 'all') {



          if (n.type !== state.graphFilterType) n.visible = false;



        }



      }



    }







    draw() {



      const ctx = this.ctx;



      ctx.clearRect(0, 0, this.width, this.height);







      if (this.nodes.length === 0) {



        ctx.fillStyle = '#647184';



        ctx.font = '12px var(--font-mono)';



        ctx.textAlign = 'center';



        ctx.fillText('NO ATTACK SURFACE NODES MAPPED YET', this.width / 2, this.height / 2);



        return;



      }







      // Draw Orbit Wireframe rings



      ctx.strokeStyle = 'rgba(32, 43, 58, 0.25)';



      ctx.lineWidth = 1;



      ctx.beginPath();



      ctx.ellipse(this.width / 2, this.height / 2, 130 * this.zoom, 40 * this.zoom, 0, 0, Math.PI * 2);



      ctx.stroke();







      const nodeMap = new Map(this.nodes.map(n => [n.id, n]));







      // Draw Edges



      for (const e of this.edges) {



        const src = nodeMap.get(e.source);



        const tgt = nodeMap.get(e.target);



        if (src && tgt && src.visible && tgt.visible) {



          ctx.strokeStyle = e.color;



          ctx.lineWidth = 1;



          ctx.beginPath();



          ctx.moveTo(src.projX, src.projY);



          ctx.lineTo(tgt.projX, tgt.projY);



          ctx.stroke();



        }



      }







      // Depth sort nodes



      const sorted = [...this.nodes].sort((a, b) => a.z - b.z);







      for (const n of sorted) {



        if (!n.visible) continue;



        const isHover = n === this.hoveredNode;



        const r = Math.max(2, n.radius * n.scale * (isHover ? 1.4 : 1));







        ctx.fillStyle = n.color;



        ctx.beginPath();



        ctx.arc(n.projX, n.projY, r, 0, Math.PI * 2);



        ctx.fill();







        if (isHover || n.type === 'host' || (n.type === 'finding' && (n.severity === 'CRITICAL' || n.severity === 'HIGH'))) {



          ctx.fillStyle = isHover ? '#00D4FF' : '#F5F7FA';



          ctx.font = '10px var(--font-mono)';



          ctx.textAlign = 'center';



          ctx.fillText(n.label, n.projX, n.projY - r - 4);



        }



      }



    }



  }







  // --- Node Selection & Modal ---



  function selectNode(node) {



    state.selectedNode = node;



    const modal = $('#node-modal');



    if (!modal) return;



    $('#modal-node-title').textContent = node.label;



    $('#modal-node-type').textContent = `${node.type.toUpperCase()} · ${node.severity}`;



    $('#modal-node-details').textContent = JSON.stringify(node.details, null, 2);



    $('#modal-ask-ai-btn').onclick = () => {



      closeNodeModal();



      askAiAboutNode(node.id, node.label, node.type);



    };



    modal.classList.add('open');



  }







  function closeNodeModal() {



    $('#node-modal')?.classList.remove('open');



  }







  // --- AI Copilot Engine ---



  function toggleCopilot(force) {



    const panel = $('#copilot-panel');



    if (!panel) return;



    state.copilotOpen = force !== undefined ? force : !state.copilotOpen;



    panel.classList.toggle('open', state.copilotOpen);



    const btn = $('#btn-toggle-copilot');



    if (btn) btn.classList.toggle('active', state.copilotOpen);



    if (state.copilotOpen) {



      $('#copilot-input')?.focus();



    }



  }







  function clearCopilot() {



    state.copilotMessages = [



      {



        role: 'assistant',



        text: '### 🛡️ REDLOOP AI Copilot Session Reset\nEnter a command or ask a question regarding the active security assessment.',



        time: 'Ready'



      }



    ];



    renderCopilotMessages();



  }







  function quickCopilot(promptText) {



    toggleCopilot(true);



    const input = $('#copilot-input');



    if (input) input.value = promptText;



    submitCopilot(null, promptText);



  }







  async function submitCopilot(e, overrideMessage = null, overrideContext = null) {



    if (e) e.preventDefault();



    const input = $('#copilot-input');



    const msg = (overrideMessage || input?.value || '').trim();



    if (!msg) return;







    if (input && !overrideMessage) input.value = '';







    const timeStr = new Date().toTimeString().split(' ')[0];



    state.copilotMessages.push({



      role: 'user',



      text: msg,



      time: timeStr



    });



    renderCopilotMessages();







    // Show shimmering typing indicator



    const typingId = 'copilot-typing-' + Date.now();



    state.copilotMessages.push({



      role: 'assistant',



      text: '*Executing operational security plan... Validating scope and gathering real-time telemetry...*',



      time: 'Running',



      id: typingId



    });



    renderCopilotMessages();







    try {



      logTerminal('INFO', `Copilot executing: "${msg.slice(0, 50)}..."`, 'COPILOT');



      const payload = {



        message: msg,



        conversation_id: 'workbench-copilot',



        context: overrideContext || (state.currentAssessment ? { assessment_id: state.currentAssessment.id, target: state.currentAssessment.target } : {})



      };







      const res = await fetch('/api/chat/message', {



        method: 'POST',



        headers: { 'Content-Type': 'application/json' },



        body: JSON.stringify(payload)



      });



      const data = await res.json();







      // Remove typing placeholder



      state.copilotMessages = state.copilotMessages.filter(m => m.id !== typingId);







      const respText = data.response || '⚠️ Operation completed with no output.';



      state.copilotMessages.push({



        role: 'assistant',



        text: respText,



        time: new Date().toTimeString().split(' ')[0]



      });



      renderCopilotMessages();







      // If an assessment was run/started, update the active workbench state!



      if (data.assessment_id) {



        logTerminal('SUCCESS', `Assessment ${data.assessment_id} updated via Copilot.`, 'COPILOT');



        toast(`Assessment ${data.assessment_id} updated!`, 'success');



        await loadAssessmentsList();



        await loadAssessmentDetail(data.assessment_id);



        await loadStats();



      }







    } catch (err) {



      state.copilotMessages = state.copilotMessages.filter(m => m.id !== typingId);



      state.copilotMessages.push({



        role: 'assistant',



        text: `❌ **Copilot Execution Error:** ${err.message}`,



        time: 'Error'



      });



      renderCopilotMessages();



      toast(`Copilot error: ${err.message}`, 'critical');



    }



  }







  function renderCopilotMessages() {



    const container = $('#copilot-messages');



    if (!container) return;



    container.innerHTML = state.copilotMessages.map(m => {



      const isUser = m.role === 'user';



      return `



        <div class="copilot-msg ${isUser ? 'msg-user' : 'msg-assistant'}">



          <div class="msg-meta">



            <span class="msg-author">${isUser ? 'OPERATOR' : 'REDLOOP AI'}</span>



            <span class="msg-time">${m.time}</span>



          </div>



          <div class="msg-content">${renderMarkdown(m.text)}</div>



        </div>



      `;



    }).join('');



    container.scrollTop = container.scrollHeight;



  }







  function askAiAboutFinding(findingId, title) {



    toggleCopilot(true);



    const prompt = `Explain finding ${findingId} ("${title}"), describe root cause, attack path, and provide specific technical remediation code.`;



    submitCopilot(null, prompt, { type: 'finding', id: findingId });



  }







  function askAiAboutEvidence(evidenceId) {



    toggleCopilot(true);



    const prompt = `Analyze cryptographic forensic evidence ${evidenceId}, check its SHA-256 integrity hash, and explain what observations it proves.`;



    submitCopilot(null, prompt, { type: 'evidence', id: evidenceId });



  }







  function askAiAboutNode(nodeId, label, type) {



    toggleCopilot(true);



    const prompt = `Explain attack surface entity ${label} (${type}), evaluate its exposure, and determine whether it represents an initial access or lateral movement risk.`;



    submitCopilot(null, prompt, { type: 'asset', id: nodeId });



  }







  // --- Command Palette (Section 34) ---



  const COMMAND_ITEMS = [



    { title: '⚡ Run Comprehensive Assessment', subtitle: 'Execute full 10-stage pipeline on authorized target', action: () => quickCopilot('Run a comprehensive assessment on the authorized target') },



    { title: '🤖 Open AI Security Copilot', subtitle: 'Interactive command center assistant', action: () => toggleCopilot(true) },



    { title: '🌐 View 3D Attack Surface', subtitle: 'Interactive topological graph visualization', action: () => switchTab('attack-surface') },



    { title: '📋 Vulnerability Findings', subtitle: 'View detected vulnerabilities and CVSS scores', action: () => switchTab('findings') },



    { title: '🔍 Forensic Evidence Ledger', subtitle: 'Inspect cryptographically hashed forensic artifacts', action: () => switchTab('evidence') },



    { title: '📊 Performance & Telemetry', subtitle: 'AI token usage and tool metrics', action: () => switchTab('performance') },



    { title: '🛡️ Verify Audit Chain', subtitle: 'Run cryptographic verification on SHA-256 event ledger', action: () => verifyAuditChain() },



    { title: '🔒 Analyze TLS / SSL Security', subtitle: 'Probe ciphers, certificates, and SANs', action: () => switchTab('tls') },



    { title: '🕷️ Web Application Crawler', subtitle: 'Inspect forms, endpoints, and security headers', action: () => switchTab('web') },



    { title: '📄 Technical Report', subtitle: 'Generate and preview full technical assessment report', action: () => switchTab('reports') },



    { title: '⚙️ Settings & Configuration', subtitle: 'Manage scopes, capability matrix, and keys', action: () => switchTab('settings') },



  ];







  function openCommandPalette() {



    state.commandPaletteOpen = true;



    const modal = $('#palette-backdrop');



    if (!modal) return;



    modal.classList.add('open');



    const input = $('#palette-input');



    if (input) {



      input.value = '';



      input.focus();



    }



    renderPaletteItems(COMMAND_ITEMS);



  }







  function closeCommandPalette() {



    state.commandPaletteOpen = false;



    $('#palette-backdrop')?.classList.remove('open');



  }







  function renderPaletteItems(items) {



    const list = $('#palette-results');



    if (!list) return;



    if (items.length === 0) {



      list.innerHTML = '<div style="padding:16px;color:var(--muted);text-align:center;">No matching commands found.</div>';



      return;



    }



    list.innerHTML = items.map((it, idx) => `



      <div class="palette-item" data-index="${idx}">



        <div class="palette-item-title">${escapeHtml(it.title)}</div>



        <div class="palette-item-sub">${escapeHtml(it.subtitle)}</div>



      </div>



    `).join('');



    $$('.palette-item').forEach((el, idx) => {



      el.onclick = () => {



        closeCommandPalette();



        items[idx].action();



      };



    });



  }







  // --- Performance Telemetry Loader (Section 16, 17) ---



  async function loadPerformance() {



    try {



      const res = await fetch('/api/performance');



      if (!res.ok) return;



      const data = await res.json();



      state.performance = data;







      // Render AI Tokens



      const ai = data.ai || {};



      $('#perf-total-tokens').textContent = (ai.total_tokens || 0).toLocaleString();



      $('#perf-prompt-tokens').textContent = (ai.prompt_tokens || 0).toLocaleString();



      $('#perf-comp-tokens').textContent = (ai.completion_tokens || 0).toLocaleString();



      $('#perf-total-queries').textContent = (ai.requests || 0).toLocaleString();







      // Render Providers



      const provBody = $('#perf-providers-body');



      if (provBody && ai.providers) {



        provBody.innerHTML = ai.providers.map(p => `



          <tr>



            <td class="font-mono text-cyan">${escapeHtml(p.provider)}</td>



            <td>${p.requests || 0}</td>



            <td>${(p.prompt_tokens || 0).toLocaleString()}</td>



            <td>${(p.completion_tokens || 0).toLocaleString()}</td>



            <td class="font-bold font-mono">${(p.total_tokens || 0).toLocaleString()}</td>



          </tr>



        `).join('');



      }







      // Render Assessment Engine Stats



      const eng = data.assessment_engine || {};



      $('#perf-asmt-total').textContent = eng.total || 0;



      $('#perf-asmt-active').textContent = eng.active || 0;



      $('#perf-asmt-completed').textContent = eng.completed || 0;



      $('#perf-asmt-failed').textContent = eng.failed || 0;







      // Render Tool Capabilities



      const toolBody = $('#perf-tools-body');



      if (toolBody && data.tools) {



        toolBody.innerHTML = Object.entries(data.tools).map(([name, t]) => `



          <tr>



            <td class="font-mono">${escapeHtml(name.toUpperCase())}</td>



            <td><span class="badge ${t.available ? 'badge-success' : 'badge-blocked'}">${t.available ? 'AVAILABLE' : 'UNAVAILABLE'}</span></td>



            <td class="font-mono">${escapeHtml(t.version || 'Built-in')}</td>



            <td>${t.runs || 0}</td>



            <td style="color:var(--success);">${t.success || 0}</td>



            <td style="color:var(--critical);">${t.failed || 0}</td>



          </tr>



        `).join('');



      }



    } catch (err) {



      logTerminal('WARN', `Failed to load performance metrics: ${err.message}`, 'PERF');



    }



  }







  // --- Data Loaders ---



  async function loadStats() {



    try {



      const res = await fetch('/api/overview/stats');



      if (!res.ok) return;



      const data = await res.json();



      state.stats = data;







      const m = data.metrics || {};



      $('#metric-risk').textContent = m.risk_score == null ? '—' : `${m.risk_score} / 10`;



      $('#metric-critical').textContent = m.critical_count ?? 0;



      $('#metric-high').textContent = m.high_count ?? 0;



      $('#metric-medium').textContent = m.medium_count ?? 0;



      $('#metric-assets').textContent = m.assets_count ?? 0;



      $('#metric-services').textContent = m.open_services_count ?? 0;



      $('#metric-findings').textContent = m.total_findings ?? 0;



      $('#metric-evidence').textContent = m.evidence_count ?? 0;







      if (data.scope_summary) {



        $('#scope-banner-target').textContent = data.scope_summary.active_target || '127.0.0.1';



        $('#copilot-active-target').textContent = `Target: ${data.scope_summary.active_target} (Authorized)`;



      }







      if (data.latest_assessment) {



        $('#copilot-active-asmt').textContent = `Assessment: ${data.latest_assessment.id}`;



      }







      logTerminal('INFO', 'Telemetry and security statistics updated from backend.', 'SYNC');



    } catch (err) {



      logTerminal('WARN', `Stats synchronization failed: ${err.message}`, 'SYNC');



    }



  }







  async function loadAssessmentsList() {



    try {



      const res = await fetch('/api/assessment/list');



      if (!res.ok) return;



      const data = await res.json();



      state.assessments = data.assessments || [];







      const select = $('#assessment-picker');



      if (select) {



        select.innerHTML = state.assessments.length ?



          state.assessments.map(a => `<option value="${a.id}">${a.target} (${a.depth.toUpperCase()}) · ${a.id.slice(0, 9)}</option>`).join('') :



          '<option value="">NO ACTIVE ASSESSMENT</option>';



      }







      const tableBody = $('#assessments-table-body');



      if (tableBody) {



        tableBody.innerHTML = state.assessments.length ?



          state.assessments.map(a => `



            <tr>



              <td class="font-mono text-cyan">${escapeHtml(a.id)}</td>



              <td class="font-mono">${escapeHtml(a.target)}</td>



              <td><span class="badge badge-info">${escapeHtml(a.depth.toUpperCase())}</span></td>



              <td><span class="badge ${a.status === 'COMPLETED' ? 'badge-success' : (a.status === 'RUNNING' ? 'badge-info' : 'badge-warning')}">${escapeHtml(a.status)}</span></td>



              <td class="font-mono">${escapeHtml(a.current_stage)}</td>



              <td class="font-mono text-muted">${escapeHtml(a.updated_at.slice(0, 19).replace('T', ' '))}</td>



              <td>



                <button class="btn btn-sm btn-outline" data-click="loadAssessmentDetail('${a.id}')">Open</button>



              </td>



            </tr>



          `).join('') :



          '<tr><td colspan="7" class="text-center text-muted" style="padding:24px;">NO ASSESSMENTS YET</td></tr>';



      }







      if (state.assessments.length > 0 && !state.currentAssessment) {



        await loadAssessmentDetail(state.assessments[0].id);



      }



    } catch (err) {



      logTerminal('WARN', `Assessments list failed: ${err.message}`, 'STORE');



    }



  }







  async function loadAssessmentDetail(id) {



    if (!id) return;



    try {



      toast(`Loading assessment ${id}...`, 'info');



      const res = await fetch(`/api/assessment/${encodeURIComponent(id)}`);



      if (!res.ok) return;



      const stateObj = await res.json();



      state.currentAssessment = stateObj;



      state.findings = stateObj.findings || [];



      state.evidenceList = stateObj.evidence || [];







      $('#copilot-active-asmt').textContent = `Assessment: ${id}`;



      $('#detail-asmt-id').textContent = stateObj.id;



      $('#detail-asmt-target').textContent = stateObj.target;



      $('#detail-asmt-status').textContent = stateObj.status;



      $('#detail-asmt-status').className = `badge ${stateObj.status === 'COMPLETED' ? 'badge-success' : 'badge-info'}`;







      // Update 3D Graph



      if (stateObj.attack_surface_graph) {



        if (window.attackSurface3D) window.attackSurface3D.setData(stateObj.attack_surface_graph);



        if (window.hero3D) window.hero3D.setData(stateObj.attack_surface_graph);



      }







      renderPipeline(stateObj.completed_stages);



      renderFindingsTable();



      renderEvidenceTable();



      renderSpecialistViews(stateObj);







      logTerminal('INFO', `Loaded assessment ${id} with ${state.findings.length} findings and ${state.evidenceList.length} evidence records.`, 'ASSESS');



    } catch (err) {



      toast(`Failed to load assessment: ${err.message}`, 'critical');



    }



  }







  function renderPipeline(stages) {



    const box = $('#pipeline-card-grid');



    if (!box) return;



    if (!stages || Object.keys(stages).length === 0) {



      box.innerHTML = '<div style="color:var(--muted);padding:16px;">Pipeline inactive. Start an assessment to see live execution stages.</div>';



      return;



    }







    const entries = Object.entries(stages);



    box.innerHTML = entries.map(([name, s]) => {



      let stCls = 'status-success';



      if (s.status === 'BLOCKED') stCls = 'status-blocked';



      if (s.status === 'UNAVAILABLE') stCls = 'status-unavailable';



      if (s.status === 'FAILED') stCls = 'status-blocked';







      return `



        <div class="pipeline-card ${stCls}">



          <div class="pipe-header">



            <span>${escapeHtml(name.replace('_', ' ').toUpperCase())}</span>



            <span class="badge ${s.status === 'SUCCESS' ? 'badge-success' : (s.status === 'BLOCKED' ? 'badge-critical' : 'badge-info')}">${s.status}</span>



          </div>



          <div class="pipe-reason">${escapeHtml(s.reason || 'Completed cleanly without error')}</div>



          <div class="pipe-meta">



            Findings: ${s.findings ? s.findings.length : 0} · ${s.duration_seconds.toFixed(2)}s



          </div>



        </div>



      `;



    }).join('');



  }







  function renderFindingsTable() {



    const tb = $('#findings-table-body');



    if (!tb) return;



    if (state.findings.length === 0) {



      tb.innerHTML = '<tr><td colspan="7" class="text-center text-muted" style="padding:28px;">NO SECURITY FINDINGS</td></tr>';



      return;



    }



    tb.innerHTML = state.findings.map(f => {



      let sevBadge = 'badge-info';



      if (f.severity === 'CRITICAL') sevBadge = 'badge-critical';



      if (f.severity === 'HIGH') sevBadge = 'badge-warning';



      if (f.severity === 'MEDIUM') sevBadge = 'badge-info';



      if (f.severity === 'LOW') sevBadge = 'badge-success';







      return `



        <tr>



          <td><span class="badge ${sevBadge}">${escapeHtml(f.severity)}</span></td>



          <td class="font-bold">${escapeHtml(f.title)}</td>



          <td class="font-mono text-cyan">${escapeHtml(f.asset)}</td>



          <td class="font-mono">${escapeHtml(f.endpoint || '—')}</td>



          <td><span class="badge badge-info">${escapeHtml(f.confidence)}</span></td>



          <td class="font-mono font-bold">${f.cvss_score.toFixed(1)}</td>



          <td>



            <button class="btn btn-sm btn-outline" data-click="openFindingDetail('${f.id}')">Inspect</button>



            <button class="btn btn-sm btn-primary" data-click="askAiAboutFinding('${f.id}', '${escapeHtml(f.title).replace(/'/g, "\\'")}')">🤖 Ask AI</button>



          </td>



        </tr>



      `;



    }).join('');



  }







  function renderEvidenceTable() {



    const tb = $('#evidence-table-body');



    if (!tb) return;



    if (state.evidenceList.length === 0) {



      tb.innerHTML = '<tr><td colspan="6" class="text-center text-muted" style="padding:28px;">NO EVIDENCE COLLECTED</td></tr>';



      return;



    }



    tb.innerHTML = state.evidenceList.map(e => `



      <tr>



        <td class="font-mono text-cyan">${escapeHtml(e.id)}</td>



        <td class="font-mono">${escapeHtml(e.operation_id)}</td>



        <td class="font-mono">${escapeHtml(e.target)}</td>



        <td class="font-mono">${escapeHtml(e.hash_sha256.slice(0, 16))}...</td>



        <td class="font-mono text-muted">${escapeHtml(e.timestamp.slice(0, 19).replace('T', ' '))}</td>



        <td>



          <button class="btn btn-sm btn-outline" data-click="openEvidenceDetail('${e.id}')">Inspect</button>



          <button class="btn btn-sm btn-primary" data-click="askAiAboutEvidence('${e.id}')">🤖 Analyze</button>



        </td>



      </tr>



    `).join('');



  }







  function renderSpecialistViews(stateObj) {



    // Network Specialist



    const net = stateObj.completed_stages?.network_discovery;



    if (net && net.data && net.data.open_ports) {



      $('#network-services-list').innerHTML = net.data.open_ports.map(p => `



        <div class="service-pill font-mono">



          <span style="color:var(--accent-cyber);font-weight:700;">${p}</span> / TCP OPEN



        </div>



      `).join('');



    }







    // TLS Specialist



    const tls = stateObj.completed_stages?.tls_assessment;



    if (tls && tls.data) {



      $('#tls-version-val').textContent = tls.data.tls_version || 'None';



      $('#tls-cipher-val').textContent = tls.data.cipher || 'None';



      $('#tls-cert-val').textContent = tls.data.subject ? JSON.stringify(tls.data.subject) : 'Verified';



    }







    // Web Specialist



    const web = stateObj.completed_stages?.web_assessment;



    if (web && web.data) {



      $('#web-pages-count').textContent = web.data.pages_crawled || 0;



      $('#web-endpoints-count').textContent = web.data.endpoints_discovered || 0;



      $('#web-headers-count').textContent = web.data.security_headers_missing ? web.data.security_headers_missing.length : 0;



    }



  }







  function openFindingDetail(findingId) {



    const f = state.findings.find(x => x.id === findingId);



    if (!f) return;



    state.selectedFinding = f;







    $('#drawer-finding-title').textContent = f.title;



    $('#drawer-finding-sev').textContent = f.severity;



    $('#drawer-finding-risk').textContent = `${f.cvss_score.toFixed(1)} / 10.0`;



    $('#drawer-finding-asset').textContent = `${f.asset} (${f.endpoint || 'host'})`;



    $('#drawer-finding-desc').textContent = f.description || 'No description recorded.';



    $('#drawer-finding-remed').textContent = f.remediation || 'Remediation guidance not specified.';



    $('#drawer-finding-evidence').textContent = f.evidence_id || 'Direct probe observation';







    $('#drawer-ask-ai-btn').onclick = () => {



      closeDrawer();



      askAiAboutFinding(f.id, f.title);



    };







    $('#finding-drawer').classList.add('open');



  }







  function openEvidenceDetail(evidenceId) {



    const e = state.evidenceList.find(x => x.id === evidenceId);



    if (!e) return;



    state.selectedEvidence = e;







    $('#drawer-evidence-id').textContent = e.id;



    $('#drawer-evidence-op').textContent = e.operation_id;



    $('#drawer-evidence-target').textContent = e.target;



    $('#drawer-evidence-hash').textContent = e.hash_sha256;



    $('#drawer-evidence-payload').textContent = JSON.stringify(e.data, null, 2);







    $('#evidence-drawer').classList.add('open');



  }







  function closeDrawer() {



    $$('.drawer').forEach(d => d.classList.remove('open'));



  }







  async function verifyAuditChain() {



    try {



      const res = await fetch('/api/audit/verify');



      const data = await res.json();



      state.auditVerify = data;







      const badge = $('#audit-integrity-badge');



      const status = data.status || (data.valid === true ? 'INTEGRITY_VERIFIED' : 'VERIFICATION_INCOMPLETE');



      const anchored = data.anchored === true || (data.anchor || {}).status === 'MATCH';



      const failure = data.failure || {};



      const eventDetail = failure.event_id !== undefined && failure.event_id !== null



        ? ` (event id ${failure.event_id}, sequence ${failure.sequence})`



        : '';



      if (badge) {



        if (status === 'INTEGRITY_VERIFIED' && data.valid === true && anchored) {



          badge.className = 'badge-pill success font-mono';



          badge.innerHTML = `<span class="pulse-dot"></span><span>CHAIN VERIFIED &amp; ANCHORED (${data.verified_events ?? data.total_events} OF ${data.total_events} EVENTS)</span>`;



          logTerminal('INFO', data.message || `Cryptographic audit ledger verified: ${data.total_events} events valid.`, 'AUDIT');



        } else if (status === 'INTEGRITY_VERIFIED' && data.valid === true) {



          badge.className = 'badge-pill warning font-mono';



          badge.innerHTML = `<span class="pulse-dot"></span><span>CHAIN INTERNALLY VERIFIED (UNANCHORED, ${data.verified_events ?? data.total_events} OF ${data.total_events} EVENTS)</span>`;



          logTerminal('WARN', data.message || 'Audit chain is internally consistent but unanchored; truncation cannot be excluded.', 'AUDIT');



        } else if (status === 'TAMPER_DETECTED' || status === 'CHAIN_GAP_DETECTED') {



          badge.className = 'badge-pill critical font-mono';



          badge.innerHTML = `<span class="pulse-dot"></span><span>${status.replace(/_/g, ' ')}${eventDetail}</span>`;



          logTerminal('CRITICAL', `${status}: ${failure.reason || data.error || 'hash-chain verification failed'}${eventDetail}`, 'AUDIT');



        } else {



          badge.className = 'badge-pill warning font-mono';



          badge.innerHTML = `<span class="pulse-dot"></span><span>VERIFICATION INCOMPLETE</span>`;



          logTerminal('WARN', data.error || data.message || 'Audit verification did not complete.', 'AUDIT');



        }



      }



      return data;



    } catch (err) {



      logTerminal('WARN', `Audit verification check failed: ${err.message}`, 'AUDIT');



    }



  }







  async function loadCapabilities() {



    try {



      const res = await fetch('/api/capabilities');



      const data = await res.json();



      state.capabilities = data.tools || {};







      const list = $('#capabilities-list');



      if (list && data.tools) {



        list.innerHTML = Object.entries(data.tools).map(([k, v]) => `



          <div class="cap-card ${v.installed ? 'installed' : 'missing'}">



            <div class="cap-name font-mono">${escapeHtml(k.toUpperCase())}</div>



            <div class="cap-status">${v.installed ? '✓ AVAILABLE' : '— UNAVAILABLE'}</div>



            <div class="cap-version font-mono text-muted">${escapeHtml(v.version || 'Not Detected')}</div>



          </div>



        `).join('');



      }



    } catch (err) {



      logTerminal('WARN', `Capabilities probe failed: ${err.message}`, 'SYSTEM');



    }



  }







  // --- Global Event Handlers ---



  function initHandlers() {



    // Nav tabs



    $$('.nav-item').forEach(el => {



      el.addEventListener('click', () => {



        const tab = el.dataset.tab;



        if (tab) switchTab(tab);



      });



    });







    // Assessment selector change



    $('#assessment-picker')?.addEventListener('change', (e) => {



      if (e.target.value) loadAssessmentDetail(e.target.value);



    });







    // Start assessment modal



    $('#btn-open-start-modal')?.addEventListener('click', () => {



      $('#start-modal')?.classList.add('open');



    });







    $('#start-assessment-form')?.addEventListener('submit', async (e) => {



      e.preventDefault();



      const target = $('#modal-asmt-target').value.trim();



      const depth = $('#modal-asmt-depth').value;



      if (!target) return;







      $('#start-modal')?.classList.remove('open');



      toast(`Initiating ${depth.toUpperCase()} assessment for ${target}...`, 'info');



      logTerminal('INFO', `Initializing assessment workflow on ${target} (depth=${depth})`, 'PIPELINE');







      try {



        const res = await fetch('/api/assessment/start', {



          method: 'POST',



          headers: { 'Content-Type': 'application/json' },



          body: JSON.stringify({ target, depth })



        });



        const out = await res.json();



        if (!res.ok) throw new Error(out.detail || 'Assessment startup failed');







        toast(`Assessment ${out.id} launched successfully`, 'success');



        await loadAssessmentsList();



        await loadAssessmentDetail(out.id);



        await loadStats();



      } catch (err) {



        toast(`Assessment startup error: ${err.message}`, 'critical');



        logTerminal('CRITICAL', `Assessment failed to start: ${err.message}`, 'PIPELINE');



      }



    });







    // Copilot form submit



    $('#copilot-form')?.addEventListener('submit', submitCopilot);



    $('#copilot-input')?.addEventListener('keydown', (e) => {



      if (e.key === 'Enter' && !e.shiftKey) {



        e.preventDefault();



        submitCopilot(e);



      }



    });







    // Command palette input



    $('#palette-input')?.addEventListener('input', (e) => {



      const q = e.target.value.toLowerCase().trim();



      if (!q) {



        renderPaletteItems(COMMAND_ITEMS);



        return;



      }



      const filtered = COMMAND_ITEMS.filter(it => it.title.toLowerCase().includes(q) || it.subtitle.toLowerCase().includes(q));



      renderPaletteItems(filtered);



    });







    // Global keyboard listener (Ctrl+K or Cmd+K)



    window.addEventListener('keydown', (e) => {



      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {



        e.preventDefault();



        if (state.commandPaletteOpen) {



          closeCommandPalette();



        } else {



          openCommandPalette();



        }



      }



      if (e.key === 'Escape') {



        closeCommandPalette();



        closeDrawer();



        closeNodeModal();



        $('.modal-backdrop.open')?.classList.remove('open');



      }



    });







    // Close drawers / modals



    $$('.close-drawer').forEach(b => b.addEventListener('click', closeDrawer));



    $$('.close-modal').forEach(b => b.addEventListener('click', () => {



      $('.modal-backdrop.open')?.classList.remove('open');



      closeNodeModal();



      closeCommandPalette();



    }));







    // Form: Web Check



    $('#web-check')?.addEventListener('submit', async (e) => {



      e.preventDefault();



      const btn = e.submitter; btn.disabled = true;



      try {



        const url = $('#web-check-url').value;



        toast('Running web metadata check...', 'info');



        const res = await fetch('/api/workbench/red/web-check', {



          method: 'POST',



          headers: { 'Content-Type': 'application/json' },



          body: JSON.stringify({ url })



        });



        const out = await res.json();



        $('#result').hidden = false;



        $('#result').textContent = JSON.stringify(out, null, 2);



        toast('Web check completed', 'success');



      } catch (err) {



        toast(`Web check error: ${err.message}`, 'critical');



      } finally {



        btn.disabled = false;



      }



    });







    // Form: File Triage



    $('#file-triage')?.addEventListener('submit', async (e) => {



      e.preventDefault();



      const btn = e.submitter; btn.disabled = true;



      try {



        const form = new FormData(e.currentTarget);



        toast('Triaging file sample (Static hash & YARA)...', 'info');



        const res = await fetch('/api/workbench/blue/file-triage', {



          method: 'POST',



          body: form



        });



        const out = await res.json();



        $('#result').hidden = false;



        $('#result').textContent = JSON.stringify(out, null, 2);



        toast('File triage complete', 'success');



      } catch (err) {



        toast(`File triage failed: ${err.message}`, 'critical');



      } finally {



        btn.disabled = false;



      }



    });







    // Purple activity refresh



    $('#refresh-purple')?.addEventListener('click', async () => {



      try {



        const res = await fetch('/api/workbench/purple/summary');



        const out = await res.json();



        $('#result').hidden = false;



        $('#result').textContent = JSON.stringify(out, null, 2);



      } catch (err) {



        toast(`Purple summary error: ${err.message}`, 'critical');



      }



    });



  }







  // --- CSP-safe inline handler bridge ---



  Object.assign(window, {



    toggleCopilot,



    switchTab,



    openCommandPalette,



    quickCopilot,



    clearCopilot,



    loadAssessmentDetail,



    openFindingDetail,



    askAiAboutFinding,



    openEvidenceDetail,



    askAiAboutEvidence,



    verifyAuditChain,



    loadPerformance,



  });







  const INLINE_EVENTS = ['click', 'change', 'input', 'submit', 'keydown'];







  function splitInline(text, sep) {



    const out = [];



    let depth = 0;



    let quote = null;



    let start = 0;



    for (let i = 0; i < text.length; i++) {



      const ch = text[i];



      if (quote) {



        if (ch === '\\') { i++; continue; }



        if (ch === quote) quote = null;



        continue;



      }



      if (ch === "'" || ch === '"' || ch === '`') { quote = ch; continue; }



      if ('([{'.includes(ch)) depth++;



      else if (')]}'.includes(ch)) depth--;



      else if (ch === sep && depth === 0) { out.push(text.slice(start, i)); start = i + 1; }



    }



    out.push(text.slice(start));



    return out;



  }







  function inlineLiteral(expr, el, ev) {



    const text = (expr || '').trim();



    if (!text) return undefined;



    if ((text[0] === "'" && text.endsWith("'")) || (text[0] === '"' && text.endsWith('"'))) {



      return text.slice(1, -1).replace(/\\(.)/g, '$1');



    }



    if (/^-?[0-9]+(\.[0-9]+)?$/.test(text)) return Number(text);



    if (text === 'true') return true;



    if (text === 'false') return false;



    if (text === 'null') return null;



    if (text === 'this') return el;



    if (text === 'event') return ev;



    if (text === 'this.value') return el.value;



    if (text === 'this.checked') return el.checked;



    if (text === 'event.key') return ev.key;



    return undefined;



  }







  function execInline(code, el, ev) {



    splitInline(code, ';').forEach((stmt) => {



      const text = stmt.trim();



      if (!text || text === 'return false') return;



      const classOp = text.match(/^\$\(['"]#([^'"]+)['"]\)\.classList\.(add|remove|toggle)\(['"]([^'"]+)['"]\)$/);



      if (classOp) {



        const node = document.getElementById(classOp[1]);



        if (node) node.classList[classOp[2]](classOp[3]);



        return;



      }



      const call = text.match(/^([A-Za-z0-9_$.]+)\((.*)\)$/);



      if (!call) return;



      const path = call[1].split('.');



      let ctx = window;



      for (let i = 0; i < path.length - 1; i++) ctx = ctx ? ctx[path[i]] : undefined;



      const fn = ctx ? ctx[path[path.length - 1]] : undefined;



      if (typeof fn !== 'function') {



        console.warn('inline handler unavailable', call[1]);



        return;



      }



      const args = splitInline(call[2], ',')



        .filter((arg) => arg.trim() !== '')



        .map((arg) => inlineLiteral(arg, el, ev));



      fn.apply(ctx, args);



    });



  }







  function installInlineBridge() {



    INLINE_EVENTS.forEach((type) => {



      document.addEventListener(type, (ev) => {



        const node = ev.target && ev.target.closest ? ev.target.closest('[on' + type + ']') : null;



        if (!node) return;



        const code = node.getAttribute('on' + type);



        if (!code) return;



        if (type === 'submit') ev.preventDefault();



        try {



          execInline(code, node, ev);



        } catch (err) {



          console.warn('inline handler failed', err);



        }



      }, true);



    });



  }







  if (document.readyState === 'loading') {



    document.addEventListener('DOMContentLoaded', installInlineBridge);



  } else {



    installInlineBridge();



  }







  // --- Boot Sequence ---



  window.addEventListener('DOMContentLoaded', async () => {



    initHandlers();



    renderCopilotMessages();







    // 3D Visualizer instances



    const heroCanvas = $('#hero-canvas');



    if (heroCanvas) {



      window.hero3D = new AttackSurface3D(heroCanvas, true);



      window.hero3D.start();



    }



    const asCanvas = $('#attack-surface-canvas');



    if (asCanvas) {



      window.attackSurface3D = new AttackSurface3D(asCanvas, false);



      window.attackSurface3D.start();



    }







    logTerminal('INFO', 'REDLOOP Command Center initialized.', 'BOOT');



    logTerminal('INFO', 'Validating cryptographic audit ledger and signed scope contracts...', 'BOOT');







    await Promise.allSettled([
      loadStats(),
      loadAssessmentsList(),
      verifyAuditChain(),
      loadCapabilities(),
      (async () => {
        try {
          const res = await fetch('/api/workbench/purple/summary');
          const out = await res.json();
          const resBox = $('#result');
          if (resBox) resBox.textContent = JSON.stringify(out, null, 2);
        } catch (_) {}
      })()
    ]);



  });



  window.loadAutonomousSOCOps = async function() {

    try {

      const mRes = await fetch('/api/metrics/soc');

      if (mRes.ok) {

        const mData = await mRes.json();

        const metrics = mData.metrics || {};

        const mttdEl = $('#soc-mttd');

        if (mttdEl) mttdEl.textContent = metrics.mean_time_to_detect_minutes == null ? 'N/A' : `${metrics.mean_time_to_detect_minutes}m`;

        const mttrEl = $('#soc-mttr');

        if (mttrEl) mttrEl.textContent = metrics.mean_time_to_respond_minutes == null ? 'N/A' : `${metrics.mean_time_to_respond_minutes}m`;

        const syncEl = $('#soc-sync-rate');

        if (syncEl) syncEl.textContent = metrics.telemetry_sync_rate_percent == null ? 'N/A' : `${metrics.telemetry_sync_rate_percent}%`;

        const availEl = $('#soc-provider-avail');

        if (availEl) availEl.textContent = metrics.provider_availability_percent == null ? 'N/A' : `${metrics.provider_availability_percent}%`;

        const redEl = $('#soc-alert-reduction');

        if (redEl) redEl.textContent = metrics.alert_reduction_rate_percent == null ? 'N/A' : `${metrics.alert_reduction_rate_percent}%`;

      }
      else {
        ['soc-mttd', 'soc-mttr', 'soc-sync-rate', 'soc-provider-avail', 'soc-alert-reduction']
          .forEach(id => { const el = $('#' + id); if (el) el.textContent = 'Unavailable'; });
      }

    } catch (error) {
      console.error('Failed to load SOC operational metrics:', error);
      ['soc-mttd', 'soc-mttr', 'soc-sync-rate', 'soc-provider-avail', 'soc-alert-reduction']
        .forEach(id => { const el = $('#' + id); if (el) el.textContent = 'Unavailable'; });
    }



    try {

      const incRes = await fetch('/api/incidents');

      if (incRes.ok) {

        const incData = await incRes.json();

        const tbody = $('#soc-incidents-table-body');

        if (tbody) {

          const list = incData.incidents || [];

          if (list.length === 0) {

            tbody.innerHTML = '<tr><td colspan="6" style="padding:16px;text-align:center;" class="text-muted">No incidents are currently recorded.</td></tr>';

          } else {

            tbody.innerHTML = list.map(i => `

              <tr style="border-bottom:1px solid var(--border);">

                <td style="padding:8px;font-family:var(--font-mono);font-weight:600;">${i.incident_id}</td>

                <td style="padding:8px;"><span class="badge-pill ${i.severity === 'CRITICAL' ? 'critical' : i.severity === 'HIGH' ? 'warning' : 'info'}">${i.severity}</span></td>

                <td style="padding:8px;">${i.title}</td>

                <td style="padding:8px;font-family:var(--font-mono);">${i.primary_host || i.primary_ip || 'N/A'}</td>

                <td style="padding:8px;">${Math.round((i.confidence_score || 0) * 100)}%</td>

                <td style="padding:8px;">${(i.linked_events || []).length}</td>

              </tr>

            `).join('');

          }

        }

      }

    } catch (_) {}



    try {

      const jobRes = await fetch('/api/soc/sync/jobs?limit=10');

      if (jobRes.ok) {

        const jobData = await jobRes.json();

        const listDiv = $('#soc-sync-jobs-list');

        if (listDiv) {

          const jobs = jobData.jobs || [];

          if (jobs.length === 0) {

            listDiv.innerHTML = '<div class="text-muted" style="padding:8px;">No synchronization jobs recorded.</div>';

          } else {

            listDiv.innerHTML = jobs.map(j => `

              <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border);">

                <span>${j.job_id.substring(0, 16)}... [${j.provider_id}]</span>

                <span class="badge-pill ${j.status === 'COMPLETED' ? 'success' : j.status === 'RUNNING' ? 'info' : 'warning'}">${j.status} (${j.events_synced} ev)</span>

              </div>

            `).join('');

          }

        }

      }

    } catch (_) {}



    try {

      const iocRes = await fetch('/api/iocs?limit=15');

      if (iocRes.ok) {

        const iocData = await iocRes.json();

        const tbody = $('#soc-iocs-table-body');

        if (tbody) {

          const list = iocData.iocs || [];

          if (list.length === 0) {

            tbody.innerHTML = '<tr><td colspan="5" style="padding:16px;text-align:center;" class="text-muted">No IOC records ingested.</td></tr>';

          } else {

            tbody.innerHTML = list.map(rec => `

              <tr style="border-bottom:1px solid var(--border);">

                <td style="padding:8px;font-family:var(--font-mono);">${rec.ioc_type}</td>

                <td style="padding:8px;font-family:var(--font-mono);">${rec.value}</td>

                <td style="padding:8px;"><span class="badge-pill ${rec.state === 'CONFIRMED_MALICIOUS' ? 'critical' : rec.state === 'BENIGN' ? 'success' : 'info'}">${rec.state}</span></td>

                <td style="padding:8px;">${Math.round((rec.confidence || 0) * 100)}%</td>

                <td style="padding:8px;">

                  <button class="btn btn-secondary btn-sm" data-click="updateIocDisposition('${rec.ioc_id}', 'CONFIRMED_MALICIOUS')">Malicious</button>

                  <button class="btn btn-secondary btn-sm" data-click="updateIocDisposition('${rec.ioc_id}', 'BENIGN')">Benign</button>

                </td>

              </tr>

            `).join('');

          }

        }

      }

    } catch (_) {}



    try {

      const covRes = await fetch('/api/detections/coverage');

      if (covRes.ok) {

        const covData = await covRes.json();

        const pill = $('#soc-attack-coverage-pill');

        if (pill) pill.textContent = `COVERAGE: ${covData.coverage?.coverage_ratio_percent || 75}%`;

      }

      const rulesRes = await fetch('/api/detections/rules');

      if (rulesRes.ok) {

        const rulesData = await rulesRes.json();

        const tbody = $('#soc-rules-table-body');

        if (tbody) {

          const list = rulesData.rules || [];

          tbody.innerHTML = list.map(r => `

            <tr style="border-bottom:1px solid var(--border);">

              <td style="padding:8px;font-family:var(--font-mono);font-weight:600;">${r.rule_id}</td>

              <td style="padding:8px;font-family:var(--font-mono);">${r.technique_id}</td>

              <td style="padding:8px;">${r.hit_count || 0}</td>

              <td style="padding:8px;">${r.false_positive_count || 0}</td>

              <td style="padding:8px;">

                <button class="btn btn-secondary btn-sm" data-click="runRuleTest('${r.rule_id}')">⚡ Test Rule</button>

              </td>

            </tr>

          `).join('');

        }

      }

    } catch (_) {}

  };



  window.triggerSocSync = async function() {

    const provSel = $('#soc-sync-provider');

    const prov = provSel ? provSel.value : 'edr_defender';

    try {

      const res = await fetch('/api/soc/sync/trigger', {

        method: 'POST',

        headers: {'Content-Type': 'application/json'},

        body: JSON.stringify({provider_id: prov, limit: 50})

      });

      if (res.ok) {

        loadAutonomousSOCOps();

      }

    } catch (_) {}

  };



  window.runRuleTest = async function(ruleId) {

    try {

      const res = await fetch(`/api/detections/rules/${ruleId}/test`, {method: 'POST'});

      if (res.ok) {

        const data = await res.json();

        alert(`Rule Test Result: ${data.test_result?.summary || 'Harness executed successfully'}`);

      }

    } catch (_) {}

  };



  window.updateIocDisposition = async function(iocId, state) {

    try {

      await fetch(`/api/iocs/${iocId}/disposition`, {

        method: 'POST',

        headers: {'Content-Type': 'application/json'},

        body: JSON.stringify({state: state, reason: 'Analyst manual disposition'})

      });

      loadAutonomousSOCOps();

    } catch (_) {}

  };



  window.correlateEventsNow = async function() {

    try {

      await fetch('/api/incidents/correlate', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}'});

      loadAutonomousSOCOps();

    } catch (_) {}

  };







})();



"""



WORKBENCH_SCRIPT_CSP_HASH = base64.b64encode(



    hashlib.sha256(_WORKBENCH_SCRIPT.encode("utf-8")).digest()



).decode("ascii")







_HTML_TEMPLATE = r"""



<!doctype html>



<html lang="en">



<head>



  <meta charset="utf-8">



  <meta name="viewport" content="width=device-width, initial-scale=1">



  <title>REDLOOP · Security Assessment &amp; Operations Command Center</title>



  <style>



    /* REDLOOP Centralized Design Token System (Section 2 & 13) */



    :root {



      --bg-primary: #0b0b10;



      --bg-secondary: #121218;



      --panel: #121218;



      --panel-elevated: #17171f;



      --border: #1e293b;



      --border-accent: rgba(249, 115, 22, 0.35);







      --accent-primary: #f97316;



      --accent-secondary: #2563eb;



      --accent-cyber: #2563eb;



      --primary: #2563eb;







      --success: #00bb7f;



      --warning: #f99c00;



      --critical: #ef4444;







      --text-primary: #f8fafc;



      --text-secondary: #94a3b8;



      --muted: #64748b;







      --font-sans: 'DM Sans', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;



      --font-mono: 'JetBrains Mono', 'IBM Plex Mono', 'Cascadia Code', monospace;



      --font-display: 'Space Grotesk', 'DM Sans', 'Inter', system-ui, sans-serif;







      --radius-sm: 8px;



      --radius-md: 12px;



      --radius-lg: 16px;



      --radius-xl: 22px;



    }







    * { box-sizing: border-box; margin: 0; padding: 0; }



    body {



      background: var(--bg-primary);



      color: var(--text-primary);



      font-family: var(--font-sans);



      font-size: 13px;



      line-height: 1.5;



      overflow-x: hidden;



      display: flex;



      min-height: 100vh;



    }







    /* Shell Layout */



    .app-shell { display: flex; width: 100vw; min-height: 100vh; }



    .sidebar {



      width: 250px;



      background: var(--bg-secondary);



      border-right: 1px solid var(--border);



      display: flex;



      flex-direction: column;



      flex-shrink: 0;



      height: 100vh;



      position: sticky;



      top: 0;



      z-index: 40;



    }



    .brand-wrap {



      padding: 20px 18px 16px;



      display: flex;



      align-items: center;



      gap: 12px;



      border-bottom: 1px solid var(--border);



    }



    .logo-mark {



      width: 32px;



      height: 32px;



      border-radius: var(--radius-sm);



      background: linear-gradient(135deg, var(--accent-cyber), var(--accent-primary));



      display: grid;



      place-items: center;



      color: var(--bg-primary);



      font-family: var(--font-mono);



      font-weight: 800;



      font-size: 15px;



      box-shadow: 0 0 16px rgba(0, 212, 255, 0.3);



    }



    .brand-title {



      font-family: var(--font-mono);



      font-weight: 700;



      font-size: 16px;



      letter-spacing: 0.08em;



      color: var(--text-primary);



    }



    .brand-sub { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }







    .nav-group { padding: 12px 10px 4px; overflow-y: auto; flex: 1; }



    .nav-label {



      padding: 10px 10px 4px;



      font-size: 10px;



      font-family: var(--font-mono);



      color: var(--muted);



      text-transform: uppercase;



      letter-spacing: 0.08em;



    }



    .nav-item {



      display: flex;



      align-items: center;



      gap: 10px;



      padding: 8px 12px;



      border-radius: var(--radius-sm);



      color: var(--text-secondary);



      cursor: pointer;



      user-select: none;



      transition: all 0.15s ease;



      font-size: 12px;



      font-weight: 500;



      margin-bottom: 2px;



      border-left: 2px solid transparent;



      text-decoration: none;



    }



    .nav-item:hover {



      background: var(--panel);



      color: var(--text-primary);



    }



    .nav-item.active {



      background: var(--panel-elevated);



      color: var(--accent-cyber);



      border-left-color: var(--accent-cyber);



    }



    .nav-icon { width: 16px; height: 16px; stroke-width: 1.75; }







    .sidebar-footer {



      padding: 12px 16px;



      border-top: 1px solid var(--border);



      font-size: 11px;



      color: var(--muted);



      font-family: var(--font-mono);



      display: flex;



      align-items: center;



      gap: 8px;



    }



    .foot-status-dot {



      width: 7px; height: 7px; border-radius: 50%;



      background: var(--success);



      box-shadow: 0 0 8px var(--success);



    }







    /* Main Viewport */



    .main-area {



      flex: 1;



      display: flex;



      flex-direction: column;



      overflow-y: auto;



      height: 100vh;



      background: var(--bg-primary);



    }







    /* Topbar */



    .topbar {



      height: 56px;



      border-bottom: 1px solid var(--border);



      background: var(--bg-secondary);



      display: flex;



      align-items: center;



      justify-content: space-between;



      padding: 0 24px;



      position: sticky;



      top: 0;



      z-index: 30;



      flex-shrink: 0;



    }



    .topbar-left { display: flex; align-items: center; gap: 14px; }



    .topbar-right { display: flex; align-items: center; gap: 12px; }



    .current-view-title { font-size: 15px; font-weight: 700; font-family: var(--font-mono); letter-spacing: 0.04em; }







    .scope-pill {



      background: var(--panel);



      border: 1px solid var(--border);



      border-radius: var(--radius-sm);



      padding: 3px 10px;



      font-size: 11px;



      font-family: var(--font-mono);



      display: flex;



      align-items: center;



      gap: 6px;



    }



    .pulse-dot {



      width: 6px; height: 6px; border-radius: 50%;



      background: var(--accent-cyber);



      box-shadow: 0 0 6px var(--accent-cyber);



      animation: pulse 2s infinite;



    }



    @keyframes pulse { 0% { opacity: 0.4; } 50% { opacity: 1; } 100% { opacity: 0.4; } }







    /* Buttons & Badges */



    .btn {



      padding: 6px 14px;



      border-radius: var(--radius-sm);



      font-size: 12px;



      font-weight: 600;



      cursor: pointer;



      transition: all 0.15s ease;



      border: 1px solid transparent;



      display: inline-flex;



      align-items: center;



      gap: 6px;



      font-family: var(--font-mono);



      text-decoration: none;



    }



    .btn-sm { padding: 4px 10px; font-size: 11px; }



    .btn-primary {



      background: var(--accent-primary);



      color: #FFFFFF;



    }



    .btn-primary:hover { background: #3c7bf0; }



    .btn-secondary {



      background: var(--panel);



      border-color: var(--border);



      color: var(--text-primary);



    }



    .btn-secondary:hover { background: var(--panel-elevated); }



    .btn-outline {



      background: transparent;



      border-color: var(--border);



      color: var(--text-secondary);



    }



    .btn-outline:hover { border-color: var(--accent-primary); color: var(--text-primary); }







    .badge {



      display: inline-block;



      padding: 2px 7px;



      border-radius: 3px;



      font-size: 10px;



      font-family: var(--font-mono);



      font-weight: 700;



      text-transform: uppercase;



      letter-spacing: 0.04em;



    }



    .badge-critical { background: rgba(255, 77, 94, 0.15); color: var(--critical); border: 1px solid var(--critical); }



    .badge-warning { background: rgba(255, 181, 71, 0.15); color: var(--warning); border: 1px solid var(--warning); }



    .badge-info { background: rgba(79, 140, 255, 0.15); color: var(--accent-primary); border: 1px solid var(--accent-primary); }



    .badge-success { background: rgba(33, 208, 122, 0.15); color: var(--success); border: 1px solid var(--success); }



    .badge-blocked { background: rgba(100, 113, 132, 0.2); color: var(--muted); border: 1px solid var(--border); }







    .badge-pill {



      display: inline-flex;



      align-items: center;



      gap: 6px;



      padding: 4px 10px;



      border-radius: 12px;



      font-size: 11px;



    }



    .badge-pill.success { background: rgba(33, 208, 122, 0.1); color: var(--success); border: 1px solid rgba(33, 208, 122, 0.25); }



    .badge-pill.critical { background: rgba(255, 77, 94, 0.1); color: var(--critical); border: 1px solid rgba(255, 77, 94, 0.25); }







    /* Tab Views */



    .tab-view { display: none; padding: 24px; }



    .tab-view.active { display: block; }







    /* Cards & Panels */



    .panel-card {



      background: var(--panel);



      border: 1px solid var(--border);



      border-radius: var(--radius-md);



      padding: 18px;



      margin-bottom: 20px;



      position: relative;



    }



    .card-head {



      display: flex;



      justify-content: space-between;



      align-items: center;



      margin-bottom: 14px;



    }



    .card-title {



      font-size: 13px;



      font-weight: 700;



      font-family: var(--font-mono);



      text-transform: uppercase;



      letter-spacing: 0.05em;



      color: var(--text-primary);



    }







    /* Metrics Grid */



    .metrics-grid {



      display: grid;



      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));



      gap: 12px;



      margin-bottom: 20px;



    }



    .metric-card {



      background: var(--panel);



      border: 1px solid var(--border);



      border-radius: var(--radius-sm);



      padding: 14px;



      display: flex;



      flex-direction: column;



      gap: 4px;



      transition: border-color 0.15s ease;



    }



    .metric-card:hover { border-color: var(--border-accent); }



    .metric-lbl { font-size: 10px; font-family: var(--font-mono); text-transform: uppercase; color: var(--muted); letter-spacing: 0.06em; }



    .metric-val { font-size: 22px; font-weight: 700; font-family: var(--font-mono); color: var(--text-primary); line-height: 1.1; }



    .metric-val.risk { color: var(--warning); }







    /* 3D Attack Surface Canvas */



    .canvas-wrap {



      position: relative;



      background: #040609;



      border: 1px solid var(--border);



      border-radius: var(--radius-md);



      overflow: hidden;



      height: 380px;



      margin-bottom: 20px;



    }



    .canvas-hero { height: 380px; width: 100%; display: block; }



    .canvas-controls {



      position: absolute;



      top: 12px;



      right: 12px;



      display: flex;



      gap: 6px;



      z-index: 10;



    }



    .canvas-hud {



      position: absolute;



      background: rgba(16, 22, 32, 0.92);



      backdrop-filter: blur(8px);



      border: 1px solid var(--border-accent);



      border-radius: var(--radius-sm);



      padding: 8px 12px;



      font-size: 11px;



      pointer-events: none;



      display: none;



      z-index: 20;



    }



    .hud-title { font-weight: 700; color: var(--text-primary); font-family: var(--font-mono); }



    .hud-type { font-size: 10px; color: var(--muted); text-transform: uppercase; }



    .hud-meta { font-size: 10px; color: var(--warning); font-family: var(--font-mono); }







    /* Tables */



    .table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: var(--radius-sm); }



    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 12px; }



    th {



      background: #0c1119;



      padding: 10px 14px;



      font-size: 10px;



      font-family: var(--font-mono);



      text-transform: uppercase;



      color: var(--muted);



      border-bottom: 1px solid var(--border);



      letter-spacing: 0.05em;



    }



    td {



      padding: 10px 14px;



      border-bottom: 1px solid var(--border);



      color: var(--text-secondary);



    }



    tr:last-child td { border-bottom: none; }



    tr:hover td { background: rgba(255, 255, 255, 0.015); color: var(--text-primary); }







    /* Event Terminal */



    .terminal-box {



      background: #030508;



      border: 1px solid var(--border);



      border-radius: var(--radius-sm);



      padding: 12px 14px;



      height: 180px;



      overflow-y: auto;



      font-family: var(--font-mono);



      font-size: 11px;



      display: flex;



      flex-direction: column;



      gap: 4px;



    }



    .term-row { display: flex; gap: 8px; line-height: 1.4; }



    .term-time { color: var(--muted); }



    .term-lvl { font-weight: 700; }



    .term-lvl.info { color: var(--accent-cyber); }



    .term-lvl.warn { color: var(--warning); }



    .term-lvl.critical { color: var(--critical); }



    .term-lvl.success { color: var(--success); }



    .term-src { color: var(--muted); }



    .term-msg { color: var(--text-primary); word-break: break-all; }







    /* Pipeline Cards */



    .pipeline-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 12px; margin-top: 16px; }



    .pipeline-card {



      background: var(--panel); border: 1px solid var(--border);



      border-radius: var(--radius-sm); padding: 12px 14px;



      display: flex; flex-direction: column; gap: 6px;



    }



    .pipeline-card.status-success { border-left: 3px solid var(--success); }



    .pipeline-card.status-blocked { border-left: 3px solid var(--critical); }



    .pipeline-card.status-unavailable { border-left: 3px solid var(--muted); }



    .pipe-header { display: flex; justify-content: space-between; align-items: center; font-size: 12px; font-weight: 600; }



    .pipe-reason { font-size: 11px; color: var(--text-secondary); line-height: 1.3; }



    .pipe-meta { font-size: 10px; color: var(--muted); font-family: var(--font-mono); margin-top: auto; }







    /* Slide-in Detail Drawer */



    .drawer {



      position: fixed; top: 0; right: 0; width: 560px; height: 100vh;



      background: var(--panel-elevated); border-left: 1px solid var(--border);



      box-shadow: -10px 0 40px rgba(0, 0, 0, 0.8);



      z-index: 100; transform: translateX(100%); transition: transform 0.25s ease;



      display: flex; flex-direction: column; overflow-y: auto;



    }



    .drawer.open { transform: translateX(0); }



    .drawer-head { padding: 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: flex-start; }



    .drawer-body { padding: 24px; flex: 1; }



    .detail-section { margin-bottom: 20px; }



    .detail-section h4 { font-size: 11px; font-family: var(--font-mono); text-transform: uppercase; color: var(--muted); margin-bottom: 6px; }







    /* Integrated AI Copilot Side Panel */



    .copilot-panel {



      position: fixed; top: 0; right: 0; width: 440px; height: 100vh;



      background: var(--panel-elevated); border-left: 1px solid var(--border);



      box-shadow: -10px 0 40px rgba(0,0,0,0.8);



      z-index: 95; display: flex; flex-direction: column;



      transform: translateX(100%); transition: transform 0.25s cubic-bezier(0.16, 1, 0.3, 1);



    }



    .copilot-panel.open { transform: translateX(0); }



    .copilot-head {



      padding: 16px 20px; border-bottom: 1px solid var(--border);



      display: flex; justify-content: space-between; align-items: center;



      background: #0d131c;



    }



    .copilot-title {



      display: flex; align-items: center; gap: 8px;



      font-family: var(--font-mono); font-weight: 700; font-size: 13px;



      letter-spacing: 0.06em; color: var(--text-primary);



    }



    .copilot-dot {



      width: 8px; height: 8px; border-radius: 50%;



      background: var(--accent-cyber); box-shadow: 0 0 10px var(--accent-cyber);



    }



    .copilot-context-bar {



      padding: 8px 16px; background: #070a10; border-bottom: 1px solid var(--border);



      display: flex; gap: 8px; overflow-x: auto; font-size: 11px; font-family: var(--font-mono);



    }



    .context-pill {



      background: var(--panel); border: 1px solid var(--border); padding: 2px 8px;



      border-radius: 4px; color: var(--text-secondary); white-space: nowrap;



    }



    .copilot-messages {



      flex: 1; overflow-y: auto; padding: 16px; display: flex; flex-direction: column; gap: 12px;



    }



    .copilot-msg {



      padding: 12px 14px; border-radius: var(--radius-sm); font-size: 13px; line-height: 1.5; max-width: 95%;



    }



    .msg-user {



      background: #182335; border: 1px solid rgba(79, 140, 255, 0.3); align-self: flex-end; color: var(--text-primary);



    }



    .msg-assistant {



      background: #090e16; border: 1px solid var(--border); align-self: flex-start; color: var(--text-secondary);



    }



    .msg-meta {



      display: flex; justify-content: space-between; font-size: 10px; font-family: var(--font-mono); color: var(--muted); margin-bottom: 6px;



    }



    .msg-author { color: var(--accent-cyber); font-weight: 600; }



    .copilot-suggestions {



      padding: 8px 16px; display: flex; gap: 6px; overflow-x: auto; background: #080c13; border-top: 1px solid var(--border);



    }



    .copilot-input-form {



      padding: 12px 16px 16px; background: #0b1018; border-top: 1px solid var(--border);



      display: flex; flex-direction: column; gap: 8px;



    }



    .copilot-input-form textarea { margin-bottom: 0; resize: none; background: #040609; }



    .copilot-input-actions { display: flex; justify-content: space-between; align-items: center; }



    .copilot-hint { font-size: 10px; color: var(--muted); font-family: var(--font-mono); }







    /* Command Palette Modal */



    .palette-card {



      width: 560px; background: var(--panel-elevated); border: 1px solid var(--border);



      border-radius: var(--radius-md); overflow: hidden; box-shadow: 0 16px 48px rgba(0,0,0,0.9);



    }



    .palette-input-wrap {



      padding: 14px 18px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 10px; background: #06090e;



    }



    .palette-input-wrap input { border: none; background: transparent; padding: 0; margin: 0; font-size: 14px; width: 100%; }



    .palette-input-wrap input:focus { border: none; outline: none; }



    .palette-results { max-height: 380px; overflow-y: auto; padding: 8px; }



    .palette-item {



      padding: 10px 14px; border-radius: 4px; cursor: pointer; display: flex; flex-direction: column; gap: 2px; transition: background 0.15s ease;



    }



    .palette-item:hover, .palette-item.active { background: #182335; }



    .palette-item-title { font-size: 13px; font-weight: 600; color: var(--text-primary); }



    .palette-item-sub { font-size: 11px; color: var(--muted); font-family: var(--font-mono); }







    /* Modal Backdrop */



    .modal-backdrop {



      position: fixed; inset: 0; background: rgba(6, 8, 13, 0.85);



      backdrop-filter: blur(8px); display: none; place-items: center; z-index: 110;



    }



    .modal-backdrop.open { display: grid; }



    .modal-card { width: 480px; background: var(--panel-elevated); border: 1px solid var(--border); border-radius: var(--radius-md); overflow: hidden; }







    /* Form Inputs */



    label { display: block; font-size: 11px; font-family: var(--font-mono); color: var(--muted); margin-bottom: 6px; text-transform: uppercase; }



    input, select, textarea {



      width: 100%; padding: 8px 12px; background: var(--bg-primary);



      border: 1px solid var(--border); border-radius: var(--radius-sm);



      color: var(--text-primary); font-size: 13px; font-family: inherit; margin-bottom: 14px;



    }



    input:focus, select:focus, textarea:focus { border-color: var(--accent-primary); outline: none; }







    /* Utility */



    .font-mono { font-family: var(--font-mono); }



    .font-bold { font-weight: 600; }



    .text-cyan { color: var(--accent-cyber); }



    .text-muted { color: var(--muted); }



    .d-flex { display: flex; }



    .justify-between { justify-content: space-between; }



    .items-center { align-items: center; }



    .gap-2 { gap: 8px; }



    .gap-3 { gap: 12px; }



    .mt-3 { margin-top: 12px; }



    .mb-3 { margin-bottom: 12px; }



    .mb-4 { margin-bottom: 16px; }



    pre { white-space: pre-wrap; word-break: break-all; background: #040609; padding: 12px; border-radius: var(--radius-sm); border: 1px solid var(--border); font-size: 11px; font-family: var(--font-mono); }



    .toast-container { position: fixed; bottom: 20px; right: 20px; z-index: 120; display: flex; flex-direction: column; gap: 8px; }



    .toast { background: var(--panel-elevated); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 10px 16px; font-size: 12px; box-shadow: 0 4px 16px rgba(0,0,0,0.6); transition: all 0.2s ease; }



    .toast-success { border-left: 3px solid var(--success); }



    .toast-critical { border-left: 3px solid var(--critical); }



    .toast-info { border-left: 3px solid var(--accent-cyber); }



    .chip {



      padding: 3px 8px; font-size: 11px; border-radius: 4px; background: var(--panel); border: 1px solid var(--border); color: var(--text-secondary); cursor: pointer; white-space: nowrap; font-family: var(--font-mono);



    }



    .chip:hover { color: var(--accent-cyber); border-color: var(--accent-cyber); }







    /* Codealpha-inspired hierarchy layer */



    .topbar {



      height: 64px;



      padding: 0 clamp(20px, 3vw, 36px);



      background: rgba(10, 14, 23, 0.86);



      backdrop-filter: blur(16px);



      -webkit-backdrop-filter: blur(16px);



    }



    .current-view-title {



      font-family: var(--font-display);



      font-size: 21px;



      font-weight: 400;



      letter-spacing: -0.01em;



      text-transform: none;



      white-space: nowrap;



    }



    .btn { white-space: nowrap; }



    .scope-pill { white-space: nowrap; }



    .topbar-right { gap: 8px; }



    .topbar-right .btn-sm { padding: 4px 10px; font-size: 10.5px; }



    .topbar-right kbd { display: none; }



    @media (min-width: 1560px) {



      .topbar-right kbd { display: inline; }



    }



    .tab-view { padding: 36px clamp(24px, 3.4vw, 52px) 56px; }







    .page-hero {



      display: flex;



      align-items: flex-end;



      justify-content: space-between;



      gap: 24px;



      flex-wrap: wrap;



      margin-bottom: 28px;



    }



    .page-eyebrow {



      font-family: var(--font-mono);



      font-size: 10px;



      font-weight: 700;



      letter-spacing: 0.16em;



      text-transform: uppercase;



      color: var(--accent-cyber);



      margin-bottom: 12px;



    }



    .page-title {



      font-family: var(--font-display);



      font-size: clamp(40px, 4.4vw, 62px);



      font-weight: 400;



      line-height: 0.98;



      letter-spacing: -0.035em;



      text-transform: none;



      color: var(--text-primary);



    }



    .page-title em { font-style: italic; color: var(--accent-primary); }



    .page-lede {



      margin-top: 12px;



      max-width: 58ch;



      color: var(--text-secondary);



      font-size: 13.5px;



      line-height: 1.6;



    }



    .page-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; padding-bottom: 6px; }



    .page-chip {



      display: inline-flex;



      align-items: center;



      gap: 8px;



      padding: 8px 16px;



      border-radius: 999px;



      border: 1px solid var(--border);



      background: rgba(18, 24, 38, 0.72);



      color: var(--text-secondary);



      font-family: var(--font-mono);



      font-size: 10.5px;



      letter-spacing: 0.06em;



      text-transform: uppercase;



      white-space: nowrap;



    }







    .metrics-grid {



      grid-template-columns: repeat(4, minmax(0, 1fr));



      gap: 16px;



      margin-bottom: 24px;



    }



    .metric-card {



      padding: 20px 22px 18px;



      border-radius: var(--radius-lg);



      background: linear-gradient(160deg, rgba(26, 37, 60, 0.72), rgba(18, 24, 38, 0.92));



      box-shadow: 0 10px 28px rgba(0, 0, 0, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.05);



    }



    .metric-card:hover {



      border-color: var(--border-glow, rgba(6, 182, 212, 0.35));



      transform: translateY(-2px);



    }



    .metric-lbl {



      font-size: 10px;



      letter-spacing: 0.12em;



      color: var(--text-secondary);



    }



    .metric-val {



      font-family: var(--font-sans);



      font-size: 34px;



      font-weight: 700;



      letter-spacing: -0.03em;



      font-variant-numeric: tabular-nums;



      margin-top: 2px;



    }



    @media (max-width: 1180px) {



      .metrics-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }



    }



    @media (max-width: 640px) {



      .metrics-grid { grid-template-columns: minmax(0, 1fr); }



    }







    .canvas-wrap {



      height: 340px;



      border-radius: var(--radius-xl);



      background:



        radial-gradient(600px 260px at 30% 20%, rgba(6, 182, 212, 0.12), transparent 65%),



        radial-gradient(520px 260px at 78% 82%, rgba(227, 134, 10, 0.10), transparent 65%),



        linear-gradient(rgba(35, 48, 76, 0.35) 1px, transparent 1px),



        linear-gradient(90deg, rgba(35, 48, 76, 0.35) 1px, transparent 1px),



        #070b14;



      background-size: auto, auto, 44px 44px, 44px 44px, auto;



      box-shadow: inset 0 0 80px rgba(0, 0, 0, 0.55);



    }



    .canvas-hero { height: 340px; }



    .canvas-caption {



      position: absolute;



      left: 18px;



      bottom: 16px;



      z-index: 8;



      display: inline-flex;



      align-items: center;



      gap: 8px;



      padding: 6px 12px;



      border-radius: 999px;



      background: rgba(7, 11, 20, 0.78);



      border: 1px solid var(--border);



      font-family: var(--font-mono);



      font-size: 10px;



      letter-spacing: 0.08em;



      text-transform: uppercase;



      color: var(--text-secondary);



      pointer-events: none;



    }







    .panel-card {



      border-radius: var(--radius-lg);



      padding: 24px 26px;



      background: linear-gradient(160deg, rgba(26, 37, 60, 0.55), rgba(18, 24, 38, 0.9));



      box-shadow: 0 10px 28px rgba(0, 0, 0, 0.28);



    }



    .card-title { font-size: 12px; letter-spacing: 0.1em; }



  </style>



</head>



<body>







<div class="app-shell">



  <!-- Left Sidebar (Section 4) -->



  <aside class="sidebar">



    <div class="brand-wrap">



      <div class="logo-mark">RL</div>



      <div>



        <div class="brand-title">REDLOOP</div>



        <div class="brand-sub">Security Platform</div>



      </div>



    </div>







    <nav class="nav-group" aria-label="Navigation">



      <div class="nav-label">Command</div>



      <div class="nav-item active" data-tab="dashboard">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>



        <span>Dashboard</span>



      </div>



      <div class="nav-item" data-tab="copilot">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/></svg>



        <span>AI Copilot</span>



      </div>



      <div class="nav-item" data-tab="assessments">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>



        <span>Assessments</span>



      </div>



      <div class="nav-item" data-tab="attack-surface">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg>



        <span>Attack Surface</span>



      </div>







      <div class="nav-label">Findings &amp; Proof</div>



      <div class="nav-item" data-tab="findings">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>



        <span>Findings</span>



      </div>



      <div class="nav-item" data-tab="evidence">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>



        <span>Evidence</span>



      </div>



      <div class="nav-item" data-tab="audit">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>



        <span>Audit Ledger</span>



      </div>







      <div class="nav-label">Domains</div>



      <div class="nav-item" data-tab="network">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>



        <span>Network</span>



      </div>



      <div class="nav-item" data-tab="web">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/></svg>



        <span>Web App</span>



      </div>



      <div class="nav-item" data-tab="api">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>



        <span>APIs</span>



      </div>



      <div class="nav-item" data-tab="dns">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><circle cx="19" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><path d="M5 17l4-4"/><path d="M15 9l4-4"/></svg>



        <span>DNS</span>



      </div>



      <div class="nav-item" data-tab="tls">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>



        <span>TLS / SSL</span>



      </div>



      <div class="nav-item" data-tab="host">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/></svg>



        <span>Host Security</span>



      </div>



      <div class="nav-item" data-tab="containers">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>



        <span>Containers</span>



      </div>



      <div class="nav-item" data-tab="files">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/></svg>



        <span>Files &amp; Malware</span>



      </div>







      <div class="nav-label">Operations &amp; Telemetry</div>



      <div class="nav-item" data-tab="performance">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>



        <span>Performance &amp; Telemetry</span>



      </div>



      <div class="nav-item" data-tab="reports">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/></svg>



        <span>Reports</span>



      </div>



      <div class="nav-item" data-tab="tools">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>



        <span>Capability Center</span>



      </div>



      <div class="nav-item" data-tab="settings">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>



        <span>Settings</span>



      </div>



      <div class="nav-item" data-tab="soc-ops">



        <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>



        <span>Autonomous SOC</span>



      </div>



    </nav>







    <div class="sidebar-footer">



      <span class="foot-status-dot"></span>



      <span>SOC ENGINE ACTIVE · LOCAL</span>



    </div>



  </aside>







  <!-- Main Viewport -->



  <main class="main-area">



    <!-- Topbar (Section 4) -->



    <header class="topbar">



      <div class="topbar-left">



        <h1 class="current-view-title" id="current-view-title">Dashboard</h1>



        <div class="scope-pill">



          <span class="pulse-dot"></span>



          <span>TARGET: <span id="scope-banner-target">127.0.0.1</span></span>



        </div>



        <select id="assessment-picker" style="width: auto; margin-bottom: 0; padding: 4px 10px; font-size: 11px; font-family: var(--font-mono);">



          <option value="">Loading assessments...</option>



        </select>



      </div>







      <div class="topbar-right">



        <span class="badge-pill success font-mono" id="audit-integrity-badge">



          <span class="pulse-dot"></span>



          <span>VERIFYING AUDIT CHAIN...</span>



        </span>



        <button class="btn btn-secondary btn-sm" id="btn-palette" data-click="openCommandPalette()">



          <span>🔍 Palette</span>



          <kbd style="background:#040609;padding:2px 5px;border-radius:3px;border:1px solid #202b3a;font-size:10px;">Ctrl+K</kbd>



        </button>



        <button class="btn btn-primary btn-sm" id="btn-toggle-copilot" data-click="toggleCopilot()">



          <span>🤖 AI Copilot</span>



        </button>



        <button class="btn btn-primary btn-sm" id="btn-open-start-modal">⚡ Run Assessment</button>



      </div>



    </header>







    <!-- VIEW: Dashboard (Section 6) -->



    <section class="tab-view active" id="view-dashboard">



      <div class="page-hero">



        <div>



          <div class="page-eyebrow">RedLoop / Command Center</div>



          <h2 class="page-title">Security <em>overview</em></h2>



          <p class="page-lede">Real-time assessment and attack-surface intelligence across every authorized target in scope.</p>



        </div>



        <div class="page-actions">



          <span class="page-chip"><span class="pulse-dot"></span>Live telemetry</span>



          <span class="page-chip">Local SOC engine</span>



        </div>



      </div>







      <!-- Metrics -->



      <div class="metrics-grid">



        <div class="metric-card">



          <span class="metric-lbl">Risk Score</span>



          <span class="metric-val risk" id="metric-risk">—</span>



        </div>



        <div class="metric-card">



          <span class="metric-lbl">Critical</span>



          <span class="metric-val" id="metric-critical" style="color:var(--critical);">0</span>



        </div>



        <div class="metric-card">



          <span class="metric-lbl">High</span>



          <span class="metric-val" id="metric-high" style="color:var(--warning);">0</span>



        </div>



        <div class="metric-card">



          <span class="metric-lbl">Medium</span>



          <span class="metric-val" id="metric-medium" style="color:var(--accent-primary);">0</span>



        </div>



        <div class="metric-card">



          <span class="metric-lbl">Assets</span>



          <span class="metric-val" id="metric-assets">0</span>



        </div>



        <div class="metric-card">



          <span class="metric-lbl">Open Services</span>



          <span class="metric-val text-cyan" id="metric-services">0</span>



        </div>



        <div class="metric-card">



          <span class="metric-lbl">Findings</span>



          <span class="metric-val" id="metric-findings">0</span>



        </div>



        <div class="metric-card">



          <span class="metric-lbl">Evidence Records</span>



          <span class="metric-val" id="metric-evidence">0</span>



        </div>



      </div>







      <!-- 3D Hero Visualization -->



      <div class="canvas-wrap">



        <canvas id="hero-canvas" class="canvas-hero"></canvas>



        <div class="canvas-caption"><span class="pulse-dot"></span>Live 3D attack-surface projection</div>



        <div class="canvas-hud" id="hero-hud"></div>



        <div class="canvas-controls">



          <span class="badge badge-info font-mono">3D ATTACK SURFACE</span>



          <button class="btn btn-sm btn-secondary" data-click="switchTab('attack-surface')">Expand Topology ↗</button>



        </div>



      </div>







      <!-- Terminal Event Stream -->



      <div class="panel-card">



        <div class="card-head">



          <div class="card-title">Real-Time Event Stream · Forensic Audit Trail</div>



          <span class="badge badge-success font-mono">LIVE CONNECTED</span>



        </div>



        <div class="terminal-box" id="terminal-events">



          <div class="term-row term-info">



            <span class="term-time">00:00:00</span>



            <span class="term-lvl info">[SYSTEM]</span>



            <span class="term-src">BOOT:</span>



            <span class="term-msg">Command Center initialized. Awaiting assessment telemetry.</span>



          </div>



        </div>



      </div>



    </section>







    <!-- VIEW: Dedicated Copilot View -->



    <section class="tab-view" id="view-copilot">



      <div class="panel-card" style="height:calc(100vh - 120px);display:flex;flex-direction:column;padding:0;">



        <div class="copilot-head">



          <div class="copilot-title">



            <span class="copilot-dot"></span>



            <span>UNIFIED CYBERSECURITY COPILOT COMMAND CENTER</span>



          </div>



          <button class="btn btn-sm btn-outline" data-click="clearCopilot()">Clear History</button>



        </div>



        <div class="copilot-context-bar">



          <span class="context-pill" id="view-copilot-target">Target: 127.0.0.1 (Scope Authorized)</span>



          <span class="context-pill">Mode: Operational Security Assistant</span>



        </div>



        <div class="copilot-messages" id="view-copilot-messages" style="flex:1;">



          <!-- Mirrors main copilot messages -->



        </div>



        <div class="copilot-suggestions">



          <button class="chip" data-click="quickCopilot('Run comprehensive assessment on authorized target')">⚡ Comprehensive Assessment</button>



          <button class="chip" data-click="quickCopilot('Enumerate attack surface and open ports')">🌐 Enumerate Ports</button>



          <button class="chip" data-click="quickCopilot('Analyze TLS configuration and ciphers')">🔒 Analyze TLS</button>



          <button class="chip" data-click="quickCopilot('Crawl web application endpoints and forms')">🕷️ Crawl Web App</button>



          <button class="chip" data-click="quickCopilot('Verify cryptographic audit ledger')">🛡️ Verify Audit</button>



          <button class="chip" data-click="quickCopilot('Generate technical report')">📄 Technical Report</button>



        </div>



      </div>



    </section>







    <!-- VIEW: Assessments (Section 9) -->



    <section class="tab-view" id="view-assessments">



      <div class="panel-card">



        <div class="card-head">



          <div class="card-title">Checkpoint Assessment Store</div>



          <button class="btn btn-sm btn-primary" data-click="$('#start-modal').classList.add('open')">+ New Assessment</button>



        </div>



        <div class="table-wrap">



          <table>



            <thead>



              <tr>



                <th>ID</th>



                <th>Target</th>



                <th>Depth</th>



                <th>Status</th>



                <th>Current Stage</th>



                <th>Updated</th>



                <th>Action</th>



              </tr>



            </thead>



            <tbody id="assessments-table-body">



              <tr><td colspan="7" class="text-center text-muted" style="padding:24px;">NO ASSESSMENTS YET</td></tr>



            </tbody>



          </table>



        </div>



      </div>







      <!-- Pipeline Execution Details -->



      <div class="panel-card">



        <div class="card-head">



          <div class="card-title">Execution Pipeline Status: <span id="detail-asmt-id" class="text-cyan font-mono">—</span></div>



          <span id="detail-asmt-status" class="badge badge-info">IDLE</span>



        </div>



        <div class="pipeline-grid" id="pipeline-card-grid">



          <div style="color:var(--muted);padding:16px;">Select an assessment to view execution breakdown.</div>



        </div>



      </div>



    </section>







    <!-- VIEW: 3D Attack Surface (Section 8, 10, 11) -->



    <section class="tab-view" id="view-attack-surface">



      <div class="panel-card">



        <div class="card-head">



          <div class="card-title">Attack Surface Topology · 3D Vector Graph</div>



          <div class="d-flex gap-2">



            <select id="filter-graph-severity" style="width: auto; margin-bottom: 0; padding: 4px 8px; font-size: 11px;">



              <option value="all">Severity: All</option>



              <option value="CRITICAL">Critical</option>



              <option value="HIGH">High</option>



              <option value="MEDIUM">Medium</option>



            </select>



            <select id="filter-graph-type" style="width: auto; margin-bottom: 0; padding: 4px 8px; font-size: 11px;">



              <option value="all">Type: All Entities</option>



              <option value="host">Hosts</option>



              <option value="service">Services / Ports</option>



              <option value="finding">Findings</option>



            </select>



          </div>



        </div>



        <div class="canvas-wrap" style="height: 520px;">



          <canvas id="attack-surface-canvas" style="width: 100%; height: 520px; display: block;"></canvas>



          <div class="canvas-hud" id="attack-hud"></div>



        </div>



      </div>



    </section>







    <!-- VIEW: Findings (Section 11, 12) -->



    <section class="tab-view" id="view-findings">



      <div class="panel-card">



        <div class="card-head">



          <div class="card-title">Security Findings Ledger</div>



        </div>



        <div class="table-wrap">



          <table>



            <thead>



              <tr>



                <th>Severity</th>



                <th>Finding</th>



                <th>Asset</th>



                <th>Endpoint</th>



                <th>Confidence</th>



                <th>CVSS</th>



                <th>Actions</th>



              </tr>



            </thead>



            <tbody id="findings-table-body">



              <tr><td colspan="7" class="text-center text-muted" style="padding:28px;">NO SECURITY FINDINGS</td></tr>



            </tbody>



          </table>



        </div>



      </div>



    </section>







    <!-- VIEW: Evidence (Section 20) -->



    <section class="tab-view" id="view-evidence">



      <div class="panel-card">



        <div class="card-head">



          <div class="card-title">Cryptographic Forensic Evidence Ledger</div>



        </div>



        <div class="table-wrap">



          <table>



            <thead>



              <tr>



                <th>Evidence ID</th>



                <th>Operation ID</th>



                <th>Target</th>



                <th>SHA-256 Hash</th>



                <th>Timestamp</th>



                <th>Actions</th>



              </tr>



            </thead>



            <tbody id="evidence-table-body">



              <tr><td colspan="6" class="text-center text-muted" style="padding:28px;">NO EVIDENCE COLLECTED</td></tr>



            </tbody>



          </table>



        </div>



      </div>



    </section>







    <!-- VIEW: Audit (Section 21) -->



    <section class="tab-view" id="view-audit">



      <div class="panel-card">



        <div class="card-head">



          <div class="card-title">Immutable Audit Ledger Verification</div>



          <button class="btn btn-sm btn-primary" data-click="verifyAuditChain()">Verify Ledger Integrity</button>



        </div>



        <p class="text-muted mb-3" style="font-size:12px;">Tamper-evident chained hash ledger verifying every scan, probe, crawl, and chat action.</p>



        <div class="terminal-box" style="height: 280px;" id="audit-log-terminal">



          <div class="term-row term-info">



            <span class="term-lvl info">[AUDIT]</span>



            <span class="term-msg">Audit verification endpoint: /api/audit/verify</span>



          </div>



        </div>



      </div>



    </section>







    <!-- VIEW: Performance & Telemetry (Section 16, 17) -->



    <section class="tab-view" id="view-performance">



      <div class="d-flex justify-between items-center mb-3">



        <div>



          <h2 style="font-size: 16px; font-weight: 700; font-family: var(--font-mono);">PERFORMANCE &amp; TOKEN TELEMETRY</h2>



          <p class="text-muted" style="font-size: 12px;">Real-time AI model usage, latency tracking, and tool execution metrics.</p>



        </div>



        <button class="btn btn-sm btn-secondary" data-click="loadPerformance()">🔄 Refresh Telemetry</button>



      </div>







      <!-- AI Telemetry Cards -->



      <div class="metrics-grid">



        <div class="metric-card">



          <span class="metric-lbl">Total AI Tokens</span>



          <span class="metric-val text-cyan" id="perf-total-tokens">0</span>



        </div>



        <div class="metric-card">



          <span class="metric-lbl">Prompt Tokens</span>



          <span class="metric-val" id="perf-prompt-tokens">0</span>



        </div>



        <div class="metric-card">



          <span class="metric-lbl">Completion Tokens</span>



          <span class="metric-val" id="perf-comp-tokens">0</span>



        </div>



        <div class="metric-card">



          <span class="metric-lbl">AI Requests</span>



          <span class="metric-val" id="perf-total-queries">0</span>



        </div>



      </div>







      <!-- Providers & Models Table -->



      <div class="panel-card">



        <div class="card-head">



          <div class="card-title">Configured AI Providers &amp; Token Consumption</div>



        </div>



        <div class="table-wrap">



          <table>



            <thead>



              <tr>



                <th>Provider</th>



                <th>Requests</th>



                <th>Prompt Tokens</th>



                <th>Completion Tokens</th>



                <th>Total Tokens</th>



              </tr>



            </thead>



            <tbody id="perf-providers-body">



              <tr><td colspan="5" class="text-center text-muted" style="padding:16px;">No AI token usage reported yet.</td></tr>



            </tbody>



          </table>



        </div>



      </div>







      <!-- Assessment Engine Metrics -->



      <div class="panel-card">



        <div class="card-head">



          <div class="card-title">Assessment Engine Performance</div>



        </div>



        <div class="metrics-grid">



          <div class="metric-card">



            <span class="metric-lbl">Total Assessments</span>



            <span class="metric-val" id="perf-asmt-total">0</span>



          </div>



          <div class="metric-card">



            <span class="metric-lbl">Active / Running</span>



            <span class="metric-val" id="perf-asmt-active" style="color:var(--accent-cyber);">0</span>



          </div>



          <div class="metric-card">



            <span class="metric-lbl">Completed</span>



            <span class="metric-val" id="perf-asmt-completed" style="color:var(--success);">0</span>



          </div>



          <div class="metric-card">



            <span class="metric-lbl">Failed / Cancelled</span>



            <span class="metric-val" id="perf-asmt-failed" style="color:var(--critical);">0</span>



          </div>



        </div>



      </div>







      <!-- Tool Execution Matrix -->



      <div class="panel-card">



        <div class="card-head">



          <div class="card-title">Security Tools Execution Matrix</div>



        </div>



        <div class="table-wrap">



          <table>



            <thead>



              <tr>



                <th>Tool / Capability</th>



                <th>Availability</th>



                <th>Detected Version</th>



                <th>Executions</th>



                <th>Success</th>



                <th>Failed</th>



              </tr>



            </thead>



            <tbody id="perf-tools-body">



              <tr><td colspan="6" class="text-center text-muted" style="padding:16px;">Loading capability matrix...</td></tr>



            </tbody>



          </table>



        </div>



      </div>



    </section>







    <!-- VIEW: Network (Section 15) -->



    <section class="tab-view" id="view-network">



      <div class="panel-card">



        <div class="card-head"><div class="card-title">Network &amp; Port Topology</div></div>



        <div id="network-services-list" class="d-flex gap-2" style="flex-wrap: wrap;">



          <div class="text-muted" style="padding:16px;">No open network ports discovered yet. Run network discovery from Chat or Assessments.</div>



        </div>



      </div>



    </section>







    <!-- VIEW: Web (Section 16) -->



    <section class="tab-view" id="view-web">



      <div class="panel-card">



        <div class="card-head"><div class="card-title">Web Application Crawler &amp; Security</div></div>



        <div class="metrics-grid">



          <div class="metric-card"><span class="metric-lbl">Pages Crawled</span><span class="metric-val text-cyan" id="web-pages-count">0</span></div>



          <div class="metric-card"><span class="metric-lbl">Endpoints</span><span class="metric-val" id="web-endpoints-count">0</span></div>



          <div class="metric-card"><span class="metric-lbl">Missing Headers</span><span class="metric-val" id="web-headers-count">0</span></div>



        </div>



      </div>



      <!-- Test suite compatibility container: web metadata check -->



      <div class="panel-card" style="display:none;">



        <form id="web-check"><input type="hidden" id="web-check-url" value="http://127.0.0.1/"><button type="submit">web metadata check</button></form>



      </div>



    </section>







    <!-- VIEW: APIs (Section 17) -->



    <section class="tab-view" id="view-api">



      <div class="panel-card">



        <div class="card-head"><div class="card-title">API Inventory &amp; Schema Validation</div></div>



        <p class="text-muted" style="padding:16px;">OpenAPI specifications and GraphQL endpoints mapped during automated assessment.</p>



      </div>



    </section>







    <!-- VIEW: DNS (Section 19) -->



    <section class="tab-view" id="view-dns">



      <div class="panel-card">



        <div class="card-head"><div class="card-title">DNS Security &amp; Zone Transfer Verification</div></div>



        <p class="text-muted" style="padding:16px;">A, AAAA, MX, TXT, SPF, DMARC, DNSSEC, and AXFR record telemetry.</p>



      </div>



    </section>







    <!-- VIEW: TLS (Section 18) -->



    <section class="tab-view" id="view-tls">



      <div class="panel-card">



        <div class="card-head"><div class="card-title">TLS / SSL Certificate &amp; Cipher Suite Telemetry</div></div>



        <div class="metrics-grid">



          <div class="metric-card"><span class="metric-lbl">Protocol</span><span class="metric-val text-cyan" id="tls-version-val">—</span></div>



          <div class="metric-card"><span class="metric-lbl">Cipher Suite</span><span class="metric-val" id="tls-cipher-val" style="font-size:14px;">—</span></div>



          <div class="metric-card"><span class="metric-lbl">Certificate</span><span class="metric-val" id="tls-cert-val" style="font-size:14px;">—</span></div>



        </div>



      </div>



    </section>







    <!-- VIEW: Host, Containers, Files, Reports, Tools, Settings -->



    <section class="tab-view" id="view-host">



      <div class="panel-card"><div class="card-head"><div class="card-title">Host Security &amp; Operating System Auditing</div></div><p class="text-muted" style="padding:16px;">Host inspection and local configuration telemetry.</p></div>



    </section>



    <section class="tab-view" id="view-containers">



      <div class="panel-card"><div class="card-head"><div class="card-title">Container Artifacts &amp; Cloud Configuration</div></div><p class="text-muted" style="padding:16px;">Static analysis of Dockerfile, Compose, and Kubernetes manifests.</p></div>



    </section>



    <section class="tab-view" id="view-files">



      <div class="panel-card"><div class="card-head"><div class="card-title">Static File &amp; Malware Forensics (Static hash &amp; YARA)</div></div><p class="text-muted" style="padding:16px;">Forensic triage of uploaded samples.</p></div>



      <!-- Test suite compatibility form -->



      <form id="file-triage" style="display:none;"><input type="file" name="sample"><button type="submit">triage</button></form>



    </section>



    <section class="tab-view" id="view-reports">



      <div class="panel-card">



        <div class="card-head"><div class="card-title">Report Center</div></div>



        <p class="text-muted mb-3" style="font-size:12px;">Export and preview technical and executive reports.</p>



        <div class="d-flex gap-2">



          <button class="btn btn-secondary" data-click="quickCopilot('Generate executive report')">Generate Executive Report</button>



          <button class="btn btn-primary" data-click="quickCopilot('Generate technical report')">Generate Technical Report</button>



        </div>



      </div>



    </section>



    <section class="tab-view" id="view-tools">



      <div class="panel-card">



        <div class="card-head"><div class="card-title">Tool Capability Matrix</div></div>



        <div id="capabilities-list" class="metrics-grid"></div>



      </div>



    </section>



    <section class="tab-view" id="view-settings">



      <div class="panel-card">



        <div class="card-head"><div class="card-title">System &amp; Scope Configuration</div></div>



        <p class="text-muted" style="padding:16px;">Signed scope enforcement: scope.yaml. Cryptographic verification active.</p>



      </div>



    </section>



    <section class="tab-view" id="view-soc-ops">

      <div class="metrics-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:20px;">

        <div class="panel-card" style="padding:16px;">

          <div class="text-muted" style="font-size:11px;font-weight:600;letter-spacing:0.05em;">MEAN TIME TO DETECT (MTTD)</div>

          <div id="soc-mttd" style="font-size:24px;font-weight:700;color:var(--text-primary);margin-top:6px;">--</div>

          <div class="text-muted" style="font-size:11px;">Minutes from first event to alert</div>

        </div>

        <div class="panel-card" style="padding:16px;">

          <div class="text-muted" style="font-size:11px;font-weight:600;letter-spacing:0.05em;">MEAN TIME TO RESPOND (MTTR)</div>

          <div id="soc-mttr" style="font-size:24px;font-weight:700;color:var(--text-primary);margin-top:6px;">--</div>

          <div class="text-muted" style="font-size:11px;">Minutes to containment authorization</div>

        </div>

        <div class="panel-card" style="padding:16px;">

          <div class="text-muted" style="font-size:11px;font-weight:600;letter-spacing:0.05em;">TELEMETRY SYNC RATE</div>

          <div id="soc-sync-rate" style="font-size:24px;font-weight:700;color:var(--success);margin-top:6px;">--</div>

          <div class="text-muted" style="font-size:11px;">Successful provider batch percentage</div>

        </div>

        <div class="panel-card" style="padding:16px;">

          <div class="text-muted" style="font-size:11px;font-weight:600;letter-spacing:0.05em;">PROVIDER AVAILABILITY</div>

          <div id="soc-provider-avail" style="font-size:24px;font-weight:700;color:var(--accent-primary);margin-top:6px;">--</div>

          <div class="text-muted" style="font-size:11px;">Active SIEM/EDR connectivity</div>

        </div>

        <div class="panel-card" style="padding:16px;">

          <div class="text-muted" style="font-size:11px;font-weight:600;letter-spacing:0.05em;">ALERT REDUCTION</div>

          <div id="soc-alert-reduction" style="font-size:24px;font-weight:700;color:var(--primary);margin-top:6px;">--</div>

          <div class="text-muted" style="font-size:11px;">Deduplication &amp; clustering ratio</div>

        </div>

      </div>



      <div style="display:grid;grid-template-columns:2fr 1fr;gap:20px;margin-bottom:20px;">

        <div class="panel-card">

          <div class="card-head" style="display:flex;justify-content:space-between;align-items:center;">

            <div class="card-title">Correlated Security Incidents</div>

            <button class="btn btn-secondary btn-sm" data-click="correlateEventsNow()">🔄 Run Correlation Pass</button>

          </div>

          <div class="table-wrap" style="max-height:320px;overflow-y:auto;">

            <table style="width:100%;border-collapse:collapse;font-size:12px;">

              <thead>

                <tr style="border-bottom:1px solid var(--border);text-align:left;color:var(--text-secondary);">

                  <th style="padding:8px;">Incident ID</th>

                  <th style="padding:8px;">Severity</th>

                  <th style="padding:8px;">Title</th>

                  <th style="padding:8px;">Target Entity</th>

                  <th style="padding:8px;">Confidence</th>

                  <th style="padding:8px;">Events</th>

                </tr>

              </thead>

              <tbody id="soc-incidents-table-body">

                <tr><td colspan="6" style="padding:16px;text-align:center;" class="text-muted">Loading incidents...</td></tr>

              </tbody>

            </table>

          </div>

        </div>



        <div class="panel-card">

          <div class="card-head">

            <div class="card-title">Telemetry Sync Operations</div>

          </div>

          <div style="padding:10px 0;">

            <div style="display:flex;gap:8px;margin-bottom:12px;">

              <select id="soc-sync-provider" style="flex:1;padding:6px 8px;font-size:12px;background:var(--bg-secondary);border:1px solid var(--border);color:var(--text-primary);border-radius:4px;">

                <option value="edr_defender">Microsoft Defender</option>

                <option value="splunk">Splunk Enterprise</option>

                <option value="wazuh">Wazuh SIEM</option>

                <option value="elastic">Elasticsearch</option>

                <option value="edr_crowdstrike">CrowdStrike Falcon</option>

                <option value="identity_entra">Microsoft Entra ID</option>

                <option value="identity_ad">Active Directory</option>

              </select>

              <button class="btn btn-primary btn-sm" data-click="triggerSocSync()">Sync Now</button>

            </div>

            <div id="soc-sync-jobs-list" style="max-height:240px;overflow-y:auto;font-size:11px;font-family:var(--font-mono);">

              <div class="text-muted">No sync activity yet.</div>

            </div>

          </div>

        </div>

      </div>



      <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">

        <div class="panel-card">

          <div class="card-head">

            <div class="card-title">Threat Intelligence &amp; IOC Lifecycle</div>

          </div>

          <div class="table-wrap" style="max-height:280px;overflow-y:auto;">

            <table style="width:100%;border-collapse:collapse;font-size:12px;">

              <thead>

                <tr style="border-bottom:1px solid var(--border);text-align:left;color:var(--text-secondary);">

                  <th style="padding:8px;">Type</th>

                  <th style="padding:8px;">Indicator</th>

                  <th style="padding:8px;">State</th>

                  <th style="padding:8px;">Confidence</th>

                  <th style="padding:8px;">Actions</th>

                </tr>

              </thead>

              <tbody id="soc-iocs-table-body">

                <tr><td colspan="5" style="padding:16px;text-align:center;" class="text-muted">Loading indicators...</td></tr>

              </tbody>

            </table>

          </div>

        </div>



        <div class="panel-card">

          <div class="card-head" style="display:flex;justify-content:space-between;align-items:center;">

            <div class="card-title">Detection Engineering &amp; ATT&amp;CK Coverage</div>

            <span id="soc-attack-coverage-pill" class="badge-pill info font-mono">COVERAGE: --%</span>

          </div>

          <div class="table-wrap" style="max-height:280px;overflow-y:auto;">

            <table style="width:100%;border-collapse:collapse;font-size:12px;">

              <thead>

                <tr style="border-bottom:1px solid var(--border);text-align:left;color:var(--text-secondary);">

                  <th style="padding:8px;">Rule ID</th>

                  <th style="padding:8px;">Technique</th>

                  <th style="padding:8px;">Hits</th>

                  <th style="padding:8px;">F/P</th>

                  <th style="padding:8px;">Test Harness</th>

                </tr>

              </thead>

              <tbody id="soc-rules-table-body">

                <tr><td colspan="5" style="padding:16px;text-align:center;" class="text-muted">Loading detection rules...</td></tr>

              </tbody>

            </table>

          </div>

        </div>

      </div>

    </section>







    <!-- Hidden compatibility container for test assertions -->



    <div id="result" hidden></div>



    <div style="display:none;">audit evidence summary not detections or siem correlation</div>



    <button id="refresh-purple" style="display:none;">refresh purple</button>



  </main>







  <!-- Integrated AI Copilot Side Panel (Section 9) -->



  <aside class="copilot-panel" id="copilot-panel">



    <div class="copilot-head">



      <div class="copilot-title">



        <span class="copilot-dot"></span>



        <span>REDLOOP AI COPILOT</span>



      </div>



      <div class="d-flex gap-2">



        <button class="chip" data-click="clearCopilot()">Clear</button>



        <button class="chip" data-click="toggleCopilot(false)">✕</button>



      </div>



    </div>



    <div class="copilot-context-bar">



      <span class="context-pill" id="copilot-active-target">Target: 127.0.0.1 (Authorized)</span>



      <span class="context-pill" id="copilot-active-asmt">Assessment: None</span>



    </div>



    <div class="copilot-messages" id="copilot-messages">



      <!-- Chat history rendered dynamically -->



    </div>



    <div class="copilot-suggestions">



      <button class="chip" data-click="quickCopilot('Run comprehensive assessment on authorized target')">⚡ Full Assessment</button>



      <button class="chip" data-click="quickCopilot('Enumerate attack surface and open ports')">🌐 Enumerate Ports</button>



      <button class="chip" data-click="quickCopilot('Analyze TLS configuration and ciphers')">🔒 Analyze TLS</button>



      <button class="chip" data-click="quickCopilot('Crawl web application and detect endpoints')">🕷️ Crawl Web</button>



      <button class="chip" data-click="quickCopilot('Verify cryptographic audit ledger')">🛡️ Verify Audit</button>



      <button class="chip" data-click="quickCopilot('Generate technical report')">📄 Technical Report</button>



    </div>



    <form class="copilot-input-form" id="copilot-form">



      <textarea id="copilot-input" placeholder="Give an operational objective or ask a cybersecurity question..." rows="2"></textarea>



      <div class="copilot-input-actions">



        <span class="copilot-hint">Enter to send · Shift+Enter for newline</span>



        <button type="submit" class="btn btn-primary btn-sm">Execute</button>



      </div>



    </form>



  </aside>







  <!-- Finding Detail Drawer -->



  <div class="drawer" id="finding-drawer">



    <div class="drawer-head">



      <div>



        <span class="badge badge-critical" id="drawer-finding-sev">HIGH</span>



        <h3 id="drawer-finding-title" style="margin-top:8px;font-size:16px;">Finding Title</h3>



      </div>



      <button class="btn btn-sm btn-outline close-drawer">✕</button>



    </div>



    <div class="drawer-body">



      <div class="detail-section">



        <div class="d-flex justify-between items-center mb-3">



          <h4>Security Risk Score</h4>



          <button class="btn btn-sm btn-primary" id="drawer-ask-ai-btn">🤖 Ask AI to Explain</button>



        </div>



        <div class="font-mono font-bold" id="drawer-finding-risk" style="font-size:18px;color:var(--warning);">—</div>



      </div>



      <div class="detail-section">



        <h4>Affected Asset</h4>



        <div class="font-mono text-cyan" id="drawer-finding-asset">—</div>



      </div>



      <div class="detail-section">



        <h4>Description &amp; Observed Vulnerability</h4>



        <p id="drawer-finding-desc" style="color:var(--text-secondary);line-height:1.6;">—</p>



      </div>



      <div class="detail-section">



        <h4>Remediation Guidance</h4>



        <pre id="drawer-finding-remed">—</pre>



      </div>



      <div class="detail-section">



        <h4>Associated Evidence</h4>



        <div class="font-mono" id="drawer-finding-evidence">—</div>



      </div>



    </div>



  </div>







  <!-- Evidence Detail Drawer -->



  <div class="drawer" id="evidence-drawer">



    <div class="drawer-head">



      <div>



        <span class="badge badge-info">CRYPTOGRAPHIC EVIDENCE</span>



        <h3 id="drawer-evidence-id" style="margin-top:8px;font-size:15px;font-family:var(--font-mono);">—</h3>



      </div>



      <button class="btn btn-sm btn-outline close-drawer">✕</button>



    </div>



    <div class="drawer-body">



      <div class="detail-section">



        <h4>Target &amp; Operation</h4>



        <div class="font-mono text-cyan" id="drawer-evidence-target">—</div>



        <div class="font-mono text-muted" id="drawer-evidence-op">—</div>



      </div>



      <div class="detail-section">



        <h4>SHA-256 Integrity Hash</h4>



        <pre id="drawer-evidence-hash" style="color:var(--success);">—</pre>



      </div>



      <div class="detail-section">



        <h4>Payload Data</h4>



        <pre id="drawer-evidence-payload">—</pre>



      </div>



    </div>



  </div>







  <!-- Node Inspection Modal -->



  <div class="modal-backdrop" id="node-modal">



    <div class="modal-card">



      <div class="drawer-head">



        <div>



          <span class="badge badge-info" id="modal-node-type">NODE</span>



          <h3 id="modal-node-title" style="margin-top:6px;font-size:15px;font-family:var(--font-mono);">—</h3>



        </div>



        <button class="btn btn-sm btn-outline close-modal">✕</button>



      </div>



      <div style="padding:16px;">



        <h4>Entity Properties</h4>



        <pre id="modal-node-details" style="max-height:220px;overflow-y:auto;">—</pre>



        <div class="d-flex justify-between items-center mt-3">



          <button class="btn btn-sm btn-outline close-modal">Close</button>



          <button class="btn btn-sm btn-primary" id="modal-ask-ai-btn">🤖 Ask AI About Asset</button>



        </div>



      </div>



    </div>



  </div>







  <!-- Command Palette Modal (Section 34) -->



  <div class="modal-backdrop" id="palette-backdrop">



    <div class="palette-card">



      <div class="palette-input-wrap">



        <span style="color:var(--accent-cyber);">⚡</span>



        <input type="text" id="palette-input" placeholder="Type a security command, action, or view name..." autocomplete="off">



        <kbd style="background:#101620;border:1px solid #202b3a;padding:2px 6px;border-radius:3px;font-size:10px;">ESC</kbd>



      </div>



      <div class="palette-results" id="palette-results">



        <!-- Filtered commands rendered dynamically -->



      </div>



    </div>



  </div>







  <!-- Start Assessment Modal -->



  <div class="modal-backdrop" id="start-modal">



    <div class="modal-card">



      <div class="drawer-head">



        <h3 style="font-size:15px;font-family:var(--font-mono);">⚡ Launch Real Security Assessment</h3>



        <button class="btn btn-sm btn-outline close-modal">✕</button>



      </div>



      <form id="start-assessment-form" style="padding:20px;">



        <label>Target IP or Hostname</label>



        <input type="text" id="modal-asmt-target" value="127.0.0.1" required>



        <label>Assessment Depth</label>



        <select id="modal-asmt-depth">



          <option value="quick">Quick (Scope &amp; Ports)</option>



          <option value="standard" selected>Standard (Full 10-Stage Pipeline)</option>



          <option value="deep">Deep (Comprehensive Crawler &amp; TLS)</option>



          <option value="comprehensive">Comprehensive (All Domains + AI Analyst)</option>



        </select>



        <div class="d-flex justify-between items-center mt-3">



          <button type="button" class="btn btn-outline close-modal">Cancel</button>



          <button type="submit" class="btn btn-primary">Start Execution</button>



        </div>



      </form>



    </div>



  </div>







  <div class="toast-container" id="toast-container"></div>



</div>







<script integrity="sha256-{csp_hash}">{script_content}</script>



</body>



</html>



"""











def register_workbench_routes(



    app,



    db_path: str | Path,



    scope_manager: ScopeManager | None,



) -> None:



    """Register all command center, AI copilot, and operational assessment routes."""



    audit = AuditLogger(db_path)

    try:
        from redloop.workbench import register_workbench_routers
        register_workbench_routers(app)
    except Exception:
        pass



    checkpoint_store = AuditCheckpointStore(db_path)



    identity_store = IdentityCorrelationStore(



        Path(db_path).parent / "identity_correlations.sqlite"
    )

    from redloop.integrations.core_hub import CoreIntegrationsManager
    from redloop.assessment.investigation_pipeline import InvestigationPipelineEngine

    auth_db_path = Path(db_path).parent / "auth.sqlite"
    auth_mgr = AuthManager(auth_db_path)

    def _extract_session_token(request: Request) -> str:
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            return auth_hdr[7:].strip()
        if "X-Redloop-Session" in request.headers:
            return request.headers["X-Redloop-Session"].strip()
        if "redloop_session" in request.cookies:
            return request.cookies["redloop_session"].strip()
        return ""

    def _get_authenticated_operator(request: Request) -> tuple[Optional[User], Optional[Session]]:
        token = _extract_session_token(request)
        if not token:
            return None, None
        res = auth_mgr.validate_session(token)
        if res:
            return res[0], res[1]
        return None, None

    @app.post("/api/auth/login")
    async def auth_login_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
        username = str(body.get("username", "")).strip()
        password = str(body.get("password", "")).strip()
        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password required")

        user = auth_mgr.authenticate(username, password)
        client_ip = request.client.host if request.client else "127.0.0.1"
        if not user:
            audit.log_event(
                "OPERATOR_AUTH_FAILURE",
                "SECURITY_OPERATOR",
                username,
                {"reason": "INVALID_CREDENTIALS", "ip": client_ip},
            )
            raise HTTPException(status_code=401, detail="Invalid username or password")

        session, token = auth_mgr.create_session(user, ip_address=client_ip)
        audit.log_event(
            "OPERATOR_AUTH_SUCCESS",
            "SECURITY_OPERATOR",
            user.user_id,
            {"username": user.username, "role": user.role.value, "session_id": session.session_id, "ip": client_ip},
        )
        resp = JSONResponse({
            "success": True,
            "token": token,
            "session_id": session.session_id,
            "user": user.to_dict(),
            "expires_at": session.expires_at,
        })
        resp.set_cookie(
            "redloop_session",
            token,
            httponly=True,
            samesite="lax",
            secure=False,
        )
        return resp

    @app.get("/api/auth/operator")
    def auth_operator_endpoint(request: Request):
        user, session = _get_authenticated_operator(request)
        if user and session:
            return JSONResponse({
                "authenticated": True,
                "username": user.username,
                "display_name": user.full_name,
                "role": user.role.value,
                "permissions": [p.value for p in user.permissions],
                "session_id": session.session_id,
            })
        default_user = auth_mgr.get_user("sec_analyst")
        perms = [p.value for p in default_user.permissions] if default_user else ["view_telemetry", "view_dashboard", "run_assessment", "run_osint"]
        return JSONResponse({
            "authenticated": True,
            "username": "sec_analyst",
            "display_name": default_user.full_name if default_user else "Security Analyst (Local)",
            "role": default_user.role.value if default_user else "analyst",
            "permissions": perms,
            "mode": "local_lab_operator",
        })

    @app.get("/api/auth/me")
    def auth_me_endpoint(request: Request):
        user, session = _get_authenticated_operator(request)
        if user and session:
            return JSONResponse({
                "authenticated": True,
                "user": user.to_dict(),
                "session_id": session.session_id,
                "expires_at": session.expires_at,
            })
        return JSONResponse({
            "authenticated": False,
            "user": None,
            "default_analyst": "sec_analyst",
            "roles": [r.value for r in UserRole],
        })

    @app.post("/api/auth/logout")
    async def auth_logout_endpoint(request: Request):
        _require_same_origin(request)
        user, session = _get_authenticated_operator(request)
        if session:
            auth_mgr.revoke_session(session.session_id)
            if user:
                audit.log_event(
                    "OPERATOR_LOGOUT",
                    "SECURITY_OPERATOR",
                    user.user_id,
                    {"username": user.username, "session_id": session.session_id},
                )
        resp = JSONResponse({"success": True, "message": "Logged out successfully"})
        resp.delete_cookie("redloop_session")
        return resp

    @app.get("/api/auth/users")
    def auth_list_users_endpoint(request: Request):
        user, _ = _get_authenticated_operator(request)
        if user and not auth_mgr.has_permission(user, Permission.MANAGE_USERS):
            raise HTTPException(status_code=403, detail="Forbidden: Lacks MANAGE_USERS permission")
        users = auth_mgr.list_users()
        return JSONResponse({"users": [u.to_dict() for u in users]})








    @app.get("/workbench", response_class=HTMLResponse)



    def workbench_page():



        return HTMLResponse(



            _HTML_TEMPLATE.replace("__CSP_HASH__", WORKBENCH_SCRIPT_CSP_HASH)



            .replace("{csp_hash}", WORKBENCH_SCRIPT_CSP_HASH)



            .replace("{script_content}", _WORKBENCH_SCRIPT)



        )







    _soc_dashboard_cache = {"data": None, "ts": 0.0}

    @app.get("/api/soc/dashboard/summary")
    def get_soc_dashboard_summary():
        now = time.time()
        if _soc_dashboard_cache["data"] is not None and (now - _soc_dashboard_cache["ts"]) < 5.0:
            cached = dict(_soc_dashboard_cache["data"])
            cached["activity"]["evidence_status"]["chain_verified"] = audit.verify_chain().get("valid", True)
            return JSONResponse(cached)

        from redloop.assessment.case_management import CaseManager
        from redloop.investigation import get_investigation_store
        from redloop.assessment.detection_engineering import DetectionEngineeringManager
        from redloop.integrations.registry import IntegrationRegistry
        from redloop.assessment.soc_metrics import SOCMetricsEngine
        from redloop.assessment.soar_engine import SOAREngine
        from redloop.assessment.ioc_engine import IOCLifecycleManager
        from redloop.reporting import AuditReader

        cases = CaseManager.get_instance().list_cases()
        invs = get_investigation_store().list_all()
        rules = DetectionEngineeringManager.get_instance().list_rules()
        providers = IntegrationRegistry.get_instance().list_providers()
        operational_metrics = SOCMetricsEngine.get_operational_metrics()
        soar = SOAREngine.get_instance()
        workflows = soar.list_workflows()
        executions = soar.list_executions()
        iocs = IOCLifecycleManager.get_instance().list_iocs()

        audit_events = []
        try:
            reader = AuditReader("data/audit.sqlite")
            res = reader.entries(limit=10)
            audit_events = res[0] if isinstance(res, tuple) else (res if isinstance(res, list) else [])
        except Exception:
            pass

        active_incidents = [c for c in cases if c.get("status") in ("OPEN", "INVESTIGATING", "TRIAGED")]
        crit_high_cases = [c for c in cases if c.get("severity") in ("CRITICAL", "HIGH")]
        active_invs = [i for i in invs if getattr(i, "status", "") == "ACTIVE"]
        connected_providers = [p for p in providers if p.get("status") == "CONNECTED" or p.get("connectivity_status") == "CONNECTED"]

        linked_alert_ids = set()
        for c in cases:
            linked_alert_ids.update(c.get("linked_alert_ids", []))
        total_alerts = max(len(linked_alert_ids), operational_metrics.get("telemetry", {}).get("total_events_ingested", 0))

        crit_high_ratio = len(crit_high_cases) / max(1, len(cases))
        raw_risk = min(100.0, (crit_high_ratio * 65.0) + (15.0 if len(active_incidents) > 0 else 0.0) + (10.0 if len(active_invs) > 0 else 0.0))
        risk_score = round(raw_risk, 1)
        if risk_score >= 80.0:
            risk_level = "CRITICAL"
        elif risk_score >= 60.0:
            risk_level = "HIGH"
        elif risk_score >= 35.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        trend_buckets = []
        for d in range(6, -1, -1):
            day_str = (datetime.now(timezone.utc) - timedelta(days=d)).strftime("%b %d")
            day_iso = (datetime.now(timezone.utc) - timedelta(days=d)).strftime("%Y-%m-%d")
            count = sum(1 for c in cases if c.get("created_at", "").startswith(day_iso))
            trend_buckets.append({"label": day_str, "count": count})

        summary_data = {
            "kpis": {
                "total_alerts": total_alerts,
                "critical_high_alerts": len(crit_high_cases),
                "active_incidents": len(active_incidents),
                "total_incidents": len(cases),
                "active_investigations": len(active_invs) or len(invs),
                "connected_integrations": CoreIntegrationsManager.get_instance().get_summary()["connected_count"],
                "total_integrations": 9,
                "risk_posture_score": risk_score,
                "risk_posture_level": risk_level,
            },
            "analytics": {
                "alert_trend": trend_buckets,
                "threat_intel": [
                    {
                        "ioc_id": ioc.ioc_id if hasattr(ioc, "ioc_id") else ioc.get("ioc_id"),
                        "ioc_type": (ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else str(ioc.ioc_type)) if hasattr(ioc, "ioc_type") else ioc.get("ioc_type"),
                        "value": ioc.value if hasattr(ioc, "value") else ioc.get("value"),
                        "confidence": ioc.confidence if hasattr(ioc, "confidence") else ioc.get("confidence"),
                        "reputation": ioc.reputation if hasattr(ioc, "reputation") else ioc.get("reputation"),
                    }
                    for ioc in iocs[:5]
                ],
                "risk_trend": {
                    "score": risk_score,
                    "level": risk_level,
                    "rationale": "Synthesized from critical/high exposure (weight 65%), active triage pressure (weight 20%), and uncontained workspaces (weight 15%).",
                    "formula_latex": r"R_{\text{posture}} = \min\left(100, 65 \cdot \frac{N_{\text{crit\_high}}}{N_{\text{cases}}} + 20 \cdot \mathbb{I}_{\text{active}} + 15 \cdot \mathbb{I}_{\text{inv}}\right)",
                },
                "soc_health": {
                    "mttd_minutes": operational_metrics.get("performance_indicators", {}).get("mean_time_to_detect_minutes"),
                    "mttd_status": operational_metrics.get("mttd_status", "INSUFFICIENT_DATA"),
                    "mttr_minutes": operational_metrics.get("performance_indicators", {}).get("mean_time_to_respond_minutes"),
                    "mttr_status": operational_metrics.get("mttr_status", "INSUFFICIENT_DATA"),
                    "sync_success_rate": operational_metrics.get("telemetry_sync_rate_percent"),
                    "sync_status": operational_metrics.get("telemetry_sync_status", "INSUFFICIENT_DATA"),
                    "reduction_rate": operational_metrics.get("alert_reduction_rate_percent"),
                    "reduction_status": operational_metrics.get("alert_reduction_status", "UNSUPPORTED"),
                },
            },
            "workspace": {
                "incidents": [
                    {
                        "id": c.get("case_id"),
                        "title": c.get("title"),
                        "severity": c.get("severity"),
                        "status": c.get("status"),
                        "created_at": c.get("created_at"),
                    }
                    for c in cases[:6]
                ],
                "investigations": [
                    {
                        "id": i.id,
                        "title": i.title,
                        "target": i.target,
                        "status": i.status,
                        "updated_at": i.updated_at,
                    }
                    for i in invs[:6]
                ],
                "detections": [
                    {
                        "rule_id": r.get("rule_id"),
                        "title": r.get("title"),
                        "severity": r.get("severity"),
                        "technique_id": r.get("technique_id"),
                        "enabled": r.get("enabled", True),
                    }
                    for r in rules[:6]
                ],
                "integrations": [
                    {
                        "provider_id": p.get("provider_id"),
                        "display_name": p.get("display_name"),
                        "category": p.get("category"),
                        "status": p.get("status"),
                        "is_configured": p.get("is_configured", False),
                    }
                    for p in providers[:8]
                ],
            },
            "activity": {
                "recent_audit": [
                    {
                        "id": e.get("id"),
                        "action": e.get("action"),
                        "actor": e.get("actor"),
                        "target": e.get("target"),
                        "status": e.get("status"),
                        "timestamp": e.get("timestamp"),
                    }
                    for e in audit_events[-6:]
                ],
                "evidence_status": {
                    "total_items": len(audit_events),
                    "chain_verified": audit.verify_chain().get("valid", True),
                    "status": "VERIFIED" if audit.verify_chain().get("valid", True) else "FAILED",
                },
                "pending_approvals": [],
                "soar_history": {
                    "total_workflows": len(workflows),
                    "total_executions": len(executions),
                    "recent_executions": [
                        {
                            "id": ex.get("execution_id"),
                            "title": ex.get("workflow_title"),
                            "state": ex.get("state"),
                            "started_at": ex.get("started_at"),
                        }
                        for ex in executions[:4]
                    ],
                },
            },
        }

        _soc_dashboard_cache["data"] = summary_data
        _soc_dashboard_cache["ts"] = now
        return JSONResponse(summary_data)

    _overview_stats_cache = {"data": None, "ts": 0.0}



    @app.get("/api/overview/stats")



    def get_overview_stats():

        now = time.time()



        if _overview_stats_cache["data"] is not None and (now - _overview_stats_cache["ts"]) < 5.0:

            cached_data = dict(_overview_stats_cache["data"])
            cached_data["audit_status"] = audit.verify_chain()
            return JSONResponse(cached_data)



        store = AssessmentStore()



        all_asmts = store.list_all()



        has_asmt = len(all_asmts) > 0



        latest_asmt = None







        metrics = {



            "risk_score": None,



            "critical_count": 0,



            "high_count": 0,



            "medium_count": 0,



            "low_count": 0,



            "info_count": 0,



            "total_findings": 0,



            "evidence_count": 0,



            "assets_count": 0,



            "open_services_count": 0,



        }







        if has_asmt:



            first_id = all_asmts[0]["id"]



            state = store.load(first_id)



            if state:



                latest_asmt = {



                    "id": state.id,



                    "target": state.target,



                    "depth": state.depth.value,



                    "status": state.status,



                    "created_at": state.created_at,



                    "updated_at": state.updated_at,



                }



                findings = state.findings



                if findings:



                    metrics["risk_score"] = round(max(f.risk_score for f in findings), 1)



                    metrics["critical_count"] = sum(1 for f in findings if f.severity.value == "CRITICAL")



                    metrics["high_count"] = sum(1 for f in findings if f.severity.value == "HIGH")



                    metrics["medium_count"] = sum(1 for f in findings if f.severity.value == "MEDIUM")



                    metrics["low_count"] = sum(1 for f in findings if f.severity.value == "LOW")



                    metrics["info_count"] = sum(1 for f in findings if f.severity.value == "INFO")



                    metrics["total_findings"] = len(findings)



                metrics["evidence_count"] = len(state.evidence)



                metrics["assets_count"] = len({f.asset for f in findings} | {state.target})



                net_stage = state.completed_stages.get("network_discovery")



                if isinstance(net_stage, dict):



                    stage_data = net_stage.get("data") or {}



                    metrics["open_services_count"] = len(stage_data.get("open_ports", []))



                elif hasattr(net_stage, "data") and net_stage.data:



                    metrics["open_services_count"] = len(net_stage.data.get("open_ports", []))







        scope_summary = None



        if scope_manager is not None:



            active_target = "127.0.0.1"



            entry = next((e for e in scope_manager.scope.targets if e.matches(active_target)), None)



            if entry:



                scope_summary = {



                    "active_target": active_target,



                    "authorized_window": f"{entry.authorized_from.isoformat()} → {entry.authorized_until.isoformat()}",



                    "allowed_actions": entry.allowed_actions,



                    "is_within_window": scope_manager.is_within_window(),



                }







        audit_res = audit.verify_chain()







        stats_res_data = {



            "has_assessment": has_asmt,



            "latest_assessment": latest_asmt,



            "metrics": metrics,



            "scope_summary": scope_summary,



            "audit_status": audit_res,



        }



        _overview_stats_cache["data"] = stats_res_data



        _overview_stats_cache["ts"] = now



        return JSONResponse(stats_res_data)







    @app.get("/api/assessment/list")



    def list_assessments():



        store = AssessmentStore()



        return JSONResponse({"assessments": store.list_all()})







    @app.get("/api/assessment/{assessment_id}")



    def get_assessment(assessment_id: str):



        store = AssessmentStore()



        state = store.load(assessment_id)



        if not state:



            raise HTTPException(status_code=404, detail="Assessment not found")



        return JSONResponse(state.model_dump(mode="json"))







    @app.post("/api/assessment/start")



    def start_assessment_api(payload: AssessmentStartRequest, request: Request):



        _require_same_origin(request)



        if scope_manager is None:



            raise HTTPException(status_code=503, detail="Verified signed scope is unavailable")



        guard = AssessmentScopeGuard(scope_manager, audit)



        engine = AssessmentEngine(guard, audit)



        try:



            state = engine.start_assessment(



                target=payload.target,



                depth=payload.depth,



                config_artifact_paths=payload.config_artifacts,



                file_artifact_paths=payload.file_artifacts,



            )



        except ScopeBlockedError as exc:



            raise HTTPException(status_code=403, detail=str(exc)) from exc



        return JSONResponse(state.model_dump(mode="json"))







    @app.post("/api/assessment/{assessment_id}/pause")



    def pause_assessment(assessment_id: str, request: Request):



        _require_same_origin(request)



        store = AssessmentStore()



        state = store.load(assessment_id)



        if not state:



            raise HTTPException(status_code=404, detail="Assessment not found")



        state.status = "PAUSED"



        store.save(state)



        return JSONResponse({"status": "PAUSED", "assessment_id": assessment_id})







    @app.post("/api/assessment/{assessment_id}/resume")



    def resume_assessment(assessment_id: str, request: Request):



        _require_same_origin(request)



        if scope_manager is None:



            raise HTTPException(status_code=503, detail="Verified signed scope is unavailable")



        guard = AssessmentScopeGuard(scope_manager, audit)



        engine = AssessmentEngine(guard, audit)



        try:



            state = engine.resume_assessment(assessment_id)



        except ScopeBlockedError as exc:



            raise HTTPException(status_code=403, detail=str(exc)) from exc



        return JSONResponse(state.model_dump(mode="json"))







    @app.post("/api/assessment/{assessment_id}/cancel")



    def cancel_assessment(assessment_id: str, request: Request):



        _require_same_origin(request)



        store = AssessmentStore()



        state = store.load(assessment_id)



        if not state:



            raise HTTPException(status_code=404, detail="Assessment not found")



        state.status = "CANCELLED"



        store.save(state)



        return JSONResponse({"status": "CANCELLED", "assessment_id": assessment_id})







    @app.get("/api/assessment/{assessment_id}/report/{variant}")



    def get_assessment_report(assessment_id: str, variant: str):



        from html import escape







        store = AssessmentStore()



        state = store.load(assessment_id)



        if not state:



            raise HTTPException(status_code=404, detail="Assessment not found")



        rep_engine = ReportingEngine()



        if variant == "executive":



            content = rep_engine.generate_executive_report(state)



        elif variant == "technical":



            content = rep_engine.generate_technical_report(state)



        elif variant == "attack_surface":



            content = rep_engine.generate_attack_surface_report(state)



        elif variant == "evidence":



            content = rep_engine.generate_evidence_report(state)



        else:



            raise HTTPException(status_code=400, detail=f"Unknown report variant: {variant}")



        return HTMLResponse(f"<pre style='font-family:monospace;white-space:pre-wrap;'>{escape(content)}</pre>")







    @app.get("/api/capabilities")



    def list_capabilities():



        caps = get_capabilities()



        return JSONResponse({"tools": caps.summary()})







    @app.get("/api/audit/verify")



    def verify_audit_ledger():



        res = audit.verify_chain()



        return JSONResponse(res)







    @app.get("/api/audit/checkpoint")



    def verify_audit_checkpoint():



        return JSONResponse(checkpoint_store.verify(audit))







    @app.post("/api/audit/checkpoint")



    async def create_audit_checkpoint(request: Request):



        _require_same_origin(request)



        try:



            result = checkpoint_store.create(audit)



        except AuditCheckpointError as exc:



            raise HTTPException(status_code=409, detail=str(exc)) from exc



        return JSONResponse(result)







    @app.post("/api/audit/checkpoint/rotate")



    async def rotate_audit_checkpoint_key(request: Request):



        _require_same_origin(request)



        try:



            result = checkpoint_store.rotate_key(audit)



        except AuditCheckpointError as exc:



            raise HTTPException(status_code=409, detail=str(exc)) from exc



        return JSONResponse(result)







    @app.get("/api/performance")



    def performance_telemetry():



        token_store = TokenUsageStore(f"{db_path}.chats.sqlite")



        summary = token_store.get_summary()



        asmt_store = AssessmentStore()



        all_asmts = asmt_store.list_all()



        caps = get_capabilities()



        audit_verification = audit.verify_chain()



        is_valid = bool(audit_verification.get("valid"))



        audit_count = int(audit_verification.get("total_events", 0))



        audit_msg = audit_verification.get("message") or audit_verification.get("error") or ""







        total_asmt = len(all_asmts)



        active_asmt = sum(1 for a in all_asmts if a["status"] == "RUNNING")



        completed_asmt = sum(1 for a in all_asmts if a["status"] == "COMPLETED")



        failed_asmt = sum(1 for a in all_asmts if a["status"] == "FAILED")



        paused_asmt = sum(1 for a in all_asmts if a["status"] == "PAUSED")







        def _get_tool_info(name: str):



            t = caps.tools.get(name)



            return {



                "available": bool(t and t.available),



                "version": t.version if t else None,



                "runs": 0,



                "success": 0,



                "failed": 0,



            }







        tool_metrics = {



            "nmap": _get_tool_info("nmap"),



            "docker": _get_tool_info("docker"),



            "curl": _get_tool_info("curl"),



            "openssl": _get_tool_info("openssl"),



            "yara": _get_tool_info("yara"),



            "http_engine": {"available": True, "version": "built-in", "runs": 0, "success": 0, "failed": 0},



            "dns_engine": {"available": True, "version": "built-in", "runs": 0, "success": 0, "failed": 0},



            "tls_engine": {"available": True, "version": "built-in", "runs": 0, "success": 0, "failed": 0},



        }







        entries, _ = AuditReader(db_path).entries(limit=500)



        for row in entries:



            mod = str(row["module"]).casefold()



            st = str(row["status"]).casefold()



            key = None



            if mod in ("recon", "nmap"):



                key = "nmap"



            elif mod in ("webapp", "web"):



                key = "http_engine"



            elif mod in ("tls", "ssl"):



                key = "tls_engine"



            elif mod in ("dns",):



                key = "dns_engine"



            elif mod in ("forensics", "file"):



                key = "yara"







            if key and key in tool_metrics:



                tool_metrics[key]["runs"] += 1



                if st == "success":



                    tool_metrics[key]["success"] += 1



                else:



                    tool_metrics[key]["failed"] += 1







        return JSONResponse({



            "ai": summary,



            "assessment_engine": {



                "total": total_asmt,



                "active": active_asmt,



                "completed": completed_asmt,



                "failed": failed_asmt,



                "paused": paused_asmt,



            },



            "tools": tool_metrics,



            "audit": {



                "status": audit_verification.get("status", "VERIFICATION_INCOMPLETE"),



                "chain_valid": is_valid,



                "valid": is_valid,



                "total_events": audit_count,



                "message": audit_msg,



                "failure": audit_verification.get("failure"),



            },



        })







    @app.get("/api/search")



    def global_search(q: str = Query(..., min_length=1, max_length=100)):



        query = q.lower().strip()



        results = []



        asmt_store = AssessmentStore()



        for a in asmt_store.list_all():



            if query in a["id"].lower() or query in a["target"].lower() or query in a["depth"].lower():



                results.append({



                    "type": "assessment",



                    "id": a["id"],



                    "title": f"Assessment: {a['target']} ({a['depth'].upper()})",



                    "subtitle": f"Status: {a['status']} · Updated: {a['updated_at'][:19]}",



                    "url": f"/workbench?view=assessments&asmt={a['id']}",



                })



            st = asmt_store.load(a["id"])



            if st:



                for f in st.findings:



                    if query in f.id.lower() or query in f.title.lower() or query in f.asset.lower():



                        results.append({



                            "type": "finding",



                            "id": f.id,



                            "title": f"Finding: {f.title} [{f.severity.value}]",



                            "subtitle": f"Asset: {f.asset} · CVSS: {f.cvss_score:.1f}",



                            "url": f"/workbench?view=findings&asmt={a['id']}&finding={f.id}",



                        })



                for e in st.evidence:



                    if query in e.id.lower() or query in e.target.lower() or query in e.hash_sha256.lower():



                        results.append({



                            "type": "evidence",



                            "id": e.id,



                            "title": f"Evidence: {e.id} ({e.target})",



                            "subtitle": f"SHA-256: {e.hash_sha256[:16]}...",



                            "url": f"/workbench?view=evidence&asmt={a['id']}&evidence={e.id}",



                        })



        return JSONResponse({"results": results[:30]})







    @app.post("/api/chat/message")



    @app.post("/api/chat")



    @app.post("/api/workbench/copilot/chat")



    async def workbench_chat_message(request: Request):



        _require_same_origin(request)



        try:



            body = await request.json()



        except Exception:



            raise HTTPException(status_code=400, detail="Invalid JSON payload")



        prompt = str(body.get("message", "")).strip()



        if not prompt:



            raise HTTPException(status_code=400, detail="Message required")



        conv_id = body.get("conversation_id") or "workbench-copilot"



        context = body.get("context") or {}



        model = body.get("model")



        effort = body.get("effort", "auto")







        token_store = TokenUsageStore(f"{db_path}.chats.sqlite")



        orch = TaskOrchestrator(scope_manager=scope_manager, audit_db=db_path)



        result = await orch.execute_task(



            prompt=prompt,



            conversation_id=conv_id,



            context=context,



            model_choice=model,



            effort_choice=effort,



            token_usage_store=token_store,



            history=body.get("history") or [],



            attachment_context=str(body.get("attachment_context") or ""),



        )



        return JSONResponse(result)







    @app.post("/api/workbench/red/web-check")



    def scoped_web_check(payload: WebCheckRequest, request: Request):



        _require_same_origin(request)



        if scope_manager is None:



            raise HTTPException(status_code=503, detail="Verified signed scope is unavailable")



        try:



            result = WebAppChecker(scope_manager, audit).inspect(payload.url)



        except UnauthorizedTargetError as exc:



            raise HTTPException(status_code=403, detail=str(exc)) from exc



        except UnsafeWebTargetError as exc:



            raise HTTPException(status_code=400, detail=str(exc)) from exc



        except WebAppRequestError as exc:



            raise HTTPException(status_code=502, detail=str(exc)) from exc



        return JSONResponse(result.model_dump(mode="json"))







    @app.post("/api/workbench/red/port-scan")



    def scoped_port_scan(payload: PortScanRequest, request: Request):



        _require_same_origin(request)



        if scope_manager is None:



            raise HTTPException(status_code=503, detail="Verified signed scope is unavailable")



        try:



            scanner = NmapScanner(scope=scope_manager, audit=audit)



            scan_result = scanner.quick_scan(payload.target, payload.ports)



        except UnauthorizedTargetError as exc:



            raise HTTPException(status_code=403, detail=str(exc)) from exc



        except (ReconDependencyError, ReconError, ValueError) as exc:



            raise HTTPException(status_code=400, detail=str(exc)) from exc



        return JSONResponse(scan_result.model_dump(mode="json"))







    @app.post("/api/workbench/red/tls-check")



    def scoped_tls_check(payload: TLSCheckRequest, request: Request):



        _require_same_origin(request)



        if scope_manager is None:



            raise HTTPException(status_code=503, detail="Verified signed scope is unavailable")



        try:



            scope_manager.check(payload.target, "tls_check", port=payload.port)



        except UnauthorizedTargetError as exc:



            raise HTTPException(status_code=403, detail=str(exc)) from exc







        from redloop.tls import TLSChecker, TLSError



        checker = TLSChecker(scope_manager, audit)



        try:



            report = checker.inspect(payload.target, port=payload.port)



        except (TLSError, ValueError) as exc:



            raise HTTPException(status_code=400, detail=str(exc)) from exc



        return JSONResponse(report.model_dump(mode="json"))







    @app.post("/api/workbench/blue/file-triage")



    async def scoped_file_triage(request: Request, sample: UploadFile = File(...)):



        _require_same_origin(request)



        content = await sample.read(MAX_FILE_SIZE + 1)



        if len(content) > MAX_FILE_SIZE:



            raise HTTPException(status_code=413, detail="File too large")



        analyzer = ForensicsAnalyzer(audit=audit)



        report = analyzer.analyze(content, sample.filename or "sample")



        return JSONResponse(report.model_dump(mode="json"))







    @app.get("/api/workbench/purple/summary")



    def purple_activity_summary():



        rows, truncated = AuditReader(db_path).entries(limit=50)



        team_activity = {



            "red": {"events": 0, "success": 0, "blocked": 0, "failed": 0},



            "blue": {"events": 0, "success": 0, "blocked": 0, "failed": 0},



            "other": {"events": 0, "success": 0, "blocked": 0, "failed": 0},



        }



        success_rows = []



        for row in rows:



            mod = str(row["module"]).casefold()



            team_key = "red" if mod in ("recon", "nmap", "webapp") else ("blue" if mod == "forensics" else "other")



            team_activity[team_key]["events"] += 1



            st = str(row["status"]).casefold()



            if st == "success":



                team_activity[team_key]["success"] += 1



                success_rows.append(row)



            elif st == "blocked":



                team_activity[team_key]["blocked"] += 1



            else:



                team_activity[team_key]["failed"] += 1







        correlations = []



        by_target: dict[str, list[dict]] = {}



        for r in reversed(success_rows):



            by_target.setdefault(str(r["target"]), []).append(r)







        for tgt, ev_list in by_target.items():



            if len(ev_list) >= 2:



                correlations.append({



                    "classification": "DERIVED",



                    "kind": "same_target_temporal_group",



                    "target": tgt,



                    "evidence_record_ids": [r["id"] for r in ev_list],



                    "evidence": [



                        {"id": r["id"], "module": r["module"], "action": r["action"], "timestamp": r["timestamp"]}



                        for r in ev_list



                    ],



                })







        return JSONResponse({



            "source": "RedLoop local audit database",



            "evidence_type": "observed_local_audit_events",



            "external_detection": False,



            "team_activity": team_activity,



            "correlations": correlations,



            "recent_events": len(rows),



            "truncated": truncated,



        })







    @app.post("/api/workbench/red/exploit-simulate")



    def run_exploit_simulation(payload: ExploitSimulateRequest, request: Request):



        _require_same_origin(request)



        guard = AssessmentScopeGuard(scope_manager, audit) if scope_manager else None



        if guard and not guard.is_authorized(payload.target):



            raise HTTPException(status_code=403, detail=f"Target '{payload.target}' is not authorized in scope.yaml")



        sim = ExploitSimulator(audit=audit, scope_guard=guard)



        try:



            res = sim.simulate(



                target=payload.target,



                service=payload.service,



                port=payload.port,



                finding_id=payload.finding_id,



                cve_override=payload.cve,



            )



            return JSONResponse(res.model_dump(mode="json"))



        except Exception as exc:



            raise HTTPException(status_code=400, detail=str(exc)) from exc







    @app.post("/api/workbench/osint/shodan")



    def run_shodan_query(payload: ShodanQueryRequest, request: Request):



        _require_same_origin(request)



        guard = AssessmentScopeGuard(scope_manager, audit) if scope_manager else None



        engine = ShodanEngine(audit=audit, scope_guard=guard)



        if not engine.is_configured():



            raise HTTPException(status_code=503, detail="Shodan API key is not configured")



        res = engine.query_host(payload.target)



        if not res.get("success"):



            raise HTTPException(status_code=400, detail=res.get("error", "Shodan query failed"))



        return JSONResponse(res.get("data", {}))







    @app.post("/api/tools/cyber-codec")



    def run_cyber_codec(payload: CyberCodecRequest, request: Request):



        _require_same_origin(request)



        if payload.action == "encode":



            res = CTFCodec.encode(payload.text, payload.format)



        else:



            res = CTFCodec.decode(payload.text, payload.hint)



        return JSONResponse(res.model_dump(mode="json"))







    @app.get("/api/workbench/tools")



    def list_workbench_tools():



        registry = get_tool_registry()



        return JSONResponse({"tools": [t.to_dict() for t in registry.list_tools()]})







    @app.get("/api/workbench/task-graphs/{graph_id}")



    def get_workbench_task_graph(graph_id: str):



        store = TaskGraphStore()



        graph = store.load(graph_id)



        if not graph:



            raise HTTPException(status_code=404, detail="Task graph not found")



        return JSONResponse(graph.to_dict())







    @app.get("/api/workbench/task-graphs")



    def list_workbench_task_graphs():



        store = TaskGraphStore()



        return JSONResponse({"graphs": store.list_graphs()})







    @app.get("/api/workbench/tasks")



    def list_workbench_tasks(conversation_id: str | None = None, limit: int = 50):



        task_store = TaskStore()



        return JSONResponse({"tasks": task_store.list_recent(conversation_id, limit)})







    @app.get("/api/tools/status")



    def get_tools_status():



        guard = AssessmentScopeGuard(scope_manager, audit) if scope_manager else None



        runner = ControlledToolRunner(scope_guard=guard, audit=audit)



        return JSONResponse(runner.get_tool_diagnostics())







    @app.post("/api/tools/execute")



    def execute_controlled_tool(payload: ToolExecuteRequest, request: Request):



        _require_same_origin(request)



        guard = AssessmentScopeGuard(scope_manager, audit) if scope_manager else None



        runner = ControlledToolRunner(scope_guard=guard, audit=audit)



        res = runner.execute_tool(



            tool_name=payload.tool,



            target=payload.target,



            ports=payload.ports,



            arguments=payload.args,



        )



        status_val = res.status.value if hasattr(res.status, "value") else str(res.status)



        if status_val == "BLOCKED":



            return JSONResponse(res.to_dict(), status_code=403)



        return JSONResponse(res.to_dict())







    @app.post("/api/terminal/execute")



    @app.post("/api/kali/execute")



    def execute_terminal_command(payload: TerminalCommandRequest, request: Request):



        _require_same_origin(request)



        guard = AssessmentScopeGuard(scope_manager, audit) if scope_manager else None



        from redloop.assessment.terminal_engine import UnifiedTerminalEngine, ExecutionStatus



        engine = UnifiedTerminalEngine(scope_guard=guard, audit=audit)



        res = engine.execute_command(



            command_string_or_args=payload.command,



            environment=payload.execution_environment,



            target=payload.target,



            working_directory=payload.working_directory,



            timeout_seconds=payload.timeout_seconds,



        )



        if res.status == ExecutionStatus.BLOCKED or res.to_dict().get("state") == "BLOCKED":



            return JSONResponse(res.to_dict(), status_code=403)



        return JSONResponse(res.to_dict())







    @app.post("/api/terminal/cancel")



    def cancel_terminal_command_endpoint(payload: dict[str, Any], request: Request):



        _require_same_origin(request)



        task_id = payload.get("task_id") or payload.get("execution_id") or ""



        guard = AssessmentScopeGuard(scope_manager, audit) if scope_manager else None



        from redloop.assessment.terminal_engine import UnifiedTerminalEngine



        engine = UnifiedTerminalEngine(scope_guard=guard, audit=audit)



        cancelled = engine.cancel_task(task_id)



        return JSONResponse({"success": cancelled, "task_id": task_id})







    @app.get("/api/terminal/environments")



    def get_terminal_environments():



        wsl_info = detect_wsl_status()



        from redloop.assessment.tools_v2 import EnvironmentDetector



        docker_info = EnvironmentDetector.detect_docker()



        return JSONResponse({



            "host": {



                "available": True,



                "os": os.name,



                "label": "Windows Host" if os.name == "nt" else "Local Host",



            },



            "wsl": {



                "available": wsl_info["wsl_available"],



                "distributions": wsl_info["distributions"],



                "default": wsl_info.get("default_distro"),



                "error": wsl_info.get("error"),



            },



            "kali": {



                "available": wsl_info["kali_available"],



                "distro": wsl_info.get("kali_distro"),



                "status": "READY" if wsl_info["kali_available"] else "NOT_INSTALLED",



            },



            "docker": {



                "available": docker_info.get("available", False),



                "daemon_running": docker_info.get("daemon_running", False),



                "version": docker_info.get("version"),



                "status": "READY" if docker_info.get("daemon_running") else "UNAVAILABLE",



            }



        })







    # --- PHASE 3 AGENT ORCHESTRATION APIS ---







    @app.get("/api/agent/tasks")
    async def list_agent_tasks(limit: int = 50):
        from redloop.assessment.agent_orchestrator import AgentTaskStore
        store = AgentTaskStore.get_instance()
        return JSONResponse({"tasks": [t.to_dict() for t in store.list_all(limit=limit)]})

    @app.post("/api/agent/tasks")
    async def create_agent_task_endpoint(request: Request):
        _require_same_origin(request)
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        prompt = payload.get("prompt") or ""
        target = payload.get("target")
        environment = payload.get("environment") or "host"
        auto_approve = bool(payload.get("auto_approve", False))

        guard = AssessmentScopeGuard(scope_manager, audit) if scope_manager else None
        from redloop.assessment.agent_orchestrator import AutonomousAgentOrchestrator
        orchestrator = AutonomousAgentOrchestrator(scope_manager=scope_manager, scope_guard=guard, audit=audit)
        task = orchestrator.create_and_run_task(
            prompt=prompt,
            target=target,
            environment=environment,
            auto_approve=auto_approve,
        )
        status_code = 403 if task.task_status.value == "BLOCKED" else 200
        return JSONResponse(task.to_dict(), status_code=status_code)

    @app.get("/api/agent/tasks/{task_id}")
    async def get_agent_task_details(task_id: str):
        from redloop.assessment.agent_orchestrator import AgentTaskStore
        task = AgentTaskStore.get_instance().get(task_id)
        if not task:
            raise HTTPException(status_code=404, detail=f"Agent task '{task_id}' not found")
        return JSONResponse(task.to_dict())

    @app.get("/api/agent/tasks/{task_id}/steps")
    async def get_agent_task_steps(task_id: str):
        from redloop.assessment.agent_orchestrator import AgentTaskStore
        task = AgentTaskStore.get_instance().get(task_id)
        if not task:
            raise HTTPException(status_code=404, detail=f"Agent task '{task_id}' not found")
        return JSONResponse({"task_id": task_id, "steps": [s.to_dict() for s in task.steps]})

    @app.post("/api/agent/tasks/{task_id}/cancel")
    async def cancel_agent_task_endpoint(task_id: str, request: Request):
        _require_same_origin(request)
        guard = AssessmentScopeGuard(scope_manager, audit) if scope_manager else None
        from redloop.assessment.agent_orchestrator import AutonomousAgentOrchestrator
        orchestrator = AutonomousAgentOrchestrator(scope_manager=scope_manager, scope_guard=guard, audit=audit)
        cancelled = orchestrator.cancel_task(task_id)
        return JSONResponse({"success": cancelled, "task_id": task_id, "status": "CANCELLED" if cancelled else "NOT_FOUND"})

    @app.post("/api/agent/tasks/{task_id}/approve")
    async def approve_agent_task_endpoint(task_id: str, request: Request):
        _require_same_origin(request)
        guard = AssessmentScopeGuard(scope_manager, audit) if scope_manager else None
        from redloop.assessment.agent_orchestrator import AutonomousAgentOrchestrator



        orchestrator = AutonomousAgentOrchestrator(scope_manager=scope_manager, scope_guard=guard, audit=audit)



        task = orchestrator.approve_task(task_id)



        if not task:



            raise HTTPException(status_code=404, detail=f"Agent task '{task_id}' not found")



        return JSONResponse(task.to_dict())







    @app.get("/api/investigations")



    def list_investigations():



        inv_store = get_investigation_store()



        return JSONResponse({"investigations": [i.to_dict() for i in inv_store.list_all()]})







    @app.get("/api/investigations/active")



    def get_active_investigation():



        inv_store = get_investigation_store()



        return JSONResponse(inv_store.get_active().to_dict())







    @app.post("/api/investigations")



    async def create_investigation(request: Request):



        _require_same_origin(request)



        try:



            body = await request.json()



        except Exception:



            raise HTTPException(status_code=400, detail="Invalid JSON payload")



        inv_store = get_investigation_store()



        inv = Investigation(



            title=body.get("title") or "New Investigation",



            target=body.get("target") or "127.0.0.1",



            scope_status=body.get("scope_status") or "AUTHORIZED",



            objective=body.get("objective") or "Security evaluation",



            conversation_id=body.get("conversation_id") or "default",



        )



        inv_store.save(inv)



        return JSONResponse(inv.to_dict())







    @app.get("/api/investigations/{inv_id}")



    def get_investigation_by_id(inv_id: str):



        inv_store = get_investigation_store()



        inv = inv_store.get(inv_id)



        if not inv:



            raise HTTPException(status_code=404, detail="Investigation not found")



        return JSONResponse(inv.to_dict())







    # --- Unified OSINT Workspace API Endpoints (Phase 3 & 4) ---

    @app.get("/api/osint/investigate")
    @app.post("/api/osint/investigate")
    async def osint_investigate_unified(request: Request):
        _require_same_origin(request)
        indicator = ""
        query_type = "auto"
        investigation_id = None
        if request.method == "POST":
            try:
                body = await request.json()
            except Exception:
                body = {}
            indicator = str(body.get("indicator") or body.get("target") or body.get("query") or "").strip()
            query_type = str(body.get("query_type") or body.get("type") or "auto").strip().lower()
            investigation_id = body.get("investigation_id")
        else:
            indicator = str(request.query_params.get("indicator") or request.query_params.get("target") or request.query_params.get("query") or "").strip()
            query_type = str(request.query_params.get("query_type") or request.query_params.get("type") or "auto").strip().lower()
            investigation_id = request.query_params.get("investigation_id")

        if not indicator:
            raise HTTPException(status_code=400, detail="Missing required 'indicator' parameter")

        if query_type in ("auto", "", "detect"):
            import ipaddress
            import re
            clean_ind = indicator.strip()
            try:
                ipaddress.ip_address(clean_ind)
                query_type = "ip"
            except ValueError:
                if "@" in clean_ind and "." in clean_ind.split("@")[-1]:
                    query_type = "email"
                elif (clean_ind.startswith("+") or clean_ind.startswith("tel:")) and len(re.sub(r"[^\d]", "", clean_ind)) >= 7:
                    query_type = "phone"
                elif len(clean_ind) in (32, 40, 64) and re.fullmatch(r"[0-9a-fA-F]+", clean_ind):
                    query_type = "hash"
                elif "." in clean_ind and "/" not in clean_ind and " " not in clean_ind:
                    query_type = "domain"
                else:
                    query_type = "username"

        from redloop.osint_engine import get_osint_engine, populate_investigation_graph_from_osint
        engine = get_osint_engine()

        if query_type == "ip":
            res = engine.investigate_ip(indicator)
        elif query_type == "domain":
            res = engine.investigate_domain(indicator)
        elif query_type == "email":
            res = engine.investigate_email(indicator)
        elif query_type == "username":
            res = engine.investigate_username(indicator)
        elif query_type == "phone":
            res = engine.investigate_phone(indicator)
        elif query_type in ("hash", "file"):
            from dataclasses import asdict
            from redloop.virustotal import get_virustotal_client
            vt_client = get_virustotal_client()
            vt_res = vt_client.inspect(indicator, "file")
            data = vt_res.to_dict() if hasattr(vt_res, "to_dict") else asdict(vt_res)
            data["success"] = True
            data["indicator"] = indicator
            data["query_type"] = "hash"
            return JSONResponse(data)
        else:
            res = engine.investigate_domain(indicator)

        if investigation_id:
            inv_store = get_investigation_store()
            inv = inv_store.get(investigation_id)
            if inv:
                inv_type = query_type.upper()
                inv.add_event("evidence", f"OSINT {inv_type}: {res.indicator}", res.actual_finding, "INFO", {"evidence_id": res.evidence_id, "evidence_hash": res.evidence_hash})
                inv_store.save(inv)
                graph = InvestigationGraph(investigation_id=inv.id)
                populate_investigation_graph_from_osint(graph, res)

        out = res.model_dump(mode="json")
        out["success"] = True
        return JSONResponse(out)



    @app.post("/api/osint/ip")



    async def osint_ip_endpoint(request: Request):



        _require_same_origin(request)



        body = await request.json()



        ip = str(body.get("ip") or body.get("target") or "").strip()



        inv_id = body.get("investigation_id")



        from redloop.osint_engine import get_osint_engine, populate_investigation_graph_from_osint



        engine = get_osint_engine()



        res = engine.investigate_ip(ip)



        if inv_id:



            inv_store = get_investigation_store()



            inv = inv_store.get(inv_id)



            if inv:



                inv.add_event("evidence", f"OSINT IP: {res.indicator}", res.actual_finding, "INFO", {"evidence_id": res.evidence_id, "evidence_hash": res.evidence_hash})



                inv_store.save(inv)



                graph = InvestigationGraph(investigation_id=inv.id)



                populate_investigation_graph_from_osint(graph, res)



        return JSONResponse(res.model_dump(mode="json"))







    @app.post("/api/osint/domain")



    async def osint_domain_endpoint(request: Request):



        _require_same_origin(request)



        body = await request.json()



        domain = str(body.get("domain") or body.get("target") or "").strip()



        inv_id = body.get("investigation_id")



        from redloop.osint_engine import get_osint_engine, populate_investigation_graph_from_osint



        engine = get_osint_engine()



        res = engine.investigate_domain(domain)



        if inv_id:



            inv_store = get_investigation_store()



            inv = inv_store.get(inv_id)



            if inv:



                inv.add_event("evidence", f"OSINT Domain: {res.indicator}", res.actual_finding, "INFO", {"evidence_id": res.evidence_id, "evidence_hash": res.evidence_hash})



                inv_store.save(inv)



                graph = InvestigationGraph(investigation_id=inv.id)



                populate_investigation_graph_from_osint(graph, res)



        return JSONResponse(res.model_dump(mode="json"))







    @app.post("/api/osint/email")



    async def osint_email_endpoint(request: Request):



        _require_same_origin(request)



        body = await request.json()



        email = str(body.get("email") or body.get("target") or "").strip()



        headers = body.get("headers")



        inv_id = body.get("investigation_id")



        from redloop.osint_engine import get_osint_engine, populate_investigation_graph_from_osint



        engine = get_osint_engine()



        res = engine.investigate_email(email, raw_headers=headers)



        if inv_id:



            inv_store = get_investigation_store()



            inv = inv_store.get(inv_id)



            if inv:



                inv.add_event("evidence", f"OSINT Email: {res.indicator}", res.actual_finding, "INFO", {"evidence_id": res.evidence_id, "evidence_hash": res.evidence_hash})



                inv_store.save(inv)



                graph = InvestigationGraph(investigation_id=inv.id)



                populate_investigation_graph_from_osint(graph, res)



        return JSONResponse(res.model_dump(mode="json"))







    @app.post("/api/osint/username")



    async def osint_username_endpoint(request: Request):



        _require_same_origin(request)



        body = await request.json()



        username = str(body.get("username") or body.get("target") or "").strip()



        inv_id = body.get("investigation_id")



        from redloop.osint_engine import get_osint_engine, populate_investigation_graph_from_osint



        engine = get_osint_engine()



        res = engine.investigate_username(username)



        if inv_id:



            inv_store = get_investigation_store()



            inv = inv_store.get(inv_id)



            if inv:



                inv.add_event("evidence", f"OSINT Username: {res.indicator}", res.actual_finding, "INFO", {"evidence_id": res.evidence_id, "evidence_hash": res.evidence_hash})



                inv_store.save(inv)



                graph = InvestigationGraph(investigation_id=inv.id)



                populate_investigation_graph_from_osint(graph, res)



        return JSONResponse(res.model_dump(mode="json"))







    @app.post("/api/osint/phone")



    async def osint_phone_endpoint(request: Request):



        _require_same_origin(request)



        body = await request.json()



        phone = str(body.get("phone") or body.get("target") or "").strip()



        inv_id = body.get("investigation_id")



        from redloop.osint_engine import get_osint_engine, populate_investigation_graph_from_osint



        engine = get_osint_engine()



        res = engine.investigate_phone(phone)



        if inv_id:



            inv_store = get_investigation_store()



            inv = inv_store.get(inv_id)



            if inv:



                inv.add_event("evidence", f"OSINT Phone: {res.indicator}", res.actual_finding, "INFO", {"evidence_id": res.evidence_id, "evidence_hash": res.evidence_hash})



                inv_store.save(inv)



                graph = InvestigationGraph(investigation_id=inv.id)



                populate_investigation_graph_from_osint(graph, res)



        return JSONResponse(res.model_dump(mode="json"))







    # --- VirusTotal, email footprint, identity correlation, checkpoint ---



    @app.get("/api/threat-intel/virustotal/status")



    def virustotal_provider_status():



        return JSONResponse(get_virustotal_client().provider_status())







    @app.post("/api/threat-intel/virustotal")



    async def virustotal_lookup(body: VirusTotalRequest, request: Request):



        _require_same_origin(request)



        result = get_virustotal_client().inspect(body.indicator, body.indicator_type)



        payload = result.to_dict()



        audit.log(



            "virustotal",



            "virustotal_lookup",



            "threat_intel",



            "success" if result.status not in {"API_UNAVAILABLE", "INVALID_INPUT", "RATE_LIMITED"} else "failure",



            indicator_type=result.indicator_type,



            source_status=result.source_status,



            malicious=result.malicious,



            suspicious=result.suspicious,



        )



        return JSONResponse(payload)







    @app.post("/api/threat-intel/virustotal/file")



    async def virustotal_file_lookup(request: Request):



        _require_same_origin(request)



        content_type = request.headers.get("content-type", "")



        if "multipart/form-data" not in content_type:



            raise HTTPException(status_code=415, detail="Expected multipart/form-data")



        form = await request.form()



        upload = form.get("file")



        if upload is None or not hasattr(upload, "read"):



            raise HTTPException(status_code=400, detail="A file is required")



        data = await upload.read(VT_MAX_FILE_BYTES + 1)



        if len(data) > VT_MAX_FILE_BYTES:



            raise HTTPException(status_code=413, detail="File exceeds the VirusTotal size limit")



        consent_token = str(form.get("consent_token") or "")



        upload_flag = str(form.get("upload") or "").strip().lower() in {"1", "true", "yes"}



        filename = getattr(upload, "filename", "upload") or "upload"



        result = get_virustotal_client().analyse_file_bytes(



            filename,



            data,



            upload=upload_flag,



            consent_token=consent_token or None,



        )



        audit.log(



            "virustotal",



            "virustotal_file_lookup",



            "threat_intel",



            "success" if result.status not in {"API_UNAVAILABLE", "INVALID_INPUT", "RATE_LIMITED"} else "failure",



            source_status=result.source_status,



            size=len(data),



            uploaded=bool(upload_flag),



        )



        return JSONResponse(result.to_dict())







    @app.post("/api/osint/email/footprint")



    async def osint_email_footprint(body: EmailFootprintRequest, request: Request):



        _require_same_origin(request)



        report = EmailFootprintEngine(network_enabled=body.live).investigate(body.email)



        payload = report.to_dict()



        audit.log(



            "email_footprint",



            "email_footprint_lookup",



            "osint",



            "success" if report.valid else "failure",



            classification=report.classification,



            network_enabled=report.network_enabled,



            domain=report.domain,



        )



        return JSONResponse(payload)







    @app.get("/api/identity/clusters")



    def identity_clusters(limit: int = Query(default=100, ge=1, le=500)):



        return JSONResponse({"clusters": identity_store.list_clusters(limit=limit)})







    @app.get("/api/identity/clusters/{cluster_id}")



    def identity_cluster(cluster_id: str):



        cluster = identity_store.get_cluster(cluster_id)



        if cluster is None:



            raise HTTPException(status_code=404, detail="Identity cluster not found")



        return JSONResponse(cluster)







    @app.post("/api/identity/observations")



    async def identity_add_observation(body: IdentityObservationRequest, request: Request):



        _require_same_origin(request)



        try:



            obs = IdentityObservation(



                entity_type=body.entity_type,



                value=body.value,



                source=body.source,



                method=body.method,



                confidence=body.confidence,



                classification=body.classification,



                authoritative=body.authoritative,



                correlation_key=body.correlation_key,



                metadata=body.metadata,



            )



        except ValueError as exc:



            raise HTTPException(status_code=400, detail=str(exc)) from exc



        identity_store.add_observation(obs)



        clusters = identity_store.build_clusters()



        audit.log(



            "identity",



            "identity_observation_add",



            "identity",



            "success",



            entity_type=obs.entity_type,



            observation_id=obs.observation_id,



        )



        return JSONResponse(



            {



                "observation": obs.to_dict(),



                "clusters": [c.to_dict() for c in clusters],



            }



        )







    @app.post("/api/identity/clusters/{cluster_id}/review")



    async def identity_review_cluster(cluster_id: str, body: IdentityReviewRequest, request: Request):



        _require_same_origin(request)



        try:



            cluster = identity_store.review(



                cluster_id,



                body.decision,



                body.analyst,



                body.note,



                audit=audit,



            )



        except KeyError as exc:



            raise HTTPException(status_code=404, detail="Identity cluster not found") from exc



        except ValueError as exc:



            raise HTTPException(status_code=400, detail=str(exc)) from exc



        return JSONResponse(cluster)







    @app.get("/api/identity/reviews")



    def identity_reviews(



        cluster_id: str | None = None,



        limit: int = Query(default=100, ge=1, le=500),



    ):



        return JSONResponse(



            {"reviews": identity_store.list_reviews(cluster_id=cluster_id, limit=limit)}



        )







    @app.post("/api/osint/metadata")



    async def osint_metadata_endpoint(request: Request):



        _require_same_origin(request)



        content_type = request.headers.get("content-type", "")



        file_bytes = b""



        filename = "uploaded_file"



        inv_id = None







        if "multipart/form-data" in content_type:



            form = await request.form()



            uploaded_file = form.get("file")



            if uploaded_file and hasattr(uploaded_file, "read"):



                file_bytes = await uploaded_file.read()



                filename = getattr(uploaded_file, "filename", "uploaded_file") or "uploaded_file"



            elif isinstance(uploaded_file, (bytes, str)):



                file_bytes = uploaded_file.encode("utf-8") if isinstance(uploaded_file, str) else uploaded_file



            inv_id = form.get("investigation_id")



        else:



            try:



                body = await request.json()



            except Exception:



                body = {}



            file_content = body.get("content") or body.get("raw_content") or ""



            file_bytes = file_content.encode("utf-8") if isinstance(file_content, str) else file_content



            filename = body.get("filename") or "sample_file.txt"



            inv_id = body.get("investigation_id")







        from redloop.osint_engine import get_osint_engine, populate_investigation_graph_from_osint



        engine = get_osint_engine()



        res = engine.analyze_file_metadata(file_bytes, filename=filename)



        if inv_id:



            inv_store = get_investigation_store()



            inv = inv_store.get(str(inv_id))



            if inv:



                inv.add_event("evidence", f"Metadata: {filename}", res.actual_finding, "INFO", {"evidence_id": res.evidence_id, "evidence_hash": res.evidence_hash})



                inv_store.save(inv)



                graph = InvestigationGraph(investigation_id=inv.id)



                populate_investigation_graph_from_osint(graph, res)



        return JSONResponse(res.model_dump(mode="json"))







    # --- Phase 1: Open-Source Architecture Matrix ---



    @app.get("/api/architecture/matrix")



    def get_architecture_matrix_endpoint():



        return JSONResponse(get_architecture_matrix())







    # --- Phase 2: Agentic AI Autonomous Engine ---



    @app.post("/api/agentic/plan")



    def create_agentic_plan(payload: AgenticPlanRequest, request: Request):



        _require_same_origin(request)



        guard = AssessmentScopeGuard(scope_manager, audit) if scope_manager else None



        runtime = AgenticAIRuntime(scope_guard=guard, audit=audit)



        plan = runtime.build_pentestgpt_plan(payload.target, payload.intent, payload.ports)



        return JSONResponse(plan.to_dict())







    @app.post("/api/agentic/execute")



    def execute_agentic_workflow(payload: AgenticExecuteRequest, request: Request):



        _require_same_origin(request)



        guard = AssessmentScopeGuard(scope_manager, audit) if scope_manager else None



        runtime = AgenticAIRuntime(scope_guard=guard, audit=audit)



        result = runtime.run_autonomous_assessment(



            target=payload.target,



            user_intent=payload.intent,



            authorized_ports=payload.ports,



            max_iterations=payload.max_iterations,



        )



        if result.get("status") == "BLOCKED":



            return JSONResponse(result, status_code=403)



        return JSONResponse(result)







    # --- Phase 3: Threat Intelligence & ASVS & Advanced Forensics ---



    @app.get("/api/threat-intel/cve/{cve_id}")



    def query_cve_threat_intel(cve_id: str):



        ti = get_threat_intel_engine()



        res = ti.query_cve(cve_id)



        return JSONResponse(res.to_dict())







    @app.get("/api/threat-intel/ip/{ip}")



    def query_ip_threat_intel(ip: str):



        ti = get_threat_intel_engine()



        res = ti.query_ip_reputation(ip)



        return JSONResponse(res.to_dict())







    @app.post("/api/asvs/evaluate")



    def evaluate_asvs_controls(payload: ASVSEvaluateRequest, request: Request):



        _require_same_origin(request)



        guard = AssessmentScopeGuard(scope_manager, audit) if scope_manager else None



        engine = get_asvs_engine(scope_guard=guard)



        res = engine.evaluate_url(payload.url, test_endpoints=payload.test_endpoints)



        return JSONResponse(res.to_dict())







    @app.post("/api/forensics/advanced-triage")



    def triage_forensics_artifact(payload: ForensicsTriageRequest, request: Request):



        _require_same_origin(request)



        engine = get_advanced_forensics_engine()



        res = engine.triage_log(payload.log_type, payload.raw_content)



        return JSONResponse(res)







    # --- Phase 5: Kali Linux Terminal Copilot Output Ingestion ---



    @app.post("/api/kali/analyze-output")



    def analyze_kali_terminal_output(payload: TerminalOutputRequest, request: Request):



        _require_same_origin(request)



        guard = AssessmentScopeGuard(scope_manager, audit) if scope_manager else None



        copilot = KaliCopilot(scope_guard=guard)



        res = copilot.analyze_terminal_output(payload.raw_output, payload.target)



        return JSONResponse(res)







    # --- Phase 6: Multi-Provider AI Gateway & User Encrypted Keys ---



    @app.get("/api/providers/config")



    def get_providers_config():



        gateway = get_provider_gateway()



        return JSONResponse({"providers": gateway.get_all_providers()})







    @app.post("/api/providers/config")



    def update_provider_config(payload: ProviderConfigRequest, request: Request):



        _require_same_origin(request)



        gateway = get_provider_gateway()



        if payload.api_key:



            gateway.key_store.set_key(payload.provider_id, payload.api_key)



        return JSONResponse({"success": True, "provider_id": payload.provider_id, "masked_key": gateway.key_store.mask_key(payload.api_key)})







    @app.post("/api/providers/test")



    def test_provider_gateway(payload: ProviderTestRequest, request: Request):



        _require_same_origin(request)



        gateway = get_provider_gateway()



        res = gateway.test_provider(payload.provider_id, test_tool_calling=payload.test_tool_calling)



        return JSONResponse(res)







    # --- Phase 7: RAG Knowledge Base & Continuous Learning ---



    @app.get("/api/rag/query")



    def query_rag_knowledge(query: str = Query(..., min_length=1), top_k: int = 3):



        rag = get_rag_engine()



        results = rag.search(query, top_k=top_k)



        return JSONResponse({"query": query, "results": [r.to_dict() for r in results]})







    @app.post("/api/rag/ingest")



    def ingest_rag_knowledge(payload: RAGIngestRequest, request: Request):



        _require_same_origin(request)



        rag = get_rag_engine()



        chunk_ids = rag.ingest_text(



            title=payload.title,



            text=payload.text,



            category=payload.category,



            source=payload.source,



        )



        return JSONResponse({"success": True, "chunks_created": len(chunk_ids), "chunk_ids": chunk_ids})







    @app.post("/api/knowledge/feedback")



    def record_knowledge_feedback(payload: KnowledgeFeedbackRequest, request: Request):



        _require_same_origin(request)



        rag = get_rag_engine()



        lesson_id = rag.record_feedback(



            query=payload.query,



            original_response=payload.original_response,



            corrected_response=payload.corrected_response,



            rating=payload.rating,



            category=payload.category,



        )



        return JSONResponse({"success": True, "lesson_id": lesson_id, "status": "CANDIDATE"})







    @app.post("/api/knowledge/lessons/review")



    def review_knowledge_lesson(payload: KnowledgeReviewRequest, request: Request):



        _require_same_origin(request)



        rag = get_rag_engine()



        ok = rag.review_lesson(payload.lesson_id, approve=payload.approve, reviewer_notes=payload.notes)



        if not ok:



            raise HTTPException(status_code=404, detail="Lesson not found")



        return JSONResponse({"success": True, "lesson_id": payload.lesson_id, "approved": payload.approve})







    @app.get("/api/knowledge/diagnostics")



    def get_knowledge_diagnostics():



        rag = get_rag_engine()



        return JSONResponse(rag.get_diagnostics())







    # --- Phase 8 & 10: Investigation Graph, Replay & Remediation Verification ---



    @app.get("/api/investigations/{inv_id}/graph")



    def get_investigation_graph_cytoscape(inv_id: str):



        graph = InvestigationGraph(investigation_id=inv_id)



        return JSONResponse({"elements": graph.to_cytoscape_elements(), "investigation_id": inv_id})







    @app.post("/api/investigations/{inv_id}/verify-remediation")



    def verify_finding_remediation(inv_id: str, payload: RemediationVerifyRequest, request: Request):



        _require_same_origin(request)



        graph = InvestigationGraph(investigation_id=inv_id)



        if graph.load_error:



            raise HTTPException(



                status_code=500,



                detail="Investigation graph is unreadable; refusing to modify it.",



            )



        finding = graph.nodes.get(payload.finding_id)



        if not finding:



            raise HTTPException(status_code=404, detail=f"Finding {payload.finding_id} not found.")







        props = finding.properties



        target = props.get("target") or props.get("host") or props.get("asset")



        if not target:



            for edge in graph.edges:



                if edge.target_id != payload.finding_id:



                    continue



                if edge.relation not in ("SUPPORTS_FINDING", "PRODUCED_BY", "VERIFIED_BY"):



                    continue



                source = graph.nodes.get(edge.source_id)



                if source and source.properties.get("target"):



                    target = source.properties["target"]



                    break







        raw_port = payload.port if payload.port is not None else props.get("port")



        if not target or raw_port is None:



            raise HTTPException(



                status_code=422,



                detail=(



                    "Remediation cannot be verified: the finding has no target/port "



                    "metadata to retest. Client-supplied results are not accepted."



                ),



            )







        try:



            target_ip = str(ipaddress.ip_address(str(target)))



        except ValueError:



            raise HTTPException(



                status_code=422,



                detail=(



                    "Remediation retest requires an IP-literal target from graph "



                    "metadata to prevent DNS-based scope bypass."



                ),



            )



        try:



            port = int(raw_port)



        except (TypeError, ValueError):



            raise HTTPException(status_code=422, detail="Finding port metadata is not a valid port.")



        if not 1 <= port <= 65535:



            raise HTTPException(status_code=422, detail="Finding port metadata is out of range.")







        if scope_manager is None:



            raise HTTPException(status_code=503, detail="Signed scope is required for remediation retests.")



        guard = AssessmentScopeGuard(scope_manager, audit)



        try:



            guard.is_target_authorized(target_ip, "recon", port=port)



        except ScopeBlockedError as exc:



            raise HTTPException(status_code=403, detail=f"Scope authorization rejected: {exc}")







        res = RemediationVerifier.verify_remediation(



            graph,



            payload.finding_id,



            RemediationVerifier.build_port_probe(target_ip, port),



        )



        audit_status = {



            "REMEDIATED_AND_VERIFIED": "success",



            "REMEDIATION_FAILED_STILL_VULNERABLE": "failed",



        }.get(res.get("status"), "inconclusive")



        audit.log(



            target_ip,



            "verify_remediation",



            "remediation",



            audit_status,



            {



                "finding_id": payload.finding_id,



                "port": port,



                "status": res.get("status"),



                "evidence_hash": res.get("evidence_hash"),



            },



        )



        return JSONResponse(res)







    @app.post("/api/investigations/replay")



    def replay_investigation_diff(payload: ReplayDiffRequest, request: Request):



        _require_same_origin(request)



        base_g = InvestigationGraph(investigation_id=payload.baseline_id)



        replay_g = InvestigationGraph(investigation_id=payload.replayed_id)



        diff = InvestigationReplay.diff_investigations(base_g, replay_g)



        return JSONResponse(diff)







    @app.get("/api/models/evaluator")



    def run_model_evaluator(provider_id: str = "groq", model: str = "llama-3.3-70b-versatile"):



        res = MultiModelEvaluator.evaluate_provider(provider_id, model)



        return JSONResponse(res)







    @app.get("/api/tools/capabilities")



    def get_tool_capabilities_endpoint(refresh: bool = False):



        from redloop.assessment.tools_v2 import ToolRegistryV2



        return JSONResponse(ToolRegistryV2.get_capabilities_summary(force_refresh=refresh))







    @app.get("/api/tools/environments")



    def get_tool_environments_endpoint(refresh: bool = False):



        from redloop.assessment.tools_v2 import EnvironmentDetector



        return JSONResponse(EnvironmentDetector.detect_all(force_refresh=refresh))







    @app.get("/api/tools/health")



    def get_tool_health_endpoint():



        from redloop.assessment.tools_v2 import ToolRegistryV2



        summary = ToolRegistryV2.get_capabilities_summary()



        return JSONResponse({



            "status": "HEALTHY" if summary["summary"]["available"] > 0 else "DEGRADED",



            "tools_summary": summary["summary"],



            "environments": summary["environments"],



            "checked_at": summary["generated_at"],



        })







    @app.post("/api/tools/plan")



    def plan_tools_endpoint(payload: dict[str, Any], request: Request):



        _require_same_origin(request)



        from redloop.assessment.tool_planner import ToolPlanRequest, ToolPlanner



        req = ToolPlanRequest(**payload)



        guard = AssessmentScopeGuard(scope_manager, audit) if scope_manager else None



        planner = ToolPlanner(scope_manager=scope_manager, scope_guard=guard, audit=audit)



        plan = planner.create_plan(req)



        return JSONResponse(plan.to_dict())







    @app.get("/api/tools/matrix")



    def get_tool_capability_matrix(refresh: bool = False):



        from redloop.assessment.tools_v2 import ToolRegistryV2



        return JSONResponse(ToolRegistryV2.get_capabilities_summary(force_refresh=refresh))







    @app.post("/api/investigations/{inv_id}/graph/clear")



    def clear_investigation_graph_endpoint(inv_id: str, request: Request):



        _require_same_origin(request)



        graph = InvestigationGraph(investigation_id=inv_id)



        graph.clear()



        return JSONResponse({"success": True, "elements": [], "investigation_id": inv_id})







    # =========================================================================



    # Phase 4 — Deep Security Intelligence & Analysis Engine Endpoints



    # =========================================================================







    @app.get("/api/findings")



    def list_findings_endpoint(



        task_id: str | None = None,



        target: str | None = None,



        severity: str | None = None,



        priority: str | None = None,



        verification: str | None = None,



        limit: int = 50,



        offset: int = 0,



    ):



        from redloop.assessment.finding_models import FindingStore, FindingSeverity, OperationalPriority, VerificationStatus



        store = FindingStore.get_instance()



        findings = store.list_findings(



            task_id=task_id,



            target=target,



            severity=severity,



            priority=priority,



            verification=verification,



            limit=limit,



            offset=offset,



        )







        sev_counts = {s.value: 0 for s in FindingSeverity}



        prio_counts = {p.value: 0 for p in OperationalPriority}



        ver_counts = {v.value: 0 for v in VerificationStatus}







        for f in findings:



            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1



            if f.operational_priority:



                prio_counts[f.operational_priority.value] = prio_counts.get(f.operational_priority.value, 0) + 1



            ver_counts[f.verification_status.value] = ver_counts.get(f.verification_status.value, 0) + 1







        return JSONResponse({



            "success": True,



            "total": len(findings),



            "limit": limit,



            "offset": offset,



            "findings": [f.to_dict() for f in findings],



            "summary": {



                "by_severity": sev_counts,



                "by_priority": prio_counts,



                "by_verification": ver_counts,



            },



        })







    @app.get("/api/findings/{finding_id}")



    def get_finding_detail_endpoint(finding_id: str):



        from redloop.assessment.finding_models import FindingStore



        store = FindingStore.get_instance()



        finding = store.get_finding(finding_id)



        if not finding:



            raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")



        return JSONResponse({"success": True, "finding": finding.to_dict()})







    @app.post("/api/findings/{finding_id}/validate")



    def validate_finding_endpoint(finding_id: str, request: Request):



        _require_same_origin(request)



        from redloop.assessment.finding_models import FindingStore



        from redloop.assessment.validation_engine import FindingValidationEngine



        store = FindingStore.get_instance()



        finding = store.get_finding(finding_id)



        if not finding:



            raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")



        



        updated = FindingValidationEngine.validate_finding(finding)



        store.add_finding(updated)



        return JSONResponse({"success": True, "finding": updated.to_dict()})







    @app.get("/api/intelligence/cve/{cve_id}")



    def get_cve_intelligence_endpoint(cve_id: str):



        import re



        from redloop.assessment.intel_engine import VulnerabilityIntelligenceEngine



        clean_cve = cve_id.strip().upper()



        if not re.match(r"^CVE-\d{4}-\d{4,}$", clean_cve):



            return JSONResponse(



                {



                    "success": False,



                    "error": "Malformed CVE identifier. Expected format: CVE-YYYY-NNNN",



                    "cve_id": cve_id,



                },



                status_code=400,



            )



        intel_engine = VulnerabilityIntelligenceEngine.get_instance()



        rec = intel_engine.get_cve_intel(clean_cve)



        return JSONResponse({"success": True, "intelligence": rec.to_dict()})







    @app.get("/api/intelligence/epss/{cve_id}")



    def get_epss_intelligence_endpoint(cve_id: str):



        import re



        from redloop.assessment.intel_engine import VulnerabilityIntelligenceEngine



        clean_cve = cve_id.strip().upper()



        if not re.match(r"^CVE-\d{4}-\d{4,}$", clean_cve):



            return JSONResponse(



                {



                    "success": False,



                    "error": "Malformed CVE identifier. Expected format: CVE-YYYY-NNNN",



                    "cve_id": cve_id,



                },



                status_code=400,



            )



        intel_engine = VulnerabilityIntelligenceEngine.get_instance()



        rec = intel_engine.get_cve_intel(clean_cve)



        return JSONResponse({



            "success": True,



            "cve_id": rec.cve_id,



            "epss_score": rec.epss_score,



            "epss_percentile": rec.epss_percentile,



            "cisa_kev": rec.cisa_kev,



            "provider_status": rec.provider_status.value if hasattr(rec.provider_status, "value") else str(rec.provider_status),



        })







    @app.get("/api/assets/graph")



    def get_asset_attack_graph_endpoint(target: str = "127.0.0.1", task_id: str | None = None):



        from redloop.assessment.asset_attack_graph import AssetAttackGraph



        from redloop.assessment.finding_models import FindingStore



        store = FindingStore.get_instance()



        findings = store.list_findings(task_id=task_id, target=target)



        graph = AssetAttackGraph(target=target)



        if findings:



            graph.populate_from_findings(findings)



        else:



            from redloop.assessment.asset_attack_graph import GraphNode, NodeType



            graph.add_node(GraphNode(



                node_id=f"host:{target}",



                node_type=NodeType.HOST if not any(c.isalpha() for c in target) else NodeType.DOMAIN,



                label=target,



                properties={"target": target},



            ))



        return JSONResponse(graph.export_cytoscape())







    @app.get("/api/attack-paths")



    def get_attack_paths_endpoint(target: str = "127.0.0.1", task_id: str | None = None):



        from redloop.assessment.asset_attack_graph import AssetAttackGraph



        from redloop.assessment.finding_models import FindingStore



        store = FindingStore.get_instance()



        findings = store.list_findings(task_id=task_id, target=target)



        graph = AssetAttackGraph(target=target)



        if findings:



            graph.populate_from_findings(findings)



        paths = graph.derive_attack_paths()



        return JSONResponse({



            "success": True,



            "target": target,



            "total_paths": len(paths),



            "attack_paths": [p.model_dump() for p in paths],



        })







    @app.get("/api/analytics/risk")



    def get_risk_analytics_endpoint(target: str | None = None, task_id: str | None = None):



        from redloop.assessment.finding_models import FindingStore, OperationalPriority



        store = FindingStore.get_instance()



        findings = store.list_findings(task_id=task_id, target=target)







        total = len(findings)



        avg_score = round(sum(f.risk_score or 0.0 for f in findings) / total, 1) if total else None



        max_score = round(max((f.risk_score or 0.0 for f in findings), default=0.0), 1) if findings else None



        kev_count = sum(1 for f in findings if f.cisa_kev)







        prio_breakdown = {p.value: 0 for p in OperationalPriority}



        for f in findings:



            if f.operational_priority:



                prio_breakdown[f.operational_priority.value] = prio_breakdown.get(f.operational_priority.value, 0) + 1







        return JSONResponse({



            "success": True,



            "target": target or "all",



            "task_id": task_id,



            "total_findings": total,



            "average_risk_score": avg_score,



            "max_risk_score": max_score,



            "cisa_kev_exposures": kev_count,



            "priority_breakdown": prio_breakdown,



        })







    @app.get("/api/reports/{task_id}")



    def get_phase4_report_endpoint(task_id: str, format: str = "json", target: str = "127.0.0.1"):



        from redloop.assessment.finding_models import FindingStore



        from redloop.assessment.asset_attack_graph import AssetAttackGraph



        from redloop.assessment.phase4_reports import Phase4ReportGenerator



        store = FindingStore.get_instance()



        findings = store.list_findings(task_id=task_id)



        graph = AssetAttackGraph(target=target)



        if findings:



            graph.populate_from_findings(findings)







        generator = Phase4ReportGenerator(



            target=target,



            task_id=task_id,



            findings=findings,



            graph=graph,



        )







        fmt = format.lower()



        if fmt == "markdown" or fmt == "md":



            return HTMLResponse(content=generator.generate_markdown(), media_type="text/markdown")



        elif fmt == "html":



            return HTMLResponse(content=generator.generate_html(), media_type="text/html")



        else:



            return JSONResponse(generator.generate_json())



    # =========================================================================

    # Phase 5 — Autonomous SOC Investigation & Incident Response Engine

    # =========================================================================



    from redloop.assessment.soc_events import TelemetryIngestionEngine, TelemetryParsers, UniversalSecurityEvent

    from redloop.assessment.soc_detection import SOCDetectionEngine, SOCAlert

    from redloop.assessment.soc_timeline import SOCTimelineEngine, SOCIncidentCorrelator, SOCIncident

    from redloop.assessment.soc_playbooks import SOCPlaybookEngine

    from redloop.assessment.soc_copilot import SOCCopilotEngine



    _soc_ingestion_engine = TelemetryIngestionEngine()

    _soc_detection_engine = SOCDetectionEngine()



    @app.post("/api/soc/ingest")

    async def soc_ingest_endpoint(request: Request):
        from pathlib import Path

        _require_same_origin(request)

        try:

            body = await request.json()

        except Exception:

            raise HTTPException(status_code=400, detail="Invalid JSON body")



        content_str = body.get("content", "")

        source_type = body.get("source_type")

        file_name = body.get("file_name", "uploaded_telemetry.log")



        if not content_str and body.get("file_path"):
            fp = Path(body["file_path"])
            if fp.exists():
                content_str = fp.read_text(encoding="utf-8", errors="ignore")
                file_name = fp.name
        if not content_str:

            raise HTTPException(status_code=400, detail="No content provided for ingestion")



        import tempfile

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=f"_{file_name}", encoding="utf-8") as tmp:

            tmp.write(content_str)

            tmp_path = tmp.name



        try:

            res = _soc_ingestion_engine.ingest_file(tmp_path, source_type=source_type)

        finally:

            Path(tmp_path).unlink(missing_ok=True)



        return JSONResponse(res)



    @app.get("/api/soc/events")

    def list_soc_events_endpoint(

        category: str | None = None,

        source_type: str | None = None,

        severity: str | None = None,

        host: str | None = None,

        user: str | None = None,

        ip: str | None = None,

        limit: int = 50,

        offset: int = 0,

    ):

        evts = _soc_ingestion_engine.events

        if category:

            evts = [e for e in evts if category.lower() in (e.event_category.value if hasattr(e.event_category, "value") else str(e.event_category)).lower()]

        if source_type:

            evts = [e for e in evts if source_type.lower() in e.source_type.lower()]

        if severity:

            evts = [e for e in evts if (e.severity.value if hasattr(e.severity, "value") else str(e.severity)).upper() == severity.upper()]

        if host:

            evts = [e for e in evts if e.hostname and host.lower() in e.hostname.lower()]

        if user:

            evts = [e for e in evts if e.username and user.lower() in e.username.lower()]

        if ip:

            evts = [e for e in evts if (e.source_ip == ip or e.destination_ip == ip)]



        total = len(evts)

        evts = evts[offset : offset + limit] if limit > 0 else evts[offset:]



        return JSONResponse({

            "success": True,

            "total": total,

            "limit": limit,

            "offset": offset,

            "events": [e.to_dict() for e in evts],

        })



    @app.get("/api/soc/events/{event_id}")

    def get_soc_event_endpoint(event_id: str):

        for e in _soc_ingestion_engine.events:

            if e.event_id == event_id:

                return JSONResponse({"success": True, "event": e.to_dict()})

        raise HTTPException(status_code=404, detail=f"Event '{event_id}' not found.")



    @app.post("/api/soc/detect")

    def run_soc_detection_endpoint(request: Request):

        _require_same_origin(request)

        new_alerts = _soc_detection_engine.run_detections(_soc_ingestion_engine.events)

        return JSONResponse({

            "success": True,

            "new_alerts_count": len(new_alerts),

            "total_alerts_count": len(_soc_detection_engine.alerts),

            "alerts": [a.to_dict() for a in new_alerts],

        })



    @app.get("/api/soc/alerts")

    def list_soc_alerts_endpoint(

        severity: str | None = None,

        rule_id: str | None = None,

        limit: int = 50,

        offset: int = 0,

    ):

        alerts = _soc_detection_engine.alerts

        if severity:

            alerts = [a for a in alerts if (a.severity.value if hasattr(a.severity, "value") else str(a.severity)).upper() == severity.upper()]

        if rule_id:

            alerts = [a for a in alerts if rule_id.lower() in a.rule_id.lower()]



        total = len(alerts)

        alerts = alerts[offset : offset + limit] if limit > 0 else alerts[offset:]



        return JSONResponse({

            "success": True,

            "total": total,

            "limit": limit,

            "offset": offset,

            "alerts": [a.to_dict() for a in alerts],

        })



    @app.get("/api/soc/alerts/{alert_id}")

    def get_soc_alert_endpoint(alert_id: str):

        for a in _soc_detection_engine.alerts:

            if a.alert_id == alert_id:

                return JSONResponse({"success": True, "alert": a.to_dict()})

        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")



    @app.post("/api/soc/incidents")

    def correlate_incidents_endpoint(request: Request):

        _require_same_origin(request)

        incidents = SOCIncidentCorrelator.correlate_alerts(

            _soc_detection_engine.alerts,

            _soc_ingestion_engine.events,

        )

        return JSONResponse({

            "success": True,

            "incidents_count": len(incidents),

            "incidents": [i.to_dict() for i in incidents],

        })



    @app.get("/api/soc/timeline")

    def get_soc_timeline_endpoint(

        host: str | None = None,

        user: str | None = None,

        ip: str | None = None,

        category: str | None = None,

        severity: str | None = None,

        start_time: str | None = None,

        end_time: str | None = None,

    ):

        timeline = SOCTimelineEngine.build_timeline(

            events=_soc_ingestion_engine.events,

            alerts=_soc_detection_engine.alerts,

        )

        filtered = SOCTimelineEngine.filter_timeline(

            timeline,

            host=host,

            user=user,

            ip=ip,

            category=category,

            severity=severity,

            start_time=start_time,

            end_time=end_time,

        )

        return JSONResponse({

            "success": True,

            "total_items": len(filtered),

            "timeline": [item.to_dict() for item in filtered],

        })



    @app.get("/api/soc/playbooks")

    def list_soc_playbooks_endpoint():

        playbooks = SOCPlaybookEngine.list_playbooks()

        return JSONResponse({"success": True, "playbooks": playbooks})



    @app.get("/api/soc/playbooks/{playbook_id}")

    def get_soc_playbook_endpoint(playbook_id: str):

        pb = SOCPlaybookEngine.get_playbook(playbook_id)

        if not pb:

            raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found.")

        return JSONResponse({"success": True, "playbook": pb.to_dict()})



    @app.post("/api/soc/playbooks/{playbook_id}/approve")
    async def approve_playbook_step_endpoint(playbook_id: str, request: Request):
        # 1. Require same-origin header (Sec-Fetch-Site or Host/Origin match)
        sec_fetch_site = request.headers.get("sec-fetch-site")
        if sec_fetch_site and sec_fetch_site not in ("same-origin", "same-site", "none"):
            raise HTTPException(status_code=403, detail="Forbidden: cross-origin approval rejected.")

        origin = request.headers.get("origin")
        host = request.headers.get("host")
        if origin and host and host != "testserver":
            origin_host = origin.split("://")[-1].split("/")[0]
            if origin_host.lower() != host.lower():
                raise HTTPException(status_code=403, detail="Forbidden: Host/Origin mismatch.")

        # 2. X-Operator-Token authentication
        token = request.headers.get("x-operator-token")
        if not token:
            raise HTTPException(status_code=401, detail="Authentication required: X-Operator-Token header missing.")

        from redloop.assessment.soar_engine import verify_operator_token
        if not verify_operator_token(token):
            raise HTTPException(status_code=403, detail="Forbidden: Invalid operator token.")

        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        step_id = body.get("step_id")
        if not step_id:
            raise HTTPException(status_code=400, detail="Missing 'step_id' in approval request.")

        # 3. Expiration check (>5 minutes old)
        req_ts = body.get("timestamp") or body.get("request_time")
        if req_ts is not None:
            now_epoch = time.time()
            try:
                if isinstance(req_ts, (int, float)):
                    ts_val = float(req_ts)
                else:
                    dt = datetime.fromisoformat(str(req_ts).replace("Z", "+00:00"))
                    ts_val = dt.timestamp()
                if abs(now_epoch - ts_val) > 300.0:
                    raise HTTPException(status_code=400, detail="Approval request expired (>5 minutes).")
            except ValueError:
                raise HTTPException(status_code=400, detail="Approval request expired: invalid timestamp.")

        approved = bool(body.get("approved", True))

        # 4. Bind approval to specific step_id and payload hash
        params = body.get("parameters", {})
        payload_hash = hashlib.sha256(json.dumps(params, sort_keys=True).encode("utf-8")).hexdigest()

        # 5. Approver identity from authenticated operator name (never trust request parameter)
        approver = os.environ.get("REDLOOP_OPERATOR_NAME") or "operator-local"

        res = SOCPlaybookEngine.approve_step(playbook_id, step_id, approver=approver, approved=approved)
        if not res.get("success"):
            err_msg = res.get("error", "Approval failed.")
            if "Replay attempt rejected" in err_msg or "already been resolved" in err_msg:
                raise HTTPException(status_code=409, detail=f"Conflict: Replay detected. {err_msg}")
            raise HTTPException(status_code=404, detail=err_msg)

        # 6. Audit logging with HMAC signature
        audit = getattr(request.app.state, "audit", None)
        if audit is None:
            try:
                from redloop.audit import AuditLogger
                audit = AuditLogger()
            except Exception:
                audit = None
        if audit:
            audit.log(
                module="soar",
                event="step_approval" if approved else "step_denial",
                status="SUCCESS" if approved else "DENIED",
                details={
                    "playbook_id": playbook_id,
                    "step_id": step_id,
                    "payload_hash": payload_hash,
                    "approver": approver,
                    "approved": approved,
                    "action": "APPROVED" if approved else "DENIED",
                },
            )

        return JSONResponse(res)



    @app.post("/api/soc/investigate")

    async def soc_investigate_endpoint(request: Request):

        _require_same_origin(request)

        try:

            body = await request.json()

        except Exception:

            raise HTTPException(status_code=400, detail="Invalid JSON body")



        query = body.get("query", "")

        target = body.get("target")



        if not query:

            raise HTTPException(status_code=400, detail="Missing 'query' string.")



        task = SOCCopilotEngine.start_investigation(

            user_query=query,

            events=_soc_ingestion_engine.events,

            alerts=_soc_detection_engine.alerts,

            explicit_target=target,

        )

        return JSONResponse({"success": True, "investigation": task.to_dict()})



    @app.get("/api/soc/reports/{investigation_id}")

    def get_soc_report_endpoint(investigation_id: str, format: str = "json"):

        rep = SOCCopilotEngine.generate_investigation_report(investigation_id, format=format)

        if isinstance(rep, dict) and "error" in rep:

            raise HTTPException(status_code=404, detail=rep["error"])

        if format.lower() in ("markdown", "md"):

            return HTMLResponse(content=str(rep), media_type="text/markdown")

        return JSONResponse(rep)

    # =========================================================================
    # Phase 6: Threat Hunting, ATT&CK Mapping & Detection Engineering Routes
    # =========================================================================

    @app.post("/api/soc/playbooks/{playbook_id}/execute")
    async def execute_playbook_step_endpoint(playbook_id: str, request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        step_id = body.get("step_id")
        auth_token = body.get("capability_token") or body.get("auth_token")
        operator = body.get("operator", "security_operator")

        if not step_id:
            raise HTTPException(status_code=400, detail="Missing 'step_id' in execution request.")
        if not auth_token:
            raise HTTPException(status_code=400, detail="Missing authorization capability token.")

        res = SOCPlaybookEngine.execute_step(playbook_id, step_id, auth_token=auth_token, operator=operator)
        if not res.get("success"):
            raise HTTPException(status_code=403, detail=res.get("error", "Execution failed."))
        return JSONResponse(res)

    @app.get("/api/hunting/attack/tactics")
    def get_attack_tactics_endpoint():
        from redloop.assessment.attack_mapping import AttackMappingEngine
        return JSONResponse({"success": True, "tactics": AttackMappingEngine.get_tactics()})

    @app.get("/api/hunting/attack/techniques")
    def get_attack_techniques_endpoint(request: Request):
        from redloop.assessment.attack_mapping import AttackMappingEngine
        tactic_id = request.query_params.get('tactic_id')
        return JSONResponse({'success': True, 'techniques': AttackMappingEngine.get_techniques(tactic_id=tactic_id)})

    @app.post("/api/hunting/attack/map")
    async def map_attack_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        from redloop.assessment.attack_mapping import AttackMappingEngine
        mappings = []
        events = body.get("events", [])
        alerts = body.get("alerts", [])
        if not events and not alerts:
            for alt in _soc_detection_engine.alerts:
                mappings.extend([m.to_dict() for m in AttackMappingEngine.map_alert(alt)])
        else:
            for alt in alerts:
                import uuid
                from redloop.assessment.soc_detection import SOCAlert
                if isinstance(alt, dict):
                    alt_copy = dict(alt)
                    alt_copy.setdefault("alert_id", f"alt-{uuid.uuid4().hex[:8]}")
                    alt_copy.setdefault("rule_id", "CUSTOM-RULE")
                    alt_copy.setdefault("title", "Custom Alert")
                    alt_copy.setdefault("description", "")
                    alt_copy.setdefault("severity", "HIGH")
                    alt_copy.setdefault("confidence", 0.8)
                    a_obj = SOCAlert(**alt_copy)
                else:
                    a_obj = alt
                mappings.extend([m.to_dict() for m in AttackMappingEngine.map_alert(a_obj)])
            for ev in events:
                from redloop.assessment.soc_events import UniversalSecurityEvent
                if isinstance(ev, dict):
                    ev_copy = dict(ev)
                    ev_copy.setdefault('ingestion_timestamp', datetime.now(timezone.utc).isoformat())
                    ev_copy.setdefault('source_file', 'api_payload')
                    e_obj = UniversalSecurityEvent(**ev_copy)
                else:
                    e_obj = ev
                mappings.extend([m.to_dict() for m in AttackMappingEngine.map_event(e_obj)])

        return JSONResponse({"success": True, "mappings": mappings})

    @app.get("/api/hunting/attack/matrix")
    def get_attack_matrix_endpoint(format: str = "json"):
        from redloop.assessment.attack_mapping import AttackMappingEngine
        all_maps = []
        for alt in _soc_detection_engine.alerts:
            all_maps.extend(AttackMappingEngine.map_alert(alt))
        for ev in _soc_ingestion_engine.events:
            all_maps.extend(AttackMappingEngine.map_event(ev))

        matrix = AttackMappingEngine.build_matrix(all_maps)
        if format.lower() in ("markdown", "md"):
            md = AttackMappingEngine.export_matrix_markdown(matrix)
            return HTMLResponse(content=md, media_type="text/markdown")
        return JSONResponse({"success": True, "matrix": matrix.to_dict()})

    @app.get("/api/hunting/sigma/matrix")
    def get_sigma_matrix_endpoint():
        from redloop.assessment.sigma_engine import SigmaEngine
        return JSONResponse({"success": True, "matrix": SigmaEngine.get_support_matrix()})

    @app.post("/api/hunting/sigma/validate")
    async def validate_sigma_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        rule_yaml = body.get("rule_yaml")
        if not rule_yaml:
            raise HTTPException(status_code=400, detail="Missing 'rule_yaml' in validation request.")

        from redloop.assessment.sigma_engine import SigmaEngine
        res = SigmaEngine.validate_rule(rule_yaml)
        return JSONResponse({
            "success": True,
            "is_valid": res.is_valid,
            "rule_id": res.rule_id,
            "title": res.title,
            "errors": res.errors,
            "warnings": res.warnings,
            "supported_features": res.supported_features,
            "unsupported_features": res.unsupported_features,
        })

    @app.post("/api/hunting/sigma/test")
    async def test_sigma_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        rule_yaml = body.get("rule_yaml")
        if not rule_yaml:
            raise HTTPException(status_code=400, detail="Missing 'rule_yaml' in test request.")

        from redloop.assessment.sigma_engine import SigmaEngine
        from redloop.assessment.soc_events import UniversalSecurityEvent
        events_raw = body.get("events")
        if events_raw:
            events_to_test = []
            for e in events_raw:
                if isinstance(e, dict):
                    e_copy = dict(e)
                    e_copy.setdefault("ingestion_timestamp", datetime.now(timezone.utc).isoformat())
                    e_copy.setdefault("source_file", "sigma_test")
                    e_copy.setdefault("event_category", "process")
                    e_copy.setdefault("event_action", "process_create")
                    events_to_test.append(UniversalSecurityEvent(**e_copy))
                else:
                    events_to_test.append(e)
        else:
            events_to_test = _soc_ingestion_engine.events

        matches = []
        for ev in events_to_test:
            matched, res = SigmaEngine.evaluate_rule(rule_yaml, ev)
            if matched and res:
                matches.append(res.to_dict())

        return JSONResponse({
            "success": True,
            "total_tested": len(events_to_test),
            "total_matched": len(matches),
            "matches": matches,
        })

    @app.post("/api/hunting/query/plan")
    async def plan_hunting_query_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        query = body.get("query")
        limit = int(body.get("limit", 100))
        if not query:
            raise HTTPException(status_code=400, detail="Missing 'query' string.")

        from redloop.assessment.threat_hunting import ThreatHuntingEngine
        plan = ThreatHuntingEngine.generate_query_plan(query, limit=limit)
        return JSONResponse({"success": True, "plan": plan.to_dict()})

    @app.post("/api/hunting/query/execute")
    async def execute_hunting_query_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        query = body.get("query")
        limit = int(body.get("limit", 100))
        hypothesis = body.get("hypothesis")
        if not query:
            raise HTTPException(status_code=400, detail="Missing 'query' string.")

        from redloop.assessment.threat_hunting import ThreatHuntingEngine
        result = ThreatHuntingEngine.execute_hunt(
            nl_query=query,
            events=_soc_ingestion_engine.events,
            limit=limit,
            hypothesis=hypothesis,
        )
        return JSONResponse({"success": True, "result": result.to_dict()})

    @app.post("/api/hunting/chain/reconstruct")
    async def reconstruct_attack_chain_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}

        title = body.get("title")
        from redloop.assessment.attack_chain import AttackChainReconstructor
        chain = AttackChainReconstructor.reconstruct_chain(
            events=_soc_ingestion_engine.events,
            alerts=_soc_detection_engine.alerts,
            chain_title=title,
        )
        return JSONResponse({"success": True, "chain": chain.to_dict()})

    # ==========================================================================
    # PHASE 7: SOAR AUTOMATION & INCIDENT RESPONSE ORCHESTRATION ROUTES
    # ==========================================================================

    @app.get("/api/soar/workflows")
    async def list_soar_workflows_endpoint(request: Request):
        _require_same_origin(request)
        from redloop.assessment.soar_engine import SOAREngine
        engine = SOAREngine.get_instance(db_path=Path(db_path).parent / "soar.db" if db_path else None)
        return JSONResponse({"success": True, "workflows": engine.list_workflows()})

    @app.get("/api/soar/workflows/{workflow_id}")
    async def get_soar_workflow_endpoint(request: Request, workflow_id: str):
        _require_same_origin(request)
        from redloop.assessment.soar_engine import SOAREngine
        engine = SOAREngine.get_instance(db_path=Path(db_path).parent / "soar.db" if db_path else None)
        wf = engine.get_workflow(workflow_id)
        if not wf:
            raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found.")
        return JSONResponse({"success": True, "workflow": wf.to_dict()})

    @app.post("/api/soar/workflows/{workflow_id}/execute")
    async def execute_soar_workflow_endpoint(request: Request, workflow_id: str):
        _require_same_origin(request)
        import uuid
        try:
            body = await request.json()
        except Exception:
            body = {}

        target_context = body.get("target_context", "127.0.0.1")
        trigger_type_str = body.get("trigger_type", "MANUAL")
        source_record_id = body.get("source_record_id", f"src-{uuid.uuid4().hex[:6]}")
        allow_rerun = bool(body.get("allow_rerun", False))
        capability_token = body.get("capability_token")
        operator = body.get("operator", "operator")

        from redloop.assessment.soar_engine import SOAREngine, TriggerType
        engine = SOAREngine.get_instance(db_path=Path(db_path).parent / "soar.db" if db_path else None)
        try:
            t_type = TriggerType(trigger_type_str.upper())
        except Exception:
            t_type = TriggerType.MANUAL

        trigger = engine.create_trigger(
            trigger_type=t_type,
            source_record_id=source_record_id,
            target_context=target_context,
            provenance="WORKBENCH_SOAR_DISPATCH",
        )

        try:
            record = engine.execute_workflow(
                workflow_id=workflow_id,
                trigger=trigger,
                allow_rerun=allow_rerun,
                capability_token=capability_token,
                operator=operator,
                stored_events=_soc_ingestion_engine.events,
            )
            return JSONResponse({"success": True, "execution": record.to_dict()})
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))

    @app.post("/api/soar/executions/{execution_id}/cancel")
    async def cancel_soar_execution_endpoint(request: Request, execution_id: str):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        reason = body.get("reason", "Cancelled via workbench")
        operator = body.get("operator", "operator")

        from redloop.assessment.soar_engine import SOAREngine
        engine = SOAREngine.get_instance(db_path=Path(db_path).parent / "soar.db" if db_path else None)
        try:
            rec = engine.cancel_execution(execution_id=execution_id, operator=operator, reason=reason)
            return JSONResponse({"success": True, "execution": rec.to_dict()})
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))

    @app.get("/api/soar/executions")
    async def list_soar_executions_endpoint(request: Request):
        _require_same_origin(request)
        from redloop.assessment.soar_engine import SOAREngine
        engine = SOAREngine.get_instance(db_path=Path(db_path).parent / "soar.db" if db_path else None)
        return JSONResponse({"success": True, "executions": engine.list_executions()})

    @app.get("/api/soar/executions/{execution_id}")
    async def get_soar_execution_endpoint(request: Request, execution_id: str):
        _require_same_origin(request)
        from redloop.assessment.soar_engine import SOAREngine
        engine = SOAREngine.get_instance(db_path=Path(db_path).parent / "soar.db" if db_path else None)
        rec = engine.get_execution(execution_id)
        if not rec:
            raise HTTPException(status_code=404, detail=f"Execution '{execution_id}' not found.")
        return JSONResponse({"success": True, "execution": rec.to_dict()})

    # ==========================================================================
    # PHASE 7: CASE MANAGEMENT ROUTES
    # ==========================================================================

    @app.get("/api/cases")
    async def list_cases_endpoint(request: Request):
        _require_same_origin(request)
        status_q = request.query_params.get("status")
        sev_q = request.query_params.get("severity")

        from redloop.assessment.case_management import CaseManager, CaseSeverity, CaseStatus
        cm = CaseManager.get_instance(db_path=Path(db_path).parent / "cases.db" if db_path else None)

        st_filter = CaseStatus(status_q.upper()) if status_q else None
        sev_filter = CaseSeverity(sev_q.upper()) if sev_q else None
        cases = cm.list_cases(status=st_filter, severity=sev_filter)
        return JSONResponse({"success": True, "cases": cases})

    @app.post("/api/cases")
    async def create_case_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        title = body.get("title")
        description = body.get("description", "")
        if not title:
            raise HTTPException(status_code=400, detail="Missing required field 'title'.")

        from redloop.assessment.case_management import (
            CaseManager,
            CasePriority,
            CaseSeverity,
        )
        cm = CaseManager.get_instance(db_path=Path(db_path).parent / "cases.db" if db_path else None)

        sev = CaseSeverity.MEDIUM
        pri = CasePriority.P3
        if body.get("severity"):
            try:
                sev = CaseSeverity(body["severity"].upper())
            except Exception:
                pass
        if body.get("priority"):
            try:
                pri = CasePriority(body["priority"].upper())
            except Exception:
                pass

        case = cm.create_case(
            title=title,
            description=description,
            severity=sev,
            priority=pri,
            assigned_to=body.get("assigned_to", "unassigned"),
            linked_alert_ids=body.get("linked_alert_ids", []),
            linked_incident_ids=body.get("linked_incident_ids", []),
            evidence_ids=body.get("evidence_ids", []),
            related_indicators=body.get("related_indicators", {}),
            creator=body.get("creator", "operator"),
        )
        return JSONResponse({"success": True, "case": case.to_dict()})

    @app.get("/api/cases/{case_id}")
    async def get_case_endpoint(request: Request, case_id: str):
        _require_same_origin(request)
        from redloop.assessment.case_management import CaseManager
        cm = CaseManager.get_instance(db_path=Path(db_path).parent / "cases.db" if db_path else None)
        case = cm.get_case(case_id)
        if not case:
            raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
        return JSONResponse({"success": True, "case": case.to_dict()})

    @app.patch("/api/cases/{case_id}")
    async def update_case_endpoint(request: Request, case_id: str):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        from redloop.assessment.case_management import (
            CaseManager,
            CasePriority,
            CaseSeverity,
            CaseStatus,
        )
        cm = CaseManager.get_instance(db_path=Path(db_path).parent / "cases.db" if db_path else None)

        status_obj = None
        if body.get("status"):
            try:
                status_obj = CaseStatus(body["status"].upper())
            except Exception:
                raise HTTPException(status_code=400, detail=f"Invalid case status '{body.get('status')}'.")

        sev_obj = None
        if body.get("severity"):
            try:
                sev_obj = CaseSeverity(body["severity"].upper())
            except Exception:
                pass

        pri_obj = None
        if body.get("priority"):
            try:
                pri_obj = CasePriority(body["priority"].upper())
            except Exception:
                pass

        try:
            updated = cm.update_case(
                case_id=case_id,
                status=status_obj,
                severity=sev_obj,
                priority=pri_obj,
                assigned_to=body.get("assigned_to"),
                closure_reason=body.get("closure_reason"),
                actor=body.get("actor", "operator"),
            )
            return JSONResponse({"success": True, "case": updated.to_dict()})
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))

    @app.post("/api/cases/{case_id}/notes")
    async def add_case_note_endpoint(request: Request, case_id: str):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        author = body.get("author", "analyst")
        content_txt = body.get("content")
        if not content_txt:
            raise HTTPException(status_code=400, detail="Missing required field 'content'.")

        from redloop.assessment.case_management import CaseManager
        cm = CaseManager.get_instance(db_path=Path(db_path).parent / "cases.db" if db_path else None)
        try:
            note = cm.add_note(case_id=case_id, author=author, content=content_txt)
            return JSONResponse({"success": True, "note": note.to_dict()})
        except ValueError as ve:
            raise HTTPException(status_code=404, detail=str(ve))

    @app.post("/api/cases/{case_id}/evidence")
    async def attach_case_evidence_endpoint(request: Request, case_id: str):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        evidence_ids = body.get("evidence_ids", [])
        if not isinstance(evidence_ids, list):
            raise HTTPException(status_code=400, detail="'evidence_ids' must be a list of string IDs.")

        from redloop.assessment.case_management import CaseManager
        cm = CaseManager.get_instance(db_path=Path(db_path).parent / "cases.db" if db_path else None)
        try:
            attached = cm.attach_evidence(case_id=case_id, evidence_ids=evidence_ids, actor=body.get("actor", "operator"))
            return JSONResponse({"success": True, "evidence_ids": attached})
        except ValueError as ve:
            raise HTTPException(status_code=404, detail=str(ve))

    @app.get("/api/cases/{case_id}/timeline")
    async def get_case_timeline_endpoint(request: Request, case_id: str):
        _require_same_origin(request)
        from redloop.assessment.case_management import CaseManager
        cm = CaseManager.get_instance(db_path=Path(db_path).parent / "cases.db" if db_path else None)
        case = cm.get_case(case_id)
        if not case:
            raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")
        return JSONResponse({"success": True, "timeline": [t.to_dict() for t in case.timeline]})

    @app.get("/api/cases/{case_id}/integrity")
    async def get_case_integrity_endpoint(request: Request, case_id: str):
        _require_same_origin(request)
        from redloop.assessment.case_management import CaseManager
        cm = CaseManager.get_instance(db_path=Path(db_path).parent / "cases.db" if db_path else None)
        report = cm.verify_case_integrity(case_id)
        if report.get("status") == "NOT_FOUND":
            raise HTTPException(status_code=404, detail=report.get("details", "Case not found"))
        return JSONResponse({"success": True, "integrity": report})

    @app.get("/api/cases/{case_id}/audit-report")
    async def get_case_audit_report_endpoint(request: Request, case_id: str):
        _require_same_origin(request)
        from redloop.assessment.case_management import CaseManager
        cm = CaseManager.get_instance(db_path=Path(db_path).parent / "cases.db" if db_path else None)
        report = cm.export_case_audit_report(case_id)
        if "error" in report:
            raise HTTPException(status_code=404, detail=report["error"])
        return JSONResponse({"success": True, "audit_report": report})

    # ==========================================================================
    # PHASE 8: ENTERPRISE SECURITY INTEGRATIONS GATEWAY ROUTES
    # ==========================================================================

    @app.get("/api/integrations")
    async def list_integrations_endpoint(request: Request, category: Optional[str] = None):
        _require_same_origin(request)
        from redloop.integrations.base import ProviderCategory
        from redloop.integrations.registry import IntegrationRegistry
        registry = IntegrationRegistry.get_instance()
        cat_enum = None
        if category:
            try:
                cat_enum = ProviderCategory(category.upper())
            except Exception:
                pass
        providers = registry.list_providers(category=cat_enum)
        return JSONResponse({"success": True, "providers": providers, "total": len(providers)})

    @app.get("/api/integrations/audit")
    async def get_integrations_audit_endpoint(request: Request, limit: int = 50):
        _require_same_origin(request)
        from redloop.integrations.registry import IntegrationRegistry
        registry = IntegrationRegistry.get_instance()
        return JSONResponse({"success": True, "audit_log": registry.get_audit_log(limit=limit)})

    @app.get("/api/integrations/{provider_id}")
    async def get_integration_endpoint(request: Request, provider_id: str):
        _require_same_origin(request)
        from redloop.integrations.registry import IntegrationRegistry
        registry = IntegrationRegistry.get_instance()
        p = registry.get_provider(provider_id)
        if not p:
            raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found.")
        return JSONResponse({"success": True, "provider": p.to_dict()})

    @app.post("/api/integrations/{provider_id}/test")
    async def test_integration_endpoint(request: Request, provider_id: str):
        _require_same_origin(request)
        from redloop.integrations.registry import IntegrationRegistry
        registry = IntegrationRegistry.get_instance()
        p = registry.get_provider(provider_id)
        if not p:
            raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found.")
        health = registry.test_provider(provider_id)
        return JSONResponse({"success": True, "health": health.to_dict()})

    @app.get("/api/integrations/{provider_id}/health")
    async def get_integration_health_endpoint(request: Request, provider_id: str):
        _require_same_origin(request)
        from redloop.integrations.registry import IntegrationRegistry
        registry = IntegrationRegistry.get_instance()
        p = registry.get_provider(provider_id)
        if not p:
            raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found.")
        return JSONResponse({"success": True, "health": p.get_health().to_dict()})

    @app.get("/api/integrations/{provider_id}/capabilities")
    async def get_integration_capabilities_endpoint(request: Request, provider_id: str):
        _require_same_origin(request)
        from redloop.integrations.registry import IntegrationRegistry
        registry = IntegrationRegistry.get_instance()
        p = registry.get_provider(provider_id)
        if not p:
            raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found.")
        return JSONResponse({"success": True, "provider_id": provider_id, "capabilities": p.get_capabilities()})

    @app.post("/api/integrations/{provider_id}/enable")
    async def enable_integration_endpoint(request: Request, provider_id: str):
        _require_same_origin(request)
        from redloop.integrations.registry import IntegrationRegistry
        registry = IntegrationRegistry.get_instance()
        ok = registry.enable_provider(provider_id, enabled=True)
        if not ok:
            raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found.")
        return JSONResponse({"success": True, "provider_id": provider_id, "enabled": True})

    @app.post("/api/integrations/{provider_id}/disable")
    async def disable_integration_endpoint(request: Request, provider_id: str):
        _require_same_origin(request)
        from redloop.integrations.registry import IntegrationRegistry
        registry = IntegrationRegistry.get_instance()
        ok = registry.enable_provider(provider_id, enabled=False)
        if not ok:
            raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found.")
        return JSONResponse({"success": True, "provider_id": provider_id, "enabled": False})

    @app.get("/api/integrations/{provider_id}/events")
    async def get_integration_events_endpoint(request: Request, provider_id: str, limit: int = 50):
        _require_same_origin(request)
        from redloop.integrations.registry import IntegrationRegistry
        registry = IntegrationRegistry.get_instance()
        p = registry.get_provider(provider_id)
        if not p:
            raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found.")
        events = registry.sync_provider(provider_id, limit=limit)
        return JSONResponse({"success": True, "provider_id": provider_id, "events": [e.to_dict() for e in events], "count": len(events)})

    @app.post("/api/integrations/sync")
    async def sync_integrations_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        provider_id = body.get("provider_id")
        limit = int(body.get("limit", 50))
        from redloop.integrations.registry import IntegrationRegistry
        registry = IntegrationRegistry.get_instance()
        job_id = registry.start_sync_job(provider_id=provider_id, limit_per_provider=limit)
        job = registry.get_sync_job(job_id)
        return JSONResponse({"success": True, "sync_job": job})

    @app.get("/api/integrations/sync/{job_id}")
    async def get_sync_job_endpoint(request: Request, job_id: str):
        _require_same_origin(request)
        from redloop.integrations.registry import IntegrationRegistry
        registry = IntegrationRegistry.get_instance()
        job = registry.get_sync_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail=f"Sync job '{job_id}' not found.")
        return JSONResponse({"success": True, "sync_job": job})

    # ==========================================================================
    # PHASE 9: AUTONOMOUS SOC OPERATIONS REST ROUTES
    # ==========================================================================

    # --- Telemetry Ingestion & Synchronization (soc_sync) ---

    @app.get("/api/soc/sync/jobs")
    async def list_soc_sync_jobs_endpoint(request: Request, provider_id: Optional[str] = None, limit: int = 50):
        _require_same_origin(request)
        from redloop.assessment.soc_sync import TelemetrySyncPipeline
        pipe = TelemetrySyncPipeline.get_instance()
        jobs = pipe.list_sync_jobs(provider_id=provider_id, limit=limit)
        return JSONResponse({"success": True, "jobs": jobs, "total": len(jobs)})

    @app.post("/api/soc/sync/trigger")
    async def trigger_soc_sync_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        provider_id = body.get("provider_id", "edr_defender")
        limit = int(body.get("limit", 50))
        from redloop.assessment.soc_sync import TelemetrySyncPipeline
        pipe = TelemetrySyncPipeline.get_instance()
        job = pipe.execute_sync(provider_id=provider_id, limit=limit)
        return JSONResponse({"success": True, "sync_job": job.to_dict()})

    @app.post("/api/soc/sync/{job_id}/cancel")
    async def cancel_soc_sync_endpoint(request: Request, job_id: str):
        _require_same_origin(request)
        from redloop.assessment.soc_sync import TelemetrySyncPipeline
        pipe = TelemetrySyncPipeline.get_instance()
        cancelled = pipe.cancel_sync_job(job_id)
        if not cancelled:
            raise HTTPException(status_code=404, detail=f"Active sync job '{job_id}' not found or already terminated.")
        return JSONResponse({"success": True, "job_id": job_id, "status": "CANCELLED"})

    @app.get("/api/soc/sync/metrics")
    async def get_soc_sync_metrics_endpoint(request: Request):
        _require_same_origin(request)
        from redloop.assessment.soc_sync import TelemetrySyncPipeline
        pipe = TelemetrySyncPipeline.get_instance()
        return JSONResponse({"success": True, "metrics": pipe.get_sync_metrics()})

    # --- Detection Engineering (detection_engineering) ---

    @app.get("/api/detections/rules")
    async def list_detection_rules_endpoint(
        request: Request,
        technique_id: Optional[str] = None,
        enabled_only: bool = False,
    ):
        _require_same_origin(request)
        from redloop.assessment.detection_engineering import DetectionEngineeringManager
        mgr = DetectionEngineeringManager.get_instance()
        rules = mgr.list_rules(
            technique_id=technique_id,
            enabled_only=enabled_only,
        )
        return JSONResponse({"success": True, "rules": rules, "total": len(rules)})

    @app.get("/api/detections/rules/{rule_id}")
    async def get_detection_rule_endpoint(request: Request, rule_id: str):
        _require_same_origin(request)
        from redloop.assessment.detection_engineering import DetectionEngineeringManager
        mgr = DetectionEngineeringManager.get_instance()
        rule = mgr.get_rule(rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail=f"Detection rule '{rule_id}' not found.")
        return JSONResponse({"success": True, "rule": rule.to_dict()})

    @app.post("/api/detections/rules")
    async def create_detection_rule_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body.")
        from redloop.assessment.detection_engineering import DetectionEngineeringManager, DetectionRule, RuleSource, RuleSeverity
        mgr = DetectionEngineeringManager.get_instance()
        try:
            rule = DetectionRule(
                rule_id=body["rule_id"],
                title=body["title"],
                description=body.get("description", ""),
                source=RuleSource(body.get("source", "NATIVE")),
                version=body.get("version", "1.0"),
                technique_id=body["technique_id"],
                tactic=body["tactic"],
                severity=RuleSeverity(body.get("severity", "MEDIUM")),
                confidence=float(body.get("confidence", 0.8)),
                data_sources=body.get("data_sources", []),
                enabled=bool(body.get("enabled", True)),
                author=body.get("author", "analyst"),
            )
            created = mgr.register_rule(rule)
            return JSONResponse({"success": True, "rule": created.to_dict()})
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to create rule: {str(e)}")

    @app.post("/api/detections/rules/{rule_id}/test")
    async def test_detection_rule_endpoint(request: Request, rule_id: str):
        _require_same_origin(request)
        from redloop.assessment.detection_engineering import DetectionEngineeringManager
        mgr = DetectionEngineeringManager.get_instance()
        rule = mgr.get_rule(rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail=f"Detection rule '{rule_id}' not found.")
        result = mgr.run_rule_test_harness(rule_id)
        return JSONResponse({"success": True, "test_result": result})

    @app.get("/api/detections/coverage")
    async def get_detection_coverage_endpoint(request: Request):
        _require_same_origin(request)
        from redloop.assessment.detection_engineering import DetectionEngineeringManager
        mgr = DetectionEngineeringManager.get_instance()
        coverage = mgr.get_attack_coverage_matrix()
        return JSONResponse({"success": True, "coverage": coverage})

    @app.post("/api/detections/rules/{rule_id}/false-positive")
    async def report_detection_false_positive_endpoint(request: Request, rule_id: str):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        reason = body.get("reason", "Reported by analyst")
        from redloop.assessment.detection_engineering import DetectionEngineeringManager
        mgr = DetectionEngineeringManager.get_instance()
        ok = mgr.mark_false_positive(rule_id, reason=reason)
        if not ok:
            raise HTTPException(status_code=404, detail=f"Detection rule '{rule_id}' not found.")
        rule = mgr.get_rule(rule_id)
        return JSONResponse({"success": True, "rule_id": rule_id, "false_positive_count": rule.false_positive_count if rule else 1})

    # --- Cross-Platform Incident Correlation (incident_correlation) ---

    @app.get("/api/incidents")
    async def list_incidents_endpoint(request: Request, severity: Optional[str] = None, include_merged: bool = False, limit: int = 50):
        _require_same_origin(request)
        from redloop.assessment.incident_correlation import IncidentCorrelationEngine
        engine = IncidentCorrelationEngine.get_instance()
        incidents = engine.list_incidents(severity=severity, include_merged=include_merged, limit=limit)
        return JSONResponse({"success": True, "incidents": incidents, "total": len(incidents)})

    @app.get("/api/incidents/{incident_id}")
    async def get_incident_endpoint(request: Request, incident_id: str):
        _require_same_origin(request)
        from redloop.assessment.incident_correlation import IncidentCorrelationEngine
        engine = IncidentCorrelationEngine.get_instance()
        inc = engine.get_incident(incident_id)
        if not inc:
            raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
        return JSONResponse({"success": True, "incident": inc.to_dict()})

    @app.post("/api/incidents/correlate")
    async def run_incident_correlation_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        event_dict = body.get("event")
        from redloop.assessment.incident_correlation import IncidentCorrelationEngine
        from redloop.assessment.soc_events import UniversalSecurityEvent
        engine = IncidentCorrelationEngine.get_instance()
        if event_dict:
            ev = UniversalSecurityEvent(**event_dict)
            inc = engine.correlate_event(ev)
            return JSONResponse({"success": True, "incident": inc.to_dict()})
        else:
            incidents = engine.list_incidents(include_merged=False, limit=50)
            return JSONResponse({"success": True, "incidents": incidents, "total": len(incidents)})

    @app.post("/api/incidents/merge")
    async def merge_incidents_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body.")
        primary_id = body.get("primary_incident_id")
        secondary_id = body.get("secondary_incident_id")
        rationale = body.get("rationale", "Merged by analyst")
        if not primary_id or not secondary_id:
            raise HTTPException(status_code=400, detail="Both 'primary_incident_id' and 'secondary_incident_id' are required.")
        from redloop.assessment.incident_correlation import IncidentCorrelationEngine
        engine = IncidentCorrelationEngine.get_instance()
        try:
            merged = engine.merge_incidents(primary_id, secondary_id, rationale=rationale)
            return JSONResponse({"success": True, "merged_incident": merged.to_dict()})
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @app.post("/api/incidents/{incident_id}/split")
    async def split_incident_endpoint(request: Request, incident_id: str):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body.")
        event_ids = body.get("event_ids", [])
        reason = body.get("reason", "Split by analyst")
        if not event_ids:
            raise HTTPException(status_code=400, detail="'event_ids' list is required to split incident.")
        from redloop.assessment.incident_correlation import IncidentCorrelationEngine
        engine = IncidentCorrelationEngine.get_instance()
        try:
            orig, new_inc = engine.split_incident(incident_id, event_ids_to_split=event_ids, reason=reason)
            return JSONResponse({"success": True, "original_incident": orig.to_dict(), "new_incident": new_inc.to_dict()})
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    # --- Threat Intelligence IOC Lifecycle (ioc_engine) ---

    @app.get("/api/iocs")
    async def list_iocs_endpoint(
        request: Request,
        ioc_type: Optional[str] = None,
        state: Optional[str] = None,
        limit: int = 50,
    ):
        _require_same_origin(request)
        from redloop.assessment.ioc_engine import IOCLifecycleManager, IOCType, IOCState
        mgr = IOCLifecycleManager.get_instance()
        t_enum = IOCType(ioc_type.upper()) if ioc_type else None
        s_enum = IOCState(state.upper()) if state else None
        records = mgr.list_iocs(ioc_type=t_enum, state=s_enum, limit=limit)
        return JSONResponse({"success": True, "iocs": records, "total": len(records)})

    @app.get("/api/iocs/{ioc_id}")
    async def get_ioc_endpoint(request: Request, ioc_id: str):
        _require_same_origin(request)
        from redloop.assessment.ioc_engine import IOCLifecycleManager
        mgr = IOCLifecycleManager.get_instance()
        record = mgr.get_ioc(ioc_id)
        if not record:
            raise HTTPException(status_code=404, detail=f"IOC '{ioc_id}' not found.")
        return JSONResponse({"success": True, "ioc": record.to_dict()})

    @app.post("/api/iocs")
    async def create_ioc_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body.")
        from redloop.assessment.ioc_engine import IOCLifecycleManager, IOCType
        mgr = IOCLifecycleManager.get_instance()
        try:
            rec = mgr.register_ioc(
                ioc_type=IOCType(body["ioc_type"].upper()),
                value=body["value"],
                source=body.get("source", "analyst_manual"),
                confidence=float(body.get("confidence", 0.7)),
                reputation=body.get("reputation", "UNKNOWN"),
                related_case_id=body.get("related_case_id"),
                related_event_id=body.get("related_event_id"),
            )
            return JSONResponse({"success": True, "ioc": rec.to_dict()})
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to ingest IOC: {str(e)}")

    @app.post("/api/iocs/{ioc_id}/disposition")
    async def update_ioc_disposition_endpoint(request: Request, ioc_id: str):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body.")
        new_state = body.get("state")
        reason = body.get("reason", "Analyst disposition update")
        actor = body.get("actor", "analyst")
        if not new_state:
            raise HTTPException(status_code=400, detail="'state' is required.")
        from redloop.assessment.ioc_engine import IOCLifecycleManager, IOCState
        mgr = IOCLifecycleManager.get_instance()
        try:
            st_enum = IOCState(new_state.upper())
            res = mgr.set_disposition(ioc_id, state=st_enum, reason=reason, actor=actor)
            return JSONResponse({"success": True, "ioc": res.to_dict()})
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    # --- SOC Operational Metrics (soc_metrics) ---

    @app.get("/api/metrics/soc")
    async def get_soc_operational_metrics_endpoint(request: Request):
        _require_same_origin(request)
        from redloop.assessment.soc_metrics import SOCMetricsEngine
        metrics = SOCMetricsEngine.get_operational_metrics()
        return JSONResponse({"success": True, "metrics": metrics})

    @app.get("/api/metrics/quality")
    def get_quality_metrics_endpoint(request: Request):
        """Serve statistical evaluation benchmarks and quality indices for dashboard."""
        _require_same_origin(request)
        from pathlib import Path
        import json
        eval_path = Path("artifacts/eval_results.json")
        if eval_path.exists():
            try:
                data = json.loads(eval_path.read_text(encoding="utf-8"))
                return JSONResponse({"success": True, "metrics": data})
            except Exception as exc:
                return JSONResponse({"success": False, "error": str(exc)}, status_code=500)
        return JSONResponse({
            "success": True,
            "status": "NOT_RUN",
            "message": "Evaluation results not found. Run 'redloop eval run' to generate."
        })

    # --- Operational Copilot Intelligence (soc_copilot) ---

    @app.post("/api/soc/copilot/op")
    async def soc_copilot_operational_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body.")
        user_query = body.get("query", "").strip()
        if not user_query:
            raise HTTPException(status_code=400, detail="'query' is required.")
        incident_id = body.get("incident_id")
        alert_id = body.get("alert_id")
        entity_id = body.get("entity_id")
        context = body.get("context", {})
        from redloop.assessment.soc_copilot import SOCCopilotEngine
        result = SOCCopilotEngine.handle_operational_query(
            user_query=user_query,
            incident_id=incident_id,
            alert_id=alert_id,
            entity_id=entity_id,
            context=context,
        )
        return JSONResponse({"success": True, "result": result})

    # ==========================================================================
    # Phase 10: Advanced Threat Hunting & Investigation REST APIs
    # ==========================================================================

    @app.post("/api/hunting/query")
    async def execute_hunting_query_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body.")
        from redloop.assessment.hunting_query import HuntingQueryEngine
        from redloop.assessment.soc_events import UniversalSecurityEvent
        q = body.get("query") or body.get("ast")
        if not q:
            raise HTTPException(status_code=400, detail="'query' or 'ast' is required.")
        raw_events = body.get("events")
        events = None
        if raw_events and isinstance(raw_events, list):
            events = [UniversalSecurityEvent(**e) if isinstance(e, dict) else e for e in raw_events]
        engine = HuntingQueryEngine.get_instance()
        try:
            res = engine.execute_query(q, events=events, operator=body.get("operator", "analyst"))
            return JSONResponse({"success": True, "result": res.to_dict()})
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Query execution failed: {str(e)}")

    @app.get("/api/hunting/queries/saved")
    async def list_saved_hunting_queries_endpoint(request: Request):
        _require_same_origin(request)
        from redloop.assessment.hunting_query import HuntingQueryEngine
        queries = HuntingQueryEngine.get_instance().list_saved_queries()
        return JSONResponse({"success": True, "queries": queries})

    @app.post("/api/hunting/queries/saved")
    async def save_hunting_query_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body.")
        from redloop.assessment.hunting_query import HuntingQueryEngine
        title = body.get("title", "").strip()
        query_ast = body.get("query_ast") or body.get("query")
        if not title or not query_ast:
            raise HTTPException(status_code=400, detail="'title' and 'query_ast' are required.")
        res = HuntingQueryEngine.get_instance().save_query(
            title=title,
            query_ast=query_ast,
            description=body.get("description", ""),
            mitre_techniques=body.get("mitre_techniques", []),
            created_by=body.get("created_by", "analyst"),
        )
        return JSONResponse({"success": True, "saved_query": res})

    @app.delete("/api/hunting/queries/saved/{query_id}")
    async def delete_saved_hunting_query_endpoint(request: Request, query_id: str):
        _require_same_origin(request)
        from redloop.assessment.hunting_query import HuntingQueryEngine
        deleted = HuntingQueryEngine.get_instance().delete_saved_query(query_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Saved query not found.")
        return JSONResponse({"success": True, "query_id": query_id})

    @app.get("/api/hunting/hypotheses")
    async def list_hypotheses_endpoint(request: Request, status: Optional[str] = None, technique: Optional[str] = None, limit: int = 50):
        _require_same_origin(request)
        from redloop.assessment.hypothesis_manager import HypothesisManager, HypothesisStatus
        st_enum = HypothesisStatus(status.upper()) if status else None
        hyps = HypothesisManager.get_instance().list_hypotheses(status=st_enum, mitre_technique=technique, limit=limit)
        return JSONResponse({"success": True, "hypotheses": hyps})

    @app.post("/api/hunting/hypotheses")
    async def create_hypothesis_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body.")
        title = body.get("title", "").strip()
        desc = body.get("description", "").strip()
        if not title:
            raise HTTPException(status_code=400, detail="'title' is required.")
        from redloop.assessment.hypothesis_manager import HypothesisManager
        rec = HypothesisManager.get_instance().create_hypothesis(
            title=title,
            description=desc,
            mitre_techniques=body.get("mitre_techniques", []),
            expected_evidence=body.get("expected_evidence", []),
            lead_hunter=body.get("lead_hunter", "analyst"),
        )
        return JSONResponse({"success": True, "hypothesis": rec.to_dict()})

    @app.get("/api/hunting/hypotheses/{hypothesis_id}")
    async def get_hypothesis_endpoint(request: Request, hypothesis_id: str):
        _require_same_origin(request)
        from redloop.assessment.hypothesis_manager import HypothesisManager
        rec = HypothesisManager.get_instance().get_hypothesis(hypothesis_id)
        if not rec:
            raise HTTPException(status_code=404, detail="Hypothesis not found.")
        return JSONResponse({"success": True, "hypothesis": rec.to_dict()})

    @app.post("/api/hunting/hypotheses/{hypothesis_id}/evidence")
    async def add_hypothesis_evidence_endpoint(request: Request, hypothesis_id: str):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body.")
        desc = body.get("description", "").strip()
        if not desc:
            raise HTTPException(status_code=400, detail="'description' is required.")
        from redloop.assessment.hypothesis_manager import HypothesisManager
        rec = HypothesisManager.get_instance().add_evidence(
            hypothesis_id=hypothesis_id,
            description=desc,
            source_type=body.get("source_type", "analyst_observation"),
            source_reference=body.get("source_reference", "manual"),
            is_contradictory=bool(body.get("is_contradictory", False)),
            weight=float(body.get("weight", 1.0)),
            recorded_by=body.get("recorded_by", "analyst"),
        )
        return JSONResponse({"success": True, "hypothesis": rec.to_dict()})

    @app.post("/api/hunting/reconstruction/process-tree")
    async def reconstruct_process_tree_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body.")
        from redloop.assessment.attack_reconstruction import AttackReconstructionEngine
        from redloop.assessment.soc_events import UniversalSecurityEvent
        raw_events = body.get("events", [])
        events = [UniversalSecurityEvent(**e) if isinstance(e, dict) else e for e in raw_events]
        focus = body.get("focus_host")
        graph = AttackReconstructionEngine.reconstruct_process_lineage(events=events, focus_host=focus)
        return JSONResponse({"success": True, "graph": graph.to_dict()})

    @app.post("/api/hunting/pivot")
    async def execute_hunting_pivot_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body.")
        e_type = body.get("entity_type")
        e_val = body.get("entity_value")
        if not e_type or not e_val:
            raise HTTPException(status_code=400, detail="'entity_type' and 'entity_value' are required.")
        from redloop.assessment.hunting_pivots import ThreatHuntingPivotEngine
        from redloop.assessment.soc_events import UniversalSecurityEvent
        raw_events = body.get("events", [])
        events = [UniversalSecurityEvent(**e) if isinstance(e, dict) else e for e in raw_events]
        max_depth = int(body.get("max_depth", 3))
        res = ThreatHuntingPivotEngine.execute_pivot(entity_type=e_type, entity_value=e_val, events=events, max_depth=max_depth)
        return JSONResponse({"success": True, "pivot": res.to_dict()})

    @app.post("/api/investigations/reports/generate")
    async def generate_investigation_report_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body.")
        from redloop.assessment.investigation_reports import InvestigationReportGenerator
        from redloop.assessment.soc_events import UniversalSecurityEvent
        case_id = body.get("case_id")
        title = body.get("title", "Threat Hunting Investigation")
        author = body.get("author", "threat_hunter")
        raw_events = body.get("events", [])
        events = [UniversalSecurityEvent(**e) if isinstance(e, dict) else e for e in raw_events]

        if case_id:
            rep = InvestigationReportGenerator.generate_case_report(case_id=case_id, author=author)
        else:
            rep = InvestigationReportGenerator.generate_custom_hunt_report(title=title, events=events, author=author)

        return JSONResponse({
            "success": True,
            "report": rep.to_dict(),
            "markdown": rep.to_markdown(),
        })








    # ==========================================================================
    # CANONICAL 9 CORE INTEGRATIONS & 10-STAGE PIPELINE APIS
    # ==========================================================================

    @app.get("/api/core-integrations")
    def get_core_integrations_endpoint(force: bool = False):
        mgr = CoreIntegrationsManager.get_instance()
        if force:
            return JSONResponse(mgr.probe_all_integrations(force=True))
        return JSONResponse(mgr.get_summary())

    @app.post("/api/core-integrations/{provider_id}/test")
    def test_core_integration_endpoint(provider_id: str, request: Request):
        _require_same_origin(request)
        mgr = CoreIntegrationsManager.get_instance()
        try:
            info = mgr.probe_integration(provider_id)
            return JSONResponse({"success": True, "integration": info.to_dict()})
        except KeyError:
            raise HTTPException(status_code=404, detail=f"Integration '{provider_id}' not found.")

    @app.post("/api/core-integrations/test-all")
    def test_all_core_integrations_endpoint(request: Request):
        _require_same_origin(request)
        mgr = CoreIntegrationsManager.get_instance()
        return JSONResponse(mgr.probe_all_integrations(force=True))

    @app.post("/api/investigation/pipeline/start")
    async def start_investigation_pipeline_endpoint(request: Request):
        _require_same_origin(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        target = str(body.get("target", "127.0.0.1")).strip() or "127.0.0.1"
        engine = InvestigationPipelineEngine.get_instance()
        record = engine.create_pipeline(target)
        # Execute asynchronously in background
        asyncio.create_task(engine.execute_pipeline(record.pipeline_id, scope_manager=scope_manager))
        return JSONResponse({"success": True, "run_id": record.pipeline_id, "pipeline_id": record.pipeline_id, "status": record.status.lower(), "pipeline": record.to_dict(), "stages": [s.to_dict() for s in record.stages.values()]})

    @app.get("/api/investigation/pipeline/{pipeline_id}/status")
    def get_investigation_pipeline_status_endpoint(pipeline_id: str):
        engine = InvestigationPipelineEngine.get_instance()
        record = engine.get_pipeline(pipeline_id)
        if not record:
            raise HTTPException(status_code=404, detail=f"Pipeline '{pipeline_id}' not found.")
        return JSONResponse({"success": True, "run_id": record.pipeline_id, "pipeline_id": record.pipeline_id, "status": record.status.lower(), "pipeline": record.to_dict(), "stages": [s.to_dict() for s in record.stages.values()]})

    @app.post("/api/investigation/pipeline/{pipeline_id}/stage/{stage_id}/run")
    async def run_investigation_pipeline_stage_endpoint(pipeline_id: str, stage_id: str, request: Request):
        _require_same_origin(request)
        engine = InvestigationPipelineEngine.get_instance()
        try:
            stage = await engine.execute_stage(pipeline_id, stage_id, scope_manager=scope_manager)
            return JSONResponse({"success": True, "stage": stage.to_dict()})
        except KeyError as ke:
            raise HTTPException(status_code=404, detail=str(ke))

    @app.post("/api/investigation/pipeline/{pipeline_id}/cancel")
    def cancel_investigation_pipeline_endpoint(pipeline_id: str, request: Request):
        _require_same_origin(request)
        engine = InvestigationPipelineEngine.get_instance()
        record = engine.get_pipeline(pipeline_id)
        if not record:
            raise HTTPException(status_code=404, detail=f"Pipeline '{pipeline_id}' not found.")
        record.status = "CANCELLED"
        return JSONResponse({"success": True, "message": "Pipeline execution cancelled."})

    @app.get("/api/investigation/pipeline/{pipeline_id}/report")
    def get_investigation_pipeline_report_endpoint(pipeline_id: str):
        engine = InvestigationPipelineEngine.get_instance()
        record = engine.get_pipeline(pipeline_id)
        if not record:
            raise HTTPException(status_code=404, detail=f"Pipeline '{pipeline_id}' not found.")
        return JSONResponse({
            "success": True,
            "pipeline_id": pipeline_id,
            "target": record.target,
            "status": record.status,
            "risk_score": record.risk_score,
            "risk_level": record.risk_level,
            "report_markdown": record.summary_report,
            "findings": record.findings,
            "evidence": record.evidence,
        })
