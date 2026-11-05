"""Canonical Core Integrations Hub for REDLOOP.

Manages, probes, verifies, and reports genuine operational health for the 9 core integrations:
1. Ollama (Local AI Daemon)
2. Groq (Cloud AI Acceleration)
3. NVIDIA NIM (Enterprise AI Microservices)
4. OpenRouter (Unified AI Gateway)
5. OpenAI (OpenAI Platform)
6. Anthropic (Claude API)
7. Gemini (Google Gemini API)
8. VirusTotal (Threat Intelligence)
9. Shodan (Internet Exposure & Attack Surface)

Strict Integrity Rule: Status is CONNECTED only when live HTTP/socket verification succeeds.
Never fakes, simulates, or hardcodes connectivity.
"""

from __future__ import annotations

import concurrent.futures
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.request
from dotenv import load_dotenv

load_dotenv(override=True)
logger = logging.getLogger("redloop.integrations.core_hub")


class IntegrationStatus:
    CONNECTED = "CONNECTED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    AUTH_FAILED = "AUTH_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    DAEMON_STOPPED = "DAEMON_STOPPED"
    TIMEOUT = "TIMEOUT"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass
class IntegrationInfo:
    id: str
    name: str
    category: str  # "LOCAL_AI", "CLOUD_AI", "THREAT_INTEL"
    description: str
    configured: bool
    status: str
    latency_ms: Optional[float] = None
    last_check: Optional[str] = None
    endpoint: str = ""
    active_model: str = ""
    masked_key: str = ""
    error_message: Optional[str] = None
    consecutive_successes: int = 0
    history: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CoreIntegrationsManager:
    """Singleton manager for the 9 canonical integrations."""

    _instance: Optional[CoreIntegrationsManager] = None

    def __init__(self) -> None:
        self._cache: Dict[str, IntegrationInfo] = {}
        self._last_all_check: float = 0.0
        self._cache_ttl: float = 60.0  # 60s cache
        self._init_registry()

    @classmethod
    def get_instance(cls) -> CoreIntegrationsManager:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _mask_key(self, key: str) -> str:
        if not key:
            return ""
        if len(key) <= 8:
            return "****"
        return f"{key[:4]}...{key[-4:]}"

    def _init_registry(self) -> None:
        load_dotenv(override=True)
        specs = [
            ("ollama", "Ollama Local AI", "LOCAL_AI", "Local-first on-device LLM inference daemon", os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434"), os.environ.get("OLLAMA_MODEL", "qwen3:8b"), ""),
            ("groq", "Groq LPU Acceleration", "CLOUD_AI", "Ultra-fast low-latency cloud LPU inference", "https://api.groq.com/openai/v1", os.environ.get("GROQ_MODEL", "qwen/qwen3.8-27b"), os.environ.get("GROQ_API_KEY", "")),
            ("nvidia_nim", "NVIDIA NIM Microservices", "CLOUD_AI", "NVIDIA enterprise AI reasoning microservices", "https://integrate.api.nvidia.com/v1", os.environ.get("NVIDIA_MODEL", "meta/llama-3.2-11b-vision-instruct"), os.environ.get("NVIDIA_API_KEY", "")),
            ("openrouter", "OpenRouter Multi-Provider", "CLOUD_AI", "Aggregated multi-model AI routing platform", "https://openrouter.ai/api/v1", os.environ.get("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct"), os.environ.get("OPENROUTER_API_KEY", "")),
            ("openai", "OpenAI Platform", "CLOUD_AI", "GPT-4o and advanced reasoning models", "https://api.openai.com/v1", os.environ.get("OPENAI_MODEL", "gpt-4o-mini"), os.environ.get("OPENAI_API_KEY", "")),
            ("anthropic", "Anthropic Claude API", "CLOUD_AI", "Claude 3.5 Sonnet frontier cybersecurity reasoning", "https://api.anthropic.com/v1", os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022"), os.environ.get("ANTHROPIC_API_KEY", "") or os.environ.get("ANTHROPIC_AUTH_TOKEN", "")),
            ("gemini", "Google Gemini API", "CLOUD_AI", "Gemini 2.0 Flash multimodal cybersecurity intelligence", "https://generativelanguage.googleapis.com", os.environ.get("GEMINI_MODEL", "gemini-2.0-flash"), os.environ.get("GEMINI_API_KEY", "") or os.environ.get("GOOGLE_API_KEY", "")),
            ("virustotal", "VirusTotal Threat Intelligence", "THREAT_INTEL", "Crowdsourced file, hash, domain, and IP malware analysis", os.environ.get("VIRUSTOTAL_BASE_URL", "https://www.virustotal.com/api/v3"), "VT v3 API", os.environ.get("VIRUSTOTAL_API_KEY", "")),
            ("shodan", "Shodan Exposure Search", "THREAT_INTEL", "Global attack surface exposure and open port discovery", "https://api.shodan.io", "Shodan API", os.environ.get("SHODAN_API_KEY", "")),
        ]

        for pid, name, cat, desc, endpoint, model, key in specs:
            is_conf = bool(key) if pid != "ollama" else True
            self._cache[pid] = IntegrationInfo(
                id=pid,
                name=name,
                category=cat,
                description=desc,
                configured=is_conf,
                status=IntegrationStatus.NOT_CONFIGURED if not is_conf else IntegrationStatus.UNAVAILABLE,
                endpoint=endpoint,
                active_model=model,
                masked_key=self._mask_key(key),
            )

    def probe_integration(self, provider_id: str, timeout: float = 4.0) -> IntegrationInfo:
        """Execute a genuine, lightweight live connectivity test against the specified provider."""
        info = self._cache.get(provider_id)
        if not info:
            raise KeyError(f"Unknown integration '{provider_id}'.")

        now_iso = datetime.now(timezone.utc).isoformat()
        t0 = time.monotonic()

        try:
            if provider_id == "ollama":
                url = f"{info.endpoint}/api/tags"
                req = urllib.request.Request(url, headers={"User-Agent": "REDLOOP-Health/1.0"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    lat = round((time.monotonic() - t0) * 1000, 1)
                    data = json.loads(resp.read().decode("utf-8"))
                    models = [m.get("name", "") for m in data.get("models", [])]
                    info.status = IntegrationStatus.CONNECTED
                    info.latency_ms = lat
                    info.error_message = None
                    if models:
                        info.active_model = models[0]

            elif provider_id == "groq":
                key = os.environ.get("GROQ_API_KEY", "")
                if not key:
                    info.status = IntegrationStatus.NOT_CONFIGURED
                    info.error_message = "GROQ_API_KEY not configured in .env"
                else:
                    url = "https://api.groq.com/openai/v1/models"
                    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {key}", "User-Agent": "REDLOOP/1.0"})
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        lat = round((time.monotonic() - t0) * 1000, 1)
                        info.status = IntegrationStatus.CONNECTED
                        info.latency_ms = lat
                        info.error_message = None

            elif provider_id == "nvidia_nim":
                key = os.environ.get("NVIDIA_API_KEY", "")
                if not key:
                    info.status = IntegrationStatus.NOT_CONFIGURED
                    info.error_message = "NVIDIA_API_KEY not configured in .env"
                else:
                    url = "https://integrate.api.nvidia.com/v1/models"
                    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {key}", "User-Agent": "REDLOOP/1.0"})
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        lat = round((time.monotonic() - t0) * 1000, 1)
                        info.status = IntegrationStatus.CONNECTED
                        info.latency_ms = lat
                        info.error_message = None

            elif provider_id == "openrouter":
                key = os.environ.get("OPENROUTER_API_KEY", "")
                if not key:
                    info.status = IntegrationStatus.NOT_CONFIGURED
                    info.error_message = "OPENROUTER_API_KEY not configured in .env"
                else:
                    url = "https://openrouter.ai/api/v1/auth/key"
                    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {key}", "User-Agent": "REDLOOP/1.0"})
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        lat = round((time.monotonic() - t0) * 1000, 1)
                        info.status = IntegrationStatus.CONNECTED
                        info.latency_ms = lat
                        info.error_message = None

            elif provider_id == "openai":
                key = os.environ.get("OPENAI_API_KEY", "")
                if not key:
                    info.status = IntegrationStatus.NOT_CONFIGURED
                    info.error_message = "OPENAI_API_KEY not configured in .env"
                else:
                    url = "https://api.openai.com/v1/models"
                    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {key}", "User-Agent": "REDLOOP/1.0"})
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        lat = round((time.monotonic() - t0) * 1000, 1)
                        info.status = IntegrationStatus.CONNECTED
                        info.latency_ms = lat
                        info.error_message = None

            elif provider_id == "anthropic":
                key = os.environ.get("ANTHROPIC_API_KEY", "") or os.environ.get("ANTHROPIC_AUTH_TOKEN", "")
                if not key:
                    info.status = IntegrationStatus.NOT_CONFIGURED
                    info.error_message = "ANTHROPIC_API_KEY not configured in .env"
                else:
                    url = "https://api.anthropic.com/v1/models"
                    req = urllib.request.Request(url, headers={"x-api-key": key, "anthropic-version": "2023-06-01", "User-Agent": "REDLOOP/1.0"})
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        lat = round((time.monotonic() - t0) * 1000, 1)
                        info.status = IntegrationStatus.CONNECTED
                        info.latency_ms = lat
                        info.error_message = None

            elif provider_id == "gemini":
                key = os.environ.get("GEMINI_API_KEY", "") or os.environ.get("GOOGLE_API_KEY", "")
                if not key:
                    info.status = IntegrationStatus.NOT_CONFIGURED
                    info.error_message = "GEMINI_API_KEY not configured in .env"
                else:
                    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={key}"
                    req = urllib.request.Request(url, headers={"User-Agent": "REDLOOP/1.0"})
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        lat = round((time.monotonic() - t0) * 1000, 1)
                        info.status = IntegrationStatus.CONNECTED
                        info.latency_ms = lat
                        info.error_message = None

            elif provider_id == "virustotal":
                key = os.environ.get("VIRUSTOTAL_API_KEY", "")
                if not key:
                    info.status = IntegrationStatus.NOT_CONFIGURED
                    info.error_message = "VIRUSTOTAL_API_KEY not configured in .env"
                else:
                    url = "https://www.virustotal.com/api/v3/users/current"
                    req = urllib.request.Request(url, headers={"x-apikey": key, "User-Agent": "REDLOOP/1.0"})
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        lat = round((time.monotonic() - t0) * 1000, 1)
                        info.status = IntegrationStatus.CONNECTED
                        info.latency_ms = lat
                        info.error_message = None

            elif provider_id == "shodan":
                key = os.environ.get("SHODAN_API_KEY", "")
                if not key:
                    info.status = IntegrationStatus.NOT_CONFIGURED
                    info.error_message = "SHODAN_API_KEY not configured in .env"
                else:
                    url = f"https://api.shodan.io/api-info?key={key}"
                    req = urllib.request.Request(url, headers={"User-Agent": "REDLOOP/1.0"})
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        lat = round((time.monotonic() - t0) * 1000, 1)
                        info.status = IntegrationStatus.CONNECTED
                        info.latency_ms = lat
                        info.error_message = None

        except urllib.error.HTTPError as he:
            lat = round((time.monotonic() - t0) * 1000, 1)
            info.latency_ms = lat
            if he.code in (401, 403):
                info.status = IntegrationStatus.AUTH_FAILED
                info.error_message = f"HTTP {he.code}: Unauthorized / Invalid API Key."
            elif he.code == 429:
                info.status = IntegrationStatus.RATE_LIMITED
                info.error_message = "HTTP 429: Rate Limit / Quota Exceeded."
            else:
                info.status = f"HTTP_{he.code}"
                info.error_message = f"HTTP {he.code}: {he.reason}"
        except Exception as exc:
            lat = round((time.monotonic() - t0) * 1000, 1)
            info.latency_ms = lat
            err_str = str(exc).lower()
            if "refused" in err_str:
                info.status = IntegrationStatus.DAEMON_STOPPED
                info.error_message = f"ConnectionRefused: Service daemon not running at {info.endpoint}."
            elif "timeout" in err_str:
                info.status = IntegrationStatus.TIMEOUT
                info.error_message = f"Timeout: Provider endpoint failed to respond within {timeout}s."
            else:
                info.status = IntegrationStatus.UNAVAILABLE
                info.error_message = f"{type(exc).__name__}: {str(exc)[:100]}"

        info.last_check = now_iso
        if info.status == IntegrationStatus.CONNECTED:
            info.consecutive_successes += 1
        else:
            info.consecutive_successes = 0

        info.history.insert(0, {
            "timestamp": now_iso,
            "status": info.status,
            "latency_ms": info.latency_ms,
            "error": info.error_message,
        })
        info.history = info.history[:10]  # retain 10 samples
        return info

    def probe_all_integrations(self, force: bool = False) -> Dict[str, Any]:
        """Probe all 9 integrations and return structured summary."""
        now = time.monotonic()
        if not force and (now - self._last_all_check) < self._cache_ttl and self._cache:
            pass  # return cached
        else:
            pids = list(self._cache.keys())
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(9, len(pids) or 1)) as executor:
                futures = {executor.submit(self.probe_integration, pid, 2.0): pid for pid in pids}
                for f in concurrent.futures.as_completed(futures):
                    pid = futures[f]
                    try:
                        f.result()
                    except Exception as exc:
                        logger.warning("Failed probing %s: %s", pid, exc)
            self._last_all_check = now

        items = list(self._cache.values())
        connected_count = sum(1 for it in items if it.status == IntegrationStatus.CONNECTED)
        total_count = len(items)

        return {
            "connected_count": connected_count,
            "total_count": total_count,
            "connected_ratio": f"{connected_count}/{total_count}",
            "status_label": f"{connected_count}/{total_count} CONNECTED",
            "last_check": datetime.now(timezone.utc).isoformat(),
            "integrations": [it.to_dict() for it in items],
        }

    def get_summary(self) -> Dict[str, Any]:
        """Fast non-blocking read of current integration health states."""
        if not self._cache or self._last_all_check == 0:
            return self.probe_all_integrations(force=True)
        items = list(self._cache.values())
        connected_count = sum(1 for it in items if it.status == IntegrationStatus.CONNECTED)
        total_count = len(items)
        return {
            "connected_count": connected_count,
            "total_count": total_count,
            "connected_ratio": f"{connected_count}/{total_count}",
            "status_label": f"{connected_count}/{total_count} CONNECTED",
            "last_check": datetime.now(timezone.utc).isoformat(),
            "integrations": [it.to_dict() for it in items],
        }
