"""Generalized Local OpenAI-Compatible Endpoint Adapter (Phase L, Gate L.7).

Extends REDLOOP's local model support beyond Ollama to any OpenAI-compatible
local inference server:
- `llama.cpp` HTTP server (`llama-server`, default `http://127.0.0.1:8080/v1`)
- `LM Studio` local server (default `http://127.0.0.1:1234/v1`)
- `vLLM` OpenAI-compatible server (default `http://127.0.0.1:8000/v1`)
- Any custom OpenAI `/v1/chat/completions` local endpoint via `base_url`

Preserves Phase C resource-aware RAM tiering (`get_system_ram_gb()`) so that
requesting an 8B/7B/14B GGUF or safetensors model on a memory-constrained host
automatically down-tiers to a lightweight Q4_K_M model (`0.5B` or `4B`) without OOM.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from redloop.llm import get_system_ram_gb

DEFAULT_BACKEND_URLS: dict[str, str] = {
    "llama_cpp": "http://127.0.0.1:8080/v1",
    "lm_studio": "http://127.0.0.1:1234/v1",
    "vllm": "http://127.0.0.1:8000/v1",
    "ollama_openai": "http://127.0.0.1:11434/v1",
}


def select_resource_aware_local_openai_model(
    requested_model: str,
    safe_ram_threshold_gb: float = 6.0,
    allow_insufficient_ram_override: bool = False,
    total_ram_override: float | None = None,
    avail_ram_override: float | None = None,
) -> tuple[str, str | None]:
    """Apply Phase C RAM tiering to OpenAI-compatible local models (GGUF / AWQ / safetensors).

    - If requested model is >= 7B/8B (or 4B) and host RAM is below safe threshold:
      - If `avail_gb < 2.0` or `total_gb <= 8.0` -> selects `qwen2.5-0.5b-instruct-q4_k_m.gguf`
      - Else (`avail_gb < safe_ram_threshold_gb` or `total_gb < 12.0`) -> selects `qwen3-4b-instruct-q4_k_m.gguf`
    """
    total_gb, avail_gb = get_system_ram_gb()
    if total_ram_override is not None:
        total_gb = total_ram_override
    if avail_ram_override is not None:
        avail_gb = avail_ram_override

    model_lower = requested_model.lower()
    is_heavy = any(
        tag in model_lower
        for tag in (
            ":8b",
            "-8b",
            ":7b",
            "-7b",
            ":13b",
            "-13b",
            ":14b",
            "-14b",
            ":32b",
            "-32b",
            ":70b",
            "-70b",
        )
    )
    is_medium = any(tag in model_lower for tag in (":4b", "-4b", ":3b", "-3b"))

    if (is_heavy or is_medium) and (avail_gb < safe_ram_threshold_gb or total_gb < 12.0):
        if not allow_insufficient_ram_override:
            if avail_gb < 2.0 or total_gb <= 8.0:
                safe_model = "qwen2.5-0.5b-instruct-q4_k_m.gguf"
            else:
                safe_model = "qwen3-4b-instruct-q4_k_m.gguf"
            warning = (
                f"RESOURCE WARNING (local_openai): Model '{requested_model}' requires >= {safe_ram_threshold_gb:.1f} GB "
                f"free RAM, but only {avail_gb:.2f} GB is available (total RAM: {total_gb:.2f} GB). "
                f"Defaulting to resource-safe GGUF tier '{safe_model}' to prevent OOM."
            )
            return safe_model, warning
        warning = (
            f"OPERATOR OVERRIDE WARNING (local_openai): Forcing heavy model '{requested_model}' "
            f"with {avail_gb:.2f} GB available RAM."
        )
        return requested_model, warning

    return requested_model, None


@dataclass(frozen=True)
class LocalOpenAIEndpointConfig:
    """Configuration for any OpenAI-compatible local model server."""

    base_url: str = "http://127.0.0.1:8080/v1"
    backend_type: str = "llama_cpp"
    requested_model: str = "qwen2.5-coder-7b-instruct-q4_k_m.gguf"
    api_key: str = "local-no-key-required"
    safe_ram_threshold_gb: float = 6.0
    allow_insufficient_ram_override: bool = False
    timeout_s: float = 15.0
    max_tokens: int = 256
    temperature: float = 0.2


@dataclass
class LocalOpenAICompletion:
    """Structured completion response from a local OpenAI-compatible endpoint."""

    text: str
    backend_type: str
    base_url: str
    requested_model: str
    effective_model: str
    ram_tier_warning: str | None
    elapsed_ms: float
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "backend_type": self.backend_type,
            "base_url": self.base_url,
            "requested_model": self.requested_model,
            "effective_model": self.effective_model,
            "ram_tier_warning": self.ram_tier_warning,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
        }


class LocalOpenAIClient:
    """Client for OpenAI-compatible local inference servers (`llama.cpp`, `LM Studio`, `vLLM`)."""

    def __init__(
        self,
        config: LocalOpenAIEndpointConfig | None = None,
        http_client: httpx.Client | None = None,
        total_ram_override: float | None = None,
        avail_ram_override: float | None = None,
    ) -> None:
        self.config = config or LocalOpenAIEndpointConfig()
        self._client = http_client
        self._total_ram_override = total_ram_override
        self._avail_ram_override = avail_ram_override

    def resolve_effective_model(self, model_override: str | None = None) -> tuple[str, str | None]:
        req_model = model_override or self.config.requested_model
        return select_resource_aware_local_openai_model(
            requested_model=req_model,
            safe_ram_threshold_gb=self.config.safe_ram_threshold_gb,
            allow_insufficient_ram_override=self.config.allow_insufficient_ram_override,
            total_ram_override=self._total_ram_override,
            avail_ram_override=self._avail_ram_override,
        )

    def list_models(self) -> list[str]:
        url = f"{self.config.base_url.rstrip('/')}/models"
        headers = {"Authorization": f"Bearer {self.config.api_key}"}
        if self._client is not None:
            resp = self._client.get(url, headers=headers, timeout=self.config.timeout_s)
        else:
            with httpx.Client(timeout=self.config.timeout_s) as client:
                resp = client.get(url, headers=headers)
        resp.raise_for_status()
        payload = resp.json()
        data = payload.get("data", [])
        return [str(item.get("id", "")) for item in data if isinstance(item, dict) and item.get("id")]

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        model_override: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LocalOpenAICompletion:
        effective_model, ram_warning = self.resolve_effective_model(model_override)
        url = f"{self.config.base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": effective_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": max_tokens if max_tokens is not None else self.config.max_tokens,
            "stream": False,
        }

        t0 = time.monotonic()
        if self._client is not None:
            resp = self._client.post(url, headers=headers, json=body, timeout=self.config.timeout_s)
        else:
            with httpx.Client(timeout=self.config.timeout_s) as client:
                resp = client.post(url, headers=headers, json=body)
        resp.raise_for_status()
        elapsed_ms = (time.monotonic() - t0) * 1000.0

        data = resp.json()
        choices = data.get("choices") or []
        if not choices:
            raise RuntimeError("Local OpenAI endpoint returned empty choices")
        msg = choices[0].get("message") or {}
        content = str(msg.get("content") or choices[0].get("text") or "").strip()
        usage = data.get("usage") or {}
        p_tok = int(usage.get("prompt_tokens", 0))
        c_tok = int(usage.get("completion_tokens", 0))
        t_tok = int(usage.get("total_tokens", p_tok + c_tok))

        return LocalOpenAICompletion(
            text=content,
            backend_type=self.config.backend_type,
            base_url=self.config.base_url,
            requested_model=model_override or self.config.requested_model,
            effective_model=effective_model,
            ram_tier_warning=ram_warning,
            elapsed_ms=elapsed_ms,
            prompt_tokens=p_tok,
            completion_tokens=c_tok,
            total_tokens=t_tok,
        )


BENCHMARK_30_PROMPTS: list[str] = [
    "Explain the difference between TCP SYN scan (-sS) and TCP Connect scan (-sT) in nmap.",
    "Summarize passive DNS enumeration techniques for an authorized bug bounty scope.",
    "How does HTTP Strict-Transport-Security (HSTS) mitigate SSL stripping attacks?",
    "Describe how Certificate Transparency (CT) logs help identify forgotten subdomains.",
    "What is the security impact of an exposed .git/config file on a production web server?",
    "Explain how SPF, DKIM, and DMARC work together to prevent email spoofing.",
    "How do you detect UPX packing in an ELF64 binary during static triage?",
    "What indicators distinguish a soft-404 page from a true account profile page in username OSINT?",
    "Explain how SQL injection parameterized queries prevent second-order command injection.",
    "What is Server-Side Request Forgery (SSRF) and why must cloud metadata IPs (169.254.169.254) be blocked?",
    "Describe the purpose of Shannon entropy analysis when inspecting unknown binary sections.",
    "How does OAuth 2.0 PKCE protect authorization codes in public clients?",
    "What are the risks of permissive CORS headers (Access-Control-Allow-Origin: *) with credentials?",
    "Explain how DNS zone transfer (AXFR) misconfigurations expose internal infrastructure.",
    "How does a circuit breaker prevent cascading failures during rate-limited OSINT API queries?",
    "What is the difference between ITU-T E.164 phone number formatting and national significant numbers?",
    "Explain how x86_64 function prologues (endbr64; push rbp; mov rbp, rsp) are identified in radare2.",
    "Why must GPL-3.0 tools like SpiderFoot be isolated over REST rather than linked into an MIT codebase?",
    "How does JWT signature verification fail when the 'alg: none' vulnerability is present?",
    "Describe how Subdomain Takeover occurs when a CNAME points to an unclaimed cloud resource.",
    "What is HTTP request smuggling (CL.TE vs TE.CL) and how is it mitigated at the reverse proxy?",
    "Explain why LLM-generated CLI flags must be validated against captured --help schemas before execution.",
    "How do you verify an Ed25519 signature over an EngagementScope YAML file?",
    "What information can be safely derived from a passive WHOIS and RDAP lookup?",
    "Explain how Content-Security-Policy (CSP) nonce-based script policies mitigate XSS.",
    "What is the role of Wilson 95% confidence intervals when reporting classifier accuracy on small holdouts?",
    "How does TLS 1.3 improve handshake latency and forward secrecy compared to TLS 1.2?",
    "Describe how gobuster vhost mode differs from gobuster dir mode during web reconnaissance.",
    "Why is air-gapped sandboxing required before running strings or disassembly on untrusted binaries?",
    "Summarize best practices for rate-limiting concurrent HTTP checks across 80+ OSINT platforms.",
]


def run_local_openai_30_prompt_benchmark(
    client: LocalOpenAIClient,
    prompts: list[str] | None = None,
) -> dict[str, Any]:
    """Execute the 30-prompt benchmark against a non-Ollama local OpenAI-compatible endpoint."""
    prompt_list = prompts or BENCHMARK_30_PROMPTS
    total_ram_gb, avail_ram_gb = get_system_ram_gb()
    latencies_ms: list[float] = []
    completions: list[dict[str, Any]] = []
    oom_errors = 0
    failures = 0

    for idx, prompt in enumerate(prompt_list, start=1):
        try:
            res = client.complete(
                system_prompt="You are REDLOOP, a grounded cybersecurity assistant. Answer concisely.",
                user_prompt=prompt,
            )
            latencies_ms.append(res.elapsed_ms)
            completions.append(
                {
                    "prompt_index": idx,
                    "prompt": prompt,
                    "requested_model": res.requested_model,
                    "effective_model": res.effective_model,
                    "ram_tier_warning": res.ram_tier_warning is not None,
                    "elapsed_ms": round(res.elapsed_ms, 2),
                    "total_tokens": res.total_tokens,
                    "response_excerpt": res.text[:120],
                }
            )
        except MemoryError:
            oom_errors += 1
            failures += 1
        except Exception:
            failures += 1

    sorted_lat = sorted(latencies_ms) if latencies_ms else [0.0]
    n = len(sorted_lat)
    p50 = sorted_lat[int(0.50 * (n - 1))]
    p95 = sorted_lat[int(0.95 * (n - 1))]
    p99 = sorted_lat[int(0.99 * (n - 1))]

    effective_model, warning = client.resolve_effective_model()
    return {
        "benchmark": "Gate L.7 Non-Ollama Local OpenAI-Compatible 30-Prompt Benchmark",
        "backend_type": client.config.backend_type,
        "base_url": client.config.base_url,
        "requested_model": client.config.requested_model,
        "effective_model": effective_model,
        "ram_tier_applied": warning is not None,
        "ram_tier_warning": warning,
        "host_total_ram_gb": total_ram_gb,
        "host_avail_ram_gb": avail_ram_gb,
        "total_prompts": len(prompt_list),
        "completed_prompts": len(completions),
        "failed_prompts": failures,
        "oom_count": oom_errors,
        "latency_p50_ms": round(p50, 2),
        "latency_p95_ms": round(p95, 2),
        "latency_p99_ms": round(p99, 2),
        "latency_mean_ms": round(statistics.mean(sorted_lat), 2),
        "samples": completions,
    }

