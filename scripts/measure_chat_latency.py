import json
import os
import time
import urllib.request
import ctypes
from pathlib import Path
from redloop.assessment.orchestrator import TaskOrchestrator

def linear_percentile(data, p):
    if not data:
        return 0.0
    s = sorted(data)
    k = (len(s) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    d = k - f
    return s[f] + d * (s[c] - s[f])

class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]

def get_ram_mb():
    stat = MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
    used = (stat.ullTotalPhys - stat.ullAvailPhys) / (1024 * 1024)
    pct = stat.dwMemoryLoad
    return used, pct

# 30 standard cybersecurity prompts
PROMPTS = [
    "What is the difference between authenticated encryption and standard block cipher modes?",
    "Explain how a DOM-based Cross-Site Scripting vulnerability differs from reflected XSS.",
    "Describe the three-way handshake in TCP and how SYN cookies mitigate SYN floods.",
    "What are the security implications of wildcard CORS headers with credentials enabled?",
    "Explain how SQL injection can lead to remote code execution in MySQL vs PostgreSQL.",
    "What is the role of the Subject Alternative Name extension in modern TLS certificates?",
    "Describe the difference between forward secrecy and regular session key exchange.",
    "How does Address Space Layout Randomization (ASLR) prevent buffer overflow exploitation?",
    "Explain how DNS rebinding attacks bypass same-origin policy on internal web interfaces.",
    "What is the function of the Content-Security-Policy nonce attribute?",
    "Describe the MITRE ATT&CK technique T1059 Command and Scripting Interpreter.",
    "How does an attacker exploit an unvalidated open redirect to steal OAuth tokens?",
    "Explain the security purpose of the HTTPOnly and SameSite cookie flags.",
    "What is the difference between a vulnerability assessment and a penetration test?",
    "Describe how a blind SSRF vulnerability can be detected using out-of-band DNS interactions.",
    "How does memory tagging (MTE) protect against use-after-free vulnerabilities?",
    "Explain the mechanics of a padding oracle attack against CBC mode encryption.",
    "What is the role of an automated Security Orchestration, Automation, and Response system?",
    "Describe how Kerberoasting works in an Active Directory environment.",
    "What are the indicators of compromise for a compromised SSH private key?",
    "Explain the principle of defense-in-depth applied to containerized microservices.",
    "How does a web application firewall detect and block SQL injection payloads?",
    "Describe the difference between symmetric AES-GCM and ChaCha20-Poly1305 ciphers.",
    "What are the risks of using MD5 or SHA-1 for digital signatures?",
    "Explain how certificate pinning works and why it has largely been deprecated for HPKP.",
    "Describe the lifecycle of a security incident from detection to post-mortem review.",
    "What is the difference between cross-site request forgery and server-side request forgery?",
    "How does an attacker bypass basic file upload filters that check only file extensions?",
    "Explain how subresource integrity (SRI) prevents third-party script tampering.",
    "Describe how rate limiting with token bucket algorithm mitigates credential stuffing.",
]

results = {}

# 1. Benchmark Offline Engine
print("Measuring Offline Engine latency across 30 prompts...")
orch = TaskOrchestrator()
offline_latencies = []
for p in PROMPTS:
    t0 = time.perf_counter()
    reply = orch._generate_offline_cyber_response(p)
    dt_ms = (time.perf_counter() - t0) * 1000.0
    offline_latencies.append(dt_ms)

p50_off = linear_percentile(offline_latencies, 50)
p95_off = linear_percentile(offline_latencies, 95)
results["offline_engine"] = {
    "prompts_count": len(PROMPTS),
    "p50_ms": p50_off,
    "p95_ms": p95_off,
    "min_ms": min(offline_latencies),
    "max_ms": max(offline_latencies),
    "notes": "Deterministic offline knowledge engine only; replaces historical 0.13ms label.",
}
print(f"Offline Engine: p50={p50_off:.4f} ms, p95={p95_off:.4f} ms")

# 2. Benchmark Ollama qwen3:8b
print("\nMeasuring Ollama qwen3:8b latency across 30 prompts...")
ollama_latencies = []
ram_readings = []

ram_start_mb, ram_start_pct = get_ram_mb()
print(f"RAM before Ollama benchmark: {ram_start_mb:.1f} MB used ({ram_start_pct:.1f}%)")

for idx, p in enumerate(PROMPTS):
    body = json.dumps({
        "model": "qwen3:8b",
        "prompt": f"You are a cybersecurity expert. Answer concisely:\n{p}",
        "stream": False,
        "options": {"num_predict": 100},
    }).encode("utf-8")

    req = urllib.request.Request(
        "http://localhost:11434/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            dt_s = time.perf_counter() - t0
            ollama_latencies.append(dt_s)
            r_mb, r_pct = get_ram_mb()
            ram_readings.append(r_mb)
            print(f"  Prompt {idx+1}/30: {dt_s:.2f}s | RAM: {r_mb:.1f} MB ({r_pct:.1f}%)")
    except Exception as exc:
        print(f"  Prompt {idx+1}/30 FAILED: {exc}")
        break

if ollama_latencies:
    p50_ol = linear_percentile(ollama_latencies, 50)
    p95_ol = linear_percentile(ollama_latencies, 95)
    max_ram_mb = max(ram_readings) if ram_readings else ram_start_mb
    results["ollama_qwen3_8b"] = {
        "prompts_count": len(ollama_latencies),
        "p50_s": p50_ol,
        "p95_s": p95_ol,
        "ram_start_mb": ram_start_mb,
        "ram_peak_mb": max_ram_mb,
        "p95_exceeds_30s": p95_ol > 30.0,
        "recommendation": "Recommend qwen3:4b for machines with <= 8 GB RAM." if p95_ol > 30.0 else "qwen3:8b operates within acceptable interactive bounds.",
    }
    print(f"Ollama qwen3:8b: p50={p50_ol:.2f}s, p95={p95_ol:.2f}s | Peak RAM: {max_ram_mb:.1f} MB")

# 3. Benchmark OpenRouter
print("\nMeasuring OpenRouter latency across 30 prompts...")
openrouter_key = os.environ.get("OPENROUTER_API_KEY")
openrouter_latencies = []
if openrouter_key:
    for idx, p in enumerate(PROMPTS):
        body = json.dumps({
            "model": "meta-llama/llama-3.3-70b-instruct",
            "messages": [{"role": "user", "content": p}],
            "max_tokens": 100,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://openrouter.ai/api/v1/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {openrouter_key}",
            },
        )
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                _ = json.loads(resp.read().decode("utf-8"))
                dt_s = time.perf_counter() - t0
                openrouter_latencies.append(dt_s)
                print(f"  Prompt {idx+1}/30: {dt_s:.2f}s")
        except Exception as exc:
            print(f"  Prompt {idx+1}/30 FAILED: {exc}")
            break

    if openrouter_latencies:
        p50_or = linear_percentile(openrouter_latencies, 50)
        p95_or = linear_percentile(openrouter_latencies, 95)
        results["openrouter"] = {
            "model": "meta-llama/llama-3.3-70b-instruct",
            "prompts_count": len(openrouter_latencies),
            "p50_s": p50_or,
            "p95_s": p95_or,
        }
        print(f"OpenRouter: p50={p50_or:.2f}s, p95={p95_or:.2f}s")
else:
    results["openrouter"] = {"status": "NOT_CONFIGURED", "reason": "OPENROUTER_API_KEY missing"}

# 4. Benchmark Groq
print("\nMeasuring Groq latency across 30 prompts...")
from dotenv import load_dotenv
load_dotenv()
groq_key = os.environ.get("GROQ_API_KEY") or os.environ.get("REDLOOP_GROQ_API_KEY")
groq_model = os.environ.get("GROQ_MODEL", "qwen/qwen3.8-27b")

groq_latencies = []
if groq_key:
    for idx, p in enumerate(PROMPTS):
        body = json.dumps({
            "model": groq_model,
            "messages": [{"role": "user", "content": p}],
            "max_tokens": 100,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.groq.com/openai/v1/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {groq_key}",
                "User-Agent": "RedLoop-Security/1.0",
            },
        )
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                _ = json.loads(resp.read().decode("utf-8"))
                dt_s = time.perf_counter() - t0
                groq_latencies.append(dt_s)
                print(f"  Prompt {idx+1}/30: {dt_s:.3f}s")
        except Exception as exc:
            print(f"  Prompt {idx+1}/30 FAILED: {exc}")
            break

    if groq_latencies:
        p50_gq = linear_percentile(groq_latencies, 50)
        p95_gq = linear_percentile(groq_latencies, 95)
        results["groq"] = {
            "model": groq_model,
            "prompts_count": len(groq_latencies),
            "p50_s": p50_gq,
            "p95_s": p95_gq,
            "min_s": min(groq_latencies),
            "max_s": max(groq_latencies),
            "linear_interpolation": True,
        }
        print(f"Groq ({groq_model}): p50={p50_gq:.3f}s, p95={p95_gq:.3f}s")
    else:
        results["groq"] = {"status": "FAILED", "reason": "No successful prompt completions"}
else:
    results["groq"] = {
        "status": "NOT_CONFIGURED",
        "reason": "GROQ_API_KEY environment variable is not set; marked NOT VERIFIED per global instructions.",
    }

# 5. Benchmark Ollama qwen3:4b (Default Edge Model for <= 8GB RAM)
print("\nMeasuring Ollama qwen3:4b latency across 30 prompts...")
ollama_4b_latencies = []
ram_4b_readings = []
ram_start_4b_mb, ram_start_4b_pct = get_ram_mb()

for idx, p in enumerate(PROMPTS):
    body = json.dumps({
        "model": "qwen3:4b",
        "prompt": f"You are a cybersecurity expert. Answer concisely:\n{p}",
        "stream": False,
        "options": {"num_predict": 100},
    }).encode("utf-8")

    req = urllib.request.Request(
        "http://localhost:11434/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            dt_s = time.perf_counter() - t0
            ollama_4b_latencies.append(dt_s)
            r_mb, r_pct = get_ram_mb()
            ram_4b_readings.append(r_mb)
            print(f"  Prompt {idx+1}/30: {dt_s:.2f}s | RAM: {r_mb:.1f} MB ({r_pct:.1f}%)")
    except Exception as exc:
        print(f"  Prompt {idx+1}/30 (4b) FAILED: {exc}")
        break

if ollama_4b_latencies:
    p50_4b = linear_percentile(ollama_4b_latencies, 50)
    p95_4b = linear_percentile(ollama_4b_latencies, 95)
    max_ram_4b_mb = max(ram_4b_readings) if ram_4b_readings else ram_start_4b_mb
    results["ollama_qwen3_4b"] = {
        "prompts_count": len(ollama_4b_latencies),
        "p50_s": p50_4b,
        "p95_s": p95_4b,
        "ram_start_mb": ram_start_4b_mb,
        "ram_peak_mb": max_ram_4b_mb,
        "p95_exceeds_30s": p95_4b > 30.0,
        "notes": "Resource-aware default edge model selected for constrained environments (RAM < 6GB).",
    }
    print(f"Ollama qwen3:4b: p50={p50_4b:.2f}s, p95={p95_4b:.2f}s | Peak RAM: {max_ram_4b_mb:.1f} MB")
else:
    results["ollama_qwen3_4b"] = {
        "status": "NOT_AVAILABLE",
        "reason": "Model qwen3:4b not loaded or unreachable.",
    }

# Save final telemetry artifact
out_file = Path("artifacts/chat_latency_benchmark.json")
with open(out_file, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)
print(f"\nSaved benchmark results to {out_file}")
