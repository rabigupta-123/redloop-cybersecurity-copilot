import json
import time
import urllib.request
import ctypes
from pathlib import Path

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

print("Benchmarking Ollama qwen3:4b across 30 prompts...")
latencies = []
ram_readings = []

ram_start_mb, ram_start_pct = get_ram_mb()
print(f"RAM before 4b benchmark: {ram_start_mb:.1f} MB used ({ram_start_pct:.1f}%)")

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
            latencies.append(dt_s)
            r_mb, r_pct = get_ram_mb()
            ram_readings.append(r_mb)
            print(f"  Prompt {idx+1}/{len(PROMPTS)}: {dt_s:.2f}s | RAM: {r_mb:.1f} MB ({r_pct:.1f}%)")
    except Exception as exc:
        print(f"  Prompt {idx+1}/{len(PROMPTS)} FAILED: {exc}")
        break

if len(latencies) >= 30:
    p50 = linear_percentile(latencies, 50)
    p95 = linear_percentile(latencies, 95)
    max_ram_mb = max(ram_readings) if ram_readings else ram_start_mb
    print(f"\nCompleted Ollama qwen3:4b benchmark: {len(latencies)} prompts")
    print(f"p50: {p50:.2f} s | p95: {p95:.2f} s | Peak RAM: {max_ram_mb:.1f} MB")

    bench_file = Path("artifacts/chat_latency_benchmark.json")
    if bench_file.exists():
        with open(bench_file, "r", encoding="utf-8") as f:
            bench_data = json.load(f)
    else:
        bench_data = {}

    bench_data["ollama_qwen3_4b"] = {
        "prompts_count": len(latencies),
        "p50_s": round(p50, 4),
        "p95_s": round(p95, 4),
        "min_s": round(min(latencies), 4),
        "max_s": round(max(latencies), 4),
        "ram_start_mb": round(ram_start_mb, 1),
        "ram_peak_mb": round(max_ram_mb, 1),
        "p95_exceeds_30s": p95 > 30.0,
        "notes": "Resource-aware default edge model selected for constrained environments (RAM < 6GB).",
    }
    with open(bench_file, "w", encoding="utf-8") as f:
        json.dump(bench_data, f, indent=2)
    print(f"Updated {bench_file} with real Ollama 4b benchmark results!")

