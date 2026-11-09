import json
import os
import time
import urllib.request
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

def linear_percentile(data, p):
    if not data:
        return 0.0
    s = sorted(data)
    k = (len(s) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    d = k - f
    return s[f] + d * (s[c] - s[f])

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

groq_key = os.environ.get("GROQ_API_KEY") or os.environ.get("REDLOOP_GROQ_API_KEY")
groq_model = os.environ.get("GROQ_MODEL", "qwen/qwen3.8-27b")

print(f"Benchmarking Groq model: {groq_model} across {len(PROMPTS)} prompts...")
groq_latencies = []

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
    max_retries = 3
    for attempt in range(max_retries):
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                dt_s = time.perf_counter() - t0
                groq_latencies.append(dt_s)
                print(f"  Prompt {idx+1}/{len(PROMPTS)}: {dt_s:.3f}s")
                time.sleep(2.0)
                break
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt < max_retries - 1:
                wait_sec = 6.0 * (attempt + 1)
                print(f"  Rate limit 429 on prompt {idx+1}, backing off {wait_sec}s...")
                time.sleep(wait_sec)
                continue
            else:
                print(f"  Prompt {idx+1}/{len(PROMPTS)} FAILED: {exc}")
                break
        except Exception as exc:
            print(f"  Prompt {idx+1}/{len(PROMPTS)} FAILED: {exc}")
            break

if len(groq_latencies) >= 30:
    p50_gq = linear_percentile(groq_latencies, 50)
    p95_gq = linear_percentile(groq_latencies, 95)
    print(f"\nCompleted Groq benchmark: {len(groq_latencies)} prompts")
    print(f"p50: {p50_gq:.4f} s | p95: {p95_gq:.4f} s | min: {min(groq_latencies):.4f} s | max: {max(groq_latencies):.4f} s")

    # Update artifacts/chat_latency_benchmark.json
    bench_file = Path("artifacts/chat_latency_benchmark.json")
    if bench_file.exists():
        with open(bench_file, "r", encoding="utf-8") as f:
            bench_data = json.load(f)
    else:
        bench_data = {}

    bench_data["groq"] = {
        "model": groq_model,
        "prompts_count": len(groq_latencies),
        "p50_s": round(p50_gq, 4),
        "p95_s": round(p95_gq, 4),
        "min_s": round(min(groq_latencies), 4),
        "max_s": round(max(groq_latencies), 4),
        "linear_interpolation": True,
        "raw_latencies_s": [round(x, 4) for x in groq_latencies],
    }
    with open(bench_file, "w", encoding="utf-8") as f:
        json.dump(bench_data, f, indent=2)
    print(f"Updated {bench_file} with real Groq benchmark results!")
else:
    print(f"Benchmark aborted early: only {len(groq_latencies)} collected")
