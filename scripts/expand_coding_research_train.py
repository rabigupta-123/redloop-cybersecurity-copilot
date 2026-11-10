import json
from pathlib import Path

train_path = Path("tests/fixtures/eval/intent_train_v2.json")
with open(train_path, "r", encoding="utf-8") as f:
    data = json.load(f)

existing_prompts = {x["prompt"].strip().lower() for x in data}
max_id = 0
for x in data:
    try:
        val = int(x["id"].replace("train-", "").replace("v2-", "").replace("phI-", ""))
        if val > max_id:
            max_id = val
    except ValueError:
        pass

new_exemplars = [
    "Explain the cryptographic difference between RSA and ECC key exchange and performance trade-offs.",
    "Explain how OAuth 2.0 Proof Key for Code Exchange (PKCE) prevents authorization code interception attacks.",
    "How does use-after-free heap exploitation work in native C and C++ memory allocators?",
    "Explain the technical mechanics of Server-Side Request Forgery (SSRF) against AWS IMDSv2 metadata endpoints.",
    "Research and explain how modern Content Security Policy (CSP) directives mitigate DOM-based XSS attacks.",
    "Explain the difference between synchronous and asynchronous socket multiplexing models in Python.",
    "How do Return-Oriented Programming (ROP) gadgets bypass Address Space Layout Randomization (ASLR)?",
    "Explain the underlying mechanism of blind SQL injection via boolean inference and time delays.",
    "Research and summarize the architectural security benefits of mutual TLS (mTLS) over standard one-way TLS.",
    "Explain how format string vulnerabilities allow arbitrary memory read and write primitives.",
    "How does a padding oracle attack compromise CBC mode block ciphertexts mathematically?",
    "Explain how HTTP request smuggling occurs due to TE.CL and CL.TE header ambiguities in reverse proxies.",
    "Research how eBPF tracing programs detect kernel-level privilege escalation attempts.",
    "Explain the technical differences between reflected, stored, and DOM-based cross-site scripting vulnerabilities.",
    "How does prototype pollution in JavaScript engines lead to remote code execution in Node.js applications?",
    "Review this Python code snippet for race conditions and insecure concurrency patterns.",
    "Explain how side-channel cache timing attacks like Spectre extract secrets from speculative CPU execution.",
    "Research the security implications of weak PRNG seeds in token generation algorithms.",
    "Can you explain the mechanics of DLL side-loading and search order hijacking on Windows?",
    "Explain how cross-origin resource sharing (CORS) misconfigurations enable credential leakage across origins.",
]

added = 0
for idx, prompt in enumerate(new_exemplars, 1):
    if prompt.strip().lower() not in existing_prompts:
        max_id += 1
        item_id = f"phJ-{max_id:04d}"
        data.append({
            "id": item_id,
            "prompt": prompt,
            "expected_intent": "CODING_AND_RESEARCH",
            "category": "coding_and_research"
        })
        existing_prompts.add(prompt.strip().lower())
        added += 1

with open(train_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)

print(f"Added {added} new CODING_AND_RESEARCH exemplars to {train_path}. Total items: {len(data)}.")
