"""Locust load test suite for REDLOOP endpoints (Phase G.3).

Simulates concurrent operators exercising Chat, OSINT, and MCP/Readiness APIs.
"""
import random
from locust import HttpUser, task, between


class RedloopOperator(HttpUser):
    wait_time = between(0.05, 0.2)

    def on_start(self):
        self.operator_id = f"op-{random.randint(1000, 999999)}"
        self.headers = {
            "X-Operator-ID": self.operator_id,
            "Origin": "http://127.0.0.1:8765",
            "Content-Type": "application/json",
        }

    @task(4)
    def test_health_and_readiness(self):
        self.client.get("/healthz", headers=self.headers, name="/healthz")
        self.client.get("/readyz", headers=self.headers, name="/readyz")

    @task(3)
    def test_chat_conversations(self):
        self.client.get("/api/chat/conversations", headers=self.headers, name="/api/chat/conversations")

    @task(3)
    def test_osint_and_models(self):
        self.client.get("/api/models", headers=self.headers, name="/api/models")
        self.client.get("/api/search?q=recon", headers=self.headers, name="/api/search")
