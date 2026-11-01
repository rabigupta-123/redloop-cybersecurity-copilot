"""Evaluation suite for benchmarking self-learning cybersecurity agent."""

from typing import Any, Dict, List

from agent.self_learning_agent import SelfLearningAgent


class ModelEvaluator:
    """Evaluates agent performance across benchmark cybersecurity challenge sets."""

    def __init__(self, agent: SelfLearningAgent):
        self.agent = agent

    async def evaluate_suite(self, benchmark_set: List[Dict[str, str]]) -> Dict[str, Any]:
        """Run benchmark set and calculate accuracy, average confidence, and latency."""
        passed = 0
        total = len(benchmark_set)
        total_time_ms = 0.0
        confidences = []

        for item in benchmark_set:
            problem = item.get("problem", "")
            expected_flag = item.get("expected", "")

            res = await self.agent.solve(problem)
            answer = res.get("answer", "")
            time_ms = res.get("response_time_ms", 0.0)
            conf = res.get("confidence", 0.0)

            total_time_ms += time_ms
            confidences.append(conf)

            if expected_flag.lower() in answer.lower():
                passed += 1

        accuracy = (passed / total) if total > 0 else 0.0
        avg_confidence = (sum(confidences) / len(confidences)) if confidences else 0.0
        avg_latency = (total_time_ms / total) if total > 0 else 0.0

        return {
            "total_tested": total,
            "passed": passed,
            "accuracy": round(accuracy, 4),
            "avg_confidence": round(avg_confidence, 2),
            "avg_latency_ms": round(avg_latency, 2),
        }
