"""Multi-agent debate engine for multi-perspective cybersecurity reasoning."""

import asyncio
import json
import re
from typing import Any, Dict, List, Optional

from utils.helpers import get_llm_client


class MultiAgentDebate:
    """Run role-based prompts through one configured model and synthesize the output."""

    PERSONAS = {
        "senior_security_analyst": (
            "You are a senior cybersecurity analyst with 15+ years of experience. "
            "You focus on practical exploits, real-world attack vectors, and concrete remediation. "
            "Be specific, authoritative, and threat-model-driven."
        ),
        "ctf_veteran": (
            "You are a CTF competition veteran who has won multiple international championships. "
            "You think laterally, consider unusual decoding methods, and know all the tricks. "
            "Be creative and exhaustive."
        ),
        "security_skeptic": (
            "You are a skeptical security auditor. Your job is to challenge assumptions, "
            "find flaws in reasoning, identify edge cases, and catch overconfidence. "
            "Be critical, detail-oriented, and thorough."
        ),
        "methodical_engineer": (
            "You are a methodical security engineer. You follow systematic processes, "
            "verify each step, document everything, and think about scalability and security best practices. "
            "Be precise and structured."
        ),
    }

    async def debate(self, problem: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run multi-agent debate and reconcile opinions into consensus."""
        context = context or {}

        # 1. Concurrent independent thinking across personas
        tasks = []
        for persona_name, persona_prompt in self.PERSONAS.items():
            tasks.append(self._agent_think(persona_name, persona_prompt, problem, context))

        answers = await asyncio.gather(*tasks, return_exceptions=True)

        debate_records = []
        for (persona_name, _), answer in zip(self.PERSONAS.items(), answers):
            if isinstance(answer, Exception):
                debate_records.append(
                    {
                        "expert": persona_name,
                        "answer": f"Error during reasoning: {answer}",
                        "reasoning": [str(answer)],
                        "confidence": 0.0,
                    }
                )
            else:
                debate_records.append(
                    {
                        "expert": persona_name,
                        "answer": answer.get("answer", "N/A"),
                        "reasoning": answer.get("reasoning", []),
                        "confidence": answer.get("confidence", 0.0),
                    }
                )

        # 2. Reconcile debate into final consensus
        reconciliation = await self._reconcile(debate_records, problem, context)

        return {
            "debate": debate_records,
            "consensus": reconciliation.get(
                "consensus", "No independently verified consensus is available."
            ),
            "residual_disagreements": reconciliation.get("disagreements", []),
            "final_answer": reconciliation.get("final_answer", ""),
            "confidence": reconciliation.get("confidence", 0.0),
            "agents_participated": len(debate_records),
        }

    async def _agent_think(
        self,
        persona_name: str,
        persona_prompt: str,
        problem: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Single agent independent reasoning."""
        client = get_llm_client()

        system_prompt = (
            f"{persona_prompt}\n\n"
            "You are providing expert analysis for this security challenge. "
            "Be thorough and state your answer clearly with reasoning."
        )
        user_prompt = (
            f"PROBLEM:\n{problem}\n\n"
            f"CONTEXT:\n{json.dumps(context, indent=2)}\n\n"
            "Please provide:\n"
            "1. Your analysis and solution\n"
            "2. Key reasoning steps\n"
            "3. Confidence score (0-100)\n"
            "4. Any caveats or alternative approaches\n"
        )

        response = await client.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=2048,
        )

        return self._parse_agent_response(response)

    def _parse_agent_response(self, response: str) -> Dict[str, Any]:
        """Parse raw persona response into structured fields."""
        confidence = 0.0
        conf_match = re.search(r"confidence[:\s]+(\d+)", response.lower())
        if conf_match:
            try:
                confidence = float(conf_match.group(1))
            except ValueError:
                pass

        lines = [line.strip() for line in response.split("\n") if line.strip()]
        return {
            "answer": response,
            "reasoning": lines[:6],
            "confidence": confidence,
        }

    async def _reconcile(
        self,
        debate: List[Dict[str, Any]],
        problem: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Reconcile expert views into a synthesized, robust final answer."""
        client = get_llm_client()

        debate_summary = ""
        for record in debate:
            debate_summary += (
                f"---\n"
                f"EXPERT: {record['expert']}\n"
                f"CONFIDENCE: {record['confidence']}\n"
                f"ANSWER: {record['answer'][:600]}\n"
            )

        reconciliation_prompt = (
            f"You are a master cybersecurity researcher synthesizing opinions from {len(debate)} "
            f"security experts who debated this problem.\n\n"
            f"PROBLEM:\n{problem}\n\n"
            f"EXPERT DEBATE:\n{debate_summary}\n\n"
            "TASK:\n"
            "1. Identify common themes across all answers\n"
            "2. Resolve disagreements\n"
            "3. Synthesize the single best, most complete solution\n"
            "4. Provide confidence (0-100)\n\n"
            "Return valid JSON:\n"
            "{\n"
            '  "consensus": "Summary of points all experts agreed upon",\n'
            '  "disagreements": ["Notable edge cases or debate points"],\n'
            '  "final_answer": "Complete, comprehensive synthesized answer",\n'
            '  "confidence": 85,\n'
            '  "rationale": "Why this answer was selected"\n'
            "}"
        )

        response = await client.generate(
            system_prompt="You are a master security researcher synthesizing expert opinions.",
            user_prompt=reconciliation_prompt,
            max_tokens=2048,
        )

        try:
            # Clean possible markdown block
            clean = response.strip()
            if clean.startswith("```json"):
                clean = clean[7:]
            if clean.endswith("```"):
                clean = clean[:-3]
            data = json.loads(clean.strip())
            return {
                "consensus": data.get(
                    "consensus", "No independently verified consensus is available."
                ),
                "disagreements": data.get("disagreements", []),
                "final_answer": data.get("final_answer", response),
                "confidence": float(data.get("confidence", 0.0)),
                "rationale": data.get("rationale", "Synthesized across experts"),
            }
        except Exception:
            return {
                "consensus": "Unstructured role-based synthesis; consensus not verified.",
                "disagreements": [],
                "final_answer": response,
                "confidence": 0.0,
                "rationale": "Direct synthesis response",
            }
