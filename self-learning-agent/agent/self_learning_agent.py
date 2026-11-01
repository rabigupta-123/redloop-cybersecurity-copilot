import json
import re
import time
from typing import Any, Dict, List, Optional

from agent.base_agent import BaseAgent
from agent.feedback import feedback_processor
from agent.verification import VerificationEngine
from config.prompts import (
    AFTER_ACTION_REVIEW,
    BAD_EXAMPLE_LEARNER,
    EXPERIENCE_STORAGE,
    SELF_LEARNING_SYSTEM_PROMPT,
)
from database.repositories import agent_stats_repo
from memory.error_store import error_store
from memory.experience_store import experience_store
from memory.retrieval import retrieval_engine
from utils.helpers import get_llm_client, safe_json_loads
from utils.logging import audit_logger


class SelfLearningAgent(BaseAgent):
    """Self-learning cybersecurity agent that improves with every interaction."""

    CATEGORIES = ["crypto", "web", "pwn", "rev", "forensics", "recon", "vuln", "general"]

    def __init__(self, mode: str = "general"):
        super().__init__(mode)
        self.llm = get_llm_client()
        self.verification = VerificationEngine(self.llm)
        self.learn_rate = 0.95
        self.retrieval = retrieval_engine
        self._messages: Dict[str, Dict[str, Any]] = {}
        self.multi_agent = None

    async def solve(self, problem: str, **kwargs) -> Dict[str, Any]:
        """Main solve method with experience retrieval and self-learning."""
        start_time = time.time()

        try:
            # Step 1: Retrieve similar past experiences
            similar_experiences = retrieval_engine.retrieve_similar(problem, top_k=2)

            # Step 2: Get recent errors to avoid
            recent_errors = await error_store.get_recent_unfixed(days=30)

            # Step 3: Format context
            experiences_str = self._format_experiences(similar_experiences)
            errors_str = self._format_errors(recent_errors)

            system_prompt = SELF_LEARNING_SYSTEM_PROMPT.format(
                experiences=experiences_str,
                errors=errors_str,
            )

            # Step 4: Generate candidate solution
            response = await self.llm.generate(
                system_prompt=system_prompt,
                user_prompt=problem,
                max_tokens=kwargs.get("max_tokens", 2048),
            )

            # Step 5: Analyze and parse response
            parsed = self.analyze_response(response)
            parsed["source"] = "retrieved" if similar_experiences else "fresh"

            # Step 6: Verify and self-critique
            verification = await self.verification.verify(parsed["answer"], problem)
            parsed["verified"] = verification

            # Adjust confidence score
            if verification.get("passed"):
                parsed["confidence"] = min(parsed["confidence"] + 5.0, 100.0)

            end_time = time.time()
            self.response_time_ms = (end_time - start_time) * 1000

            result = {
                "success": True,
                "answer": parsed["answer"],
                "reasoning": parsed["reasoning"],
                "confidence": parsed["confidence"],
                "learning": parsed["learning"],
                "uncertainty": parsed["uncertainty"],
                "verified": verification,
                "response_time_ms": round(self.response_time_ms, 2),
                "sources": [
                    e["experience"].problem_type
                    for e in similar_experiences
                    if e.get("experience")
                ],
            }

            message_id = kwargs.get("message_id") or f"msg_{int(time.time() * 1000)}"
            result["message_id"] = message_id
            self.last_response = result
            self._messages[message_id] = {
                "id": message_id,
                "problem": problem,
                "answer": parsed["answer"],
                "result": result,
            }

            # Record telemetry stats
            try:
                agent_stats_repo.record_interaction(
                    correct=verification.get("passed", False),
                    confidence=parsed["confidence"],
                    tokens=0,
                    response_time=self.response_time_ms,
                )
                audit_logger.log_interaction(
                    problem=problem,
                    answer=parsed["answer"],
                    confidence=parsed["confidence"],
                    response_time_ms=self.response_time_ms,
                    verified=verification.get("passed", False),
                    mode=self.mode,
                )
            except Exception:
                pass

            return result

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "answer": f"Error: {str(e)}",
            }

    async def learn_from_feedback(
        self,
        problem: Optional[str] = None,
        answer: Optional[str] = None,
        feedback: Optional[str] = None,
        message_id: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Learn from user feedback. Supports both (problem, answer, feedback) and (message_id, feedback)."""
        if feedback is None and answer is not None and message_id is None:
            target_msg_id = problem
            fb_text = answer
            msg = self._get_message_by_id(target_msg_id)
            if msg:
                actual_problem = msg.get("problem", "")
                actual_answer = msg.get("answer", "")
            else:
                actual_problem = target_msg_id or ""
                actual_answer = self.last_response.get("answer", "") if self.last_response else ""
        elif message_id is not None:
            fb_text = feedback or answer or kwargs.get("feedback", "")
            msg = self._get_message_by_id(message_id)
            if msg:
                actual_problem = msg.get("problem", "")
                actual_answer = msg.get("answer", "")
            else:
                actual_problem = problem or message_id
                actual_answer = answer or (self.last_response.get("answer", "") if self.last_response else "")
        else:
            actual_problem = problem or ""
            actual_answer = answer or ""
            fb_text = feedback or kwargs.get("feedback", "")

        fb_lower = fb_text.lower()
        if feedback_processor.is_positive(fb_text) or any(
            w in fb_lower for w in ["correct", "yes", "success", "✅", "good", "right"]
        ):
            if "ctf{" in actual_answer.lower() or "flag{" in actual_answer.lower():
                await self.store_ctf_experience({"source": actual_problem, "solution": actual_answer})
            res = await self.store_experience(actual_problem, actual_answer)
            res["status"] = "learned"
            res["type"] = "success"
            return res
        else:
            if "fix:" in fb_lower or "should be" in fb_lower:
                correct = (
                    fb_text.split("fix:")[-1].strip()
                    if "fix:" in fb_lower
                    else fb_text.split("should be")[-1].strip()
                )
            else:
                correct = await self._generate_correction(actual_problem, actual_answer)
            res = await self.handle_wrong_answer(actual_problem, actual_answer, correct)
            res["status"] = "learned"
            res["type"] = "error_corrected"
            return res

    async def store_experience(
        self,
        problem: str,
        answer: str,
        learning_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Store user-approved interaction as an unverified experience."""
        # Extract pattern, tags, and approach
        pattern_extract = await self.llm.generate(
            system_prompt="You are a pattern extraction expert. Extract the core problem-solving pattern from this interaction.",
            user_prompt=f"PROBLEM: {problem}\n\nSOLUTION: {answer}",
        )

        tags_extract = await self.llm.generate(
            system_prompt="Extract 3-5 relevant lowercase tags as a JSON array of strings, e.g. [\"crypto\", \"xor\"].",
            user_prompt=f"PROBLEM: {problem}",
        )

        approach_extract = await self.llm.generate(
            system_prompt="Summarize the solution approach into clear steps.",
            user_prompt=f"SOLUTION: {answer}",
        )

        # Parse tags safely
        parsed_tags = safe_json_loads(tags_extract)
        if not isinstance(parsed_tags, list):
            parsed_tags = [self._detect_problem_type(problem, answer)]

        # Store the experience for offline lexical retrieval.
        exp = await experience_store.add(
            problem_type=self._detect_problem_type(problem, answer),
            tags=parsed_tags,
            pattern=pattern_extract.strip()[:500],
            approach=approach_extract.strip(),
            example_prompt=problem[:1000],
            confidence=0.0,
        )

        await experience_store.increment_success(exp.id)
        audit_logger.log_learning(exp.id, exp.problem_type, exp.pattern)

        return {"stored": True, "experience_id": exp.id}

    async def handle_wrong_answer(
        self,
        problem: str,
        wrong_answer: str,
        feedback: str,
    ) -> Dict[str, Any]:
        """Record mistakes and synthesize corrective lessons."""
        correct_answer = None
        if "correct answer:" in feedback.lower():
            correct_answer = feedback.lower().split("correct answer:")[1].strip()

        if not correct_answer:
            correct_answer = await self.llm.generate(
                system_prompt="You are a cybersecurity expert. Provide the correct answer.",
                user_prompt=f"Problem: {problem}\n\nWrong answer given: {wrong_answer}\n\nWhy it might be wrong: {feedback}",
            )

        category_extract = await self.llm.generate(
            system_prompt="Categorize this cybersecurity error into one word (e.g. crypto, web, logic, oversight).",
            user_prompt=f"PROBLEM: {problem}\nWRONG ANSWER: {wrong_answer}\nFEEDBACK: {feedback}",
        )

        lesson_extract = await self.llm.generate(
            system_prompt="Extract a concise one-sentence rule to prevent this mistake in the future.",
            user_prompt=f"PROBLEM: {problem}\nWRONG ANSWER: {wrong_answer}\nCORRECT: {correct_answer}",
        )

        error = await error_store.add(
            problem=problem,
            wrong_answer=wrong_answer,
            correct_answer=correct_answer,
            error_category=category_extract.strip()[:50] or "general",
            lesson=lesson_extract.strip()[:1000],
        )

        audit_logger.log_error(error.id, error.error_category, error.learned_lesson)
        return {"logged": True, "error_id": error.id}

    def _format_experiences(self, experiences: List[Dict[str, Any]]) -> str:
        """Format retrieved experiences for prompt context."""
        if not experiences:
            return "No prior matching experiences found."

        formatted = []
        for exp_info in experiences:
            exp = exp_info.get("experience")
            if not exp:
                continue
            sim = exp_info.get("similarity", 0.0)
            formatted.append(
                f"- TYPE: {exp.problem_type} | RELEVANCE: {sim:.2f}\n"
                f"  PATTERN: {exp.pattern}\n"
                f"  APPROACH: {exp.approach[:250]}..."
            )
        return "\n".join(formatted) if formatted else "No prior matching experiences found."

    def _format_errors(self, errors: List[Any]) -> str:
        """Format recent errors for prompt context."""
        if not errors:
            return "No recent mistakes to avoid."

        formatted = []
        for err in errors[:3]:
            formatted.append(
                f"- {err.error_category}: {err.problem[:100]}\n"
                f"  Avoid: {err.wrong_answer[:100]}...\n"
                f"  Rule: {err.learned_lesson[:100]}"
            )
        return "\n".join(formatted) if formatted else "No recent mistakes to avoid."

    def _detect_problem_type(self, problem: str, answer: str) -> str:
        """Auto-detect cybersecurity problem category."""
        keywords = {
            "crypto": ["encrypt", "decrypt", "xor", "base64", "aes", "rsa", "cipher", "hash"],
            "web": ["xss", "sqli", "csrf", "ssrf", "injection", "html", "javascript", "php"],
            "pwn": ["overflow", "buffer", "rop", "exploit", "shellcode", "binary", "heap"],
            "rev": ["reverse", "decompile", "ghidra", "ida", "disassemble", "assembly"],
            "forensics": ["forensic", "pcap", "memory", "wireshark", "volatility", "dump"],
            "recon": ["recon", "scan", "nmap", "enumeration", "subdomain", "dns"],
            "vuln": ["vulnerability", "cve", "patch", "exploit", "advisory"],
        }

        combined = (problem + " " + answer).lower()
        for category, kws in keywords.items():
            if any(kw in combined for kw in kws):
                return category
        return "general"

    async def generate_training_data(self) -> Dict[str, Any]:
        """Generate fine-tuning examples from accumulated experiences."""
        experiences = await experience_store.get_all()
        training_examples = []

        for exp in experiences[:50]:
            training_examples.append({
                "prompt": exp.example_prompt or f"Analyze {exp.problem_type} challenge",
                "completion": exp.approach or exp.pattern,
                "quality_score": (
                    exp.confidence if exp.confidence is not None else 0.0
                ),
            })

        return {"examples": training_examples, "count": len(training_examples)}

    # ================= MYTHOS INTEGRATION METHODS =================

    async def initialize(self) -> None:
        """Initialize all sub-engines for autonomous operation."""
        from agent.multi_agent import MultiAgentDebate

        self.retrieval = retrieval_engine
        self.multi_agent = MultiAgentDebate()

    async def stream_answer(self, problem: str, context: Optional[Dict[str, Any]] = None):
        """Streaming answer generator yielding structured SSE/WS event chunks with metrics tracking."""
        context = context or {}
        files = context.get("uploadedFiles") or []
        intent = self.detect_intent(problem, files)
        start_time = time.time()

        try:
            # 1. CTF file triage and solving
            if intent == "ctf_file" and files:
                workflow_result = {"success": False, "verified": False}
                async for chunk in self._handle_ctf_file(context):
                    if chunk.get("type") == "done":
                        workflow_result = chunk.get("data", workflow_result)
                    yield chunk
                self._record_metrics(
                    mode=intent,
                    start_time=start_time,
                    confidence=0.0,
                    success=bool(workflow_result.get("success")),
                    verified=bool(workflow_result.get("verified")),
                    tools_called=["ctf_tool"],
                )
                return

            # 2. Targeted vulnerability or web security task
            if intent in ("ctf_web", "vulnerability"):
                workflow_result = {"success": False, "verified": False}
                async for chunk in self._handle_security_task(problem):
                    if chunk.get("type") == "done":
                        workflow_result = chunk.get("data", workflow_result)
                    yield chunk
                self._record_metrics(
                    mode=intent,
                    start_time=start_time,
                    confidence=0.0,
                    success=bool(workflow_result.get("success")),
                    verified=bool(workflow_result.get("verified")),
                )
                return

            # 3. Multi-agent debate for complex architectural/exploitation problems
            if self._should_use_multi_agent(problem):
                yield {
                    "type": "info",
                    "data": (
                        "Running role-based prompts through the configured model; "
                        "these are not independent experts."
                    ),
                }
                if self.multi_agent is None:
                    await self.initialize()

                debate_result = await self.multi_agent.debate(problem, context)
                for expert in debate_result.get("debate", []):
                    preview = (expert.get("answer") or "")[:260]
                    yield {
                        "type": "expert_opinion",
                        "data": f"[{expert['expert']}]: {preview}...",
                    }

                yield {
                    "type": "info",
                    "data": (
                        f"Generated {debate_result.get('agents_participated', 0)} "
                        "prompted perspectives; no independent verification was performed."
                    ),
                }
                final_ans = debate_result.get("final_answer", "")
                conf_val = float(debate_result.get("confidence", 85.0))
                yield {"type": "answer", "data": final_ans}
                yield {"type": "confidence", "data": conf_val}
                yield {"type": "done", "data": {}}

                self._record_metrics(
                    mode=intent,
                    start_time=start_time,
                    confidence=conf_val,
                    success=bool(final_ans.strip()),
                    verified=False,
                    agents_used=debate_result.get("agents_participated", 4),
                )
                return

            # 4. Standard self-learning agent solve
            yield {"type": "info", "data": "Analyzing challenge with retrieved memory..."}
            result = await self.solve(problem)

            if result.get("reasoning"):
                for reason in result["reasoning"]:
                    yield {"type": "reasoning", "data": reason}

            ans_text = result.get("answer", "")
            yield {"type": "answer", "data": ans_text}

            conf_data = self.calculate_confidence(result, context)
            yield {"type": "confidence", "data": conf_data}

            is_verified = bool(result.get("verified", {}).get("passed", False))
            if result.get("verified"):
                if is_verified:
                    yield {"type": "info", "data": "Verification engine: passed"}
                else:
                    yield {"type": "warning", "data": "Verification engine: uncertainty detected"}

            if result.get("learning"):
                yield {"type": "learning", "data": result["learning"]}

            if result.get("uncertainty") and result["uncertainty"] != "NONE":
                yield {"type": "uncertainty", "data": result["uncertainty"]}

            yield {"type": "done", "data": {}}

            self._record_metrics(
                mode=intent,
                start_time=start_time,
                confidence=conf_data,
                success=result.get("success", True),
                verified=is_verified,
                agents_used=1,
            )

        except Exception as e:
            self._record_metrics(
                mode=context.get("mode", intent or "general"),
                start_time=start_time,
                confidence=0.0,
                success=False,
                verified=False,
                agents_used=0,
                error=str(e),
            )
            raise

    def _record_metrics(
        self,
        mode: str,
        start_time: float,
        confidence: float,
        success: bool = True,
        verified: bool = False,
        agents_used: int = 1,
        tools_called: Optional[List[str]] = None,
        error: Optional[str] = None,
    ) -> None:
        """Helper to record performance metrics into MetricsCollector."""
        try:
            from redloop.performance import record_query_metric
            latency_ms = (time.time() - start_time) * 1000.0
            record_query_metric(
                mode=mode,
                latency_ms=latency_ms,
                confidence=confidence,
                tokens_used=0,
                success=success,
                verified=verified,
                agents_used=agents_used,
                tools_called=tools_called or [],
                error=error,
                token_usage_reported=False,
            )
        except Exception:
            pass

    async def _handle_ctf_file(self, context: Dict[str, Any]):
        """Analyze attached CTF files through CTFTool."""
        from services.learning_service.ctf_tool import CTFTool

        tool = CTFTool()
        files = context.get("uploadedFiles") or []
        first_file = files[0]
        filename = first_file.get("name", "challenge.bin")

        yield {"type": "info", "data": f"Analyzing CTF challenge file: {filename}"}

        content_bytes = first_file.get("bytes")
        if not isinstance(content_bytes, bytes) or not content_bytes:
            yield {"type": "error", "data": "Uploaded file content is unavailable or empty."}
            yield {"type": "done", "data": {"success": False, "verified": False}}
            return

        res = await tool.analyze_file_stream(content_bytes, filename)

        if res.get("success"):
            data = res["result"]
            yield {"type": "info", "data": f"Classified Category: {data.get('category', 'unknown')}"}

            if data.get("flag_found") and data.get("flag"):
                yield {"type": "flag", "data": data["flag"]}
                yield {"type": "info", "data": "FLAG SOLVED!"}
                await self.store_ctf_experience(data)
                yield {"type": "learning", "data": f"Learned solution for CTF flag {data['flag']}"}
            else:
                yield {"type": "info", "data": "Triage complete. Investigating decoders:"}
                for step in data.get("steps", [])[:6]:
                    yield {"type": "step", "data": step}

            yield {"type": "confidence", "data": float(data.get("confidence", 70.0))}
        else:
            yield {"type": "error", "data": res.get("error", "CTF file triage failed")}

        yield {
            "type": "done",
            "data": {
                "success": bool(res.get("success")),
                "verified": False,
            },
        }

    async def _handle_security_task(self, problem: str):
        """Execute focused security analysis."""
        yield {"type": "info", "data": "Running vulnerability assessment..."}
        result = await self.solve(problem)
        yield {"type": "answer", "data": result.get("answer", "")}
        yield {"type": "confidence", "data": float(result.get("confidence", 0.0))}
        yield {
            "type": "done",
            "data": {
                "success": bool(result.get("success")),
                "verified": bool(result.get("verified", {}).get("passed")),
            },
        }

    def _should_use_multi_agent(self, problem: str) -> bool:
        """Determine whether problem complexity warrants multi-agent debate."""
        keywords = [
            "analyze", "evaluate", "assess", "compare", "design",
            "troubleshoot", "diagnose", "investigate", "debate", "consensus"
        ]
        prob_lower = problem.lower()
        return any(kw in prob_lower for kw in keywords) and len(problem) > 40

    def detect_intent(self, message: str, files: Optional[List[Dict[str, Any]]] = None) -> str:
        """Classify user query intent into specialized domains."""
        combined = message.lower()
        file_exts = ""
        if files:
            file_exts = " ".join([f.get("name", "").split(".")[-1].lower() for f in files])
        combined += " " + file_exts

        if any(ext in file_exts for ext in [
            "pka", "pkt", "pcap", "zip", "tar", "7z", "rar", "bin", "elf", "iso", "img"
        ]):
            return "ctf_file"

        if any(kw in combined for kw in [
            "encrypt", "decrypt", "xor", "base64", "aes", "rsa", "cipher", "hash"
        ]):
            return "ctf_crypto"

        if any(kw in combined for kw in [
            "xss", "sqli", "csrf", "ssrf", "injection", "rce"
        ]):
            return "ctf_web"

        if any(kw in combined for kw in [
            "overflow", "buffer", "shellcode", "pwn", "rop", "heap"
        ]):
            return "ctf_pwn"

        if any(kw in combined for kw in [
            "vuln", "cve", "scan", "pentest", "assessment"
        ]):
            return "vulnerability"

        return "general"

    def calculate_confidence(self, result: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> float:
        """Multi-signal confidence scoring calibrated against experience and verification."""
        signals = {}

        # Signal 1: Similar experience found
        sources = result.get("sources", [])
        signals["pattern_match"] = 30.0 if sources else 0.0

        # Signal 2: Verification check
        ver = result.get("verified", {})
        signals["verification"] = 30.0 if ver.get("passed", False) else 10.0

        # Signal 3: Stated confidence
        base_conf = float(result.get("confidence", 70.0))
        signals["base_confidence"] = base_conf * 0.2

        # Signal 4: Answer clarity
        clarity = self._measure_answer_clarity(result.get("answer", ""))
        signals["clarity"] = clarity * 0.2

        score = sum(signals.values())
        return round(min(max(score, 10.0), 100.0), 1)

    def _measure_answer_clarity(self, answer: str) -> float:
        """Heuristic score of how definitive and well-structured an answer is."""
        if not answer:
            return 0.0
        definite_words = ["is", "definite", "clearly", "therefore", "conclude", "solution", "flag"]
        words = re.findall(r"[a-zA-Z]+", answer.lower())
        positives = sum(1 for w in words if w in definite_words)
        has_structure = bool(re.search(r"(##|###|ANSWER:|REASONING:)", answer))
        raw = (positives * 5.0) + (20.0 if has_structure else 0.0)
        return min(raw, 100.0)

    async def store_ctf_experience(self, ctf_data: Dict[str, Any]) -> Dict[str, Any]:
        """Store CTF solve outcome as a persistent learning memory."""
        problem = ctf_data.get("filename") or ctf_data.get("source") or "CTF Challenge"
        solution = ctf_data.get("flag") or ctf_data.get("solution") or "Solved"
        return await self.store_experience(
            problem=f"CTF challenge: {problem}",
            answer=f"Flag: {solution}\nSteps: {ctf_data.get('steps', [])}",
            learning_type="ctf_solved",
        )

    async def _generate_correction(self, problem: str, wrong: str) -> str:
        """Generate a corrected answer using LLM reasoning."""
        client = get_llm_client()
        return await client.generate(
            system_prompt="You are a senior cybersecurity expert. Provide the exact correct solution.",
            user_prompt=f"PROBLEM:\n{problem}\n\nWRONG ANSWER PREVIOUSLY GIVEN:\n{wrong}\n\nProvide the corrected solution with brief explanation:",
            max_tokens=1024,
        )

    def _get_message_by_id(self, message_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve stored interaction by message ID."""
        return self._messages.get(message_id)

    def get_overall_stats(self) -> Dict[str, Any]:
        """Get aggregate agent statistics."""
        try:
            from database.repositories import agent_stats_repo, experience_repo
            experiences = experience_repo.get_all()
            total_exp = len(experiences)
            avg_conf = (
                sum(e.confidence for e in experiences) / max(total_exp, 1)
                if total_exp else 0.0
            )
            return {
                "total_experiences": total_exp,
                "avg_experience_confidence": round(avg_conf, 2),
                "total_successes": sum(e.success_count for e in experiences),
                "agent_mode": "mythos",
                "uptime": "running",
            }
        except Exception as e:
            return {"error": str(e), "total_experiences": 0}
