"""RedLoop CLI entrypoint.

Commands:
  redloop scope init    — sign a scope.yaml with HMAC
  redloop scope check   — verify a target/action against scope
  redloop sandbox run   — execute a trivial script in the sandbox (smoke test)
  redloop llm test      — call the LLM with a trivial prompt
  redloop recon <target>  — Phase 2: run recon modules
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
import yaml
from docker.errors import DockerException
from rich.console import Console
from rich.table import Table

from redloop.audit import AuditLogger
from redloop.config import settings
from redloop.ctf import CTFSimulator
from redloop.ctf_files import CTFArchiveAnalyzer, MAX_ARCHIVE_BYTES
from redloop.executor import ExecutionFailedError, SelfHealingExecutor
from redloop.forensics import ForensicsAnalyzer, MAX_FILE_SIZE, YaraScanner
from redloop.llm import LLMError, Provider, get_llm
from redloop.memory import EpisodicMemory, MemoryRecord
from redloop.reporting import AuditReader, AuditReportGenerator, MAX_DASHBOARD_ROWS
from redloop.recon import (
    DEFAULT_PORTS,
    MAX_PORTS,
    NmapScanner,
    ReconDependencyError,
    ReconError,
    ReconExecutionError,
)
from redloop.sandbox import DockerSandbox, build_sandbox_image
from redloop.scope import ScopeManager, UnauthorizedTargetError
from redloop.webapp import WebAppCheckError, WebAppChecker

app = typer.Typer(
    name="redloop",
    help="RedLoop — scope-limited security testing toolkit",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()

scope_app = typer.Typer(name="scope", help="Scope management")
sandbox_app = typer.Typer(name="sandbox", help="Docker sandbox utilities")
llm_app = typer.Typer(name="llm", help="LLM backend utilities")
agent_app = typer.Typer(name="agent", help="Bounded local agent utilities")
web_app = typer.Typer(name="web", help="Loopback-only web metadata checks")
ctf_app = typer.Typer(name="ctf", help="Offline CTF workflows and file analysis")
forensics_app = typer.Typer(name="forensics", help="Static file triage")
memory_app = typer.Typer(name="memory", help="Local episodic memory")
report_app = typer.Typer(name="report", help="Read-only audit reports and dashboard")
recon_app = typer.Typer(name="recon", help="Explicit-port loopback recon")
tls_app = typer.Typer(name="tls", help="TLS configuration and certificate inspection")
audit_app = typer.Typer(name="audit", help="Tamper-evident audit utilities")
assessment_app = typer.Typer(name="assessment", help="Deep modular assessment engine")
findings_app = typer.Typer(name="findings", help="Security findings repository")
evidence_app = typer.Typer(name="evidence", help="Cryptographic evidence ledger")
network_app = typer.Typer(name="network", help="Network security assessment")
dns_app = typer.Typer(name="dns", help="DNS security assessment")
api_app = typer.Typer(name="api", help="API security assessment")
host_app = typer.Typer(name="host", help="Host security assessment")
target_app = typer.Typer(name="target", help="Target discovery and technology fingerprinting")
container_app = typer.Typer(name="container", help="Container and Dockerfile security assessment")
file_app = typer.Typer(name="file", help="Static file and malware triage")

app.add_typer(scope_app)
app.add_typer(sandbox_app)
app.add_typer(llm_app)
app.add_typer(agent_app)
app.add_typer(web_app)
app.add_typer(ctf_app)
app.add_typer(forensics_app)
app.add_typer(memory_app)
app.add_typer(report_app)
app.add_typer(recon_app)
app.add_typer(tls_app)
app.add_typer(audit_app)
app.add_typer(assessment_app)
app.add_typer(findings_app)
app.add_typer(evidence_app)
app.add_typer(network_app)
app.add_typer(dns_app)
app.add_typer(api_app)
app.add_typer(host_app)
app.add_typer(target_app)
app.add_typer(container_app)
app.add_typer(file_app)


def _get_scope_manager() -> ScopeManager:
    secret = settings.scope_secret or None
    return ScopeManager(settings.scope_file, secret)


def _get_audit() -> AuditLogger:
    return AuditLogger(settings.audit_db)


# -- scope commands -----------------------------------------------------------
@scope_app.command("init")
def scope_init(
    infile: Path = typer.Option(..., "--in", help="Unsigned scope.yaml to sign"),
    outfile: Path = typer.Option(..., "--out", help="Signed scope.yaml output path"),
    secret: str = typer.Option("", "--secret", help="HMAC secret (generated if omitted)"),
):
    """Sign a scope.yaml with HMAC-SHA256."""
    import yaml
    from redloop.scope import sign_scope

    raw = yaml.safe_load(infile.read_text(encoding="utf-8"))
    used_secret = secret or settings.scope_secret
    if not used_secret:
        import secrets

        used_secret = secrets.token_hex(32)
        console.print(f"[yellow]Generated secret:[/yellow] {used_secret}")
        console.print("[dim]Store this in REDLOOP_SCOPE_SECRET or .env[/dim]")

    raw["signature"] = sign_scope(raw, used_secret)
    outfile.write_text(yaml.dump(raw, sort_keys=False), encoding="utf-8")
    console.print(f"[green]Signed scope written to {outfile}[/green]")


@scope_app.command("check")
def scope_check(
    target: str = typer.Argument(..., help="Target IP or hostname"),
    action: str = typer.Argument(..., help="Action to check (recon, web_test, exploit, etc.)"),
):
    """Verify that target/action is authorized by the signed scope."""
    try:
        sm = _get_scope_manager()
        entry = sm.check(target, action)
        console.print(f"[green]OK Authorized[/green]: {target} -> {action} (entry: {entry.label})")
    except UnauthorizedTargetError as e:
        console.print(f"[red]BLOCKED[/red]: {e}")
        raise typer.Exit(1)


# -- sandbox commands ---------------------------------------------------------
@sandbox_app.command("build")
def sandbox_build(
    tag: str = typer.Option("redloop-sandbox", "--tag", help="Image tag"),
):
    """Build the default hardened sandbox image."""
    console.print(f"Building {tag}...")
    try:
        build_sandbox_image(tag)
        console.print(f"[green]Built {tag}[/green]")
    except DockerException as exc:
        console.print(
            f"[red]Build failed ({type(exc).__name__}): {exc}[/red]"
        )
        raise typer.Exit(1)


@sandbox_app.command("run")
def sandbox_run(
    code: str = typer.Option("print('hello from sandbox')", "--code", "-c", help="Code to run"),
    language: str = typer.Option("python", "--lang", "-l", help="python | bash"),
):
    """Execute a trivial script in the sandbox (smoke test)."""
    console.print(f"Running {language} code in sandbox...")
    sandbox = DockerSandbox()
    result = sandbox.run(code, language=language)

    table = Table(title="Sandbox Result")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Success", "OK" if result.success else "FAIL")
    table.add_row("Exit code", str(result.exit_code))
    table.add_row("Container", result.container_id or "N/A")
    table.add_row("Stdout", result.stdout.strip() or "(empty)")
    table.add_row("Stderr", result.stderr.strip() or "(empty)")
    console.print(table)

    if not result.success:
        raise typer.Exit(1)


# -- llm commands -------------------------------------------------------------
@llm_app.command("test")
def llm_test(
    prompt: str = typer.Option("Say hello in JSON: {\"msg\": \"hello\"}", "--prompt", "-p"),
    provider: str = typer.Option("", "--provider", help="Override provider (ollama|openrouter|...)"),
):
    """Call the configured LLM with a trivial prompt."""
    client = get_llm()
    try:
        selected_provider = Provider(provider) if provider else client.default_provider
    except ValueError as exc:
        choices = ", ".join(item.value for item in Provider)
        raise typer.BadParameter(f"Choose one of: {choices}") from exc

    console.print(f"Provider: [cyan]{selected_provider.value}[/cyan]")
    console.print(f"Model:    [cyan]{client.model_string(selected_provider)}[/cyan]")
    console.print("Calling LLM...")

    try:
        resp = client.complete(
            "You are a helpful assistant. Reply only with valid JSON.",
            prompt,
            provider=selected_provider,
        )
        console.print("[green]Response:[/green]")
        console.print(resp["text"])
        console.print(
            f"[dim]Elapsed: {resp['elapsed_seconds']:.2f}s[/dim]"
        )
    except LLMError as e:
        console.print(f"[red]LLM error:[/red] {e}")
        raise typer.Exit(1)


@app.command("llm-bench")
def llm_bench():
    """Measure one identical, trivial prompt against each configured provider."""
    client = get_llm()
    providers = client.configured_providers()
    table = Table(title="LLM provider latency")
    table.add_column("Provider")
    table.add_column("Model")
    table.add_column("Elapsed")
    table.add_column("Result")

    for provider in providers:
        model = client.model_string(provider)
        try:
            result = client.complete(
                "Reply with exactly one word.",
                "ping",
                provider=provider,
                temperature=0,
                max_tokens=8,
                timeout=20,
            )
            table.add_row(
                provider.value,
                model,
                f"{result['elapsed_seconds']:.2f}s",
                "ok",
            )
        except LLMError as exc:
            table.add_row(
                provider.value,
                model,
                "—",
                f"failed ({type(exc).__name__})",
            )
    console.print(table)


@llm_app.command("generate")
def llm_generate(
    task: str = typer.Argument(..., help="Task description for code generation"),
):
    """Ask the LLM to generate a script for a task."""
    client = get_llm()
    code = client.generate_code(task)
    console.print("[green]Generated code:[/green]")
    console.print(code)


@agent_app.command("run")
def agent_run(
    task: str = typer.Argument(..., help="Task for a fixed local operation"),
    target: str = typer.Option(..., "--target", help="Target authorized in scope.yaml"),
    action: str = typer.Option("recon", "--action", help="Authorized scope action"),
    max_retries: int = typer.Option(3, "--max-retries", min=1, max=5),
):
    """Run a bounded, local-only operation selected by the LLM."""
    try:
        executor = SelfHealingExecutor(
            llm=get_llm(),
            audit=_get_audit(),
            scope=_get_scope_manager(),
            memory=_get_memory(),
            max_retries=max_retries,
        )
        report = executor.run(task, target, action)
    except UnauthorizedTargetError as exc:
        console.print(f"[red]BLOCKED[/red]: {exc}")
        raise typer.Exit(1) from exc
    except ExecutionFailedError as exc:
        console.print(f"[red]Failed after {len(exc.attempts)} attempts[/red]")
        for attempt in exc.attempts:
            console.print(
                f"Attempt {attempt.attempt_number}: "
                f"{attempt.error or 'operation failed'}"
            )
        raise typer.Exit(1) from exc

    console.print(
        f"[green]Completed[/green] using {len(report.attempts)} attempt(s)"
    )
    console.print_json(data=report.result)


@web_app.command("inspect")
def web_inspect(
    url: str = typer.Argument(..., help="Root URL of a scoped loopback service"),
):
    """Inspect basic response headers without following redirects or sending payloads."""
    try:
        checker = WebAppChecker(
            scope=_get_scope_manager(), audit=_get_audit(), memory=_get_memory()
        )
        report = checker.inspect(url)
    except (WebAppCheckError, UnauthorizedTargetError) as exc:
        console.print(f"[red]BLOCKED / FAILED[/red]: {exc}")
        raise typer.Exit(1) from exc
    console.print_json(data=report.model_dump(mode="json"))


@ctf_app.command("list")
def ctf_list():
    """List offline synthetic workflow challenges."""
    challenges = CTFSimulator.list_challenges()
    table = Table(title="Synthetic CTF Challenges")
    table.add_column("ID")
    table.add_column("Title")
    table.add_column("Target (fictional)")
    for challenge in challenges:
        table.add_row(challenge.id, challenge.title, challenge.synthetic_target)
    console.print(table)


@ctf_app.command("show")
def ctf_show(
    challenge_id: str = typer.Argument(..., help="Synthetic challenge ID"),
):
    """Show a synthetic challenge briefing and suggested module."""
    try:
        challenge = CTFSimulator.get_challenge(challenge_id)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    console.print(f"[bold]{challenge.title}[/bold]")
    console.print(challenge.briefing)
    console.print(f"Target: {challenge.synthetic_target}")
    console.print(f"Suggested module: {challenge.suggested_module}")
    console.print(f"Hint: {challenge.hint}")


@ctf_app.command("simulate")
def ctf_simulate(
    challenge_id: str = typer.Argument(..., help="Synthetic challenge ID"),
    module_name: str = typer.Option(
        ..., "--module", help="Module name shown by `redloop ctf show`"
    ),
    confirm: bool = typer.Option(
        False,
        "--confirm",
        help="Confirm the in-memory simulation (does not contact a target)",
    ),
):
    """Simulate confirmation/job/session flow entirely offline."""
    simulator = CTFSimulator(_get_audit(), memory=_get_memory())
    try:
        result = simulator.simulate(challenge_id, module_name, confirmed=confirm)
    except ValueError as exc:
        console.print(f"[red]Blocked[/red]: {exc}")
        raise typer.Exit(1) from exc
    console.print_json(data=result.model_dump(mode="json"))


@ctf_app.command("solve-file")
def ctf_solve_file(
    archive_path: Path = typer.Argument(
        ..., exists=True, file_okay=True, dir_okay=False, readable=True
    ),
    flag_prefixes: list[str] = typer.Option(
        [], "--flag-prefix", help="Additional literal flag wrapper prefix"
    ),
):
    """Inspect a ZIP archive locally without extraction or execution."""
    try:
        with archive_path.open("rb") as archive:
            archive_bytes = archive.read(MAX_ARCHIVE_BYTES + 1)
        report = CTFArchiveAnalyzer(
            audit=_get_audit(),
            memory=_get_memory(),
        ).analyze(
            archive_bytes,
            original_filename=archive_path.name,
            flag_prefixes=flag_prefixes,
        )
    except (OSError, ValueError, TypeError) as exc:
        console.print(f"[red]Archive analysis failed[/red]: {exc}")
        raise typer.Exit(1) from exc
    console.print_json(data=report.model_dump(mode="json"))


@forensics_app.command("analyze")
def forensics_analyze(
    file_path: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False),
    rules_dir: Path | None = typer.Option(
        None,
        "--rules-dir",
        help="Optional directory of local .yar/.yara rules",
        file_okay=False,
    ),
):
    """Run bounded static analysis; never executes the input file."""
    try:
        with file_path.open("rb") as sample:
            file_bytes = sample.read(MAX_FILE_SIZE + 1)
        scanner = YaraScanner(rules_dir) if rules_dir is not None else None
        report = ForensicsAnalyzer(
            _get_audit(), yara_scanner=scanner, memory=_get_memory()
        ).analyze(file_bytes, file_path.name)
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(f"[red]Analysis failed[/red]: {exc}")
        raise typer.Exit(1) from exc
    console.print_json(data=report.model_dump(mode="json"))


def _get_memory() -> EpisodicMemory:
    return EpisodicMemory(settings.memory_db, audit=_get_audit())


@memory_app.command("recall")
def memory_recall(
    task: str = typer.Argument(..., help="Search task history"),
    module: str | None = typer.Option(
        None,
        "--module",
        help="Filter: executor, forensics, webapp, ctf_simulator, recon",
    ),
    limit: int = typer.Option(3, "--limit", min=1, max=10),
):
    """Recall similar local task outcomes and symbolic approaches."""
    try:
        matches = _get_memory().retrieve_similar(task, module=module, n_results=limit)
    except ValueError as exc:
        console.print(f"[red]Invalid query[/red]: {exc}")
        raise typer.Exit(1) from exc
    if not matches:
        console.print("No similar memory records found.")
        return
    table = Table(title="Local Memory Matches")
    table.add_column("Similarity")
    table.add_column("Module")
    table.add_column("Outcome")
    table.add_column("Task")
    table.add_column("Approach")
    for match in matches:
        table.add_row(
            f"{match.similarity:.2f}",
            match.record.module,
            match.record.outcome,
            match.record.task_description,
            match.record.approach,
        )
    console.print(table)


@report_app.command("targets")
def report_targets():
    """List targets present in the local audit database."""
    targets = AuditReader(settings.audit_db).targets()
    if not targets:
        console.print("No audit targets found.")
        return
    for target in targets:
        console.print(target)


@report_app.command("generate")
def report_generate(
    target: str = typer.Argument(..., help="Assessment ID (asmt-...) or exact audit target"),
    output: Path | None = typer.Option(
        None, "--output", help="Markdown output path"
    ),
):
    """Generate reports for an assessment ID or from existing audit rows."""
    from redloop.assessment.engine import AssessmentStore
    from redloop.assessment.reporting import ReportingEngine

    store = AssessmentStore()
    state = store.load(target)
    if state:
        rep_engine = ReportingEngine()
        tech = rep_engine.generate_technical_report(state)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(tech, encoding="utf-8")
            console.print(f"[green]Assessment report written[/green]: {output}")
        else:
            console.print(tech)
        return

    try:
        path = AuditReportGenerator(
            settings.audit_db, settings.data_dir / "reports"
        ).generate(target, output)
    except (OSError, ValueError) as exc:
        console.print(f"[red]Report generation failed[/red]: {exc}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Report written[/green]: {path}")


@report_app.command("serve")
def report_serve(
    port: int = typer.Option(8765, "--port", min=1024, max=65535),
):
    """Start the read-only dashboard on loopback only."""
    try:
        import uvicorn
        from redloop.dashboard import create_app

        try:
            scope_manager = _get_scope_manager()
        except (OSError, UnauthorizedTargetError, ValueError, yaml.YAMLError) as exc:
            console.print(
                f"[red]Refusing to start dashboard[/red]: verified signed scope is "
                f"unavailable ({type(exc).__name__}: {exc})"
            )
            raise typer.Exit(1) from exc
        dashboard = create_app(str(settings.audit_db), scope_manager=scope_manager)
    except (ImportError, RuntimeError) as exc:
        console.print(f"[red]Dashboard unavailable[/red]: {exc}")
        raise typer.Exit(1) from exc
    console.print(f"Read-only dashboard: http://127.0.0.1:{port}")
    uvicorn.run(dashboard, host="127.0.0.1", port=port, access_log=False)


@recon_app.command("scan")
def recon_scan(
    target: str = typer.Argument(..., help="Literal loopback IP in scope"),
    ports: list[int] = typer.Option(
        ...,
        "--port",
        min=1,
        max=65_535,
        help=(
            "Explicit TCP port to check; repeat up to "
            f"{MAX_PORTS} times. Default candidate ports: {DEFAULT_PORTS}"
        ),
    ),
):
    """Inventory explicitly authorized ports on a local loopback service."""
    try:
        scope = _get_scope_manager()
        scanner = NmapScanner(
            scope=scope,
            audit=_get_audit(),
            memory=_get_memory(),
        )
        result = scanner.quick_scan(target, ports)
    except (UnauthorizedTargetError, ReconError, ValueError) as exc:
        console.print(f"[red]Recon blocked / failed[/red]: {exc}")
        raise typer.Exit(1) from exc
    console.print_json(data=result.model_dump(mode="json"))


@recon_app.command("profile")
def recon_profile(
    target: str = typer.Argument(..., help="Literal loopback IP to profile"),
    ports: list[int] = typer.Option(
        list(DEFAULT_PORTS),
        "--port",
        min=1,
        max=65_535,
        help="Explicit loopback ports that must be authorized in signed scope.",
    ),
):
    """Run Nmap service detection on explicitly scoped loopback ports."""
    try:
        scope = _get_scope_manager()
        scanner = NmapScanner(
            scope=scope,
            audit=_get_audit(),
            memory=_get_memory(),
        )
        result = scanner.profile_target(
            target,
            ports=ports,
        )
    except (UnauthorizedTargetError, ReconError, ValueError) as exc:
        console.print(f"[red]Profile blocked / failed[/red]: {exc}")
        raise typer.Exit(1) from exc
    console.print_json(data=result.model_dump(mode="json"))


# -- tls commands -------------------------------------------------------------
@tls_app.command("check")
def tls_check(
    target: str = typer.Argument(..., help="Explicitly authorized hostname or IP"),
    port: int = typer.Option(443, "--port", "-p", min=1, max=65_535, help="Port to connect to"),
    timeout: float = typer.Option(5.0, "--timeout", "-t", min=0.1, max=10.0, help="Connection timeout in seconds"),
):
    """Inspect TLS configuration, certificate chain, expiry, and weak ciphers."""
    from redloop.tls import TLSChecker, TLSError
    try:
        scope = _get_scope_manager()
        checker = TLSChecker(
            scope=scope,
            audit=_get_audit(),
            memory=_get_memory(),
            timeout=timeout,
        )
        report = checker.inspect(target, port=port)
    except (UnauthorizedTargetError, TLSError, ValueError) as exc:
        console.print(f"[red]TLS check blocked / failed[/red]: {exc}")
        raise typer.Exit(1) from exc
    console.print_json(data=report.model_dump(mode="json"))


# -- audit commands -----------------------------------------------------------
@audit_app.command("verify")
def audit_verify():
    """Verify cryptographic SHA-256 integrity chain of the audit database (Section 26)."""
    audit = _get_audit()
    res = audit.verify_chain()
    status = res.get("status", "VERIFICATION_INCOMPLETE")
    anchored = bool(res.get("anchored"))
    if status == "INTEGRITY_VERIFIED":
        label = "PASS (ANCHORED)" if anchored else "PASS (UNANCHORED)"
        style = "bold green" if anchored else "bold yellow"
        console.print(
            f"[{style}]{label}[/]: All {res.get('total_events', 0)} events internally verified. "
            f"Cryptographic hash chain intact (Head: {res.get('head_hash', '')[:16]}...)."
        )
        if not anchored:
            console.print(
                "[yellow]WARNING[/]: No trusted chain anchor exists; truncation cannot be excluded. "
                "Run the explicit seal operation to anchor the current head."
            )
    elif status in ("TAMPER_DETECTED", "CHAIN_GAP_DETECTED"):
        failure = res.get("failure") or {}
        console.print(
            f"[bold red]FAIL - {status}[/bold red]: {res.get('error')} "
            f"(event id={failure.get('event_id')}, sequence={failure.get('sequence')})"
        )
        raise typer.Exit(2)
    else:
        console.print(
            f"[bold yellow]{status}[/bold yellow]: {res.get('message') or 'verification could not complete'}"
        )
        raise typer.Exit(3)


# -- assessment commands ------------------------------------------------------
@assessment_app.command("start")
def assessment_start(
    target: str = typer.Argument(..., help="Authorized target host, IP, or domain"),
    depth: str = typer.Option("standard", "--depth", "-d", help="quick | standard | deep | comprehensive"),
    config_artifact: list[str] = typer.Option([], "--config", help="Path to config artifact (Dockerfile, compose, k8s)"),
    file_artifact: list[str] = typer.Option([], "--file", help="Path to binary or artifact for static triage"),
):
    """Start an automated security assessment workflow within machine-enforced scope."""
    from redloop.assessment.engine import AssessmentEngine
    from redloop.assessment.models import AssessmentDepth
    from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError

    depth_enum = getattr(AssessmentDepth, depth.upper(), AssessmentDepth.STANDARD)
    guard = AssessmentScopeGuard(_get_scope_manager(), _get_audit())
    engine = AssessmentEngine(guard, _get_audit())

    console.print(f"[bold blue]Starting RedLoop Security Assessment[/bold blue] -> Target: {target} (Depth: {depth_enum.value})")

    def on_progress(asmt_id: str, stage: str, res: Any):
        if res is None:
            console.print(f" [cyan]>[/cyan] Executing stage: [bold]{stage}[/bold]...")
        else:
            status_color = "green" if res.status.value == "SUCCESS" else ("yellow" if res.status.value in ("UNAVAILABLE", "PARTIAL") else "red")
            console.print(f"   [{status_color}]{res.status.value}[/{status_color}] {stage} - {res.reason} ({res.duration_seconds}s)")

    try:
        state = engine.start_assessment(
            target=target,
            depth=depth_enum,
            progress_callback=on_progress,
            config_artifact_paths=config_artifact,
            file_artifact_paths=file_artifact,
        )
    except ScopeBlockedError as sbe:
        console.print(f"[bold red]Assessment Blocked by Scope Guard[/bold red]: {sbe}")
        raise typer.Exit(1) from sbe

    console.print(f"\n[bold green]Assessment Completed[/bold green] (ID: `{state.id}`)")
    console.print(f"Total Findings: {len(state.findings)} | Total Evidence Items: {len(state.evidence)}")

    if state.findings:
        table = Table(title="Assessment Findings")
        table.add_column("ID", style="dim")
        table.add_column("Severity")
        table.add_column("Confidence")
        table.add_column("Title")
        table.add_column("Port/Endpoint")
        table.add_column("Risk")
        for f in sorted(state.findings, key=lambda x: x.risk_score, reverse=True):
            sev_color = "red" if f.severity.value in ("CRITICAL", "HIGH") else ("yellow" if f.severity.value == "MEDIUM" else "cyan")
            table.add_row(
                f.id,
                f"[{sev_color}]{f.severity.value}[/{sev_color}]",
                f.confidence.value,
                f.title,
                str(f.endpoint or f.port or "-"),
                f"{f.risk_score:.1f}",
            )
        console.print(table)


@assessment_app.command("resume")
def assessment_resume(
    assessment_id: str = typer.Argument(..., help="Assessment ID to resume"),
):
    """Resume an interrupted assessment from its persistent checkpoint (Section 30)."""
    from redloop.assessment.engine import AssessmentEngine
    from redloop.assessment.scope_guard import AssessmentScopeGuard

    guard = AssessmentScopeGuard(_get_scope_manager(), _get_audit())
    engine = AssessmentEngine(guard, _get_audit())

    def on_progress(asmt_id: str, stage: str, res: Any):
        if res is None:
            console.print(f" [cyan]>[/cyan] Executing stage: [bold]{stage}[/bold]...")
        else:
            status_color = "green" if res.status.value == "SUCCESS" else "yellow"
            console.print(f"   [{status_color}]{res.status.value}[/{status_color}] {stage} - {res.reason}")

    try:
        state = engine.resume_assessment(assessment_id, progress_callback=on_progress)
        console.print(f"[bold green]Resumed Assessment Finished[/bold green] (Status: {state.status})")
    except ValueError as ve:
        console.print(f"[red]{ve}[/red]")
        raise typer.Exit(1) from ve


@assessment_app.command("status")
def assessment_status(
    assessment_id: str = typer.Argument(..., help="Assessment ID"),
):
    """Inspect state, stages, and findings of an assessment."""
    from redloop.assessment.engine import AssessmentStore
    store = AssessmentStore()
    state = store.load(assessment_id)
    if not state:
        console.print(f"[red]Assessment {assessment_id} not found[/red]")
        raise typer.Exit(1)
    console.print_json(data=state.model_dump(mode="json"))


@assessment_app.command("list")
def assessment_list():
    """List all assessments recorded in the persistent store."""
    from redloop.assessment.engine import AssessmentStore
    store = AssessmentStore()
    asmts = store.list_all()
    if not asmts:
        console.print("No assessments recorded.")
        return
    table = Table(title="Security Assessments")
    table.add_column("ID")
    table.add_column("Target")
    table.add_column("Depth")
    table.add_column("Status")
    table.add_column("Current Stage")
    table.add_column("Updated At")
    for a in asmts:
        table.add_row(a["id"], a["target"], a["depth"], a["status"], a["current_stage"], a["updated_at"])
    console.print(table)


@assessment_app.command("pause")
def assessment_pause(
    assessment_id: str = typer.Argument(..., help="Assessment ID to pause"),
):
    """Pause an active assessment and persist its current checkpoint."""
    from datetime import datetime, timezone
    from redloop.assessment.engine import AssessmentStore

    store = AssessmentStore()
    state = store.load(assessment_id)
    if not state:
        console.print(f"[red]Assessment '{assessment_id}' not found.[/red]")
        raise typer.Exit(1)
    state.status = "PAUSED"
    state.updated_at = datetime.now(timezone.utc).isoformat()
    store.save(state)
    console.print(f"[yellow]Assessment '{assessment_id}' paused.[/yellow]")


@assessment_app.command("cancel")
def assessment_cancel(
    assessment_id: str = typer.Argument(..., help="Assessment ID to cancel"),
):
    """Cancel an active assessment and record its terminal state."""
    from datetime import datetime, timezone
    from redloop.assessment.engine import AssessmentStore

    store = AssessmentStore()
    state = store.load(assessment_id)
    if not state:
        console.print(f"[red]Assessment '{assessment_id}' not found.[/red]")
        raise typer.Exit(1)
    state.status = "CANCELLED"
    state.updated_at = datetime.now(timezone.utc).isoformat()
    store.save(state)
    console.print(f"[red]Assessment '{assessment_id}' cancelled.[/red]")


# -- findings commands --------------------------------------------------------
@findings_app.command("list")
def findings_list(
    assessment_id: str | None = typer.Option(None, "--assessment-id", "-a", help="Filter by assessment ID"),
):
    """List findings from the latest or specified assessment."""
    from redloop.assessment.engine import AssessmentStore
    store = AssessmentStore()
    asmts = store.list_all()
    if not asmts:
        console.print("No assessments or findings found.")
        return
    target_id = assessment_id or asmts[0]["id"]
    state = store.load(target_id)
    if not state or not state.findings:
        console.print(f"No findings in assessment {target_id}.")
        return

    table = Table(title=f"Findings for Assessment {target_id}")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Category")
    table.add_column("Risk Score")
    for f in state.findings:
        table.add_row(f.id, f.severity.value, f.title, f.category, f"{f.risk_score:.1f}")
    console.print(table)


@findings_app.command("show")
def findings_show(
    finding_id: str = typer.Argument(..., help="Finding ID (e.g. RL-XXXXXX)"),
):
    """Show detailed finding record and associated evidence hashes."""
    from redloop.assessment.engine import AssessmentStore
    store = AssessmentStore()
    for row in store.list_all():
        state = store.load(row["id"])
        if state:
            for f in state.findings:
                if f.id == finding_id:
                    console.print_json(data=f.model_dump(mode="json"))
                    return
    console.print(f"[red]Finding {finding_id} not found in any assessment record.[/red]")
    raise typer.Exit(1)


# -- evidence commands --------------------------------------------------------
@evidence_app.command("show")
def evidence_show(
    evidence_id: str = typer.Argument(..., help="Evidence ID or SHA-256 hash"),
):
    """Display raw evidence record and verification details."""
    from redloop.assessment.engine import AssessmentStore
    store = AssessmentStore()
    for row in store.list_all():
        state = store.load(row["id"])
        if state:
            for ev in state.evidence:
                if ev.id == evidence_id or ev.sha256_hash.startswith(evidence_id):
                    console.print_json(data=ev.model_dump(mode="json"))
                    return
    console.print(f"[red]Evidence artifact '{evidence_id}' not found.[/red]")
    raise typer.Exit(1)


# -- domain scanner commands --------------------------------------------------
@network_app.command("scan")
def network_scan(
    target: str = typer.Argument(..., help="Authorized target IP or hostname"),
    ports: list[int] = typer.Option([80, 443, 8080, 22], "--port", "-p", help="Target TCP ports"),
):
    """Perform real network enumeration and banner collection within signed scope."""
    from redloop.assessment.network import NetworkEngine
    from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError

    guard = AssessmentScopeGuard(_get_scope_manager(), _get_audit())
    engine = NetworkEngine(guard, _get_audit())
    try:
        res = engine.scan_tcp_ports(target, ports=ports)
    except ScopeBlockedError as exc:
        console.print(f"[red]Blocked by scope[/red]: {exc}")
        raise typer.Exit(1) from exc

    console.print(f"Status: {res.status.value} - {res.reason}")
    if "open_ports" in res.data:
        console.print(f"Open Ports: {res.data['open_ports']}")
    for banner in res.data.get("banners", []):
        console.print(f"Port {banner.get('port')}: {banner.get('banner')}")


@dns_app.command("scan")
def dns_scan(
    target: str = typer.Argument(..., help="Target domain"),
):
    """Audit DNS records, mail authentication (SPF, DMARC), and DNSSEC within scope."""
    from redloop.assessment.dns_engine import DNSEngine
    from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError

    guard = AssessmentScopeGuard(_get_scope_manager(), _get_audit())
    engine = DNSEngine(guard, _get_audit())
    try:
        res = engine.assess_dns(target)
    except ScopeBlockedError as exc:
        console.print(f"[red]Blocked by scope[/red]: {exc}")
        raise typer.Exit(1) from exc

    console.print(f"Status: {res.status.value} - {res.reason}")
    console.print_json(data=res.data)


@api_app.command("scan")
def api_scan(
    target_url: str = typer.Argument(..., help="Target API base URL (e.g. http://localhost:8765)"),
):
    """Discover API schemas (OpenAPI, Swagger, GraphQL) and assess endpoints."""
    from redloop.assessment.api_engine import APIEngine
    from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError

    guard = AssessmentScopeGuard(_get_scope_manager(), _get_audit())
    engine = APIEngine(guard, _get_audit())
    try:
        res = engine.assess_api(target_url)
    except ScopeBlockedError as exc:
        console.print(f"[red]Blocked by scope[/red]: {exc}")
        raise typer.Exit(1) from exc

    console.print(f"Status: {res.status.value} - {res.reason}")
    console.print(f"Findings: {len(res.findings)}")
    console.print_json(data=res.data)


@host_app.command("scan")
def host_scan(
    target: str = typer.Argument("127.0.0.1", help="Target host (LOCAL_HOST only)"),
):
    """Audit local host listening sockets, processes, environment secrets, and SSH."""
    from redloop.assessment.host_engine import HostEngine
    from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError

    guard = AssessmentScopeGuard(_get_scope_manager(), _get_audit())
    engine = HostEngine(guard, _get_audit())
    try:
        res = engine.assess_host(target)
    except ScopeBlockedError as exc:
        console.print(f"[red]Blocked by scope[/red]: {exc}")
        raise typer.Exit(1) from exc

    console.print(f"Status: {res.status.value} - {res.reason}")
    console.print(f"Findings: {len(res.findings)}")
    for f in res.findings:
        console.print(f"[{f.severity.value}] {f.title}")


@report_app.command("executive")
def report_executive(
    assessment_id: str = typer.Argument(..., help="Assessment ID"),
):
    """Display Executive Security Assessment Report."""
    from redloop.assessment.engine import AssessmentStore
    from redloop.assessment.reporting import ReportingEngine

    store = AssessmentStore()
    state = store.load(assessment_id)
    if not state:
        console.print(f"[red]Assessment '{assessment_id}' not found.[/red]")
        raise typer.Exit(1)

    rep = ReportingEngine().generate_executive_report(state)
    console.print(rep)


@report_app.command("technical")
def report_technical(
    assessment_id: str = typer.Argument(..., help="Assessment ID"),
):
    """Display Technical Security Assessment Report."""
    from redloop.assessment.engine import AssessmentStore
    from redloop.assessment.reporting import ReportingEngine

    store = AssessmentStore()
    state = store.load(assessment_id)
    if not state:
        console.print(f"[red]Assessment '{assessment_id}' not found.[/red]")
        raise typer.Exit(1)

    rep = ReportingEngine().generate_technical_report(state)
    console.print(rep)


# -- target discovery and fingerprinting ---------------------------------------
@target_app.command("discover")
def target_discover(
    target: str = typer.Argument(..., help="Target host, IP, or domain"),
):
    """Discover assets, DNS records, and open network ports within signed scope."""
    from redloop.assessment.dns_engine import DNSEngine
    from redloop.assessment.network import NetworkEngine
    from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError

    guard = AssessmentScopeGuard(_get_scope_manager(), _get_audit())
    try:
        guard.validate_target(target, "assess")
    except ScopeBlockedError as exc:
        console.print(f"[red]Blocked by scope[/red]: {exc}")
        raise typer.Exit(1) from exc

    console.print(f"[bold blue]Asset Discovery for {target}[/bold blue]")
    net_engine = NetworkEngine(guard, _get_audit())
    dns_engine = DNSEngine(guard, _get_audit())

    dns_res = dns_engine.assess_dns(target)
    console.print(f"DNS Resolution: {dns_res.status.value}")
    if dns_res.data:
        console.print_json(data=dns_res.data)

    net_res = net_engine.scan_tcp_ports(target, ports=[80, 443, 8080, 8765, 22])
    console.print(f"Port Scan: {net_res.status.value} - Open: {net_res.data.get('open_ports', [])}")


@target_app.command("fingerprint")
def target_fingerprint(
    target: str = typer.Argument(..., help="Target host or IP"),
    port: int = typer.Option(80, "--port", "-p", help="Service port to fingerprint"),
):
    """Fingerprint service banners, protocol versions, and web technologies."""
    from redloop.assessment.network import NetworkEngine
    from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError

    guard = AssessmentScopeGuard(_get_scope_manager(), _get_audit())
    engine = NetworkEngine(guard, _get_audit())
    try:
        banner = engine.grab_banner(target, port)
    except ScopeBlockedError as exc:
        console.print(f"[red]Blocked by scope[/red]: {exc}")
        raise typer.Exit(1) from exc

    if banner:
        console.print(f"Port {port} Banner: {banner}")
    else:
        console.print(f"Port {port}: No banner returned or port closed")


# -- web scan ------------------------------------------------------------------
@web_app.command("scan")
def web_scan(
    target_url: str = typer.Argument(..., help="Target HTTP/HTTPS URL"),
    max_pages: int = typer.Option(10, "--max-pages", "-m", help="Maximum pages to crawl"),
):
    """Perform bounded web crawling, security headers, and input analysis."""
    from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError
    from redloop.assessment.web_engine import WebEngine

    guard = AssessmentScopeGuard(_get_scope_manager(), _get_audit())
    engine = WebEngine(guard, _get_audit(), max_pages=max_pages)
    try:
        res = engine.crawl_and_assess(target_url)
    except ScopeBlockedError as exc:
        console.print(f"[red]Blocked by scope[/red]: {exc}")
        raise typer.Exit(1) from exc

    console.print(f"Status: {res.status.value} - {res.reason}")
    console.print(f"Pages crawled: {len(res.data.get('visited_urls', []))}")
    console.print(f"Findings: {len(res.findings)}")
    for f in res.findings:
        console.print(f"[{f.severity.value}] {f.title}")


# -- tls scan ------------------------------------------------------------------
@tls_app.command("scan")
def tls_scan(
    target: str = typer.Argument(..., help="Target host or IP"),
    port: int = typer.Option(443, "--port", "-p", help="TLS port"),
):
    """Deep TLS assessment: certificates, protocol versions, ciphers, and trust."""
    from redloop.assessment.scope_guard import AssessmentScopeGuard, ScopeBlockedError
    from redloop.assessment.tls_engine import TLSEngine

    guard = AssessmentScopeGuard(_get_scope_manager(), _get_audit())
    engine = TLSEngine(guard, _get_audit())
    try:
        res = engine.assess_tls(target, port=port)
    except ScopeBlockedError as exc:
        console.print(f"[red]Blocked by scope[/red]: {exc}")
        raise typer.Exit(1) from exc

    console.print(f"Status: {res.status.value} - {res.reason}")
    console.print(f"Findings: {len(res.findings)}")
    for f in res.findings:
        console.print(f"[{f.severity.value}] {f.title}")


# -- container scan ------------------------------------------------------------
@container_app.command("scan")
def container_scan(
    path: Path = typer.Argument(..., help="Path to Dockerfile or container configuration"),
):
    """Static security audit of Dockerfile and container configuration."""
    from redloop.assessment.config_engine import ConfigEngine
    from redloop.assessment.scope_guard import AssessmentScopeGuard

    guard = AssessmentScopeGuard(_get_scope_manager(), _get_audit())
    engine = ConfigEngine(guard, _get_audit())
    res = engine.audit_config_file(path, target_label="127.0.0.1")
    console.print(f"Status: {res.status.value} - {res.reason}")
    console.print(f"Findings: {len(res.findings)}")
    for f in res.findings:
        console.print(f"[{f.severity.value}] {f.title}")


# -- file triage scan ----------------------------------------------------------
@file_app.command("scan")
def file_scan(
    path: Path = typer.Argument(..., help="Path to binary or artifact for static triage"),
):
    """Static file triage: entropy, PE/ELF headers, IOCs, and signatures without execution."""
    from redloop.assessment.file_engine import FileTriageEngine
    from redloop.assessment.scope_guard import AssessmentScopeGuard

    guard = AssessmentScopeGuard(_get_scope_manager(), _get_audit())
    engine = FileTriageEngine(guard, _get_audit())
    res = engine.triage_file(path, target_label="127.0.0.1")
    console.print(f"Status: {res.status.value} - {res.reason}")
    console.print(f"Findings: {len(res.findings)}")
    for f in res.findings:
        console.print(f"[{f.severity.value}] {f.title}")
    console.print_json(data=res.data)


# -- main ---------------------------------------------------------------------
@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """RedLoop — locally run, scope-limited security testing toolkit."""
    if verbose:
        import logging

        logging.basicConfig(level=logging.DEBUG)


if __name__ == "__main__":
    app()