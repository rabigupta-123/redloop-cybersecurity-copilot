import asyncio

import httpx
import pytest

from redloop.llm import LLMError, LLMSettings, Provider


class FakeLLM:
    def __init__(self, **settings):
        self.calls = []
        values = {
            "llm_provider": "ollama",
            "llm_model": "qwen3:8b",
            "openrouter_api_key": None,
            "nvidia_api_key": None,
            "gemini_api_key": None,
        }
        values.update(settings)
        self.settings = LLMSettings(_env_file=None, **values)

    @property
    def default_provider(self):
        return Provider(self.settings.llm_provider)

    def is_provider_configured(self, provider):
        if provider == Provider.OLLAMA:
            return True
        setting_name = {
            Provider.OPENROUTER: "openrouter_api_key",
            Provider.NVIDIA: "nvidia_api_key",
            Provider.GEMINI: "gemini_api_key",
        }.get(provider)
        return bool(setting_name and getattr(self.settings, setting_name))

    def complete(self, system_prompt, user_prompt, **kwargs):
        self.calls.append((system_prompt, user_prompt, kwargs))
        return {
            "text": "<answer>",
            "provider": kwargs.get("provider", Provider.OLLAMA).value,
            "elapsed_seconds": 0.12,
        }


def make_client(app):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1",
    )


def test_chat_page_has_modes_and_persistent_secure_session_cookie(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    import redloop.chat as chat
    from redloop.chat import CHAT_SCRIPT, CHAT_SCRIPT_CSP_HASH
    from redloop.dashboard import create_app

    monkeypatch.setattr(chat, "get_llm", FakeLLM)

    async def run():
        async with make_client(create_app(str(tmp_path / "audit.sqlite"))) as client:
            response = await client.get("/chat")
            return response

    response = asyncio.run(run())

    assert response.status_code == 200
    assert "General assistant" in response.text
    assert "Offline CTF" in response.text
    assert "Report explainer" in response.text
    assert "No tool execution" in response.text
    assert "target access" in response.text
    assert "--bg: #F8FAFC" in response.text
    assert "--accent: #0284C7" in response.text
    assert "What would you like to work through?" in response.text
    assert "Auto · Best fit" in response.text
    assert "Effort · Low" in response.text
    assert "Add files" in response.text
    assert "Add folder" in response.text
    assert "data-suggestion" not in response.text
    assert 'id="suggestions"' not in response.text
    assert "Ollama · Configured: qwen3:8b" in response.text
    assert 'placeholder="Ask a question or paste text to discuss…"' in response.text
    assert "data-regenerate" in CHAT_SCRIPT
    assert "keydown" in CHAT_SCRIPT
    assert f"script-src 'sha256-{CHAT_SCRIPT_CSP_HASH}'" in response.headers[
        "content-security-policy"
    ]
    cookie = response.headers["set-cookie"].casefold()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "max-age=2592000" in cookie


def test_chat_uses_configured_llm_and_keeps_escaped_turns_in_session(
    tmp_path, monkeypatch
):
    pytest.importorskip("fastapi")
    import redloop.chat as chat
    from redloop.dashboard import create_app

    llm = FakeLLM()
    monkeypatch.setattr(chat, "get_llm", lambda: llm)

    async def run():
        async with make_client(create_app(str(tmp_path / "audit.sqlite"))) as client:
            await client.get("/chat")
            first = await client.post(
                "/chat",
                data={"message": "first <question>", "mode": "ctf"},
                headers={"Origin": "http://127.0.0.1"},
            )
            second = await client.post(
                "/chat",
                data={"message": "second question", "mode": "report"},
                headers={"Origin": "http://127.0.0.1"},
            )
            return first, second

    first, second = asyncio.run(run())

    assert first.status_code == 200
    assert "&lt;answer&gt;" in first.text
    assert "&lt;question&gt;" in first.text
    assert len(llm.calls) == 2
    assert "offline CTF" in llm.calls[0][0]
    assert "security reports" in llm.calls[1][0]
    assert "Current user message:\nsecond question" in llm.calls[1][1]
    assert "user: first &lt;question&gt;" not in llm.calls[1][1]
    assert "user: first <question>" in llm.calls[1][1]
    assert "ollama · qwen3:8b · 0.12s" in second.text
    assert "first &lt;question&gt;" in second.text


def test_chat_rejects_cross_origin_posts_and_invalid_modes(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    import redloop.chat as chat
    from redloop.dashboard import create_app

    llm = FakeLLM()
    monkeypatch.setattr(chat, "get_llm", lambda: llm)

    async def run():
        async with make_client(create_app(str(tmp_path / "audit.sqlite"))) as client:
            await client.get("/chat")
            cross_origin = await client.post(
                "/chat",
                data={"message": "hello", "mode": "general"},
                headers={"Origin": "https://attacker.example"},
            )
            invalid_mode = await client.post(
                "/chat",
                data={"message": "hello", "mode": "unrestricted"},
                headers={"Origin": "http://127.0.0.1"},
            )
            return cross_origin, invalid_mode

    cross_origin, invalid_mode = asyncio.run(run())

    assert cross_origin.status_code == 403
    assert invalid_mode.status_code == 400
    assert "supported chat mode" in invalid_mode.text
    assert not llm.calls


def test_chat_selects_configured_nvidia_model_and_rejects_unknown_model(
    tmp_path, monkeypatch
):
    pytest.importorskip("fastapi")
    import redloop.chat as chat
    from redloop.dashboard import create_app

    llm = FakeLLM(nvidia_api_key="test-nvidia-key")
    monkeypatch.setattr(chat, "get_llm", lambda: llm)

    async def run():
        async with make_client(create_app(str(tmp_path / "audit.sqlite"))) as client:
            page = await client.get("/chat")
            successful = await client.post(
                "/chat",
                data={
                    "message": "hello",
                    "mode": "general",
                    "model": "nvidia_nim|deepseek-ai/deepseek-v4-flash",
                },
                headers={"Origin": "http://127.0.0.1"},
            )
            rejected = await client.post(
                "/chat",
                data={
                    "message": "hello",
                    "mode": "general",
                    "model": "nvidia_nim|made-up-model",
                },
                headers={"Origin": "http://127.0.0.1"},
            )
            return page, successful, rejected

    page, successful, rejected = asyncio.run(run())

    assert page.status_code == 200
    assert "NVIDIA NIM · DeepSeek V4 Flash" in page.text
    assert "OpenRouter ·" not in page.text
    assert successful.status_code == 200
    assert llm.calls[0][2]["provider"] == Provider.NVIDIA
    assert llm.calls[0][2]["model_override"] == "deepseek-ai/deepseek-v4-flash"
    assert "deepseek-ai/deepseek-v4-flash" in successful.text
    assert rejected.status_code == 400
    assert "configured provider model" in rejected.text
    assert len(llm.calls) == 1


def test_chat_selects_configured_openrouter_model(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    import redloop.chat as chat
    from redloop.dashboard import create_app

    llm = FakeLLM(openrouter_api_key="test-openrouter-key")
    monkeypatch.setattr(chat, "get_llm", lambda: llm)

    async def run():
        async with make_client(create_app(str(tmp_path / "audit.sqlite"))) as client:
            page = await client.get("/chat")
            response = await client.post(
                "/chat",
                data={
                    "message": "hello",
                    "mode": "general",
                    "model": "openrouter|deepseek/deepseek-r1",
                },
                headers={"Origin": "http://127.0.0.1"},
            )
            return page, response

    page, response = asyncio.run(run())

    assert "OpenRouter · DeepSeek R1" in page.text
    assert response.status_code == 200
    assert llm.calls[0][2]["provider"] == Provider.OPENROUTER
    assert llm.calls[0][2]["model_override"] == "deepseek/deepseek-r1"


def test_chat_selects_configured_gemini_model(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    import redloop.chat as chat
    from redloop.dashboard import create_app

    llm = FakeLLM(gemini_api_key="test-gemini-key")
    monkeypatch.setattr(chat, "get_llm", lambda: llm)

    async def run():
        async with make_client(create_app(str(tmp_path / "audit.sqlite"))) as client:
            page = await client.get("/chat")
            response = await client.post(
                "/chat",
                data={
                    "message": "hello",
                    "mode": "general",
                    "model": "gemini|gemini-2.5-flash",
                },
                headers={"Origin": "http://127.0.0.1"},
            )
            return page, response

    page, response = asyncio.run(run())

    assert "Gemini · Gemini 2.5 Flash" in page.text
    assert "Gemini · Gemini 2.5 Pro" in page.text
    assert response.status_code == 200
    assert llm.calls[0][2]["provider"] == Provider.GEMINI
    assert llm.calls[0][2]["model_override"] == "gemini-2.5-flash"


def test_chat_accepts_text_and_binary_attachments_and_applies_effort(
    tmp_path, monkeypatch
):
    pytest.importorskip("fastapi")
    import redloop.chat as chat
    from redloop.dashboard import create_app

    llm = FakeLLM()
    monkeypatch.setattr(chat, "get_llm", lambda: llm)

    async def run():
        async with make_client(create_app(str(tmp_path / "audit.sqlite"))) as client:
            await client.get("/chat")
            response = await client.post(
                "/chat",
                data={
                    "message": "Please review these files",
                    "mode": "general",
                    "model": "auto",
                    "effort": "high",
                },
                files=[
                    ("files", ("notes.txt", b"safe sample text", "text/plain")),
                    ("files", ("opaque.bin", b"\x00\x01\x02", "application/octet-stream")),
                ],
                headers={"Origin": "http://127.0.0.1"},
            )
            return response

    response = asyncio.run(run())

    assert response.status_code == 200
    assert "notes.txt" in response.text
    assert "opaque.bin" in response.text
    assert "Please review these files" in llm.calls[0][1]
    assert "safe sample text" in llm.calls[0][1]
    assert "not text-extracted or executed" in llm.calls[0][1]
    assert llm.calls[0][2]["reasoning_effort"] == "high"
    assert "high effort" in response.text


def test_chat_accepts_attachment_without_text_prompt(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    import redloop.chat as chat
    from redloop.dashboard import create_app

    llm = FakeLLM()
    monkeypatch.setattr(chat, "get_llm", lambda: llm)

    async def run():
        async with make_client(create_app(str(tmp_path / "audit.sqlite"))) as client:
            await client.get("/chat")
            return await client.post(
                "/chat",
                data={"message": "", "mode": "general", "model": "auto"},
                files={"files": ("notes.txt", b"attached only", "text/plain")},
                headers={"Origin": "http://127.0.0.1"},
            )

    response = asyncio.run(run())

    assert response.status_code == 200
    assert "attached only" in llm.calls[0][1]


def test_auto_model_falls_back_to_another_configured_provider(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    import redloop.chat as chat
    from redloop.dashboard import create_app

    class FallbackLLM(FakeLLM):
        def complete(self, system_prompt, user_prompt, **kwargs):
            self.calls.append((system_prompt, user_prompt, kwargs))
            if kwargs["provider"] == Provider.GEMINI:
                raise LLMError("gemini request failed (AuthenticationError)")
            return {
                "text": "Fallback answer",
                "provider": kwargs["provider"].value,
                "elapsed_seconds": 0.12,
            }

    llm = FallbackLLM(gemini_api_key="configured")
    monkeypatch.setattr(chat, "get_llm", lambda: llm)

    async def run():
        async with make_client(create_app(str(tmp_path / "audit.sqlite"))) as client:
            await client.get("/chat")
            return await client.post(
                "/chat",
                data={"message": "A simple question", "mode": "general", "model": "auto"},
                headers={"Origin": "http://127.0.0.1"},
            )

    response = asyncio.run(run())

    assert response.status_code == 200
    assert "Fallback answer" in response.text
    assert [call[2]["provider"] for call in llm.calls] == [
        Provider.GEMINI,
        Provider.OLLAMA,
    ]


def test_chat_limits_request_size_and_displays_provider_errors(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    import redloop.chat as chat
    from redloop.dashboard import create_app

    class FailingLLM:
        settings = LLMSettings(_env_file=None, llm_provider="ollama")
        default_provider = Provider.OLLAMA

        def is_provider_configured(self, provider):
            return provider == Provider.OLLAMA

        def complete(self, *_args, **_kwargs):
            raise LLMError("ollama request failed (ConnectionError)")

    monkeypatch.setattr(chat, "get_llm", FailingLLM)

    async def run():
        async with make_client(create_app(str(tmp_path / "audit.sqlite"))) as client:
            await client.get("/chat")
            too_large = await client.post(
                "/chat",
                content="message=" + ("a" * 40_001),
                headers={
                    "Origin": "http://127.0.0.1",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            failed = await client.post(
                "/chat",
                data={"message": "hello", "mode": "general"},
                headers={"Origin": "http://127.0.0.1"},
            )
            return too_large, failed

    too_large, failed = asyncio.run(run())

    assert too_large.status_code == 413
    assert failed.status_code == 502
    assert "ollama request failed" in failed.text


def test_chat_extracts_all_document_types(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    import io
    import zipfile
    import redloop.chat as chat
    from redloop.dashboard import create_app

    llm = FakeLLM()
    monkeypatch.setattr(chat, "get_llm", lambda: llm)

    # 1. ODT
    odt_bio = io.BytesIO()
    with zipfile.ZipFile(odt_bio, "w") as z:
        z.writestr("content.xml", "<text:p>ODT document sample text</text:p>")

    # 2. RTF
    rtf_data = b"{\\rtf1\\ansi Hello from RTF format\\par Second line}"

    # 3. EPUB
    epub_bio = io.BytesIO()
    with zipfile.ZipFile(epub_bio, "w") as z:
        z.writestr("chapter.xhtml", "<html><body><p>EPUB chapter content</p></body></html>")

    # 4. XLSX
    xlsx_bio = io.BytesIO()
    with zipfile.ZipFile(xlsx_bio, "w") as z:
        z.writestr("xl/sharedStrings.xml", """<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><si><t>Revenue</t></si></sst>""")
        z.writestr("xl/worksheets/sheet1.xml", """<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row><c r="A1" t="s"><v>0</v></c><c r="B1"><v>5000</v></c></row></sheetData></worksheet>""")

    # 5. HTML
    html_data = b"<html><body><h1>Page Title</h1><p>HTML paragraph text</p></body></html>"

    # 6. JSON
    json_data = b'{"status": "ok", "count": 42}'

    # 7. CSV
    csv_data = b"col1,col2\nval1,val2"

    async def run():
        async with make_client(create_app(str(tmp_path / "audit.sqlite"))) as client:
            await client.get("/chat")
            return await client.post(
                "/chat",
                data={"message": "Examine documents", "mode": "general", "model": "auto"},
                files=[
                    ("files", ("data.csv", csv_data, "text/csv")),
                    ("files", ("doc.html", html_data, "text/html")),
                    ("files", ("doc.odt", odt_bio.getvalue(), "application/vnd.oasis.opendocument.text")),
                    ("files", ("doc.rtf", rtf_data, "application/rtf")),
                    ("files", ("book.epub", epub_bio.getvalue(), "application/epub+zip")),
                    ("files", ("config.json", json_data, "application/json")),
                    ("files", ("table.xlsx", xlsx_bio.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")),
                ],
                headers={"Origin": "http://127.0.0.1"},
            )

    resp = asyncio.run(run())
    assert resp.status_code == 200
    prompt = llm.calls[0][1]
    assert "col1 | col2" in prompt
    assert "HTML paragraph text" in prompt
    assert "ODT document sample text" in prompt
    assert "Hello from RTF format" in prompt
    assert "EPUB chapter content" in prompt
    assert '"status": "ok"' in prompt
    assert "Revenue | 5000" in prompt
    assert "data.csv" in resp.text
    assert "table.xlsx" in resp.text


def test_chat_extracts_all_image_types(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    import io
    from PIL import Image
    import redloop.chat as chat
    from redloop.dashboard import create_app

    llm = FakeLLM()
    monkeypatch.setattr(chat, "get_llm", lambda: llm)

    def make_img(fmt):
        im = Image.new("RGB", (32, 24), color="blue")
        bio = io.BytesIO()
        im.save(bio, format=fmt)
        return bio.getvalue()

    jpeg_data = make_img("JPEG")
    png_data = make_img("PNG")
    gif_data = make_img("GIF")
    webp_data = make_img("WEBP")

    async def run():
        async with make_client(create_app(str(tmp_path / "audit.sqlite"))) as client:
            await client.get("/chat")
            return await client.post(
                "/chat",
                data={"message": "Analyze images", "mode": "general", "model": "auto"},
                files=[
                    ("files", ("photo.jpg", jpeg_data, "image/jpeg")),
                    ("files", ("chart.png", png_data, "image/png")),
                    ("files", ("anim.gif", gif_data, "image/gif")),
                    ("files", ("graphic.webp", webp_data, "image/webp")),
                ],
                headers={"Origin": "http://127.0.0.1"},
            )

    resp = asyncio.run(run())
    assert resp.status_code == 200
    prompt = llm.calls[0][1]
    assert "[Image File: photo.jpg (JPEG, 32x24 px" in prompt
    assert "[Image File: chart.png (PNG, 32x24 px" in prompt
    assert "[Image File: anim.gif (GIF, 32x24 px" in prompt
    assert "[Image File: graphic.webp (WEBP, 32x24 px" in prompt
    assert "photo.jpg" in resp.text
    assert "chart.png" in resp.text


def test_get_api_models_endpoint(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    import redloop.chat as chat
    from redloop.dashboard import create_app

    llm = FakeLLM()
    monkeypatch.setattr(chat, "get_llm", lambda: llm)

    async def run():
        async with make_client(create_app(str(tmp_path / "audit.sqlite"))) as client:
            return await client.get("/api/models")

    resp = asyncio.run(run())
    assert resp.status_code == 200
    data = resp.json()
    assert "models" in data
    assert len(data["models"]) >= 1
    model_ids = [m["id"] for m in data["models"]]
    assert "auto" in model_ids
    assert any("ollama" in mid for mid in model_ids)
