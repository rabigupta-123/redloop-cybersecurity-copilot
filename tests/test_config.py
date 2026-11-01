from redloop.config import Settings


def test_shodan_api_key_loads_from_conventional_environment_name(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    monkeypatch.delenv("REDLOOP_SHODAN_API_KEY", raising=False)
    monkeypatch.setenv("SHODAN_API_KEY", "test-shodan-key")

    settings = Settings(_env_file=None)

    assert settings.shodan_api_key == "test-shodan-key"


def test_shodan_api_key_loads_from_redloop_environment_name(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    monkeypatch.delenv("REDLOOP_SHODAN_API_KEY", raising=False)
    monkeypatch.setenv("REDLOOP_SHODAN_API_KEY", "test-redloop-shodan-key")

    settings = Settings(_env_file=None)

    assert settings.shodan_api_key == "test-redloop-shodan-key"
