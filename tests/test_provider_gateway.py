"""Unit tests for Multi-Provider AI Gateway, Key Encryption-at-Rest, and SSRF Defense."""

import pytest
from redloop.provider_gateway import (
    ProviderGateway,
    ProviderKeyStore,
    SSRFValidationError,
    SSRFValidator,
    get_provider_gateway,
)


def test_keystore_encryption_and_decryption(tmp_path):
    store = ProviderKeyStore(storage_dir=str(tmp_path), master_secret="test_vault_secret_999")
    store.set_key("groq", "gsk_secret_token_1234567890", user_id="user_alice")

    # Raw file should not contain plaintext key
    enc_file = tmp_path / "provider_keys.enc"
    assert enc_file.exists()
    raw_content = enc_file.read_bytes()
    assert b"gsk_secret_token_1234567890" not in raw_content

    # Decrypted retrieval matches
    retrieved = store.get_key("groq", user_id="user_alice")
    assert retrieved == "gsk_secret_token_1234567890"

    # User isolation: user_bob should not see user_alice's key
    assert store.get_key("groq", user_id="user_bob") is None


def test_key_masking():
    masked = ProviderKeyStore.mask_key("gsk_secret_long_token_xyz99")
    assert masked.startswith("gsk_")
    assert masked.endswith("yz99")
    assert "..." in masked
    assert "secret_long_token" not in masked


def test_ssrf_validator_blocks_metadata():
    with pytest.raises(SSRFValidationError):
        SSRFValidator.validate_endpoint("http://169.254.169.254/latest/meta-data")

    with pytest.raises(SSRFValidationError):
        SSRFValidator.validate_endpoint("http://metadata.google.internal/computeMetadata/v1")


def test_ssrf_validator_permits_legitimate_endpoints():
    url = SSRFValidator.validate_endpoint("https://api.groq.com/openai/v1")
    assert url == "https://api.groq.com/openai/v1"

    local = SSRFValidator.validate_endpoint("http://localhost:11434", allow_localhost=True)
    assert local == "http://localhost:11434"


def test_gateway_provider_listing():
    gw = get_provider_gateway()
    providers = gw.get_all_providers()
    assert len(providers) >= 7
    provider_ids = [p["provider_id"] for p in providers]
    assert "groq" in provider_ids
    assert "openrouter" in provider_ids
    assert "ollama" in provider_ids
    assert "gemini" in provider_ids
    assert "anthropic" in provider_ids
