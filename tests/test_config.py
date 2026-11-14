from detectforge.config import Settings


def test_settings_read_env_without_exposing_secrets(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-not-real")
    monkeypatch.setenv("DETECTFORGE_MAX_ITERATIONS", "3")
    monkeypatch.setenv("DETECTFORGE_MODEL", "some/model:free")
    settings = Settings(_env_file=None)
    assert settings.max_iterations == 3 and settings.model == "some/model:free"
    assert settings.llm_api_key.get_secret_value() == "sk-test-not-real"
    assert "sk-test-not-real" not in repr(settings)


def test_local_model_is_configuration_only(monkeypatch):
    monkeypatch.setenv("DETECTFORGE_LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("DETECTFORGE_FALLBACK_MODEL", "")
    settings = Settings(_env_file=None)
    assert settings.llm_base_url == "http://localhost:11434/v1"
