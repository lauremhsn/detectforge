from detectforge.config import Settings


def test_settings_read_env_without_exposing_secrets(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-real")
    monkeypatch.setenv("DETECTFORGE_MAX_ITERATIONS", "3")
    settings = Settings(_env_file=None)
    assert settings.max_iterations == 3
    assert settings.anthropic_api_key.get_secret_value() == "sk-test-not-real"
    assert "sk-test-not-real" not in repr(settings)
