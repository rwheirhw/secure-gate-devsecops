from securegate.paths import (
    load_sample_manifests,
    packaged_policy,
    resolve_policy,
    web_dir,
    workspace_root,
)


def test_workspace_root_uses_securegate_home(monkeypatch, tmp_path):
    monkeypatch.setenv("SECUREGATE_HOME", str(tmp_path))
    assert workspace_root() == tmp_path.resolve()


def test_resolve_policy_uses_workspace_config(monkeypatch, tmp_path):
    config = tmp_path / "config"
    config.mkdir()
    policy = config / "policy.yaml"
    policy.write_text("severity_policy: {}\n", encoding="utf-8")
    monkeypatch.setenv("SECUREGATE_HOME", str(tmp_path))
    assert resolve_policy() == policy.resolve()


def test_resolve_policy_falls_back_to_packaged(monkeypatch, tmp_path):
    monkeypatch.setenv("SECUREGATE_HOME", str(tmp_path))
    monkeypatch.delenv("SECUREGATE_POLICY", raising=False)
    resolved = resolve_policy()
    assert resolved == packaged_policy().resolve()
    assert resolved.is_file()


def test_packaged_web_and_samples_are_present():
    assert (web_dir() / "index.html").is_file()
    samples = load_sample_manifests()
    assert "enterprise_sample" in samples
    assert "hardened_sample" in samples
    assert "insecure_sample" in samples
    assert "kind: Deployment" in samples["hardened_sample"]
