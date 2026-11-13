import json
import re
import stat

import pytest

from lab.config import ROOT, ConfigError, Settings, parse_env
from lab.setup_env import (
    CANDIDATES,
    PLACEHOLDER,
    SECRET_KEYS,
    build_s3_config,
    generate,
    generate_candidate_keys,
    generate_secrets,
    render_env,
)

TEMPLATE = ROOT / ".env.example"


def test_parse_env_ignores_comments_and_strips_quotes():
    text = "# comment\n\nA=1\nB = \"two\"\nC='three'\nnot a pair\n"
    assert parse_env(text) == {"A": "1", "B": "two", "C": "three"}


def test_generated_secrets_are_random_and_well_formed():
    first, second = generate_secrets(), generate_secrets()
    assert set(first) == set(SECRET_KEYS)
    assert first != second
    assert len(set(first.values())) == len(SECRET_KEYS)  # no key reused for two purposes
    assert re.fullmatch(r"[A-Z0-9]{20}", first["WRITER_ACCESS_KEY"])
    assert re.fullmatch(r"[A-Za-z0-9]{40}", first["WRITER_SECRET_KEY"])


def test_render_env_replaces_only_placeholders():
    rendered = render_env(TEMPLATE.read_text(), {"PG_PASSWORD": "s3cret"})
    values = parse_env(rendered)
    assert values["PG_PASSWORD"] == "s3cret"
    assert values["PG_DB"] == "shopdb"
    assert values["WRITER_ACCESS_KEY"] == PLACEHOLDER  # untouched: not in overrides
    assert "# Safety switch" in rendered  # comments preserved


def test_s3_config_scopes_writer_and_gives_attacker_admin():
    values = parse_env(render_env(TEMPLATE.read_text(), generate_secrets()))
    identities = {i["name"]: i for i in build_s3_config(values)["identities"]}
    writer, attacker = identities["backup-writer"], identities["attacker"]
    # Locked uploads need Admin on the bucket (docs/DECISIONS.md), but never global Admin.
    assert set(writer["actions"]) == {
        "Admin:lab-backups",
        "Read:lab-backups",
        "Write:lab-backups",
        "List:lab-backups",
        "Tagging:lab-backups",
    }
    assert "Admin" not in writer["actions"]
    assert "Admin" in attacker["actions"]
    assert writer["credentials"] != attacker["credentials"]


def test_experiments_add_candidates_and_a_normal_run_removes_them(tmp_path):
    env_file, lab_dir = tmp_path / ".env", tmp_path / ".lab"
    generate(env_file, lab_dir, TEMPLATE)
    generate(env_file, lab_dir, TEMPLATE, experiments=True)
    names = [i["name"] for i in json.loads((lab_dir / "s3.json").read_text())["identities"]]
    assert {"backup-writer", "attacker", *CANDIDATES} == set(names)
    keys = json.loads((lab_dir / "experiments.json").read_text())
    assert set(keys) == set(CANDIDATES)
    assert stat.S_IMODE((lab_dir / "experiments.json").stat().st_mode) == 0o600
    generate(env_file, lab_dir, TEMPLATE)  # plain run cleans up
    names = [i["name"] for i in json.loads((lab_dir / "s3.json").read_text())["identities"]]
    assert names == ["backup-writer", "attacker"]
    assert not (lab_dir / "experiments.json").exists()


def test_candidate_actions_are_scoped_to_the_bucket():
    values = parse_env(render_env(TEMPLATE.read_text(), generate_secrets()))
    config = build_s3_config(values, generate_candidate_keys())
    scoped = next(i for i in config["identities"] if i["name"] == "exp-a-scoped")
    assert scoped["actions"] == [f"{a}:lab-backups" for a in ("Read", "Write", "List", "Tagging")]


def test_generate_writes_private_env_and_s3_config(tmp_path):
    env_file, lab_dir = tmp_path / ".env", tmp_path / ".lab"
    notes = generate(env_file, lab_dir, TEMPLATE)
    values = parse_env(env_file.read_text())
    assert all(values[k] != PLACEHOLDER for k in SECRET_KEYS)
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    s3 = json.loads((lab_dir / "s3.json").read_text())
    assert s3["identities"][0]["credentials"][0]["accessKey"] == values["WRITER_ACCESS_KEY"]
    assert (lab_dir / "logs").is_dir()
    assert not any(values["PG_PASSWORD"] in n for n in notes)  # secrets never printed


def test_generate_keeps_existing_env_unless_forced(tmp_path):
    env_file, lab_dir = tmp_path / ".env", tmp_path / ".lab"
    generate(env_file, lab_dir, TEMPLATE)
    original = env_file.read_text()
    generate(env_file, lab_dir, TEMPLATE)
    assert env_file.read_text() == original
    generate(env_file, lab_dir, TEMPLATE, force=True)
    assert env_file.read_text() != original


def test_generate_rejects_env_with_placeholders(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(TEMPLATE.read_text())
    with pytest.raises(SystemExit):
        generate(env_file, tmp_path / ".lab", TEMPLATE)


def test_settings_load_and_hide_secrets_in_repr(tmp_path):
    env_file = tmp_path / ".env"
    generate(env_file, tmp_path / ".lab", TEMPLATE)
    settings = Settings.load(env_file)
    assert settings.lab_mode is True
    assert settings.pg_port == 5432
    assert settings.pg_password not in repr(settings)
    assert settings.attacker_secret_key not in repr(settings)


def test_settings_reports_missing_keys():
    with pytest.raises(ConfigError, match="PG_HOST"):
        Settings.from_values({})
