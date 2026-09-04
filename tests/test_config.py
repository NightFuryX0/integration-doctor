from pathlib import Path

import pytest

from analyzer.config import DEFAULT_IGNORED_DIRECTORIES, load_config


def test_load_config_returns_defaults_when_file_does_not_exist(tmp_path):
    config = load_config(tmp_path)

    assert config.exclude == set()
    assert config.disabled_rules == set()


def test_load_config_reads_exclude_directories(tmp_path):
    config_file = tmp_path / "integration-doctor.toml"

    config_file.write_text(
        """
[tool.integration-doctor]
exclude = ["tests", "examples"]
""",
        encoding="utf-8",
    )

    config = load_config(tmp_path)

    assert config.exclude == {"tests", "examples"}


def test_load_config_reads_disabled_rules(tmp_path):
    config_file = tmp_path / "integration-doctor.toml"

    config_file.write_text(
        """
[tool.integration-doctor]
disabled_rules = ["WEBHOOK-001", "PAYMENT-003"]
""",
        encoding="utf-8",
    )

    config = load_config(tmp_path)

    assert config.disabled_rules == {
        "WEBHOOK-001",
        "PAYMENT-003",
    }


def test_load_config_reads_all_supported_settings(tmp_path):
    config_file = tmp_path / "integration-doctor.toml"

    config_file.write_text(
        """
[tool.integration-doctor]
exclude = ["tests", "examples"]
disabled_rules = ["WEBHOOK-001"]
""",
        encoding="utf-8",
    )

    config = load_config(tmp_path)

    assert config.exclude == {"tests", "examples"}
    assert config.disabled_rules == {"WEBHOOK-001"}


def test_default_ignored_directories_are_not_part_of_user_config(tmp_path):
    config = load_config(tmp_path)

    assert config.exclude == set()
    assert ".git" in DEFAULT_IGNORED_DIRECTORIES
    assert ".venv" in DEFAULT_IGNORED_DIRECTORIES


def test_load_config_accepts_file_path_as_scan_target(tmp_path):
    config_file = tmp_path / "integration-doctor.toml"

    config_file.write_text(
        """
[tool.integration-doctor]
exclude = ["tests"]
""",
        encoding="utf-8",
    )

    nested_file = tmp_path / "example.py"
    nested_file.write_text("print('hello')", encoding="utf-8")

    config = load_config(nested_file)

    assert config.exclude == {"tests"}


def test_load_config_rejects_invalid_toml(tmp_path):
    config_file = tmp_path / "integration-doctor.toml"

    config_file.write_text(
        """
[tool.integration-doctor
exclude = ["tests"]
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid Integration Doctor configuration"):
        load_config(tmp_path)


def test_load_config_rejects_invalid_exclude_type(tmp_path):
    config_file = tmp_path / "integration-doctor.toml"

    config_file.write_text(
        """
[tool.integration-doctor]
exclude = "tests"
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exclude"):
        load_config(tmp_path)


def test_load_config_rejects_invalid_disabled_rule_type(tmp_path):
    config_file = tmp_path / "integration-doctor.toml"

    config_file.write_text(
        """
[tool.integration-doctor]
disabled_rules = "WEBHOOK-001"
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="disabled_rules"):
        load_config(tmp_path)
