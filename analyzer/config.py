from __future__ import annotations
# Python 3.11+ includes tomllib in the standard library.
# Python 3.10 needs the tomli compatibility package instead.
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib
from dataclasses import dataclass
from pathlib import Path


# These directories are always ignored by Integration Doctor.
# They are scanner defaults, not user configuration.
DEFAULT_IGNORED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".tox",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "build",
    "dist",
    ".eggs",
}

# This is the name of the optional project-level configuration file.
CONFIG_FILE_NAME = "integration-doctor.toml"


@dataclass(frozen=True)
class IntegrationDoctorConfig:
    """Configuration used by Integration Doctor."""

    exclude: set[str]
    disabled_rules: set[str]


def _find_config_file(target: Path) -> Path:
    """Find the configuration file associated with a scan target."""

    if target.is_file():
        return target.parent / CONFIG_FILE_NAME

    return target / CONFIG_FILE_NAME


def _read_config_file(config_file: Path) -> dict:
    """Read and parse an Integration Doctor TOML configuration file."""

    try:
        with config_file.open("rb") as file:
            data = tomllib.load(file)
    except tomllib.TOMLDecodeError as error:
        raise ValueError(
            f"Invalid Integration Doctor configuration: {error}"
        ) from error
    except OSError as error:
        raise ValueError(
            f"Could not read Integration Doctor configuration: {error}"
        ) from error

    return data


def _read_string_set(data: dict, key: str) -> set[str]:
    """Read a configuration value that must be a list of strings."""

    value = data.get(key, [])

    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
        raise ValueError(
            f"Integration Doctor configuration '{key}' "
            "must be a list of strings."
        )

    return set(value)


def load_config(target: str | Path) -> IntegrationDoctorConfig:
    """Load Integration Doctor configuration for a scan target."""

    target_path = Path(target)
    config_file = _find_config_file(target_path)

    if not config_file.exists():
        return IntegrationDoctorConfig(
            exclude=set(),
            disabled_rules=set(),
        )

    data = _read_config_file(config_file)

    section = data.get("tool", {}).get("integration-doctor", {})

    if not isinstance(section, dict):
        raise ValueError(
            "Integration Doctor configuration section "
            "'[tool.integration-doctor]' must be a table."
        )

    return IntegrationDoctorConfig(
        exclude=_read_string_set(section, "exclude"),
        disabled_rules=_read_string_set(section, "disabled_rules"),
    )
