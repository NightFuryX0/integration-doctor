from pathlib import Path

from analyzer.ai.context import build_repository_context


def test_context_excludes_environment_files(tmp_path):
    # Create a normal source file that should be included.
    source_file = tmp_path / "app.py"
    source_file.write_text(
        "def hello():\n    return 'hello'\n",
        encoding="utf-8",
    )

    # Create an environment file that must never reach the AI.
    env_file = tmp_path / ".env"
    env_file.write_text(
        "GEMINI_API_KEY=super-secret-key\n",
        encoding="utf-8",
    )

    context = build_repository_context(
        str(source_file),
        str(tmp_path),
    )

    context_files = {
        Path(item["file"]).name
        for item in context
    }

    assert "app.py" in context_files
    assert ".env" not in context_files


def test_context_excludes_environment_file_variants(tmp_path):
    # Create the source file that produces the context request.
    source_file = tmp_path / "app.py"
    source_file.write_text(
        "def hello():\n    return 'hello'\n",
        encoding="utf-8",
    )

    # Create several environment-file variants.
    for filename in [
        ".env.local",
        ".env.production",
        ".env.staging",
    ]:
        (tmp_path / filename).write_text(
            "SECRET=value\n",
            encoding="utf-8",
        )

    context = build_repository_context(
        str(source_file),
        str(tmp_path),
    )

    context_files = {
        Path(item["file"]).name
        for item in context
    }

    assert ".env.local" not in context_files
    assert ".env.production" not in context_files
    assert ".env.staging" not in context_files


def test_context_excludes_credential_files(tmp_path):
    # Create the source file that should remain available to the AI.
    source_file = tmp_path / "app.py"
    source_file.write_text(
        "def hello():\n    return 'hello'\n",
        encoding="utf-8",
    )

    # Create common credential files.
    (tmp_path / "credentials.json").write_text(
        '{"api_key": "secret"}',
        encoding="utf-8",
    )

    (tmp_path / "service-account.json").write_text(
        '{"private_key": "secret"}',
        encoding="utf-8",
    )

    context = build_repository_context(
        str(source_file),
        str(tmp_path),
    )

    context_files = {
        Path(item["file"]).name
        for item in context
    }

    assert "credentials.json" not in context_files
    assert "service-account.json" not in context_files


def test_context_excludes_private_key_files(tmp_path):
    # Create a normal Python source file.
    source_file = tmp_path / "app.py"
    source_file.write_text(
        "def hello():\n    return 'hello'\n",
        encoding="utf-8",
    )

    # Create files containing private-key material.
    (tmp_path / "server.pem").write_text(
        "-----BEGIN PRIVATE KEY-----",
        encoding="utf-8",
    )

    (tmp_path / "secret.key").write_text(
        "private-key-material",
        encoding="utf-8",
    )

    (tmp_path / "UPPERCASE.KEY").write_text(
        "private-key-material",
        encoding="utf-8",
    )

    context = build_repository_context(
        str(source_file),
        str(tmp_path),
    )

    context_files = {
        Path(item["file"]).name
        for item in context
    }

    assert "server.pem" not in context_files
    assert "secret.key" not in context_files
    assert "UPPERCASE.KEY" not in context_files


def test_context_excludes_symlink_that_points_outside_repository(tmp_path):
    # Create a directory outside the repository containing sensitive source.
    outside_directory = tmp_path.parent / "outside_repository"
    outside_directory.mkdir(exist_ok=True)

    outside_file = outside_directory / "secret.py"
    outside_file.write_text(
        "SECRET = 'do-not-send-this-to-ai'\n",
        encoding="utf-8",
    )

    # Create the repository directory.
    repository = tmp_path / "repository"
    repository.mkdir()

    # Create the legitimate source file.
    source_file = repository / "app.py"
    source_file.write_text(
        "def hello():\n    return 'hello'\n",
        encoding="utf-8",
    )

    # Create a symlink inside the repository pointing outside it.
    symlink = repository / "linked.py"

    try:
        symlink.symlink_to(outside_file)
    except OSError:
        # Some environments do not allow symlink creation.
        return

    context = build_repository_context(
        str(source_file),
        str(repository),
    )

    context_files = {
        Path(item["file"]).resolve()
        for item in context
    }

    # The legitimate repository file should be included.
    assert source_file.resolve() in context_files

    # The outside file must never enter the AI context.
    assert outside_file.resolve() not in context_files
