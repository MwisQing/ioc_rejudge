import json
import re
import zipfile
from pathlib import Path

import pack
import push


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_MEMBERS = {
    "README.md",
    "CHANGELOG.md",
    "CLAUDE.md",
    "VERSION",
    "requirements.txt",
    "requirements-dev.txt",
    "iocProducer_api_ioc_info.py",
    "docs/ARCHITECTURE.md",
    "docs/DEVELOPMENT.md",
    "docs/HISTORY.md",
    "ioc_rejudge/anonymize_ioc.py",
}

FORBIDDEN_PREFIXES = (
    "ioc_info/",
    "outputs/",
    "release/",
    "docs/agent-prompts/",
    "docs/superpowers/",
)

REQUIRED_INIT_PATHS = {
    "README.md",
    "CHANGELOG.md",
    "CLAUDE.md",
    "VERSION",
    "requirements.txt",
    "requirements-dev.txt",
    "iocProducer_api_ioc_info.py",
    "docs/ARCHITECTURE.md",
    "docs/DEVELOPMENT.md",
    "docs/HISTORY.md",
}

REQUIRED_GITIGNORE_ENTRIES = {
    "token_icp.txt",
    "credentials.local.json",
    "ioc_info/",
    "outputs/",
    "其他接口/",
    "回扫报告/",
    "docs/superpowers/",
    ".venv/",
    "runs/",
    "provider-cache/",
}


def test_release_member_allowlist_is_complete_and_deterministic():
    members = [relative for _, relative in pack._iter_package_files(ROOT)]

    assert members == sorted(set(members))
    assert REQUIRED_MEMBERS <= set(members)
    assert any(member.startswith("ioc_rejudge/") for member in members)
    assert any(member.startswith("rules/") for member in members)
    assert any(member.startswith("tests/") for member in members)
    assert not any(member.startswith(FORBIDDEN_PREFIXES) for member in members)
    assert not any("__pycache__" in Path(member).parts for member in members)
    assert not any(member.endswith((".pyc", ".zip")) for member in members)


def test_release_zip_contains_matching_manifest(tmp_path):
    version = pack._read_version(ROOT)
    assert re.fullmatch(r"\d+\.\d+\.\d+", version)

    zip_path = pack._create_zip(ROOT, version, tmp_path)

    assert zip_path.parent == tmp_path
    assert zip_path.name.startswith(f"ioc_rejudge_v{version}_")
    with zipfile.ZipFile(zip_path) as archive:
        names = archive.namelist()
        assert names.count("RELEASE.json") == 1
        manifest = json.loads(archive.read("RELEASE.json"))

    package_members = sorted(name for name in names if name != "RELEASE.json")
    assert manifest["project"] == "ioc_rejudge"
    assert manifest["version"] == version
    assert manifest["zip_name"] == zip_path.name
    assert manifest["included_paths"] == package_members
    assert REQUIRED_MEMBERS <= set(package_members)


def test_push_initial_commit_allowlist_contains_public_project_files():
    assert REQUIRED_INIT_PATHS <= set(push._INIT_PATHS)
    assert not any(path in push._INIT_PATHS for path in FORBIDDEN_PREFIXES)


def test_gitignore_protects_local_data_credentials_and_runtime_outputs():
    entries = {
        line.strip().lstrip("/")
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert REQUIRED_GITIGNORE_ENTRIES <= entries
