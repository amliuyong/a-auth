#!/usr/bin/env python3
"""Build and qualify the exact distributable artifacts in independent projects."""

import argparse
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile

if not __debug__:
    raise SystemExit("Release checks require Python without optimization")

REPO = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--output", required=True, type=Path)
parser.add_argument("--build-python", default=sys.executable)
parser.add_argument("--require-clean", action="store_true")
args = parser.parse_args()
args.build_python = os.path.abspath(
    shutil.which(args.build_python) or args.build_python
)
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=True)
if any(output.iterdir()):
    raise SystemExit("Output directory must be empty")
env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
receipt = {
    "result": "RUNNING",
    "source_commit": subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
    ).strip(),
    "source_dirty": bool(
        subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO)
    ),
    "registry_publication": "NOT_RUN",
    "artifacts": [],
    "installed_checks": [],
    "package_names": {
        "npm": json.loads((REPO / "sdk/ts/package.json").read_text())["name"],
        "pypi": tomllib.loads((REPO / "sdk/python/pyproject.toml").read_text())[
            "project"
        ]["name"],
    },
}
python_package = re.sub(r"[-_.]+", "_", receipt["package_names"]["pypi"])


def run(command, cwd, log):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
    (output / log).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f"Command failed; see {log}")
    return result.stdout


def inspect_artifact(path, files):
    """A filename allowlist and license-byte check cover accidental packaging."""

    def allowed(name):
        if path.suffix == ".whl":
            return (
                name.startswith("agent_auth_rs/")
                and name.endswith((".py", "/py.typed"))
                or ".dist-info/" in name
                and name.rsplit("/", 1)[-1]
                in {
                    "METADATA",
                    "WHEEL",
                    "top_level.txt",
                    "RECORD",
                    "LICENSE",
                    "THIRD_PARTY_NOTICES.md",
                }
            )
        if path.name.endswith(".tgz"):
            return (
                name
                in {
                    "package/package.json",
                    "package/README.md",
                    "package/LICENSE",
                    "package/THIRD_PARTY_NOTICES.md",
                }
                or name.startswith("package/dist/")
                and name.endswith((".js", ".d.ts"))
            )
        return (
            name.split("/", 1)[-1]
            in {
                "pyproject.toml",
                "MANIFEST.in",
                "README.md",
                "LICENSE",
                "THIRD_PARTY_NOTICES.md",
                "PKG-INFO",
                "setup.cfg",
            }
            or "/agent_auth_rs/" in name
            and name.endswith((".py", "/py.typed"))
            or f"/{python_package}.egg-info/" in name
            and name.rsplit("/", 1)[-1]
            in {
                "PKG-INFO",
                "SOURCES.txt",
                "dependency_links.txt",
                "requires.txt",
                "top_level.txt",
            }
        )

    assert all(allowed(name) for name in files), f"Unexpected file in {path.name}"
    license_files = [name for name in files if name.rsplit("/", 1)[-1] == "LICENSE"]
    assert license_files, f"Artifact has no license text: {path.name}"
    assert all(files[name] == (REPO / "LICENSE").read_bytes() for name in license_files)
    assert any(name.endswith("THIRD_PARTY_NOTICES.md") for name in files)
    receipt["artifacts"].append(
        {
            "file": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": path.stat().st_size,
            "files": sorted(files),
        }
    )


try:
    if args.require_clean:
        assert not receipt["source_dirty"], (
            "Registry qualification requires clean committed source"
        )
    version = json.loads((REPO / "sdk/ts/package.json").read_text())["version"]
    assert (
        tomllib.loads((REPO / "sdk/python/pyproject.toml").read_text())["project"][
            "version"
        ]
        == version
    )
    run(["npm", "ci", "--ignore-scripts"], REPO / "sdk/ts", "npm-ci.log")
    run(["npm", "run", "build"], REPO / "sdk/ts", "npm-build.log")
    # npm publish of a prebuilt tarball must preserve an explicit source identity.
    with tempfile.TemporaryDirectory(prefix="rs-sdk-pack-") as staging:
        stage = Path(staging)
        for name in ["LICENSE", "README.md", "THIRD_PARTY_NOTICES.md"]:
            shutil.copyfile(REPO / "sdk/ts" / name, stage / name)
        shutil.copytree(REPO / "sdk/ts/dist", stage / "dist")
        package = json.loads((REPO / "sdk/ts/package.json").read_text())
        package["gitHead"] = receipt["source_commit"]
        (stage / "package.json").write_text(json.dumps(package, indent=2) + "\n")
        packed = json.loads(
            run(
                [
                    "npm",
                    "pack",
                    "--ignore-scripts",
                    "--json",
                    "--pack-destination",
                    str(output),
                ],
                stage,
                "npm-pack.json",
            )
        )[0]
    npm_artifact = output / packed["filename"]
    run(
        [args.build_python, "-m", "build", "--outdir", str(output)],
        REPO / "sdk/python",
        "python-build.log",
    )
    wheel = next(output.glob("*.whl"))
    sdist = next(output.glob("*.tar.gz"))
    run(
        [args.build_python, "-m", "twine", "check", str(wheel), str(sdist)],
        REPO,
        "twine-check.log",
    )
    for artifact in [npm_artifact, wheel, sdist]:
        if artifact.suffix == ".whl":
            with zipfile.ZipFile(artifact) as archive:
                files = {
                    name: archive.read(name)
                    for name in archive.namelist()
                    if not name.endswith("/")
                }
        else:
            with tarfile.open(artifact) as archive:
                files = {
                    member.name: archive.extractfile(member).read()
                    for member in archive.getmembers()
                    if member.isfile()
                }
        inspect_artifact(artifact, files)
        if artifact == npm_artifact:
            package = json.loads(files["package/package.json"])
            assert package["name"] == receipt["package_names"]["npm"]
            assert package["gitHead"] == receipt["source_commit"]
            assert package["license"] == "Apache-2.0"
            assert package["version"] == version
            assert package["exports"]["."]["import"] == "./dist/index.js"
            assert package["exports"]["."]["types"] == "./dist/index.d.ts"
        else:
            metadata_file = next(
                name
                for name in files
                if name.endswith("/METADATA")
                or name.count("/") == 1
                and name.endswith("/PKG-INFO")
            )
            metadata = BytesParser().parsebytes(files[metadata_file])
            assert metadata["Name"] == receipt["package_names"]["pypi"]
            assert metadata["Version"] == version
            assert metadata["License-Expression"] == "Apache-2.0"
            assert metadata["Requires-Python"] == ">=3.10"
    with tempfile.TemporaryDirectory(prefix="rs-sdk-independent-") as temporary:
        root = Path(temporary)
        node = root / "node"
        node.mkdir()
        (node / "package.json").write_text('{"private":true,"type":"module"}\n')
        shutil.copyfile(REPO / "scripts/sdk_artifact_smoke.mjs", node / "smoke.mjs")
        run(
            [
                "npm",
                "install",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                str(npm_artifact),
            ],
            node,
            "npm-independent-install.log",
        )
        assert not (
            node / "node_modules" / receipt["package_names"]["npm"]
        ).is_symlink()
        receipt["installed_checks"].append(
            {
                "artifact": npm_artifact.name,
                **json.loads(
                    run(["node", "smoke.mjs"], node, "npm-installed-smoke.json")
                ),
                "dependencies": json.loads(
                    run(
                        ["npm", "ls", "--all", "--json"],
                        node,
                        "npm-installed-dependencies.json",
                    )
                ),
            }
        )
        for artifact in [wheel, sdist]:
            project = root / artifact.name
            project.mkdir()
            run(
                [sys.executable, "-m", "venv", str(project / ".venv")],
                project,
                artifact.name + "-venv.log",
            )
            python = str(project / ".venv/bin/python")
            shutil.copyfile(
                REPO / "scripts/sdk_artifact_smoke.py", project / "smoke.py"
            )
            run(
                [python, "-m", "pip", "install", str(artifact)],
                project,
                artifact.name + "-install.log",
            )
            receipt["installed_checks"].append(
                {
                    "artifact": artifact.name,
                    **json.loads(
                        run(
                            [python, "-I", str(project / "smoke.py")],
                            project,
                            artifact.name + "-smoke.json",
                        )
                    ),
                    "dependencies": run(
                        [python, "-m", "pip", "freeze"],
                        project,
                        artifact.name + "-dependencies.txt",
                    ).splitlines(),
                }
            )
    assert (
        subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
        ).strip()
        == receipt["source_commit"]
    )
    if args.require_clean:
        assert not subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=REPO
        ), "Source changed during artifact qualification"
    receipt.update(result="PASS", version=version)
except Exception as error:
    receipt.update(result="FAIL", failure=str(error))
finally:
    (output / "qualification.json").write_text(json.dumps(receipt, indent=2) + "\n")
    (output / "SHA256SUMS").write_text(
        "".join(f"{item['sha256']}  {item['file']}\n" for item in receipt["artifacts"])
    )
    print(
        json.dumps(
            {
                "result": receipt["result"],
                "artifacts": len(receipt["artifacts"]),
                "installed_checks": len(receipt["installed_checks"]),
                "registry_publication": "NOT_RUN",
            }
        )
    )
    raise SystemExit(0 if receipt["result"] == "PASS" else 1)
