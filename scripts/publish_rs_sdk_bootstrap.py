#!/usr/bin/env python3
"""Owner-authorized first publish of qualified artifacts from an immutable tag."""
import argparse
import base64
import configparser
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

if not __debug__:
    raise SystemExit("Release checks require Python without optimization")

REPO = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("registry", choices=["npm", "pypi"])
parser.add_argument("--qualified", required=True, type=Path)
parser.add_argument("--credentials", required=True, type=Path)
parser.add_argument("--receipt", required=True, type=Path)
args = parser.parse_args()
qualified = args.qualified.resolve()
receipt = {"registry": args.registry, "result": "RUNNING",
           "publication": "NOT_RUN", "stage": "qualification"}
secrets = []


def run(command, *, env=None, cwd=REPO):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError("Command failed: " + command[0])
    return result.stdout.strip()


def read(url, token=None):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def publish(command, *, env, cwd):
    # An upload can have succeeded even when its CLI reports failure. Never
    # retry an ambiguous upload without reading and comparing registry bytes.
    receipt["publication"] = "ATTEMPTED"
    receipt["stage"] = "upload"
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
    output = result.stdout + result.stderr
    for secret in secrets:
        output = output.replace(secret, "[REDACTED]")
    args.receipt.with_suffix(".upload.log").write_text(output)
    if result.returncode:
        receipt["publication"] = "UNKNOWN_PENDING_READBACK"
        raise RuntimeError("Upload command failed; inspect registry before retry")
    receipt["publication"] = "UPLOADED_PENDING_READBACK"


try:
    proof = json.loads((qualified / "qualification.json").read_text())
    assert proof["result"] == "PASS" and not proof["source_dirty"]
    source = proof["source_commit"]
    version = proof["version"]
    name = proof["package_names"][args.registry]
    tag = "rs-sdk-v" + version
    receipt.update(package=name, version=version, source_commit=source, tag=tag)
    receipt["stage"] = "source-and-tag"
    assert run(["git", "rev-parse", "HEAD"]) == source
    assert not run(["git", "status", "--porcelain"]), "Source must stay clean"
    run(["git", "fetch", "origin", "main"])
    run(["git", "merge-base", "--is-ancestor", source, "origin/main"])
    assert run(["git", "rev-parse", f"refs/tags/{tag}^{{commit}}"]) == source
    refs = run(["git", "ls-remote", "origin", f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"])
    remote = {ref: sha for sha, ref in (line.split() for line in refs.splitlines())}
    assert remote.get(f"refs/tags/{tag}^{{}}", remote.get(f"refs/tags/{tag}")) == source
    environment = dict(os.environ, GITHUB_REPOSITORY="amliuyong/a-auth",
                       GITHUB_TOKEN=run(["gh", "auth", "token"]))
    receipt["stage"] = "publisher-protections"
    run(["python3", "scripts/check_rs_sdk_publisher_setup.py"], env=environment)
    environment.pop("GITHUB_TOKEN")
    environment.pop("PYTHONPATH", None)
    receipt["stage"] = "artifact-digests"
    expected = {item["file"]: item["sha256"] for item in proof["artifacts"]}
    assert len(expected) == 3
    for filename, digest in expected.items():
        assert Path(filename).name == filename
        assert hashlib.sha256((qualified / filename).read_bytes()).hexdigest() == digest
    if args.registry == "npm":
        receipt["stage"] = "npm-publisher-identity"
        token = args.credentials.read_text().strip()
        assert token
        secrets.append(token)
        identity = read("https://registry.npmjs.org/-/whoami", token)
        receipt["publisher"] = identity["username"]
        package_url = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="")
        package = read(package_url)
        if package:
            collaborators = read("https://registry.npmjs.org/-/package/" +
                                 urllib.parse.quote(name, safe="") + "/collaborators", token)
            assert collaborators.get(identity["username"]) in {"write", "read-write"}, (
                "Publisher lacks write permission for the existing package")
        elif name.startswith("@"):
            assert name.split("/", 1)[0] == "@" + identity["username"], (
                "First publish requires the publisher's personal scope")
        if package and version in package.get("versions", {}):
            receipt["publication"] = "EXISTING_PENDING_READBACK"
        else:
            artifact = next(qualified / filename for filename in expected if filename.endswith(".tgz"))
            with tempfile.TemporaryDirectory(prefix="rs-sdk-npm-publish-") as temporary:
                config = Path(temporary) / ".npmrc"
                config.write_text("registry=https://registry.npmjs.org/\n"
                                  "//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}\n")
                config.chmod(0o600)
                environment.update(NODE_AUTH_TOKEN=token, NPM_CONFIG_USERCONFIG=str(config))
                publish(["npm", "publish", str(artifact), "--access", "public", "--ignore-scripts",
                         "--registry", "https://registry.npmjs.org/"],
                        env=environment, cwd=temporary)
    else:
        receipt["stage"] = "pypi-configuration-and-existing-artifacts"
        config = configparser.RawConfigParser()
        config.read(args.credentials)
        assert config.get("pypi", "username") == "__token__"
        endpoint = config.get("pypi", "repository", fallback="https://upload.pypi.org/legacy/")
        assert endpoint == "https://upload.pypi.org/legacy/", "Only production PyPI is accepted"
        token = config.get("pypi", "password").strip()
        assert token.startswith("pypi-")
        secrets.extend([token, base64.b64encode(("__token__:" + token).encode()).decode()])
        environment.update(TWINE_USERNAME="__token__", TWINE_PASSWORD=token)
        metadata = read(f"https://pypi.org/pypi/{urllib.parse.quote(name, safe='')}/{version}/json")
        existing = {}
        if metadata:
            for item in metadata["urls"]:
                filename = item["filename"]
                assert filename in expected, "Unexpected distribution already exists"
                url = urllib.parse.urlparse(item["url"])
                assert url.scheme == "https" and url.hostname == "files.pythonhosted.org"
                with urllib.request.urlopen(item["url"], timeout=60) as response:
                    digest = hashlib.sha256(response.read()).hexdigest()
                assert digest == expected[filename], "Existing distribution differs; never overwrite"
                existing[filename] = digest
        artifacts = [str(qualified / filename) for filename in expected
                     if filename.endswith((".whl", ".tar.gz")) and filename not in existing]
        if artifacts:
            publish([sys.executable, "-m", "twine", "upload", "--non-interactive", "--disable-progress-bar",
                     "--repository-url", endpoint, *artifacts], env=environment, cwd=qualified)
        else:
            receipt["publication"] = "EXISTING_PENDING_READBACK"
    registry_receipt = args.receipt.with_suffix(".registry.json")
    receipt["stage"] = "registry-readback"
    run(["python3", "scripts/verify_rs_sdk_registry.py", args.registry, "--qualified", str(qualified),
         "--receipt", str(registry_receipt)])
    receipt.update(result="PASS", publication="VERIFIED", stage="complete",
                   registry_receipt=str(registry_receipt))
except Exception as error:
    # Credential-bearing responses and exception messages are never serialized.
    receipt.update(result="FAIL", failure_type=type(error).__name__)
finally:
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))
    raise SystemExit(0 if receipt["result"] == "PASS" else 1)
