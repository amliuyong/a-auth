"""Read back actual registry bytes and bind them to a qualified source commit."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import urllib.parse
import urllib.request

if not __debug__:
    raise SystemExit("Release checks require Python without optimization")

parser = argparse.ArgumentParser()
parser.add_argument("registry", choices=["npm", "pypi"])
parser.add_argument("--qualified", type=Path, required=True)
parser.add_argument("--receipt", type=Path, required=True)
args = parser.parse_args()
qualified = json.loads((args.qualified / "qualification.json").read_text())
assert qualified["result"] == "PASS" and not qualified["source_dirty"]
version = qualified["version"]
source = qualified["source_commit"]
package_name = qualified["package_names"][args.registry]
if os.environ.get("GITHUB_SHA"):
    assert source == os.environ["GITHUB_SHA"]


def read(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


if args.registry == "npm":
    metadata = json.loads(
        read(
            "https://registry.npmjs.org/"
            + urllib.parse.quote(package_name, safe="")
            + "/"
            + urllib.parse.quote(version)
        )
    )
    assert metadata["name"] == package_name and metadata["version"] == version
    assert metadata["license"] == "Apache-2.0"
    assert metadata.get("gitHead") == source
    urls = {
        next(
            item["file"]
            for item in qualified["artifacts"]
            if item["file"].endswith(".tgz")
        ): metadata["dist"]["tarball"]
    }
else:
    metadata = json.loads(
        read(
            f"https://pypi.org/pypi/{urllib.parse.quote(package_name, safe='')}/{version}/json"
        )
    )
    assert metadata["info"]["name"] == package_name
    assert metadata["info"]["version"] == version
    urls = {item["filename"]: item["url"] for item in metadata["urls"]}
    expected = {
        item["file"]
        for item in qualified["artifacts"]
        if item["file"].endswith((".whl", ".tar.gz"))
    }
    assert set(urls) == expected
checked = []
for filename, url in urls.items():
    assert urllib.parse.urlparse(url).scheme == "https"
    allowed_host = (
        "registry.npmjs.org" if args.registry == "npm" else "files.pythonhosted.org"
    )
    assert urllib.parse.urlparse(url).hostname == allowed_host
    digest = hashlib.sha256(read(url)).hexdigest()
    expected = next(
        item["sha256"] for item in qualified["artifacts"] if item["file"] == filename
    )
    assert digest == expected, (
        "Registry artifact differs from the installed qualified artifact"
    )
    checked.append({"file": filename, "sha256": digest, "url": url})
receipt = {
    "result": "PASS",
    "registry": args.registry,
    "package": package_name,
    "version": version,
    "source_commit": source,
    "tag": f"rs-sdk-v{version}",
    "artifacts": checked,
    "workflow_run": (
        f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
        if os.environ.get("GITHUB_RUN_ID")
        else None
    ),
}
args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
print(
    json.dumps(
        {
            "result": "PASS",
            "registry": args.registry,
            "verified_artifacts": len(checked),
        }
    )
)
