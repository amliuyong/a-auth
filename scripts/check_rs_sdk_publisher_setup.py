"""Fail closed until release environments actually require independent review."""
import json
import os
import urllib.request

repo = os.environ["GITHUB_REPOSITORY"]
assert repo == "amliuyong/a-auth"
token = os.environ["GITHUB_TOKEN"]


def api(path):
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


for name in ["rs-sdk-npm-release", "rs-sdk-pypi-release"]:
    config = api("environments/" + name)
    reviewers = next((rule for rule in config["protection_rules"]
                      if rule["type"] == "required_reviewers"), None)
    assert reviewers and reviewers.get("reviewers") and reviewers.get("prevent_self_review"), (
        name + " requires an independent reviewer and prevent_self_review")
    assert config.get("deployment_branch_policy", {}).get("custom_branch_policies")
    policies = api("environments/" + name + "/deployment-branch-policies")
    assert any(policy["name"] == "rs-sdk-v*" and policy.get("type") == "tag"
               for policy in policies["branch_policies"]), name + " requires the rs-sdk-v* tag policy"
protected_tags = False
for summary in api("rulesets"):
    if summary["target"] != "tag" or summary["enforcement"] != "active":
        continue
    ruleset = api("rulesets/" + str(summary["id"]))
    refs = ruleset.get("conditions", {}).get("ref_name", {})
    types = {rule["type"] for rule in ruleset["rules"]}
    if ("refs/tags/rs-sdk-v*" in refs.get("include", []) and not refs.get("exclude")
            and {"update", "deletion"}.issubset(types)):
        protected_tags = True
assert protected_tags, "SDK release tags require active update/deletion protection"
print("Protected SDK release environments and tags verified")
