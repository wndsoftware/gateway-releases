#!/usr/bin/env python3
"""Private inputs and encrypted outputs on a standard public Ubuntu runner.

No source, license, subprocess output or unencrypted build artifact is emitted
to public Actions logs, caches or artifacts. Only dispatch pins and status are
public. All product commands run without the release-upload token or URLs.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import traceback
from urllib.parse import urlparse, quote
from urllib.request import Request, build_opener, HTTPRedirectHandler

REPO = "wndsoftware/gateway-releases"
TAG = "v1.0.543-ubuntu-isolated-output"
ROOT = Path(__file__).resolve().parents[1]


def require(ok, message):
    if not ok:
        raise ValueError(message)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Redirect refused")


def request(url, *, token=None, data=None, method=None, content_type=None):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "WND-release-custody"}
    if token:
        require(urlparse(url).hostname in {"api.github.com", "uploads.github.com"}, "Invalid upload destination")
        headers["Authorization"] = "Bearer " + token
    if content_type:
        headers["Content-Type"] = content_type
    return build_opener(NoRedirect()).open(Request(url, data=data, headers=headers, method=method), timeout=120)


def api(path, token):
    with request("https://api.github.com/repos/" + REPO + path, token=token) as response:
        return json.load(response)


def download(url, target, expected_sha, expected_size):
    parsed = urlparse(url)
    require(parsed.scheme == "https" and parsed.hostname == "release-assets.githubusercontent.com"
            and parsed.port in (None, 443) and not parsed.username and not parsed.password and not parsed.fragment,
            "Invalid private input location")
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha) and isinstance(expected_size, int)
            and 0 < expected_size <= 512 * 1024 * 1024, "Invalid private input pin")
    digest, total = hashlib.sha256(), 0
    with request(url) as incoming, target.open("xb") as output:
        while chunk := incoming.read(1024 * 1024):
            total += len(chunk)
            require(total <= expected_size, "Input exceeds pinned size")
            digest.update(chunk)
            output.write(chunk)
    require(total == expected_size and digest.hexdigest() == expected_sha, "Private input digest mismatch")


def execute(config, stage, log, source_url, signed_url, license_text):
    source = stage / "source"
    source.mkdir(mode=0o700)
    archive = stage / "source.tar.gz"
    download(source_url, archive, config["sourceArchiveSha256"], config["sourceArchiveBytes"])
    with tarfile.open(archive, "r:gz") as tar:
        require(sum(member.size for member in tar.getmembers()) <= 2 * 1024**3, "Source archive too large")
        tar.extractall(source, filter="data")
    env = {key: value for key, value in os.environ.items()
           if key in {"PATH", "HOME", "LANG", "RUNNER_TEMP", "RUNNER_OS", "RUNNER_ARCH", "CI", "RUSTUP_HOME", "CARGO_HOME"}
           or key.startswith("GITHUB_") and key not in {
               "GITHUB_TOKEN", "GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH", "GITHUB_STEP_SUMMARY"}}
    env.update(WND_UBUNTU_PUBLIC_RUN="1", SOURCE_SHA=config["sourceSha"],
               WND_APPROVED_PUBLIC_WORKFLOW_SHA=os.environ["GITHUB_SHA"],
               WND_VERIFIED_BUILD_GIT_SHA=config["sourceSha"], CANDIDATE_TARGET="ubuntu-24.04-x64",
               CANDIDATE_OUTPUT=str(stage / "candidate"))

    def run(args, *, timeout=2400, capture=False, extra=None):
        result = subprocess.run(args, cwd=source, env=env | (extra or {}),
                                stdout=subprocess.PIPE if capture else log, stderr=log,
                                check=True, timeout=timeout)
        return result.stdout.decode().strip() if capture else None

    checkout_sha = config.get("qualificationSha", config["sourceSha"])
    checkout_tree = config.get("qualificationTree", config["sourceTree"])
    require(run(["git", "--no-replace-objects", "rev-parse", "HEAD"], capture=True) == checkout_sha,
            "Private checkout commit differs")
    require(run(["git", "--no-replace-objects", "rev-parse", "HEAD^{tree}"], capture=True) == checkout_tree,
            "Private checkout tree differs")
    require(run(["git", "--no-replace-objects", "rev-parse", config["sourceSha"] + "^{tree}"], capture=True)
            == config["sourceTree"], "Signed product tree differs")
    require(not run(["git", "status", "--porcelain=v1", "--untracked-files=all"], capture=True), "Dirty private source")
    if config["mode"] == "qualify":
        run(["python3", "-c", "import sys;sys.path.insert(0,'tools/release');"
             "from gateway_ubuntu_local_profile import verify_qualification_revision;"
             "verify_qualification_revision('.',sys.argv[1],sys.argv[2])", config["sourceSha"], checkout_sha])
    if config["mode"] == "build":
        run(["bash", "tools/ci/apt-install.sh", "libssl-dev", "pkg-config", "binutils"])
        commands = [
            ["python3", "tools/ci/gateway-qualification-candidate.py", "check"],
            ["npm", "ci"],
            ["python3", "tools/ci/gateway-qualification-candidate.py", "stamp"],
            ["npm", "run", "build:web"],
            ["cargo", "build", "--release", "--locked", "-p", "wnd-gateway"],
            ["python3", "tools/ci/gateway-qualification-candidate.py", "package", "--ubuntu-local-setup"],
        ]
        for command in commands:
            run(command)
        shutil.copytree(stage / "candidate", stage / "output" / "candidate")
    else:
        require(license_text and re.fullmatch(r"[0-9a-f]{64}", config["manifestSha256"]), "Missing qualification inputs")
        signed = Path(env["RUNNER_TEMP"]) / "gateway-ubuntu-qualification.tar.gz"
        download(signed_url, signed, config["signedArchiveSha256"], config["signedArchiveBytes"])
        # sudo inherits only this explicitly named environment. URL/upload token
        # have already been removed and are never supplied to product commands.
        additions = {"MANIFEST_SHA256": config["manifestSha256"], "WND_CI_LICENSE": license_text}
        preserved = sorted(set(env) | set(additions))
        run(["sudo", "--preserve-env=" + ",".join(preserved), "python3",
             "tools/ci/gateway-native-ubuntu-local-qualification.py", shutil.which("node")], extra=additions)
        shutil.copyfile(Path(env["RUNNER_TEMP"]) / "gateway-ubuntu-local-journey.json",
                        stage / "output" / "installed-journey.json")


def main():
    os.umask(0o077)
    token = os.environ.pop("GH_TOKEN")
    source_url = os.environ.pop("WND_SOURCE_URL")
    signed_url = os.environ.pop("WND_SIGNED_URL", "")
    license_text = os.environ.pop("WND_CI_LICENSE", "")
    config = json.loads(os.environ.pop("WND_OPERATION"))
    require(config["mode"] in {"build", "qualify"}, "Invalid operation")
    require(all(re.fullmatch(r"[0-9a-f]{40}", config[key]) for key in ("sourceSha", "sourceTree")), "Invalid source pins")
    if config["mode"] == "qualify":
        require(all(re.fullmatch(r"[0-9a-f]{40}", config[key])
                    for key in ("qualificationSha", "qualificationTree")), "Invalid qualification pins")
    else:
        require("qualificationSha" not in config and "qualificationTree" not in config, "Build must use the product source")
    require(os.environ["GITHUB_REPOSITORY"] == REPO and os.environ["GITHUB_REPOSITORY_ID"] == "1456635236"
            and os.environ["GITHUB_REF"] == "refs/heads/main" and os.environ["GITHUB_RUN_ATTEMPT"] == "1",
            "Invalid runner identity")
    require(api("/git/ref/heads/main", token)["object"]["sha"] == os.environ["GITHUB_SHA"], "Public main changed")
    draft_id = str(config["outputDraftId"])
    require(re.fullmatch(r"[1-9][0-9]*", draft_id), "Invalid private output draft")

    def verify_draft():
        draft = api("/releases/" + draft_id, token)
        require(draft["draft"] is True and draft["prerelease"] is True and draft["tag_name"] == TAG,
                "Output destination must remain the exact unpublished draft")

    verify_draft()
    run_id = os.environ["GITHUB_RUN_ID"]
    stage = Path(os.environ["RUNNER_TEMP"]) / ("wnd-private-" + run_id)
    stage.mkdir(mode=0o700)
    output = stage / "output"
    output.mkdir(mode=0o700)
    status = "failed"
    with (output / "private.log").open("w") as log:
        try:
            execute(config, stage, log, source_url, signed_url, license_text)
            status = "passed"
        except BaseException:
            traceback.print_exc(file=log)
    record = {"status": status, "mode": config["mode"], "repository": REPO,
              "workflowRevision": os.environ["GITHUB_SHA"], "runId": run_id,
              "sourceRevision": config["sourceSha"], "sourceTree": config["sourceTree"]}
    if config["mode"] == "qualify":
        record.update(qualificationRevision=config["qualificationSha"], qualificationTree=config["qualificationTree"])
    (output / "operation.json").write_text(json.dumps(record, indent=2) + "\n")
    plain = stage / "output.tar.gz"
    with tarfile.open(plain, "w:gz") as tar:
        tar.add(output, arcname="output", recursive=True)
    cipher = stage / "output.cms"
    subprocess.run(["openssl", "cms", "-encrypt", "-binary", "-aes-256-cbc", "-in", str(plain),
                    "-out", str(cipher), "-outform", "DER", str(ROOT / "ops/ubuntu-local-output.pem")],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    verify_draft()
    name = f"ubuntu-{config['mode']}-{run_id}.cms"
    content = cipher.read_bytes()
    url = f"https://uploads.github.com/repos/{REPO}/releases/{draft_id}/assets?name={quote(name)}"
    with request(url, token=token, data=content, method="POST", content_type="application/octet-stream") as response:
        asset = json.load(response)
    require(asset["name"] == name and asset["size"] == len(content)
            and asset["digest"] == "sha256:" + hashlib.sha256(content).hexdigest(), "Encrypted upload mismatch")
    # Only public operation metadata is emitted. Detailed errors remain encrypted.
    print(json.dumps(record | {"encryptedAssetId": asset["id"], "encryptedSha256": hashlib.sha256(content).hexdigest()}))
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # Do not print exception details: they may contain expiring input URLs.
        sys.exit("Isolated operation failed before encrypted output could be returned.")
