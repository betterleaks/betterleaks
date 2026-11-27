"""On retry, remove only release files already published with the same digest."""

import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # PyPI's release endpoint is canonical. Treat redirects as HTTP errors.
        return None


def check_published(root, version, index):
    host = {"pypi": "pypi.org", "testpypi": "test.pypi.org"}[index]
    number = r"(?:0|[1-9][0-9]*)"
    if not re.fullmatch(rf"2\.{number}\.{number}(?:rc{number})?", version):
        raise ValueError(f"Expected a v2 release or release candidate version, got {version!r}")
    opener = build_opener(NoRedirect)
    projects = ("betterleaks-cli", "betterleaks-sdk", "betterleaks")
    if {path.name for path in root.iterdir()} != set(projects):
        raise ValueError("Expected a release artifact containing all three projects")
    for project in projects:
        files = root / project
        if not any(files.glob("*.whl")) or not any(files.glob("*.tar.gz")):
            raise ValueError(f"Missing wheel or source distribution for {project}")
        try:
            with opener.open(f"https://{host}/pypi/{project}/{version}/json", timeout=30) as response:
                release = json.load(response)
        except HTTPError as error:
            if error.code == 404:
                continue
            raise
        for item in release["urls"]:
            filename = item["filename"]
            path = root / project / filename
            if filename != Path(filename).name or not path.is_file():
                raise ValueError(f"Unexpected published file: {filename}")
            if item["digests"]["sha256"] != hashlib.sha256(path.read_bytes()).hexdigest():
                raise ValueError(f"Already published with different bytes: {filename}")
            path.unlink()


if __name__ == "__main__":
    check_published(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
