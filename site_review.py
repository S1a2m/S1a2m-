"""Review defensive headers from one approved HTTPS URL."""

import json
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def review(url, scope_path):
    endpoint = urlsplit(url)
    if (endpoint.scheme != "https" or not endpoint.hostname
            or endpoint.username is not None or endpoint.password is not None
            or "?" in url or "#" in url or any(char.isspace() for char in url)):
        raise ValueError("provide a full HTTPS page URL without credentials, query, or fragment")
    scope = json.loads(scope_path.read_text(encoding="utf-8-sig"))
    rules = scope.get("rules_reference")
    allowed = scope.get("urls")
    if (scope.get("activity") != "https-header-review" or scope.get("approved") is not True
            or not isinstance(rules, str) or not rules.strip()
            or not isinstance(allowed, list) or url not in allowed):
        raise ValueError("scope must explicitly approve HTTPS header review for this exact URL")

    request = Request(url, headers={"User-Agent": "Hunter-Header-Review/1.0"})
    try:
        with build_opener(NoRedirect()).open(request, timeout=10) as response:
            status = response.status
            headers = response.headers
    except HTTPError as error:
        with error:
            return {"url": url, "http_status": error.code,
                    "status": "review_incomplete", "observations": []}

    expected = ["Strict-Transport-Security"]
    if headers.get_content_type() == "text/html":
        expected.extend(["Content-Security-Policy", "X-Content-Type-Options"])
    observations = [
        {"header": name, "observation": "header absent or empty"}
        for name in expected if not headers.get(name, "").strip()
    ]
    return {
        "url": url,
        "http_status": status,
        "status": "headers_reviewed",
        "observations": observations,
        "cve_status": "not_assessed",
    }
