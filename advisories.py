"""Match local advisory snapshots to owner-approved software inventory."""

import csv
import gzip
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from itertools import chain
from pathlib import Path
from zipfile import ZipFile

from packaging.utils import canonicalize_name
from packaging.version import Version as PythonVersion

CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
MAX_ADVISORY_BYTES = 16 * 1024 * 1024
SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


def semver_key(version):
    match = SEMVER.fullmatch(version)
    if match is None:
        raise ValueError("invalid semantic version")
    major, minor, patch, prerelease = match.groups()
    identifiers = []
    for part in prerelease.split(".") if prerelease else ():
        if part.isdecimal():
            if len(part) > 1 and part.startswith("0"):
                raise ValueError("invalid numeric prerelease identifier")
            identifiers.append((0, int(part)))
        else:
            identifiers.append((1, part))
    return int(major), int(minor), int(patch), prerelease is None, tuple(identifiers)


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def required_text(record, key):
    value = record.get(key)
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{key} requires a nonempty string without surrounding whitespace")
    return value


def package_key(ecosystem, name):
    return ecosystem, canonicalize_name(name) if ecosystem == "PyPI" else name


def approved_inventory(scope_path, inventory_path):
    scope = load_json(scope_path)
    if scope.get("activity") != "offline-advisory-review" or scope.get("approved") is not True:
        raise ValueError("scope must explicitly approve offline-advisory-review")
    required_text(scope, "rules_reference")
    assets = scope.get("assets")
    if not isinstance(assets, list) or not assets or any(
        not isinstance(asset, str) or not asset.strip() or "*" in asset for asset in assets
    ):
        raise ValueError("scope must list exact asset identifiers")
    allowed = set(assets)
    index = defaultdict(set)
    for row in load_json(inventory_path)["components"]:
        asset = required_text(row, "asset")
        if asset not in allowed:
            raise ValueError(f"inventory asset is outside approved scope: {asset}")
        key = package_key(required_text(row, "ecosystem"), required_text(row, "name"))
        version = row.get("version")
        if version is not None:
            version = required_text(row, "version")
        index[key].add((asset, version))
    if not index:
        raise ValueError("inventory must include at least one component")
    return index


def matches_range(version, events, parse):
    candidate = parse(version)
    start = None
    matched = False
    for event in events:
        if len(event) != 1:
            raise ValueError("invalid OSV range event")
        kind, value = next(iter(event.items()))
        if kind == "introduced" and start is None:
            start = value
            if start != "0":
                parse(start)
        elif kind in {"fixed", "last_affected", "limit"} and start is not None:
            end = parse(value)
            if start != "0" and end < parse(start):
                raise ValueError("invalid OSV range bounds")
            if start == "0" or candidate >= parse(start):
                matched |= candidate < end or (kind == "last_affected" and candidate == end)
            start = None
        else:
            raise ValueError("invalid OSV range sequence")
    if not events:
        raise ValueError("empty OSV range")
    return matched or (start is not None and (start == "0" or candidate >= parse(start)))


def assess_version(version, ecosystem, affected):
    if version is None:
        return "review_required", "inventory version missing"
    listed = affected.get("versions", [])
    if version in listed:
        return "version_match", {"listed_version": version}
    unresolved = False
    for interval in affected.get("ranges", []):
        kind = interval.get("type")
        if kind == "SEMVER":
            parse = semver_key
        elif kind == "ECOSYSTEM" and ecosystem == "PyPI":
            parse = PythonVersion
        else:
            unresolved = True
            continue
        try:
            if matches_range(version, interval["events"], parse):
                return "version_match", {"range_type": kind, "events": interval["events"]}
        except (KeyError, TypeError, ValueError):
            unresolved = True
    if unresolved or not (affected.get("ranges") or affected.get("versions")):
        return "review_required", "affected range could not be evaluated"
    return None


def records(paths):
    for path in paths:
        if path.suffix.lower() == ".json":
            with path.open("rb") as stream:
                content = stream.read(MAX_ADVISORY_BYTES + 1)
            if len(content) > MAX_ADVISORY_BYTES:
                raise ValueError(f"advisory too large: {path.name}")
            yield path, json.loads(content)
            continue
        with ZipFile(path) as archive:
            for member in archive.infolist():
                if member.is_dir() or not member.filename.endswith(".json"):
                    continue
                if member.file_size > MAX_ADVISORY_BYTES:
                    raise ValueError(f"advisory too large: {path.name}/{member.filename}")
                try:
                    yield path, json.loads(archive.read(member))
                except ValueError as exc:
                    raise ValueError(f"invalid advisory: {path.name}/{member.filename}") from exc


def epss_scores(path, requested):
    if path is None:
        return {}, None
    opener = gzip.open if path.suffix == ".gz" else Path.open
    with opener(path, "rt", encoding="utf-8-sig", newline="") as stream:
        first = stream.readline()
        metadata = re.search(r"\bscore_date:(\d{4}-\d{2}-\d{2})", first) if first.startswith("#") else None
        rows = csv.DictReader(chain([] if first.startswith("#") else [first], stream))
        if not {"cve", "epss"} <= set(rows.fieldnames or []):
            raise ValueError("EPSS file must include cve and epss columns")
        scores = {}
        for row in rows:
            if row["cve"] in requested:
                score = float(row["epss"])
                if not 0 <= score <= 1:
                    raise ValueError("EPSS score must be between zero and one")
                scores[row["cve"]] = score
    return scores, metadata.group(1) if metadata else None


def report(scope, inventory, archives, year=2026, kev=None, epss=None):
    index = approved_inventory(scope, inventory)
    kev_data = load_json(kev) if kev else {}
    known_exploited = {row["cveID"] for row in kev_data["vulnerabilities"]} if kev else set()
    findings = {}
    by_ecosystem = defaultdict(list)
    for key in index:
        by_ecosystem[key[0]].append(key)
    counts = dict(records_read=0, published_in_year=0, missing_publication=0, withdrawn=0)
    latest = dict.fromkeys(archives)
    assessed = {}
    status_priority = {"no_version_match": 0, "version_match": 1, "review_required": 2}
    for source, advisory in records(archives):
        counts["records_read"] += 1
        modified = advisory.get("modified")
        if modified:
            timestamp = datetime.fromisoformat(modified)
            if timestamp.tzinfo is None:
                raise ValueError("OSV modified timestamp must have a timezone")
            if latest[source] is None or timestamp > latest[source]:
                latest[source] = timestamp
        if advisory.get("withdrawn"):
            counts["withdrawn"] += 1
            continue
        published = advisory.get("published")
        if not published:
            counts["missing_publication"] += 1
            continue
        timestamp = datetime.fromisoformat(published)
        if timestamp.tzinfo is None:
            raise ValueError("OSV published timestamp must have a timezone")
        if timestamp.astimezone(timezone.utc).year != year:
            continue
        counts["published_in_year"] += 1
        advisory_id = required_text(advisory, "id")
        cves = sorted({value for value in [advisory_id, *advisory.get("aliases", [])]
                       if CVE_ID.fullmatch(value)})
        for affected in advisory.get("affected", []):
            package = affected.get("package", {})
            ecosystem, name = package_key(package.get("ecosystem"), package.get("name") or "")
            keys = by_ecosystem[ecosystem] if name == "*" else [(ecosystem, name)]
            for package_id in keys:
                for asset, version in index.get(package_id, ()):
                    assessment = assess_version(version, ecosystem, affected)
                    component = (*package_id, asset, version)
                    status = assessment[0] if assessment else "no_version_match"
                    previous = assessed.get(component, "no_version_match")
                    if status_priority[status] >= status_priority[previous]:
                        assessed[component] = status
                    if assessment is None:
                        continue
                    status, evidence = assessment
                    key = (advisory_id, *package_id, asset, version)
                    finding = findings.setdefault(key, dict(
                        advisory=advisory_id, ecosystem=ecosystem, name=package_id[1], asset=asset,
                        version=version, status=status, evidence=evidence, published=published,
                        cves=[], references=[
                            ref["url"] for ref in advisory.get("references", [])
                            if ref.get("type") == "ADVISORY" and ref.get("url")
                        ],
                    ))
                    finding["cves"] = sorted(set(finding["cves"]) | set(cves))
                    if status == "version_match":
                        finding.update(status=status, evidence=evidence)

    scores, score_date = epss_scores(
        epss, {cve for finding in findings.values() for cve in finding["cves"]}
    )
    for finding in findings.values():
        cves = finding["cves"]
        finding["kev"] = sorted(known_exploited.intersection(cves)) if kev else None
        finding["epss"] = max((scores[cve] for cve in cves if cve in scores), default=None)

    def priority(finding):
        score = finding["epss"]
        return (
            finding["status"] != "version_match", not finding["kev"],
            -(score if score is not None else -1), finding["advisory"], finding["asset"],
            finding["ecosystem"], finding["name"], finding["version"] or "",
        )

    component_count = sum(map(len, index.values()))
    component_coverage = dict(
        no_advisory_data=component_count - len(assessed),
        no_version_match=0, version_match=0, review_required=0,
    )
    for status in assessed.values():
        component_coverage[status] += 1
    return dict(
        publication_year=year, archives=[path.name for path in archives],
        kev_snapshot=kev.name if kev else None, epss_snapshot=epss.name if epss else None,
        sources=dict(
            osv=[dict(file=path.name, latest_record_modified_utc=(
                latest[path].astimezone(timezone.utc).isoformat() if latest[path] else None
            )) for path in archives],
            kev_catalog_version=kev_data.get("catalogVersion"),
            epss_score_date=score_date,
        ),
        components_reviewed=component_count, coverage=counts, component_coverage=component_coverage,
        findings=sorted(findings.values(), key=priority),
    )
