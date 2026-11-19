# AI Bug Bounty Hunter

This workbench reviews approved local GitHub Actions YAML for defensive configuration issues. It reads text and produces local reports for human triage. The original third-party repository list and program catalog are historical inputs and are unused by the current runner.

## Run locally

Install the parser with `python -m pip install -r requirements.txt`. Run `python -m unittest discover -s tests -v` and `python hunter.py --demo` for an offline check. The demo uses a synthetic example.

For your own or explicitly approved source, a human reviewer must verify permission, program rules and exclusions, then save a scope JSON outside the checkout being reviewed. Use the checkout's resolved absolute path exactly as Python prints it. List each workflow individually.

```json
{
  "activity": "offline-workflow-review",
  "approved": true,
  "rules_reference": "Internal owner approval or applicable program rule reference",
  "checkout": "C:\\path\\to\\approved-checkout",
  "files": [".github/workflows/ci.yml"]
}
```

Run `python hunter.py --checkout <approved-checkout> --scope <reviewed-scope.json>`. Run the workbench and keep its scope file in locations the reviewed source cannot modify. The scope is a record of human approval. Confirm that approval and the referenced rules are still current before each use.

Reports are written to `reports/daily-report.md` and `reports/findings.json`. Treat a nonzero exit as a failed run even if older reports still exist. Findings are unverified and include local source locations for human triage. Review effective permissions and trust boundaries, and redact sensitive material before sharing evidence.

## Integration and updates

### Offline advisory and patch review

Use an owner-supplied software inventory to check which deployments match published
advisories. Save approval separately from the inventory. An example scope file:

```json
{"activity":"offline-advisory-review","approved":true,"rules_reference":"Internal approval record","assets":["web-prod"]}
```

An example inventory file:

```json
{"components":[{"asset":"web-prod","ecosystem":"PyPI","name":"example","version":"1.2.3"}]}
```

Use exact asset identifiers and OSV ecosystem and package names. A version of
`null` sends advisories for that package to manual review. The check validates
every inventory row against the approved asset list and makes zero network requests.

Download current [OSV archives](https://google.github.io/osv.dev/data/) for the
ecosystems in the inventory. Optionally supply a [CISA KEV JSON snapshot](https://github.com/cisagov/kev-data)
and a [FIRST EPSS CSV or CSV.GZ snapshot](https://www.first.org/epss/data).
Repeat `--osv` for multiple ecosystems.

```sh
python hunter.py advisories --scope approved.json --inventory inventory.json --osv pypi.zip --osv npm.zip --kev kev.json --epss epss.csv.gz > reports/advisories.json
```

The default year is 2026 and can be changed with `--year`. The filter uses the
advisory's UTC publication date. The runner reads archives one record at a time
with no target record count and reports coverage, including records missing a
publication date and withdrawn records. Refresh the snapshots and rerun to
incorporate changes. Check the command's exit status before using the report.

Findings include the installed version, package, advisory ID, CVE aliases, and
matched version or range evidence. Confirm applicable build details, vendor
backports and required configuration against the vendor notice. Ordering starts
with version matches, then KEV-listed CVEs and descending EPSS scores within
each status. A missing score is reported as `null`.

Coverage depends on the supplied snapshots and package mappings. The matcher
supports explicit version lists, SemVer ranges and PyPI ecosystem ranges.
Unknown installed versions, Git-only ranges and unsupported ecosystem
comparisons require review. Separate OSV advisory IDs remain visible even
when they share a CVE alias. An empty findings list covers only the matching
data in these snapshots. Vendor products outside the snapshots require
additional vendor data.

`component_coverage` counts each distinct asset/package/version once.
`review_required` takes precedence when any relevant comparison is unresolved.
`no_version_match` means the supplied records for that package and year were
evaluated without an affected-version match. `no_advisory_data` means none of
the supplied records in that year mapped to the package. Source metadata shows
the newest OSV record modification timestamp, the KEV catalog version and the
EPSS score date when available.

For upstream PHP builds in the 8.2–8.5 release lines, use ecosystem `PHP`
and package `php-src`. Add these two vendor-derived records to the invocation
with `--osv data/php/GHSA-w8hw-w9fx-j79w.json --osv data/php/GHSA-6wmf-4rv5-p3rp.json`.
They cover CVE-2026-109618 and CVE-2026-109619. Use your distribution's
advisories for downstream builds or backports, and check end-of-life release
lines separately.

### HTTPS inventory review

Point the advisory check at an inventory endpoint you operate or are authorized
to use. The endpoint should return the same inventory JSON as the local file
example, with HTTP 200 and Content-Type `application/json`. Keep deployed
inventory endpoints access-controlled. For bearer authentication, supply the
token in the local `HUNTER_INVENTORY_TOKEN` environment variable.

```json
{"activity":"https-inventory-review","approved":true,"rules_reference":"Internal approval record","assets":["web-prod"],"inventory_url":"https://inventory.example.net/api/components"}
```

```sh
python hunter.py advisories --scope approved-https.json --inventory-url https://inventory.example.net/api/components --osv pypi.zip
```

Keep the scope file under the operator's control. The command makes a read-only
GET to the exact approved URL over verified HTTPS, disallows redirects and checks
every returned asset ID against the approved list. Advisory matching still uses
local snapshots. A site's homepage cannot substitute for its inventory endpoint.

### GitHub Actions workflow review

Claude-BugHunter's human triage and evidence-handling approach informed the reports. The workbench uses its existing Python analyzer. See the [upstream project](https://github.com/elementalsouls/Claude-BugHunter) and its [license notice](https://github.com/elementalsouls/Claude-BugHunter/blob/main/NOTICE). No upstream code or skills were copied.

The workflow review runs offline and uses no API credentials. The legacy environment example is historical. GitHub Actions runs fixture checks on pull requests targeting main and supports manual runs.
