# Landscape research: how existing patch- and vulnerability-management tools work

*Read 2026-11-07 from each project's own documentation or repository. This is the long-form
companion to `docs/landscape.md`, which was the pre-build survey; that file decided what to wrap,
this one records how the alternatives actually behave and what is worth stealing.*

The question asked of every tool below is narrower than "does it find CVEs". It is: **does it tell
an operator whether this machine is patched, and does it admit when it could not look?** Most of
this landscape answers the first half with package versions and stays silent on the second.

---

## 1. Trivy (Aqua)

Trivy detects known vulnerabilities in OS packages, language packages, non-packaged software and
Kubernetes components, across container images, VM images, filesystems and running hosts. For OS
packages it deliberately consumes **only** the vendor's own advisory feed (Ubuntu CVE Tracker,
Debian Security Bug Tracker/OVAL, RHEL OVAL, Alpine secdb, SUSE CVRF, and so on) rather than NVD,
because vendors backport and the upstream fixed version is the wrong comparison; severity is taken
from the vendor for the same reason. SBOM output is SPDX and CycloneDX. Advisories arrive as
`trivy-db`, an OCI artefact pulled from GHCR, Docker Hub or ECR and cached locally, with
`--download-db-only` to pre-warm and `--skip-db-update` for air-gapped runs. There is no remediation
path: Trivy reports, and can gate a pipeline with an exit code.

- **What Patch Sentinel could borrow.** Vendor-feed-first severity, instead of enriching from NVD
  and cve.org — the enrichment is the thing Trivy explicitly avoids for OS packages because it
  produces ratings the distribution disagrees with. Second, the OCI-distributed database is a
  better cache-refresh story than a file with a timestamp, and `--download-db-only` is the right
  shape for a pre-window warm-up.
- **Where Patch Sentinel is already different.** Trivy answers "which CVEs are in this artefact",
  not "is this host patched". Scanning a running host yields a package inventory compared against
  advisory fixed versions; nothing in the documentation asks the host's *configured repositories*
  what they actually offer, and nothing applies a fix. Patch Sentinel's archive-versus-advisory
  comparison is a different question, and Trivy does not ask it. The honest reverse: Trivy's
  in-image layer inventory is real, and Patch Sentinel has only registry-digest comparison.

## 2. Grype + Syft (Anchore)

Syft catalogues packages from images, directories, archives and OCI registries into an SBOM (SPDX,
CycloneDX, or Syft's own JSON); Grype matches that SBOM against a SQLite vulnerability database.
Feed selection is by package type: OS packages use the distribution's security feed, language
packages use GitHub Security Advisories, and everything else falls back to CPE matching against
NVD — which the docs warn may produce false positives. Fix state is a first-class field with four
values — `fixed`, `not-fixed`, `unknown`, `wont-fix` — exposed as a `FIXED-IN` column and as
`--only-fixed` / `--ignore-states` filters, and the default sort is by `risk`, with `epss` and `kev`
alternatives. Grype also detects end-of-life distributions and warns that results may be
artificially incomplete. It does not remediate; that is the commercial product's job.

- **What Patch Sentinel could borrow.** The four-state fix vocabulary. "Won't fix" is a real state
  that Patch Sentinel currently has to fold into vendor lag or silence, and those are different
  answers to the operator. Also: an SBOM is a scan you can hand to another tool, or re-run later
  without re-reading the machine — portability the current SQLite store does not provide. Also:
  the EOL warning as an explicit incompleteness signal rather than a generic stale-feed flag.
- **Where Patch Sentinel is already different.** Same boundary as Trivy — Grype reports, never
  applies, and never asks the local archive. The typed-confirmation apply gate has no counterpart
  here at all.

## 3. OSV-Scanner (Google)

OSV-Scanner works in two steps — extract packages, then match against OSV.dev. Its documented
targets are source projects (`scan source`, lockfiles and manifests across thirteen language
ecosystems, with transitive resolution for Maven via deps.dev) and container images
(`scan image`, reporting fix availability and the layer a package was introduced in). Its `fix`
subcommand performs guided remediation for lockfiles and is explicitly flagged as risky because it
may let the package manager execute scripts or follow registries named in the project. Offline mode
caches the OSV databases for air-gapped use.

- **What Patch Sentinel could borrow.** `fix` is the only place in this landscape where a scanner
  computes an *upgrade path* rather than a fixed version — which version you actually have to move
  to, and what comes with it. Patch Sentinel's plan stops at the fixed version. Second, OSV-Scalibr
  is the honest way to add in-image inventory later without writing extractors.
- **Where Patch Sentinel is already different.** OSV-Scanner has no host patching. Its unit is a
  project or an image; the documented CLI offers no host inventory, no archive comparison and no
  apply step. It also scans only what a lockfile pins — its own docs warn that manifest versions
  are best-effort and may not be the installed version. Patch Sentinel's machine-wide scope (every
  virtualenv, deduplicated across environments) and its "a range is not a version" rule are a
  different and, for this question, more useful scope. Conversely, for `project` scope Patch
  Sentinel is weaker: it reports a fixed version and offers no remediation.

## 4. Wazuh, osquery, Vuls

**Wazuh** is agent-based: the Syscollector module ships OS and package inventory to a server, which
correlates it against the Wazuh CTI platform — vendor feeds plus NVD, OSV and CISA — and keeps a
per-agent vulnerability inventory. It knows only whether a version falls in an affected range;
patch confirmation exists for Windows and certain Microsoft products only, through the agent's
hotfix inventory. **osquery** is an inventory and query
layer, not a scanner: its vulnerability pack is a set of queries over `deb_packages`,
`rpm_packages`, `os_version` and similar, and the correlation is left to whatever consumes the
results. **Vuls** is the closest relative: agentless over SSH, it collects package inventory and
matches it against per-distribution OVAL plus vendor advisories (USN, RHSA, Debian Security
Tracker, Alpine secdb) and NVD/JVN, with a *changelog double-check* in deep scan mode; fast scan
needs no root and puts almost no load on the target, and fast-root adds `yum-ps` / `checkrestart` to
find processes that were updated but not restarted.

- **What Patch Sentinel could borrow.** Vuls' changelog double-check is direct precedent for the
  archive-versus-advisory rule — a second, independent signal before declaring a fix absent. Its
  fast/deep split (unprivileged, low-load versus root and expensive) maps onto the scan/apply
  separation already in the design. And "processes updated but not restarted" is a surface Patch
  Sentinel does not measure for userland at all.
- **Where Patch Sentinel is already different.** Not in coverage — Vuls covers far more
  distributions, more ecosystems and more advisory sources, and should be conceded. The difference
  is shape: Vuls is a fleet scanner with a server and several databases per source, it reports and
  never applies, and it has no notion of a verdict per host that fails closed. Patch Sentinel is one
  machine, one operator, one answer, with a gate.

## 5. unattended-upgrades, dnf-automatic, yum-cron, needrestart

`unattended-upgrade` applies upgrades from `Allowed-Origins`, which by default is
`${distro}:${codename}`, `-security`, and the two ESM origins — **`-updates` is present but
commented out** — so a fix that ships through `-updates` is not applied by default. It runs daily
from `apt-daily-upgrade.timer`, and rebooting is opt-in: `Automatic-Reboot` is commented out in the
shipped `50unattended-upgrades` on this machine (2.12ubuntu9). `dnf-automatic` defaults to
`upgrade_type = default` (all updates, *not* security), `apply_updates = False` and
`reboot = never` — the alternatives are `when-changed` and `when-needed`, and `systemd_inhibit`
blocks shutdown during the transaction. `yum-cron` is the same shape for yum, with separate config
files deciding whether it checks, downloads or applies. `needrestart` is the odd one out and the
most useful: after library upgrades it finds daemons still mapping deleted libraries, detects an
obsolete running kernel, scans interpreters, detects microcode updates and containerised processes,
and offers a batch mode and a Nagios plugin mode for machine consumption.

- **What Patch Sentinel could borrow.** `needrestart -b` is the single highest-value borrow in this
  document. It extends "a patch counts only when it is running" from the kernel to every service on
  the box, using the tool that is already the Debian/Ubuntu convention, and its batch output is
  parseable without a privilege escalation beyond what the scan already does. Second,
  `dnf-automatic`'s `when-needed` semantics and the `systemd_inhibit` guard are worth naming as
  preconditions in the plan rather than rediscovering.
- **Where Patch Sentinel is already different.** None of these will ever report that it could not
  look. `unattended-upgrades` doing nothing because the fix is not in an allowed origin is
  indistinguishable, from the machine's point of view, from there being nothing to do — which is
  precisely the "updates are on and still unpatched" case the plugin exists to name. And none of
  them compares the running kernel against the *installable* one; `needrestart` detects an obsolete
  kernel but not an available one.

## 6. debsecan, Ubuntu Pro/ESM, Landscape, Uyuni, Red Hat Satellite

`debsecan` maps installed binaries to the Debian security tracker. Its manual carries the caveat
that matters here: for some architectures build daemons lag, so it "may incorrectly mark a package
as fixed, even if an update is not yet available in the Debian archive", and unknown versions from
backports are compared against unstable only. **Ubuntu Pro/ESM** extends security maintenance from
five years to ten across the whole archive including Universe, fifteen with the Legacy add-on, and
adds Livepatch for kernel fixes without a reboot. **Landscape** takes security-update information
from USNs server-side while clients also report from whatever sources they are configured for, and
its upgrade profiles can be security-only on a weekly schedule. **Red Hat Satellite** formalises the
problem in two words: an erratum is *applicable* when it applies to packages present on a host, and
*installable* only once it is present in that host's content view and lifecycle environment —
publishing an incremental content view is what moves it from one to the other. **Uyuni/SUSE
Manager** makes the same distinction structurally, through channels and content lifecycle
management; for live patching it requires excluding newer kernel packages from the channel so that
only livepatch packages are offered.

- **What Patch Sentinel could borrow.** Satellite's applicable/installable pair is the best existing
  formalisation of vendor lag, and it is **two axes, not one**: Patch Sentinel's `vendor lag` is
  the (applicable ∧ ¬installable) cell, but it does not yet separate "no archive anywhere has this
  fix" from "an archive has it and this host is not configured for that pocket". `debsecan`'s
  caveat is the citation for the rule, useful when someone asks why the comparison exists. And a
  release past standard support should be a *state* (as with ESM and the Legacy add-on), not a stale
  feed warning.
- **Where Patch Sentinel is already different.** These are fleet consoles: an agent or a
  subscription, a server, a content pipeline, and in Satellite's case a per-organisation lifecycle.
  Patch Sentinel works on an unmanaged host with no agent and no subscription, and cannot match
  their scale — nor should it try. It also has a typed apply gate on the host itself, whereas these
  apply through a central console. Whether Landscape models "fix exists upstream but not in this
  archive" as a distinct state is **unverified**; the docs describe USN-derived availability and
  client-reported sources without stating how the mismatch is rendered.

## 7. Dependency bots: Dependabot, Renovate, npm audit, pip-audit, cargo-audit

**Dependabot** scans a repository's default branch against the GitHub Advisory Database, raises
alerts with a fixed version where one exists, and can open security-update pull requests; only
GitHub-reviewed advisories trigger alerts, and reachability analysis is in preview for JavaScript
and TypeScript only. **Renovate** opens pull requests to update dependencies and lockfiles on a
schedule, configured by presets — it is an updater that also reports, rather than a scanner.
**npm audit** posts the dependency tree to the registry's bulk advisory endpoint and computes
meta-vulnerabilities; `npm audit fix` runs a real `npm install`, and `--force` is required when the
remediation needs a semver-major change to a top-level range. **pip-audit** scans Python
environments against the PyPA advisory database via the PyPI JSON API. **cargo-audit** scans
`Cargo.lock` against RustSec, has a feature-gated `cargo audit fix` that edits `Cargo.toml`
requirements, and a `cargo audit bin` mode that reads versions out of compiled binaries.

- **What Patch Sentinel could borrow.** npm's meta-vulnerability distinction: a finding whose fix
  needs a range change is a different decision from one that needs a patch bump, and the current
  plan does not say which it is. Also `cargo audit bin` is precedent for reading versions out of
  binaries — the same trick already used for Go via `go version -m`, and the route to covering
  statically linked software the package database cannot see.
- **Where Patch Sentinel is already different.** These are repository-scoped and lockfile-centric;
  none can see a host. Patch Sentinel reads the machine and can name one package in three
  virtualenvs as one finding with three environments. The reverse must be conceded: in `project`
  scope Patch Sentinel reads the same lockfiles and stops at a fixed version, which is weaker than
  `npm audit fix` or `osv-scanner fix`.

## 8. VulnCheck, EPSS and KEV-driven prioritisation

EPSS is a daily 0–1 probability, with percentile, that a published CVE will be exploited in the
next thirty days, published as CSV and API by FIRST. CISA KEV is the authoritative catalogue of
vulnerabilities exploited in the wild, machine-readable as CSV/JSON, and it now carries remediation
due dates under BOD 26-04 rather than being a bare list. VulnCheck publishes a competing KEV
catalogue and supplies exploitation data to the EPSS model, which FIRST credits on its own page.
The category's convention is that **ordering is the product**: Grype's default sort is `risk`, with
`epss` and `kev` as alternatives.

- **What Patch Sentinel could borrow.** Let EPSS/KEV drive the *plan's* order rather than only
  annotating each finding, and carry the KEV due date as a deadline field — a KEV item with four
  days left is a different message from one with forty. Whether VulnCheck's catalogue is materially
  larger than CISA's, and whether it is usable without a subscription, is **unverified**.
- **Where Patch Sentinel is already different.** It can put a KEV item next to the command that
  closes it and the reboot that follows, which none of the scoring vendors can. The prioritisation
  itself is not a differentiator; Grype does it better and earlier.

---

## Gaps this research exposes in Patch Sentinel

Ranked by value against effort. "Effort" means implementation work in this repository, not
research.

| # | Item | Why it matters | Effort | Value |
|---|---|---|---|---|
| 1 | Parse `needrestart -b` and report services still mapping deleted libraries | Extends "a patch counts only when it is running" from the kernel to userland; closes the largest gap between the verdict and the operator's question | S | High |
| 2 | Four-state fix vocabulary per finding: `fixed` / `not-fixed` / `won't-fix` / `unknown` | "Won't fix" currently collapses into vendor lag or silence; the operator cannot tell a vendor refusal from a vendor delay | S | High |
| 3 | Separate "no archive has this fix" from "the host is not configured for the pocket that has it" | The real cause of "updates are on and still unpatched"; readable from `/etc/apt/sources.list*` without privileges | M | High |
| 4 | Per-host release-support state (past standard support / ESM-only), distinct from feed staleness | The frozen Leap 15.6 OVAL case is already observed; a terminal feed is not a slow vendor | S | High |
| 5 | EPSS/KEV drives plan order; carry the KEV due date | Triage value is in the ordering, and the deadline is the actionable part | S | High |
| 6 | Re-verify by effect after apply: `uname -r` plus a second `needrestart` pass | Turns "the transaction succeeded" into "the machine is now patched", which is the plugin's own standard | S (after 1) | High |
| 7 | CycloneDX export of the scan's inventory and versions | Makes the scan portable — the same data can be re-scanned by Grype or fed to OSV-Scanner, and gives an audit artefact | M | Medium-high |
| 8 | Optional `osv-scanner scan image` (or syft+grype) adapter, absent by default, returning `could-not-look` when the binary is missing | Closes the standing in-image blindness without writing extractors; note the tension with stdlib-only — this is a runtime dependency, not a code one, and must degrade honestly | M | High |
| 9 | Classify the remediation as patch-level or range-changing for `project` scope | Borrowed from npm's meta-vulnerability model; tells the operator whether this is a bump or a decision | M | Medium |

Explicitly not recommended: fleet management, agent-based collection, or hosting an advisory
database. Vuls, Wazuh and Satellite already do those, better, and each would turn a single-host
verdict tool into a different product.

---

## Sources

Read directly, 2026-11-07.

**Trivy**
- https://trivy.dev/latest/docs/scanner/vulnerability/
- https://trivy.dev/latest/docs/supply-chain/sbom/
- https://trivy.dev/latest/docs/coverage/os/
- https://trivy.dev/docs/latest/configuration/db/

**Grype / Syft**
- https://oss.anchore.com/docs/guides/vulnerability/
- https://oss.anchore.com/docs/guides/vulnerability/interpreting-results/
- https://oss.anchore.com/docs/guides/vulnerability/ecosystems/
- https://oss.anchore.com/docs/guides/vulnerability/eol-detection/
- https://oss.anchore.com/docs/guides/vulnerability/scan-targets/
- https://oss.anchore.com/docs/reference/grype/cli/
- https://oss.anchore.com/docs/guides/sbom/
- https://github.com/anchore/grype

**OSV-Scanner**
- https://google.github.io/osv-scanner/usage/
- https://google.github.io/osv-scanner/usage/scan-image/
- https://google.github.io/osv-scanner/supported-languages-and-lockfiles/

**Wazuh / osquery / Vuls**
- https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html
- https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html
- https://vuls.io/docs/en/main-features.html
- https://vuls.io/docs/en/architecture-fast-scan.html
- https://vuls.io/docs/en/architecture-deep-scan.html
- https://github.com/osquery/osquery/blob/master/packs/vuln-management.conf

**Linux patching mechanisms**
- https://manpages.ubuntu.com/manpages/noble/man8/unattended-upgrade.8.html
- https://ubuntu.com/server/docs/how-to/software/automatic-updates/
- https://dnf.readthedocs.io/en/latest/automatic.html
- https://man7.org/linux/man-pages/man8/yum-cron.8.html
- https://github.com/liske/needrestart

**Vendor-side patch management**
- https://manpages.debian.org/bookworm/debsecan/debsecan.1.en.html
- https://ubuntu.com/pro
- https://ubuntu.com/landscape/docs/how-to-guides/security/apply-security-updates/
- https://ubuntu.com/landscape/docs/reference/terms/profiles/
- https://www.uyuni-project.org/uyuni-docs/en/uyuni/administration/live-patching.html
- https://docs.redhat.com/en/documentation/red_hat_satellite/6.19/html/managing_content/making-errata-available-through-content-views

**Dependency bots**
- https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-alerts
- https://docs.renovatebot.com/
- https://docs.npmjs.com/cli/v10/commands/npm-audit
- https://pypi.org/project/pip-audit/
- https://github.com/rustsec/rustsec/tree/main/cargo-audit

**Prioritisation**
- https://www.first.org/epss/
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- https://www.vulncheck.com/kev

**Local verification**
- `grep -n "Automatic-Reboot" /etc/apt/apt.conf.d/50unattended-upgrades` (commented out on
  unattended-upgrades 2.12ubuntu9, Ubuntu 26.04)
