# CMMC GCC-High Evidence Collector

Open-source pre-assessment readiness tool for small Defense Industrial Base (DIB) contractors on Microsoft 365 GCC-High. Point it at your tenant; get back a self-contained HTML dashboard, a raw JSON evidence snapshot, and a prioritized remediation backlog for NIST 800-171 r2 / CMMC Level 2.

Built for the common small-DIB shape: 3-10 users, macOS endpoints managed by Intune, Defender for Endpoint, a single GCC-High tenant.

## What it does

1. Authenticates to the GCC-High Graph API (`graph.microsoft.us`) as an app-only principal.
2. Collects evidence in parallel from:
   - **Azure AD / Entra ID** — users, MFA registration, privileged role membership, conditional-access policies, directory audit events, risky sign-ins, password policy.
   - **Intune** — macOS-filtered managed devices, compliance state, compliance policies.
   - **Defender for Endpoint** — vulnerabilities, alerts (past 90 days), Secure Score; falls back to Intune antivirus signals when Defender Graph surfaces are not available.
   - **Exchange Online** — mailbox inventory, DLP policies, directory-audit events scoped to Exchange.
3. Maps raw evidence to 18 NIST 800-171 r2 controls (`AC-1/2/3/6`, `IA-2/4/5`, `AU-2/3/6/12`, `SC-7`, `SI-2/3/4`, `IR-1/4`, `AT-1`) with per-control status (`COMPLIANT` / `PARTIAL` / `NOT_ADDRESSED`), evidence bullets, gaps, and remediation steps.
4. Writes three files to `./reports/`:
   - `compliance-report.html` — interactive dashboard.
   - `evidence.json` — raw evidence from all collectors.
   - `remediation-backlog.json` — tasks bucketed into `quick_win` / `medium` / `heavy_lift`.

See [`reports/sample-report.html`](reports/sample-report.html) for a preview (rendered from `tests/sample_data.json` — no real tenant data).

## Quick start

```bash
git clone https://github.com/decisivellc/gcc-cmmc-collector.git
cd gcc-cmmc-collector

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp config.template.json config.json
# Fill in tenant_id, client_id, client_secret — see SETUP.md

python main.py --config config.json --output ./reports
open reports/compliance-report.html
```

The `client_secret` can also be provided via the `CMMC_CLIENT_SECRET` environment variable, which overrides the value in `config.json` — useful when you keep the config file in source control but want the secret elsewhere.

## Azure app registration

You need an Entra (Azure AD) app registration in the GCC-High tenant with the following **Application** Graph permissions (admin consent required):

- `User.Read.All`
- `Directory.Read.All`
- `AuditLog.Read.All`
- `Policy.Read.All`
- `IdentityRiskEvent.Read.All`
- `DeviceManagementManagedDevices.Read.All`
- `DeviceManagementConfiguration.Read.All`
- `SecurityEvents.Read.All`
- `ThreatIndicators.Read.All`

Full step-by-step walkthrough: [`SETUP.md`](SETUP.md) and [`docs/app-registration-setup.md`](docs/app-registration-setup.md).

## Running the tests

```bash
pip install -r requirements.txt
python -m pytest -q
```

Fixtures in `tests/sample_data.json` drive the suite; no network access is required.

Render a fresh sample report from fixtures:

```bash
python tests/render_sample.py
```

## Project layout

```
main.py                     CLI entry, parallel collection, report generation
graph_client.py             MSAL auth + paginated GET against graph.microsoft.us
collectors/                 One module per system (Azure AD, Intune, Defender, Exchange)
mappers/nist_800_171.py     Raw evidence -> per-control status
templates/report.html       Jinja2 dashboard
tests/                      Fixtures and unit tests
docs/                       Setup, permissions, control mapping, FAQ
```

## Security notes

- `config.json` is gitignored; do not commit tenant secrets. `config.template.json` is the only version that should be in source control.
- The app registration needs only **read** permissions to produce this report.
- All Graph calls go to `https://graph.microsoft.us/v1.0`; the MSAL authority is `https://login.microsoftonline.us/{tenant_id}`. These are hard-coded defaults and configurable via `config.json`.

## License

[Apache 2.0](LICENSE).

## Contributing

Bug reports and PRs welcome at [github.com/decisivellc/gcc-cmmc-collector](https://github.com/decisivellc/gcc-cmmc-collector). Add fixtures to `tests/sample_data.json` when introducing new evidence signals.
