# FAQ

## `401 Unauthorized` on every request

MSAL acquired a token successfully but Graph rejected it. Common causes:

- Client secret was rotated or expired — generate a new one under **Certificates & secrets** and update `config.json` (or `CMMC_CLIENT_SECRET`).
- You used a token from the **commercial** Azure cloud (`login.microsoftonline.com`) against the GCC-High Graph. Verify `authority` in `config.json` is `https://login.microsoftonline.us`.
- The tenant ID in `config.json` belongs to a different tenant than the app registration.

## `403 Forbidden` on `/users` (or any other endpoint)

Admin consent is missing for the required **Application** Graph permission. Open the app registration in the GCC-High portal, go to **API permissions**, and click **Grant admin consent for `<tenant>`**. Every permission must show the green "Granted" state.

If you added the permission as **Delegated** by mistake, remove it and re-add as **Application**.

## `429 Too Many Requests` / slow runs

The collector retries 429 responses once, respecting `Retry-After`. Large tenants (100+ users or devices) may still hit throttling — rerun the collector a few minutes later. We do not currently run collectors with exponential backoff beyond one retry; contributions welcome.

## Defender endpoints return empty / 404

Defender for Endpoint licensing and Graph surface coverage vary between GCC-High tenants. If `/security/vulnerabilities` or `/security/alerts` is unavailable, the collector falls back to Intune `managedDevices.windowsProtectionState` to produce an antivirus health signal. You will see a note like `source: "Intune managedDevices (Defender fallback)"` in `evidence.json`.

## Exchange audit shows `logsAvailable: false`

The Exchange Graph surface on GCC-High is intentionally limited for many tenants. The collector looks for Exchange-scoped directory-audit events; when there are none it writes `logsAvailable: false` with a `reason`. For full Exchange audit coverage, export from Microsoft Purview or use the Security & Compliance PowerShell module.

## Can the tool fix things automatically?

Not in the current release. The app registration only requests **read** permissions by design. Remediation steps are listed in `compliance-report.html` and `remediation-backlog.json` so a human can apply them.

## What Python version do I need?

3.10 or newer. The codebase uses PEP 604 union syntax (`str | None`) and `concurrent.futures.ThreadPoolExecutor`.

## How do I keep the report up to date?

Re-run `python main.py --config config.json` on whatever cadence suits your risk tolerance. GitHub Actions or cron are fine. The `config.json` `schedule` block is documentation only — it does not run anything on its own.

## Is the report enough to pass a C3PAO assessment?

No. This is a **pre-assessment** readiness tool. A C3PAO needs:

- Documented policies (IR plan, access control policy, training records).
- Evidence of process execution, not just configuration state.
- Interview-based verification.

Use this report to close automated-signal gaps before engaging a C3PAO, and to keep your posture measurable between formal assessments.
