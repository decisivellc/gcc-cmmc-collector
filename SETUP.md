# Setup

Complete end-to-end setup for a GCC-High tenant. Time: ~20 minutes.

## 1. Prerequisites

- GCC-High Microsoft 365 tenant (`login.microsoftonline.us`).
- An account with **Global Administrator** or **Application Administrator** + **Privileged Role Administrator** to create and consent the app registration.
- Python 3.10 or newer on the machine running the collector.

## 2. Create the app registration

Walk through each step in the Entra admin center for GCC-High (`https://entra.microsoft.us`):

1. **Entra admin center > Applications > App registrations > New registration**
   - Name: `cmmc-gcc-evidence-collector`
   - Supported account types: **Accounts in this organizational directory only** (single tenant)
   - Redirect URI: *(leave blank — this is a daemon app)*
   - Click **Register**.
2. Copy **Application (client) ID** and **Directory (tenant) ID** from the Overview page into `config.json`.
3. **Certificates & secrets > New client secret**
   - Description: `cmmc-collector`, expiry: 180 days (rotate regularly).
   - Copy the *Value* **before** leaving the page into `config.json` as `client_secret` (or set `CMMC_CLIENT_SECRET` env var).

## 3. Grant API permissions

Under **API permissions > Add a permission > Microsoft Graph > Application permissions**, add all of the following. After adding, click **Grant admin consent for `<tenant>`**.

| Permission | Why |
|---|---|
| `User.Read.All` | Enumerate user accounts, sign-in activity |
| `Directory.Read.All` | Read directory roles and role membership |
| `AuditLog.Read.All` | Read `/auditLogs/directoryAudits` |
| `Policy.Read.All` | Read conditional-access and authorization policies |
| `IdentityRiskEvent.Read.All` | Read risky sign-in detections |
| `DeviceManagementManagedDevices.Read.All` | Read Intune device inventory |
| `DeviceManagementConfiguration.Read.All` | Read Intune compliance policies |
| `SecurityEvents.Read.All` | Read Secure Score, Defender alerts |
| `ThreatIndicators.Read.All` | Read Defender vulnerability data |
| `Sites.Read.All` | Read SharePoint policy document library |

All permissions must show **Status: Granted for `<tenant>`**. Missing consent is the most common cause of `403` errors.

### Optional: policies collector

If you enable the `policies` collector (on by default), set `collectors.policies.site_url` in `config.json` to the URL of your SharePoint document library holding NIST 800-171 policy docs. The URL from the SharePoint browser address bar works, e.g.:

```
https://contoso.sharepoint.us/IT%20Policies/Forms/AllItems.aspx
```

The collector matches filenames against keywords for each `-1` control (e.g. "Access Control Policy.pdf" → AC-1). Leave `site_url` blank to skip; unmatched controls then show as `NOT_ADDRESSED` with a "library not configured" note.

## 4. Fill in `config.json`

```bash
cp config.template.json config.json
```

Edit the three required fields:

```json
{
  "tenant_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  "client_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
  "client_secret": "..."
}
```

The `authority` and `graph_base_url` fields default to the GCC-High endpoints; leave them as-is unless Microsoft changes the sovereign-cloud URL.

## 5. Install and run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python main.py --config config.json --output ./reports
```

Expected run time: 10-60 seconds depending on tenant size. Progress appears as log lines prefixed with `cmmc.main`.

Open the report in a browser:

```bash
open reports/compliance-report.html   # macOS
xdg-open reports/compliance-report.html  # Linux
```

## 6. Troubleshooting

See [`docs/faq.md`](docs/faq.md) for common errors (401, 403, throttling, Defender licensing).
