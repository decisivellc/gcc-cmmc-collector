# Azure App Registration for GCC-High

This is the same material as `SETUP.md` §2-3, with more detail on what each screen looks like and common pitfalls. If you have already completed setup, you can skip this file.

## 1. Navigate to the correct portal

GCC-High has **its own portal** — do not use `portal.azure.com` / `entra.microsoft.com`. Use:

- Entra admin center: <https://entra.microsoft.us>
- Azure portal: <https://portal.azure.us>

Sign in with an account in the GCC-High tenant that holds the **Global Administrator** role (or **Application Administrator** + **Privileged Role Administrator**).

## 2. Register the application

1. **Applications > App registrations > + New registration**
2. Name: `cmmc-gcc-evidence-collector` (any name works).
3. Supported account types: **Single tenant**.
4. Redirect URI: leave blank — this is a daemon / service app that uses the client-credentials flow.
5. Click **Register**.

On the Overview page you will see:

- **Application (client) ID** — copy to `config.json:client_id`.
- **Directory (tenant) ID** — copy to `config.json:tenant_id`.

## 3. Create a client secret

1. **Certificates & secrets > Client secrets > + New client secret**.
2. Description: `cmmc-collector`. Expires: 180 days (rotate via `az ad app credential reset` or re-add here).
3. **Copy the `Value` immediately** — Microsoft only shows it once. Paste into `config.json:client_secret`, or set `CMMC_CLIENT_SECRET` in the environment.

## 4. API permissions

1. **API permissions > + Add a permission > Microsoft Graph > Application permissions**.
2. Add each permission from the table in `SETUP.md` §3. Tip: use the search box.
3. After all permissions are added, click **Grant admin consent for `<tenant>`**.
4. Verify every row shows the green checkmark under Status.

If you do not see **Application permissions** as an option, you selected a non-Graph API; go back and pick **Microsoft Graph** explicitly.

## 5. Verify you can acquire a token

Quickest validation from the machine running the collector:

```bash
python - <<'PY'
import msal
app = msal.ConfidentialClientApplication(
    client_id="<your-client-id>",
    client_credential="<your-secret>",
    authority="https://login.microsoftonline.us/<your-tenant-id>",
)
print(app.acquire_token_for_client(scopes=["https://graph.microsoft.us/.default"]).get("token_type"))
PY
```

If you see `Bearer`, auth is working and you are ready to run `python main.py --config config.json`.

## Common pitfalls

- **"AADSTS700016" / "Application not found"** — the `tenant_id` or `client_id` is from the wrong tenant (likely a commercial Azure AD, not GCC-High).
- **"AADSTS90002"** — tenant ID does not exist at the GCC-High authority. Verify the authority in `config.json` is `https://login.microsoftonline.us` (US-Gov), not `https://login.microsoftonline.com` (commercial).
- **`403 Forbidden` on `/users`** — admin consent was not granted, or `User.Read.All` was added as *Delegated* instead of *Application*.
