# Automate Entra app-registration provisioning

## Problem

First-time setup currently requires ~20 minutes of manual clicking through the GCC-High Entra admin center: create the app registration, copy tenant/client IDs, mint a client secret, add 10 Graph permissions, and grant admin consent. The README and the login-page "How do I find these?" panel document the flow, but every new operator/tenant has to repeat it by hand, and human error (missing a permission, forgetting to grant consent) is the #1 cause of `403` errors when the collector actually runs.

## Goal

Let an operator bootstrap the full app registration — name, secret, all 10 permissions, admin consent — in a single interactive step, with no manual Entra portal clicks.

## Proposed shape

Add a CLI subcommand (and eventually a web UI "Bootstrap" button) that runs Microsoft's **device-code OAuth flow** as a privileged user, then uses the resulting token to drive Microsoft Graph.

```bash
python main.py bootstrap --tenant-domain decisivellc.onmicrosoft.us
```

1. Print: *"Open https://microsoft.com/devicelogin in a browser and enter code **XYZ-123**. Sign in as a Global Administrator (with PIM activated if applicable)."*
2. Poll for token. Once acquired:
   - `POST /applications` — create the `cmmc-gcc-evidence-collector` app with `requiredResourceAccess` pre-populated (Microsoft Graph `00000003-0000-0000-c000-000000000000` + all 10 role IDs).
   - `POST /applications/{id}/addPassword` — mint a client secret with configurable TTL (default 180 days).
   - `POST /servicePrincipals` — create the service principal for the app if it doesn't exist.
   - For each required app role: `POST /servicePrincipals/{graph-sp-id}/appRoleAssignedTo` to grant admin consent programmatically.
3. Write `tenant_id` and `client_id` to `config.json`. Either print the secret once (CLI flow) or hand it directly to the running Flask process's in-memory secret store (web flow) and never display it.

## Permissions needed by the bootstrapper itself

The **user** signing in must hold one of:
- Global Administrator
- Application Administrator + Privileged Role Administrator

The **scopes** requested in the device-code flow:
- `Application.ReadWrite.All` — create/update the app registration.
- `AppRoleAssignment.ReadWrite.All` — grant admin consent via appRoleAssignedTo.
- `Directory.ReadWrite.All` — fallback for service-principal operations.

No new service principal is required to bootstrap — we ride on Azure CLI's / MSAL's default public client ID (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`) for device-code auth, so there's nothing to pre-create.

## Graph reference

- `POST /v1.0/applications` — app registration. Body includes `requiredResourceAccess`.
- `POST /v1.0/applications/{id}/addPassword` — mint secret.
- `POST /v1.0/servicePrincipals` — create SP for the new app.
- `POST /v1.0/servicePrincipals/{resource-sp-id}/appRoleAssignedTo` — grant admin consent for each role (principalId = new SP's id, resourceId = Graph SP's id, appRoleId = the role GUID).
- `GET /v1.0/servicePrincipals?$filter=appId eq '00000003-0000-0000-c000-000000000000'` — resolve Microsoft Graph's SP id to use as `resourceId`.

## Risks / tradeoffs

- **Bootstrap token is high-privilege**. An attacker who intercepts it during device-code auth can create arbitrary apps and grant arbitrary consent. Mitigation: short token lifetime, never persist the token, document that the user should sign out after bootstrap.
- **Audit footprint**. Programmatic app creation shows up in the Entra audit log as the signed-in user, same as a manual click, so no concealment concern.
- **Idempotency**. If `cmmc-gcc-evidence-collector` already exists, we have to decide: update in place, rotate the secret, or error out. First version should error out and print instructions.
- **GCC-High specifics**. All endpoints live under `graph.microsoft.us` and `login.microsoftonline.us`. Device-code auth against the US-Gov authority works identically to commercial; just different hostnames.
- **Web-UI version adds a persistence concern**. If the "Bootstrap" button is in the Flask app, the privileged token briefly lives in the Flask process. The CLI version avoids this. Do the CLI first.

## Acceptance criteria

- `python main.py bootstrap` from a clean tenant produces a working app registration end-to-end with zero Entra portal clicks.
- Running `python main.py --config config.json --output ./reports` immediately afterward succeeds.
- If the app registration already exists, the command exits non-zero with a clear error.
- Unit tests for the Graph-call sequences (mocked) covering success + "app already exists" + "permission not granted" paths.
- README updated with a `bootstrap` section; SETUP.md notes this as the recommended first step.

## Estimate

150&ndash;250 LOC in a new `bootstrap.py` module + tests + docs. ~1 day.

## Priority

**Medium.** Not blocking for a single-tenant user who has already done the manual setup. Unblocks multi-tenant onboarding and reduces the error surface for new operators.
