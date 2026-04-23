# GCC-High Graph API Permissions

All permissions below are **Application** (not Delegated), requested on Microsoft Graph in the GCC-High tenant. All require admin consent.

| Permission | Used by | Graph endpoints touched |
|---|---|---|
| `User.Read.All` | azure_ad | `/users`, `/users/{id}/registeredDevices` |
| `Directory.Read.All` | azure_ad | `/directoryRoles`, `/directoryRoles/{id}/members`, `/organization` |
| `AuditLog.Read.All` | azure_ad, exchange | `/auditLogs/directoryAudits` |
| `Policy.Read.All` | azure_ad | `/identity/conditionalAccess/policies`, `/policies/authorizationPolicy` |
| `IdentityRiskEvent.Read.All` | azure_ad | `/identity/riskDetections` |
| `DeviceManagementManagedDevices.Read.All` | intune, defender | `/deviceManagement/managedDevices` |
| `DeviceManagementConfiguration.Read.All` | intune | `/deviceManagement/deviceCompliancePolicies`, `.../deviceStatuses` |
| `SecurityEvents.Read.All` | defender | `/security/alerts`, `/security/secureScores` |
| `ThreatIndicators.Read.All` | defender | `/security/vulnerabilities` |

## GCC-High endpoint differences

The sovereign US-Gov cloud uses different hostnames than commercial Azure. The collector uses these defaults:

- Authority: `https://login.microsoftonline.us`
- Graph base URL: `https://graph.microsoft.us/v1.0`
- Scope: `https://graph.microsoft.us/.default`

Microsoft may rename these in the future. They are configurable via `config.json:authority` and `config.json:graph_base_url`.

## Permissions **not** requested

The tool intentionally does not request any write permissions. If a future release adds remediation automation (e.g., auto-disabling inactive accounts) it would need additional Application permissions such as `User.ReadWrite.All` — that would be a breaking change gated by a config flag.

## Things still unreachable via Graph on GCC-High

Some signals are either not exposed on GCC-High or require different product licensing. When these are missing, the collector records a fallback note rather than failing:

- **Exchange mailbox audit configuration** — requires Security & Compliance PowerShell (`Connect-IPPSSession`). The tool flags `exchangeAuditLog.logsAvailable = false` when nothing comes back.
- **DLP rule match counts** — exported via Purview, not Graph.
- **Per-mailbox audit record counts** — same as above.
