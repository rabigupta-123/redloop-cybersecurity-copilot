# REDLOOP Enterprise Integrations Setup & Configuration Guide

This guide details configuration, credential resolution, health verification, and operational guidelines for connecting external security providers to REDLOOP.

---

## 1. Global Configuration Principles

REDLOOP resolves integration parameters with the following precedence:
1. Provider-specific environment variable: `REDLOOP_INTEGRATION_{PROVIDER}_{KEY}`
2. Generic environment variable: `{PROVIDER}_{KEY}`
3. Local file store: `~/.redloop/integrations.json`
4. Safe defaults / simulated offline mode

If credentials are not supplied, the adapter automatically initializes in `NOT_CONFIGURED` status and falls back to local simulation mode without interrupting application startup.

---

## 2. Environment Variable Reference

### 2.1 Wazuh SIEM / XDR Manager
| Parameter | Env Variable | Example Value | Description |
|-----------|--------------|---------------|-------------|
| API URL | `WAZUH_URL` or `REDLOOP_WAZUH_URL` | `https://wazuh.corp.local:55000` | Wazuh manager REST endpoint |
| Username | `WAZUH_USER` or `REDLOOP_WAZUH_USERNAME` | `wazuh-wui` | API user account |
| Password | `WAZUH_PASSWORD` or `REDLOOP_WAZUH_PASSWORD` | `SecretPass123` | API user password |
| SSL Verification | `WAZUH_VERIFY_SSL` | `true` | Enforce TLS cert validation |

### 2.2 Elastic Security SIEM
| Parameter | Env Variable | Example Value | Description |
|-----------|--------------|---------------|-------------|
| Cluster URL | `ELASTIC_URL` or `REDLOOP_ELASTIC_URL` | `https://es.corp.local:9200` | Elasticsearch base endpoint |
| API Key | `ELASTIC_API_KEY` or `REDLOOP_ELASTIC_API_KEY` | `V2FyZ2FtZXNBcGlLZXk...` | Base64-encoded Elastic API key |
| Username | `ELASTIC_USER` | `elastic` | Basic auth user (alternative to API key) |
| Password | `ELASTIC_PASSWORD` | `ElasticPass123` | Basic auth password |

### 2.3 Splunk Enterprise / Cloud SIEM
| Parameter | Env Variable | Example Value | Description |
|-----------|--------------|---------------|-------------|
| Host | `SPLUNK_HOST` or `REDLOOP_SPLUNK_HOST` | `splunk.corp.net` | Splunk search head hostname |
| Management Port | `SPLUNK_PORT` or `REDLOOP_SPLUNK_PORT` | `8089` | REST API management port |
| Auth Token | `SPLUNK_TOKEN` or `REDLOOP_SPLUNK_TOKEN` | `eyJhbGciOiJIUzI1Ni...` | Bearer/Splunk session token |

### 2.4 Microsoft Defender for Endpoint (MDE)
| Parameter | Env Variable | Example Value | Description |
|-----------|--------------|---------------|-------------|
| Tenant ID | `DEFENDER_TENANT_ID` | `11111111-2222-3333-4444-555555555555` | Microsoft Entra Directory ID |
| Client ID | `DEFENDER_CLIENT_ID` | `66666666-7777-8888-9999-000000000000` | Azure App Registration Client ID |
| Client Secret | `DEFENDER_CLIENT_SECRET` | `MySecretClientSecret` | App Registration Client Secret |

### 2.5 CrowdStrike Falcon
| Parameter | Env Variable | Example Value | Description |
|-----------|--------------|---------------|-------------|
| Client ID | `CROWDSTRIKE_CLIENT_ID` | `falcon_client_id_xyz` | CrowdStrike API client ID |
| Client Secret | `CROWDSTRIKE_CLIENT_SECRET` | `falcon_client_secret_xyz` | CrowdStrike API client secret |
| Base URL | `CROWDSTRIKE_BASE_URL` | `https://api.crowdstrike.com` | Regional Falcon API base URL |

### 2.6 Microsoft Entra ID (Azure AD)
| Parameter | Env Variable | Example Value | Description |
|-----------|--------------|---------------|-------------|
| Tenant ID | `ENTRA_TENANT_ID` | `11111111-2222-3333-4444-555555555555` | Entra Tenant ID |
| Client ID | `ENTRA_CLIENT_ID` | `66666666-7777-8888-9999-000000000000` | App Registration Client ID |
| Client Secret | `ENTRA_CLIENT_SECRET` | `EntraClientSecretValue` | App Registration Secret |

### 2.7 Active Directory (LDAP)
| Parameter | Env Variable | Example Value | Description |
|-----------|--------------|---------------|-------------|
| Server | `AD_SERVER` | `dc01.corp.local` | Domain Controller IP/hostname |
| Port | `AD_PORT` | `636` | LDAPS (636) or LDAP (389) |
| Bind DN | `AD_BIND_DN` | `CN=svc_redloop,OU=ServiceAccounts,DC=corp,DC=local` | Bind account DN |
| Bind Password | `AD_BIND_PASSWORD` | `LdapPassword123` | Bind account password |

### 2.8 Atlassian Jira
| Parameter | Env Variable | Example Value | Description |
|-----------|--------------|---------------|-------------|
| URL | `JIRA_URL` | `https://jira.enterprise.org` | Jira instance base URL |
| Username | `JIRA_USER` | `secops_bot` | Service account username |
| API Token | `JIRA_API_TOKEN` | `ATATT3xFfGF0...` | Jira API access token |

### 2.9 ServiceNow Table API
| Parameter | Env Variable | Example Value | Description |
|-----------|--------------|---------------|-------------|
| Instance URL | `SERVICENOW_URL` | `https://mycorp.service-now.com` | ServiceNow instance base URL |
| Username | `SERVICENOW_USER` | `snow_secops` | Integration username |
| Password | `SERVICENOW_PASSWORD` | `SnowPassword123` | Integration password |

---

## 3. Testing Provider Connectivity

Connectivity can be tested via the REST API or python CLI:

```bash
# Probing Wazuh health check
curl -X POST http://127.0.0.1:8765/api/integrations/wazuh/test

# Expected response (when unconfigured):
# {"success": true, "health": {"status": "NOT_CONFIGURED", "latency_ms": 0.0, "message": "Wazuh integration is not configured..."}}
```
