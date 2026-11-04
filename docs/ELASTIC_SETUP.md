# Elastic Security & Elasticsearch SIEM Integration Setup

## Overview

The REDLOOP Elastic Security Adapter connects to Elasticsearch 8.x and Kibana Detection Engine. It queries security detection alerts, searches logs using safe parameterized DSL, and transforms ECS (Elastic Common Schema) documents into REDLOOP Universal Security Events.

---

## 1. Capabilities Supported

- `READ_ALERTS`: Reads detection alerts from `.alerts-security.alerts-default*`.
- `SEARCH_EVENTS`: Executes bounded time-range queries against indices.

---

## 2. Configuration & Authentication

Supports either API Key authentication (`ApiKey <base64>`) or HTTP Basic authentication (`Basic <base64>`).

### Environment Variables
```bash
export ELASTIC_URL="https://elastic.corp.internal:9200"
export ELASTIC_API_KEY="V2FyZ2FtZXNBcGlLZXlWYWx1ZTEyMzQ1Njc4OTA="
# Alternative basic auth:
# export ELASTIC_USER="elastic"
# export ELASTIC_PASSWORD="YourElasticPassword"
```

---

## 3. Query DSL Safety Controls

All Elasticsearch queries are strictly bounded:
- Hard limit clamped to `size: 100` max per request.
- Default time filter on `@timestamp` (e.g. `now-7d/d`).
- Read-only queries only (`_search` API); write and destructive APIs (`_delete_by_query`, `_update`) are prohibited.
