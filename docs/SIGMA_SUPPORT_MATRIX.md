# REDLOOP Sigma Detection Support Matrix

**Specification:** Sigma Specification v2.0  
**Engine:** `src/redloop/assessment/sigma_engine.py`  
**API Endpoint:** `GET /api/hunting/sigma/matrix`

---

## 1. Supported Log Sources & Categories

| Category | Typical Data Sources | Event Model Attribute Mapping |
|:---|:---|:---|
| `process_creation` | Sysmon Event ID 1, Linux auditd | `process_name`, `command_line`, `parent_process` |
| `webserver` | Apache / Nginx Combined Logs | `url`, `source_ip`, `status_code`, `raw_data` |
| `network_connection` | Sysmon Event ID 3, Suricata EVE | `source_ip`, `destination_ip`, `destination_port`, `protocol` |
| `authentication` | Linux `/var/log/auth.log`, Sysmon 4624/4625 | `username`, `source_ip`, `event_action` |
| `syslog` | Linux `/var/log/syslog` | `hostname`, `raw_data`, `command_line` |

---

## 2. Field Modifiers Support Matrix

| Modifier | Supported | Description / Behavior |
|:---|:---:|:---|
| `|contains` | **YES** | Case-insensitive substring search |
| `|startswith` | **YES** | Case-insensitive prefix match |
| `|endswith` | **YES** | Case-insensitive suffix match |
| `|re` | **YES** | Safe regular expression matching (ReDoS protected) |
| `|all` | **YES** | All items in the list must match |
| `|base64offset` | **YES** | Base64 encoded payload matching across 0, 1, and 2 byte offsets |
| `|windash` | *NO* | Planned for future release |
| `|cidr` | *NO* | Handled via IP normalization |
| `|expand` | *NO* | Dynamic placeholders not supported |

---

## 3. Condition Logic Capabilities

| Condition Feature | Supported | Safety Enforcement |
|:---|:---:|:---|
| Selection Identifiers | **YES** | `selection`, `filter` identifiers |
| Boolean Operators | **YES** | `and`, `or`, `not` |
| Grouping Parentheses | **YES** | Nested parentheses up to depth 3 |
| Quantifier `1 of them` | **YES** | Any selection evaluates to true |
| Quantifier `all of them` | **YES** | All selections evaluate to true |
| Quantifier `1 of selection*`| **YES** | Wildcard prefix matching over selection keys |
| Code Execution | **PROHIBITED** | Never uses Python `eval()` or `exec()` |
| ReDoS Protection | **YES** | Rejects nested repeat groups like `(a+)+` and `(a*)*` |

---

## 4. API Usage Examples

### Validating a Sigma Rule
```bash
curl -X POST http://127.0.0.1:8765/api/hunting/sigma/validate \
  -H "Content-Type: application/json" \
  -H "Origin: http://127.0.0.1:8765" \
  -d '{"rule_yaml": "title: Test Rule\nid: 12345\nstatus: stable\ndescription: Test\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: cmd.exe\n  condition: selection\nlevel: high"}'
```

### Testing a Rule Against Ingested Telemetry
```bash
curl -X POST http://127.0.0.1:8765/api/hunting/sigma/test \
  -H "Content-Type: application/json" \
  -H "Origin: http://127.0.0.1:8765" \
  -d '{"rule_yaml": "title: Web Shell\nid: ws-1\nstatus: stable\ndescription: Web shell\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    ParentImage|contains: w3wp\n    Image|endswith: cmd.exe\n  condition: selection\nlevel: critical"}'
```


---

## 5. Formal Compatibility & Error Classification

REDLOOP categorizes Sigma rules into explicit execution tiers:

1. **Parsed Successfully:** YAML structure conforms to mapping specification.
2. **Validated Successfully:** All required top-level fields (`id`, `title`, `status`, `description`, `logsource`, `detection`) present, supported modifiers validated, conditions syntax verified, and rule IDs checked for batch uniqueness.
3. **Supported for Evaluation:** Rules that pass validation and utilize supported field modifiers (`contains`, `startswith`, `endswith`, `re`, `all`, `base64offset`) and supported condition syntax.
4. **Unsupported:** Rules containing unhandled modifiers (`windash`, `cidr`, `expand`) or unmapped log sources. **These are explicitly reported with an error and never silently treated as non-matches.**
5. **Rejected as Unsafe or Malformed:**
   - Syntax/YAML errors
   - Missing condition block
   - Regex exceeding `MAX_REGEX_PATTERN_LENGTH = 200` characters
   - Regex with catastrophic backtracking patterns (nested quantifiers `(a+)+`, `(a*)*`, adjacent unbounded quantifiers)
   - Regex execution exceeding strict worker thread timeout (`100ms`)
