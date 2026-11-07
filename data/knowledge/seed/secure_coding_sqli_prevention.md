---
title: "Secure Coding: SQL Injection Prevention Across Languages"
tags: ["secure-coding", "sqli", "python", "database", "parameterization"]
source: "OWASP SQL Injection Prevention Cheat Sheet / CWE-89"
---

# Secure Coding: SQL Injection Prevention Across Languages
## Source & Authority
OWASP SQL Injection Prevention Cheat Sheet; Common Weakness Enumeration CWE-89.

## Code Implementations
### Python (sqlite3 / psycopg2)
```python
# VULNERABLE: String formatting allows SQL injection
cursor.execute(f"SELECT * FROM users WHERE username = '{user}'")

# SECURE: Parameterized placeholder (tuple binding)
cursor.execute("SELECT * FROM users WHERE username = ?", (user,))
```

### Node.js (pg / mysql2)
```javascript
// SECURE: Parameterized query array
const res = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
```
