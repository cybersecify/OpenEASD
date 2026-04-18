# Nuclei Network: Service-Aware Scan Design

**Date:** 2026-04-13  
**Status:** Approved  
**Scope:** `apps/nuclei_network/collector.py` only

---

## Problem

The current nuclei_network collector runs all 280 network templates against every non-web port regardless of what service is running on that port. This is slow and produces irrelevant findings (e.g., running Redis templates against an FTP port).

---

## Solution

Build the nuclei `-tags` flag dynamically from the `Port.service` field (set by service_detection). Run a single nuclei process per session with only the tags relevant to services actually discovered.

---

## Service → Tag Mapping

| nmap service name (partial match) | nuclei tags |
|-----------------------------------|-------------|
| `ftp` | `ftp` |
| `smtp`, `smtps` | `smtp` |
| `redis` | `redis` |
| `mysql` | `mysql` |
| `postgresql`, `postgres` | `postgresql` |
| `mongodb` | `mongodb` |
| `ldap`, `ldaps` | `ldap` |
| `vnc` | `vnc` |
| `rdp` | `rdp` |
| `elasticsearch` | `elasticsearch` |
| `memcached` | `memcached` |
| `smb`, `microsoft-ds` | `smb` |
| `mssql`, `ms-sql` | `mssql` |
| `cassandra` | `cassandra` |
| `rabbitmq`, `amqp` | `rabbitmq` |
| `ssh` | **skip** — owned by ssh_checker |

Always append: `misconfig,exposures,default-login,cves` as baseline tags regardless of services found.

**Fallback:** If no services match the mapping (e.g., service_detection didn't run or all services are unknown), use `["misconfig", "exposures", "default-login", "cves"]` only.

---

## Updated Command

```python
cmd = [BINARY, "-list", tmp,
       "-pt", "network,ssl",
       "-tags", ",".join(tags),          # dynamically built
       "-severity", "critical,high,medium,low",  # drop info noise
       "-jsonl", "-silent", "-no-color"]
```

---

## Files Changed

| File | Change |
|------|--------|
| `apps/nuclei_network/collector.py` | Add `_build_tags(ports)` function + update `collect()` to use it |

No other files change. analyzer.py, scanner.py, apps.py are untouched.

---

## Verification

1. Run an Infra Scan against a domain with known services (FTP, Redis, SMTP, etc.)
2. Check logs: `[nuclei_network:...] tags=ftp,smtp,redis,...`
3. Confirm findings are service-relevant (no Redis findings on FTP ports)
4. Confirm scan completes faster than the blanket approach
