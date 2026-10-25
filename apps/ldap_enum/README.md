# LDAP RootDSE metadata tool

This is a narrowly scoped **read-only** slice of #72, not the complete multi-service
enumeration phase. The plugin runs after `service_detection` (phase 7.5) and only
when `Port.service` identifies LDAP, the port is open TCP and `is_web=False`.

It invokes Nmap's `ldap-rootdse` NSE script (the Nmap "safe" discovery category)
using the Nmap binary already required by OpenEASD. It **does not** send
credentials, query user objects, attempt anonymous directory binds/searches, or
try passwords. It requires OpenEASD's existing domain authorization for active
scanning; the migration adds it only to the authorized **Full Scan** workflow.

An informational Finding is stored if useful root DSE fields are returned. Its
text explicitly says that ordinary root DSE disclosure is **not proof** of a
vulnerability or anonymous directory access. Only a small allowlist of fields
is persisted (LDAP versions, naming contexts, SASL capability, vendor).
Unsuccessful probes are not reported as clean results. Malformed XML is
skipped; no raw LDAP response is stored. There are no new database tables or
third-party Python dependencies.

## Limitations

- This does **not** implement SMB, SNMP, FTP, database, or other #72 services.
- Not a test of LDAP anonymous authentication or credential strength.
- Nmap XML result fields vary by server; a valid response may produce no
  finding if no allowlisted metadata is present.
- Successful checks against multiple hosts with other hosts failing log a
  warning; they do not automatically make the entire workflow partial.
- Real-server validation requires a separately authorized test environment.
