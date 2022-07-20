# jumptoolkit
 A collection of dropable biniaries for red teamers

---
To build

```
make windows
```

---
## Jump_ldap_scanner
An ldap scanner that find low hanging fruit:
- Kerberoastable Account
- AS-Reproasting
- Descriptions for users
- Members of High Value groups
### TODO
Add Old Passwords Flag
Add Support for finding machines with delegate powers
Better Domain Controller finder (Maybe us Global Catalog flag)
Add output file

## Jump_Port_scan
A port scanning tool that can be dropped on a victim computer

## Jump_PTR_Lookup
A DNS Bruteforce scanner that does a reverse IP lookup for every IP scanner.

## Jump_pipe_enum
???
