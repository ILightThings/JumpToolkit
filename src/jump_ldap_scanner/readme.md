# Jump_ldap_scanner

ID high value targets and find vulnerabilites in active directory using LDAP

```
jump_ldap_scanner.exe -u gogo -d light.local -t '192.168.1.178' -p '123Admin123!!'
```

```
---Members of High Value Groups---
#DOMAIN ADMINS#
[High Value] [User] Administrator [Pass not expire]
[High Value] [User] Golang Test
[High Value] [User] HUGH_WILLIAM
[High Value] [User] BRIANA_PEREZ [AS-RepRoastable]

#Administrators#
[High Value] [User] Administrator [Pass not expire]
[High Value] [Group] Enterprise Admins
[High Value] [Group] Domain Admins
[High Value] [User] ULYSSES_BURNS
[High Value] [User] RUSTY_OWENS

#Enterprise Admins#
[High Value] [User] Administrator [Pass not expire]

---Exploitable Accounts---
#Kerberoastable Users
[User] krbtgt [Kerberoastable]
[User] MALLORY_CHASE [Kerberoastable]
[User] TRICIA_MEYER [Kerberoastable] [AS-RepRoastable]
[User] AMELIA_BLAIR [Kerberoastable]
[User] ALICIA_AGUIRRE [Kerberoastable]
[User] LATASHA_DOUGLAS [Kerberoastable]
[User] DANNY_SHORT [Kerberoastable]
[User] COREY_FREDERICK [Kerberoastable] [AS-RepRoastable]

#AS-Reproastable Users
[User] OCTAVIO_BARRETT [Kerberoastable] [AS-RepRoastable]
[User] CHRISTOPER_WOODARD [AS-RepRoastable]
[User] SCOTTIE_FOREMAN [AS-RepRoastable]
[User] SETH_PAGE [AS-RepRoastable]
[User] 8606848964SA [AS-RepRoastable]
[User] ROSALIND_MULLINS [AS-RepRoastable]
[User] SONDRA_CAREY [AS-RepRoastable]
[High Value] [User] BRIANA_PEREZ [AS-RepRoastable]
[User] LAVERNE_BUTLER [AS-RepRoastable]
[User] BEATRIZ_VAUGHN [AS-RepRoastable]
[User] ADELA_CAREY [AS-RepRoastable]
[User] DEAN_ODONNELL [Kerberoastable] [AS-RepRoastable]
[User] JACKIE_CASTRO [AS-RepRoastable]
[User] CARMELLA_HURST [AS-RepRoastable]

---Informational---
#Users with passwords that don't expire
[High Value] [User] Administrator [Pass not expire]
[High Value] [User] Administrator [Pass not expire]
[User] Guest [Pass not expire]
[User] Guest [Pass not expire]

#Users with descriptions
Administrator - Built-in account for administering the computer/domain
Guest - Built-in account for guest access to the computer/domain
krbtgt - Key Distribution Center Service Account
OLIN_RIVERS - Just so I dont forget my password is #UwUJZyYR!f!hMi!WAz9B8f
TORY_FARLEY - Just so I dont forget my password is UFcmTc4RqebVCfBbf!2vZU#



# Domain Objects with password policies
---Fine Grained---
CN=CleanGetAway,CN=Password Settings Container,CN=System,DC=light,DC=local
Lockout Theshold: 2
Lockout Duration: 100
Lockout Observation: 30

        Password Minimum Length: 7
        Password Minimum Age: 1
        Password Maximum Age: 42
        Password Complexity: TRUE

        Policy Priority: 2
        Policy Applies to:
                CN=Teir1people,OU=Tier 1,DC=light,DC=local

---DC default policy (potentally default)---
DC=light,DC=local
Lockout Theshold: 0
Lockout Duration: 30
Lockout Observation: 30

        Password Minimum Length: 7
        Password Minimum Age: 1
        Password Maximum Age: 42

CN=Builtin,DC=light,DC=local
Lockout Theshold: 0
Lockout Duration: 30
Lockout Observation: 30

        Password Minimum Length: 0
        Password Minimum Age: 0
        Password Maximum Age: 42
```

## Usage
```
usage: jump_port_scan [-h|--help] -u|--username "<value>" -p|--password    
                      "<value>" -d|--domain "<value>" -t|--jump_ldap-server
                      "<value>" [-P|--port <integer>]                      
                                                                           
                      A quick, concurrent port scanner, that can be dropped
                      onto a victim machine and ran.                       

Arguments:

  -h  --help              Print help information
  -u  --username
  -p  --password
  -d  --domain            DNS name of domain. Example: paperproducts.local
  -t  --jump_ldap-server  IP of LDAP Server
  -P  --port

```