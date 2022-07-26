# Jump_share_scanner
Scans for smb shares on the network and test if you can read and write to them.

```
jump_share_scanner -u gogo -p '123Admin123!!' -d light.local -t '192.168.1.176,192.168.1.177,192.168.1.178,192.168.1.159'
```

```
Error Reaching Host 192.168.1.176
Error Authenticating Host 192.168.1.177
Authentication to 192.168.1.178 Successful
Error Authenticating Host 192.168.1.159
### RESULTS ###
Host 192.168.1.176 is unreachable

Host 192.168.1.177 failed to authenticate with light.local\gogo
192.168.1.178
ADMIN$              READ/WRITE ACCESS
C$                  READ/WRITE ACCESS
DemoSystem          READ/WRITE ACCESS
IPC$                READ ACCESS
Materclass          READ/WRITE ACCESS
NETLOGON            READ/WRITE ACCESS
SYSVOL              NOT TESTED

Host 192.168.1.159 failed to authenticate with light.local\gogo

```


## Usage

```
usage: jump_share_scanner [-h|--help] -t|--target "<value>" [-P|--port
<integer>] [-u|--username "<value>"] [-p|--password
"<value>"] [-d|--domain "<value>"] [-f|--filename
"<value>"]

                          A share scanner that will detect and test network
                          shares.


-h  --help      Print help information
-t  --target    IPv4 to target. Single, CIDR, comma seperated
-P  --port      Port to scan for SMB Shares. Default: 445
-u  --username  Username to authenticate with. Default: guest
-p  --password  Password to authenticate with. Default:
-d  --domain    domain to authenticate with. Default: .
-f  --filename  name of the test file to write to disk (Useful for logging).
Default: .msds_info
```

### TODO
- [ ] File Output
- [ ] MultiThreading
- [ ] Timing
- [ ] Better Logging