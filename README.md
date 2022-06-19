# pySpray

Lockout number and window aware password spraying tool.

This project was built out of necessity while looking for password spraying tools that take spraying limitations into account.

```
usage: LDAPspray.py [-h] -U USERS -P PASSWORDS -D DOMAIN -S SERVER -L LOCKOUT -W WINDOW [-v] [--debug]

LDAPSpray.py v.0.1 - LDAP password spraying tool

optional arguments:
  -h, --help            show this help message and exit
  -U USERS, --Users USERS
                        Text file of usernames
  -P PASSWORDS, --Passwords PASSWORDS
                        Text file of passwords
  -D DOMAIN, --Domain DOMAIN
                        Domain used in authentication
  -S SERVER, --Server SERVER
                        IP/Hostname of LDAP Server used in authentication
  -L LOCKOUT, --Lockout LOCKOUT
                        Lockout threshold of bad passwords, inclusive number
  -W WINDOW, --Window WINDOW
                        Window of time before lockout counter resets (in MINUTES)
  -v, --verbose         List all authentication attempts
  --debug               Debug activity

Written by m4lwhere - YOU ARE RESPONSIBLE FOR YOUR OWN ACTIONS WITH THIS TOOL
```