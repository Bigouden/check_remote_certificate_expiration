# check_remote_certificate_expiration

```
>>> python3.8 check_remote_certificate_expiration.py -h
usage: check_remote_certificate_expiration.py [-h] [--port PORT]
                                              [--timeout TIMEOUT]
                                              [--warning WARNING]
                                              [--critical CRITICAL]
                                              [--insecure]
                                              [--smtp | --ldap]
                                              [--proxy PROXY]
                                              [--proxy-port PROXY_PORT]
                                              [--proxy-username PROXY_USERNAME]
                                              [--proxy-password PROXY_PASSWORD]
                                              [--proxy-user-agent PROXY_USER_AGENT]
                                              [--ehlo-hostname EHLO_HOSTNAME]
                                              host

positional arguments:
  host                  ssl protected server (ip or hostname)

optional arguments:
  -h, --help            show this help message and exit
  --port PORT           ssl port (default: 443)
  --timeout TIMEOUT     socket timeout (default: 5s)
  --warning WARNING     warning day(s) until expiration date (default: 60)
  --critical CRITICAL   critical day(s) until expiration date (default: 30)
  --insecure            insecure ssl (default: false)
  --smtp                smtp mode with starttls (default: false)
  --ldap                ldap mode with starttls (default: false)

PROXY:
  --proxy PROXY         http proxy server (ip or hostname)
  --proxy-port PROXY_PORT
                        http proxy port (default: 3128)
  --proxy-username PROXY_USERNAME
                        http proxy username (basic auth)
  --proxy-password PROXY_PASSWORD
                        http proxy password (basic auth)
  --proxy-user-agent PROXY_USER_AGENT
                        set custom user agent when using proxy (default: http-client)

SMTP:
  --ehlo-hostname EHLO_HOSTNAME
                        set custom ehlo hostname (default: smtp-client)
```
