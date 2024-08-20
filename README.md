# WIP
# Usage
## Client
```
usage: Wstunnel client [-h] --uri ws[s]://HOST:PORT [--listen tcp:IP:PORT] [--token TOKEN] [--server-cert server.crt] [--client-cert client.pem]
                       [--host HOST] [--log-level {debug,info,warning,error,critical}]

options:
  -h, --help            show this help message and exit
  --uri ws[s]://HOST:PORT
                        Server URI
  --listen tcp:IP:PORT, -l tcp:IP:PORT
                        Listen address
  --token TOKEN, -t TOKEN
  --server-cert server.crt, -s server.crt
                        Server certificate
  --client-cert client.pem, -c client.pem
                        Client certificate with private key
  --host HOST           Connect to HOST instead of the one in uri
  --log-level {debug,info,warning,error,critical}
```
## Server
```
usage: Wstunnel server [-h] --listen IP:PORT --backend tcp:IP:PORT [--token TOKEN] [--server-cert server.pem] [--client-cert client.crt]
                       [--log-level {debug,info,warning,error,critical}]

options:
  -h, --help            show this help message and exit
  --listen IP:PORT, -l IP:PORT
                        Listen address
  --backend tcp:IP:PORT, -b tcp:IP:PORT
                        Backend address
  --token TOKEN, -t TOKEN
  --server-cert server.pem, -s server.pem
                        Server certificate with private key. This enables TLS.
  --client-cert client.crt, -c client.crt
                        Client certificate
  --log-level {debug,info,warning,error,critical}
```
