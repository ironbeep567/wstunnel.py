Tunnel your traffic through websocket.

# Features
- Multiple backends
- mTLS
- Shared secret authentication
- TOTP authentication

# Demo
Create an echo server that listens to `127.0.0.1:9091`.
```
ncat -vkl 127.0.0.1 9091 -e /usr/bin/cat
```
And create a wstunnel server that listens to `127.0.0.1:9090`. Path `/a` is assigned to the echo server.
```
python3 server.py -l 127.0.0.1:9090 -b /a:tcp:127.0.0.1:9091 -t SECRET
```
To access the echo server, create a wstunnel client.
```
TOKEN=SECRET python3 client.py --listen tcp:127.0.0.1:8080 --uri ws://127.0.0.1:9090/a
```
Connect to the wstunnel client, and type anything. You should see it echoes back.
```
ncat 127.0.0.1 8080
```

# Usage
## Client
```
usage: Wstunnel client [-h] --uri ws[s]://HOST:PORT [--listen tcp:IP:PORT] [--token TOKEN] [--server-cert server.crt] [--client-cert client.pem]
                       [--host HOST] [--totp-secret TOTP_SECRET] [--log-level {debug,info,warning,error,critical}]

options:
  -h, --help            show this help message and exit
  --uri ws[s]://HOST:PORT
                        Server URI
  --listen tcp:IP:PORT, -l tcp:IP:PORT
                        Listen address
  --token TOKEN, -t TOKEN
                        Secret token for authentication. This overrides the TOKEN env variable.
  --server-cert server.crt, -s server.crt
                        Server certificate
  --client-cert client.pem, -c client.pem
                        Client certificate with private key
  --host HOST           Connect to HOST instead of the one in uri
  --totp-secret TOTP_SECRET
                        Base64 encoded secret for time based OTP. This overrides the TOTP_SECRET_BASE64 env variable.
  --log-level {debug,info,warning,error,critical}
```
## Server
```
usage: Wstunnel server [-h] --listen IP:PORT --backend /PATH:tcp:IP:PORT [/PATH:tcp:IP:PORT ...] [--token TOKEN] [--server-cert server.pem]
                       [--client-cert client.crt] [--totp-secret TOTP_SECRET] [--log-level {debug,info,warning,error,critical}]

options:
  -h, --help            show this help message and exit
  --listen IP:PORT, -l IP:PORT
                        Listen address
  --backend /PATH:tcp:IP:PORT [/PATH:tcp:IP:PORT ...], -b /PATH:tcp:IP:PORT [/PATH:tcp:IP:PORT ...]
                        Backend address
  --token TOKEN, -t TOKEN
                        Secret token for authentication. This overrides the TOKEN env variable.
  --server-cert server.pem, -s server.pem
                        Server certificate with private key. This enables TLS.
  --client-cert client.crt, -c client.crt
                        Client certificate
  --totp-secret TOTP_SECRET
                        Base64 encoded secret for time based OTP. This overrides the TOTP_SECRET_BASE64 env variable.
  --log-level {debug,info,warning,error,critical}
```
## Tools
Script for generating and signing ca/server/client certificates is available under `tools/`. You may modify it to fit your own needs before running it.

