import asyncio, logging, hmac, functools, argparse, ssl, os, base64
import websockets, websockets.server
from base import async_copy, wrap_stream_writer
from totp import TOTP

logger = logging.getLogger(__name__)

class WebSocketServerProtocol(websockets.server.WebSocketServerProtocol):
    def __init__(self, *args, token="", totp_secret=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._token = token
        self._totp = TOTP(totp_secret) if totp_secret else None
    
    async def process_request(self, path, request_headers):
        if self._token and not hmac.compare_digest(self._token, request_headers.get("x-token", "")):
            logger.info(f"Connection {self.remote_address!r} auth failed (TOKEN)")
            return 404, [], b""
        if self._totp and not self._totp.vaildate_now(request_headers.get("x-totp", "")):
            logger.info(f"Connection {self.remote_address!r} auth failed (TOTP)")
            return 404, [], b""
        return await super().process_request(path, request_headers)

async def ws_handler(ws, backends):
    logger.info(f"Connection {ws.remote_address!r} accepted")
    if not (backend := backends.get(ws.path, None)):
        logger.info(f"Connection {ws.remote_address!r} closed")
        return
    reader,writer = await asyncio.open_connection(backend[1], backend[2])
    f_write, f_close_writer = wrap_stream_writer(writer)
    tasks = [asyncio.create_task(async_copy(ws.recv, f_write,
                                            f_close_writer, False)),
             asyncio.create_task(async_copy(lambda: reader.read(65536), ws.send,
                                            ws.close, True))]
    await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)
    logger.info(f"Connection {ws.remote_address!r} closed")

async def start(args):
    async def handler(ws):
        return await ws_handler(ws, args.backend)
    class ServerProtocol(WebSocketServerProtocol):
        __init__ = functools.partialmethod(WebSocketServerProtocol.__init__,
                                           token=args.token,
                                           totp_secret=args.totp_secret)
    if args.server_cert:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.options |= ssl.OP_NO_TICKET
        ssl_context.load_cert_chain(args.server_cert)
        if args.client_cert:
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            ssl_context.load_verify_locations(args.client_cert)
        ssl_params = {"ssl": ssl_context}
    else:
        ssl_params = {}
    async with websockets.serve(handler, args.listen[0], args.listen[1],
                                create_protocol=ServerProtocol,
                                server_header="",
                                **ssl_params):
        await asyncio.Future() # Serve forever

def main():
    def parse_listen(listen):
        ip,port = listen.split(":")
        return ip,int(port)
    def parse_backends(backends):
        d = {}
        for backend in backends:
            path,proto,ip,port = backend.rsplit(':', 3)
            if not path.startswith('/'):
                path = "/" + path
            port = int(port)
            d[path] = (proto,ip,port)
        return d
    parser = argparse.ArgumentParser(prog="Wstunnel server")
    parser.add_argument("--listen", "-l", required=True,
                        metavar="IP:PORT", help="Listen address")
    parser.add_argument("--backend", "-b", required=True, nargs='+',
                        metavar="/PATH:tcp:IP:PORT", help="Backend address")
    parser.add_argument("--token", "-t", help="Secret token for authentication. This overrides the TOKEN env variable.")
    parser.add_argument("--server-cert", "-s", metavar="server.pem",
                        help="Server certificate with private key. This enables TLS.")
    parser.add_argument("--client-cert", "-c", metavar="client.crt",
                        help="Client certificate")
    parser.add_argument("--totp-secret",
                        help="Base32 encoded secret for time based OTP. This overrides the TOTP_SECRET_BASE32 env variable.")
    parser.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error", "critical"])
    args = parser.parse_args()
    if args.client_cert and not args.server_cert:
        raise ValueError("Use --server-cert to enable TLS")
    if args.log_level == "debug":
        logging.basicConfig(level=logging.DEBUG)
    elif args.log_level == "warning":
        logging.basicConfig(level=logging.WARNING)
    elif args.log_level == "error":
        logging.basicConfig(level=logging.ERROR)
    elif args.log_level == "critical":
        logging.basicConfig(level=logging.CRITICAL)
    else:
        logging.basicConfig(level=logging.INFO)
    if args.token is None:
        args.token = os.environ.get("TOKEN", None)
    if args.totp_secret is None:
        args.totp_secret = os.environ.get("TOTP_SECRET_BASE32", None)
    if args.totp_secret:
        args.totp_secret = base64.b32decode(args.totp_secret)
    args.listen = parse_listen(args.listen)
    args.backend = parse_backends(args.backend)
    if args.server_cert:
        print(f"Listening on wss://{args.listen[0]}:{args.listen[1]}")
    else:
        print(f"Listening on ws://{args.listen[0]}:{args.listen[1]}")
    asyncio.run(start(args))

if __name__ == "__main__":
    main()
