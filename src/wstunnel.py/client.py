import asyncio, logging, argparse, ssl, os, base64
import websockets
from base import async_copy, wrap_stream_writer
from totp import TOTP

logger = logging.getLogger(__name__)

async def conn_handler(reader, writer, args, totp_):
    peer_addr = writer.get_extra_info("peername")
    logger.info(f"Connection {peer_addr!r} open")
    add_params = {}
    if args.uri.startswith("wss://"):
        ssl_context = ssl.create_default_context(cafile=args.server_cert)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        if args.client_cert:
            ssl_context.load_cert_chain(args.client_cert)
        add_params["ssl"] = ssl_context
    if args.host:
        add_params["host"] = args.host
    extra_headers = {}
    if args.token:
        extra_headers["x-token"] = args.token
    if totp_:
        extra_headers["x-totp"] = totp_.now()
    async with websockets.connect(args.uri, extra_headers=extra_headers,
                                  user_agent_header="", **add_params) as ws:
        f_write, f_close_writer = wrap_stream_writer(writer)
        tasks = [asyncio.create_task(async_copy(lambda: reader.read(65536), ws.send,
                                                ws.close, True)),
                 asyncio.create_task(async_copy(ws.recv, f_write,
                                                f_close_writer, False))]
        await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)
    logger.info(f"Connection {peer_addr!r} closed")

async def main(args):
    totp_ = TOTP(args.totp_secret) if args.totp_secret else None
    async def handler(reader, writer):
        return await conn_handler(reader, writer, args, totp_)
    server = await asyncio.start_server(handler, args.listen[1], args.listen[2])
    async with server:
        logger.info(f"Listening on {args.listen!r}")
        await server.serve_forever()

if __name__ == "__main__":
    def parse_listen(listen):
        proto,rest = listen.split(":", 1)
        ip,port = rest.rsplit(":", 1)
        return proto,ip,int(port)
    parser = argparse.ArgumentParser(prog="Wstunnel client")
    parser.add_argument("--uri", required=True,
                        metavar="ws[s]://HOST:PORT", help="Server URI")
    parser.add_argument("--listen", "-l", default="tcp:127.0.0.1:8080",
                        metavar="tcp:IP:PORT", help="Listen address")
    parser.add_argument("--token", "-t")
    parser.add_argument("--server-cert", "-s", metavar="server.crt",
                        help="Server certificate")
    parser.add_argument("--client-cert", "-c", metavar="client.pem",
                        help="Client certificate with private key")
    parser.add_argument("--host", metavar="HOST",
                        help="Connect to HOST instead of the one in uri")
    parser.add_argument("--totp-secret", metavar="SECRET",
                        help="Base32 encoded secret")
    parser.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error", "critical"])
    args = parser.parse_args()
    if not args.uri.startswith("wss://") and not args.uri.startswith("ws://"):
        raise ValueError(f"Not a valid websocket uri: {uri}")
    if args.uri.startswith("ws://") and (args.server_cert or args.client_cert):
        raise ValueError("Use a URI beginning with wss:// to enable TLS")
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
    if args.token is not None and args.uri.startswith("ws://"):
        logger.warning("Sending token over insecure connection")
    print(f"Listening on {args.listen[1]}:{args.listen[2]}")
    asyncio.run(main(args))

