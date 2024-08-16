import asyncio, logging, argparse
import websockets
from base import async_copy, wrap_stream_writer

logger = logging.getLogger(__name__)

async def conn_handler(reader, writer, uri, token):
    peer_addr = writer.get_extra_info("peername")
    logger.info(f"Connection {peer_addr!r} open")
    async with websockets.connect(uri, extra_headers={"x-token":token}, user_agent_header="p") as ws:
        f_write, f_close_writer = wrap_stream_writer(writer)
        tasks = [asyncio.create_task(async_copy(lambda: reader.read(65536), ws.send,
                                                ws.close, True)),
                 asyncio.create_task(async_copy(ws.recv, f_write,
                                                f_close_writer, False))]
        await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)
    logger.info(f"Connection {peer_addr!r} closed")

async def main(args):
    async def handler(reader, writer):
        return await conn_handler(reader, writer, args.uri, args.token)
    server = await asyncio.start_server(handler, args.listen[1], args.listen[2])
    async with server:
        logger.info(f"Listening on {args.listen!r}")
        await server.serve_forever()

if __name__ == "__main__":
    def parse_listen(listen):
        proto,rest = listen.split(":", 1)
        ip,port = rest.rsplit(":", 1)
        return proto,ip,int(port)
    def validate_ws_uri(uri):
        if not uri.startswith("wss://") and not uri.startswith("ws://"):
            raise ValueError(f"Not a valid websocket uri: {uri}")
    parser = argparse.ArgumentParser(prog="Wstunnel client")
    parser.add_argument("--uri", required=True,
                        metavar="ws[s]://HOST:PORT", help="Server URI")
    parser.add_argument("--token", "-t")
    parser.add_argument("--listen", "-l", default="tcp:127.0.0.1:8080",
                        metavar="tcp:IP:PORT", help="Listen address")
    parser.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error", "critical"])
    args = parser.parse_args()
    if args.log_level == "debug":
        logLevel = logging.DEBUG
    elif args.log_level == "warning":
        logLevel = logging.WARNING
    elif args.log_level == "error":
        logLevel = logging.ERROR
    elif args.log_level == "critical":
        logLevel = logging.CRITICAL
    else:
        logLevel = logging.INFO
    logging.basicConfig(level=logLevel)
    args.listen = parse_listen(args.listen)
    validate_ws_uri(args.uri)
    if args.token is not None and args.uri.startswith("ws://"):
        logger.warning("Sending token over insecure connection")
    print(f"Listening on {args.listen[1]}:{args.listen[2]}")
    asyncio.run(main(args))

