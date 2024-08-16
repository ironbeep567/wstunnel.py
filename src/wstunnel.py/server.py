import asyncio, logging, hmac, functools, argparse
import websockets, websockets.server
from base import async_copy, wrap_stream_writer

logger = logging.getLogger(__name__)

class WebSocketServerProtocol(websockets.server.WebSocketServerProtocol):
    def __init__(self, *args, token="", **kwargs):
        super().__init__(*args, **kwargs)
        self.token = token
    
    async def process_request(self, path, request_headers):
        if not hmac.compare_digest(self.token, request_headers.get("x-token", "")):
            logger.info(f"Connection {self.remote_address!r} auth failed")
            return 404, [], b""
        return await super().process_request(path, request_headers)

async def ws_handler(ws, backend):
    logger.info(f"Connection {ws.remote_address!r} accepted")
    reader,writer = await asyncio.open_connection(backend[1], backend[2])
    f_write, f_close_writer = wrap_stream_writer(writer)
    tasks = [asyncio.create_task(async_copy(ws.recv, f_write,
                                            f_close_writer, False)),
             asyncio.create_task(async_copy(lambda: reader.read(65536), ws.send,
                                            ws.close, True))]
    await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)
    logger.info(f"Connection {ws.remote_address!r} closed")

async def main(args):
    async def handler(ws):
        return await ws_handler(ws, args.backend)
    class ServerProtocol(WebSocketServerProtocol):
        __init__ = functools.partialmethod(WebSocketServerProtocol.__init__, token=args.token)
    async with websockets.serve(handler, args.listen[0], args.listen[1],
                                create_protocol=ServerProtocol,
                                server_header=""):
        await asyncio.Future() # Serve forever

if __name__ == "__main__":
    def parse_listen(listen):
        ip,port = listen.split(":")
        return ip,int(port)
    def parse_backend(backend):
        proto,rest = backend.split(":", 1)
        ip,port = rest.rsplit(":", 1)
        return proto,ip,int(port)
    parser = argparse.ArgumentParser(prog="Wstunnel server")
    parser.add_argument("--listen", "-l", required=True,
                        metavar="IP:PORT", help="Listen address")
    parser.add_argument("--backend", "-b", required=True,
                        metavar="tcp:IP:PORT", help="Backend address")
    parser.add_argument("--token", "-t")
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
    args.backend = parse_backend(args.backend)
    print(f"Listening on ws://{args.listen[0]}:{args.listen[1]}")
    asyncio.run(main(args))

