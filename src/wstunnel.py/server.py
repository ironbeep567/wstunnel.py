import asyncio, logging, hmac, functools
import websockets, websockets.server
from base import async_copy, wrap_stream_writer

logger = logging.getLogger(__name__)

class WebSocketServerProtocol(websockets.server.WebSocketServerProtocol):
    def __init__(self, *args, token="", **kwargs):
        super().__init__(*args, **kwargs)
        self.token = token
    
    async def process_request(self, path, request_headers):
        if not hmac.compare_digest(token, request_headers.get("x-token", "")):
            logger.info(f"Connection {self.remote_address!r} auth failed")
            return 404, [], b""
        return await super().process_request(path, request_headers)

async def ws_handler(ws, backend):
    logger.info(f"Connection {ws.remote_address!r} accepted")
    reader,writer = await asyncio.open_connection(backend[0], backend[1])
    f_write, f_close_writer = wrap_stream_writer(writer)
    tasks = [asyncio.create_task(async_copy(ws.recv, f_write,
                                            f_close_writer, False)),
             asyncio.create_task(async_copy(lambda: reader.read(65536), ws.send,
                                            ws.close, True))]
    await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)
    logger.info(f"Connection {ws.remote_address!r} closed")

async def main(listen, backend, token):
    async def handler(ws):
        return await ws_handler(ws, backend)
    class ServerProtocol(WebSocketServerProtocol):
        __init__ = functools.partialmethod(WebSocketServerProtocol.__init__, token=token)
    async with websockets.serve(handler, listen[0], listen[1],
                                create_protocol=ServerProtocol,
                                server_header=""):
        await asyncio.Future() # Serve forever

if __name__ == "__main__":
    listen = ("127.0.0.1", 9090)
    backend = ("127.0.0.1", 9091)
    token = "test"
    logLevel = logging.INFO
    logging.basicConfig(level=logLevel)
    asyncio.run(main(listen, backend, token))

