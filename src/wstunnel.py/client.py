import asyncio, logging
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

async def main(listen, uri, token):
    async def handler(reader, writer):
        return await conn_handler(reader, writer, uri, token)
    server = await asyncio.start_server(handler, listen[0], listen[1])
    async with server:
        logger.info(f"Listening on {listen!r}")
        await server.serve_forever()

if __name__ == "__main__":
    listen = ("127.0.0.1", 8080)
    uri = "ws://127.0.0.1:9090"
    token = "test"
    logLevel = logging.INFO
    logging.basicConfig(level=logLevel)
    asyncio.run(main(listen, uri, token))

