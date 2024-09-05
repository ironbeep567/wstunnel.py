import asyncio, logging
import websockets.exceptions

logger = logging.getLogger(__name__)

TOKEN_HDR = "x-token"
TOTP_HDR = "x-totp"

def wrap_stream_writer(writer):
    async def f_write(data):
        writer.write(data)
        await writer.drain()
    async def f_close_writer():
        writer.close()
        await writer.wait_closed()
    return f_write, f_close_writer

async def async_copy(f_read, f_write, f_close_writer, stop_read_if_empty):
    try:
        while True:
            logger.debug(f"reading")
            data = await f_read()
            if stop_read_if_empty and not data:
                break
            logger.debug(f"writing")
            await f_write(data)
    except websockets.exceptions.ConnectionClosedOK:
        pass
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logger.info(repr(e))
    finally:
        logger.debug(f"closing")
        if asyncio.iscoroutinefunction(f_close_writer):
            await f_close_writer()
        else:
            f_close_writer()

