import asyncio
import aiohttp
from aiohttp import web
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def main(request):
    return web.Response(text='Hello, world!')

async def init():
    app = web.Application()
    app.router.add_get('/', main)
    return app

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    app = loop.run_until_complete(init())
    web.run_app(app)
