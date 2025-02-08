import asyncio
import aiohttp
from aiohttp import web

async def main(request):
    # Your main function logic here
    return web.Response(text='Hello, world!')

async def init():
    app = web.Application()
    app.router.add_get('/', main)
    return app

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    app = loop.run_until_complete(init())
    web.run_app(app)
