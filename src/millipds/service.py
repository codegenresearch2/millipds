import asyncio
import aiohttp
import logging
import sqlite3
from aiohttp import web
from aiohttp.web_request import Request
from aiohttp.web_response import Response

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database initialization
def initialize_database():
    conn = sqlite3.connect('config.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS config
                      (key TEXT PRIMARY KEY, value TEXT)''')
    conn.commit()
    conn.close()

# Update configuration
async def update_config(key: str, value: str) -> None:
    conn = sqlite3.connect('config.db')
    cursor = conn.cursor()
    cursor.execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', (key, value))
    conn.commit()
    conn.close()

# Service runner
async def service_run_and_capture_port(service_command: list, queue: asyncio.Queue) -> None:
    process = await asyncio.create_subprocess_exec(*service_command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        logger.error(f'Service failed with error: {stderr.decode()}')
        await queue.put(None)
        return
    port = stdout.decode().strip()
    await queue.put(port)

# Queue getter
async def queue_get_task(queue: asyncio.Queue) -> str:
    try:
        return await queue.get()
    except asyncio.QueueEmpty:
        return None

# Middleware to handle security headers
async def security_headers_middleware(app, handler):
    async def middleware_handler(request):
        response = await handler(request)
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = 'default-src \'none\'; sandbox'
        return response
    return middleware_handler

# Main function
async def main(request: Request) -> Response:
    queue = asyncio.Queue()
    service_command = ['your_service_command_here']
    await asyncio.gather(
        service_run_and_capture_port(service_command, queue),
        update_config('service_port', await queue_get_task(queue))
    )
    port = await queue_get_task(queue)
    if port is None:
        return web.Response(text='Service failed to start', status=500)
    return web.Response(text='Service started on port ' + port)

# Setup the web application
app = web.Application(middlewares=[security_headers_middleware])
app.router.add_get('/start_service', main)

# Run the web application
if __name__ == '__main__':
    initialize_database()
    web.run_app(app)