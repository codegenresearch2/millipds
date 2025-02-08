import asyncio
import aiohttp
from aiohttp import web
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define a route table
routes = web.RouteTableDef()

@routes.get('/')
async def main_route(request):
    return web.Response(text='Hello, world!')

# Middleware to inject security headers
async def security_headers_middleware(app, handler):
    async def middleware_handler(request):
        response = await handler(request)
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('Content-Security-Policy', "default-src 'none'; sandbox")
        return response
    return middleware_handler

# Initialize the application with middleware
app = web.Application(middlewares=[security_headers_middleware])
app.router.add_routes(routes)

# Function to run the service and capture the port
async def service_run_and_capture_port(queue):
    # Simulate running the service and capturing the port
    # Replace this with actual service running logic
    port = 8080
    await queue.put(port)

# Main function to run the application
if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    q = asyncio.Queue()
    loop.create_task(service_run_and_capture_port(q))
    port = loop.run_until_complete(q.get())
    logger.info(f'Service running on port {port}')
    web.run_app(app, port=port)