# Import necessary modules and functions
from typing import Optional
import importlib.metadata
import logging
import asyncio
import time
import os
import json

import apsw
import aiohttp
from aiohttp_middlewares import cors_middleware
from aiohttp import web
import jwt

import cbrrr

from . import static_config
from . import database
from . import auth_oauth
from . import atproto_sync
from . import atproto_repo
from . import util
from .appview_proxy import service_proxy
from .auth_bearer import authenticated
from .app_util import get_db

# Set up logging
logger = logging.getLogger(__name__)

# Define routes
routes = web.RouteTableDef()

@web.middleware
async def atproto_service_proxy_middleware(request: web.Request, handler):
    # Handle ATProto service proxying
    atproto_proxy = request.headers.get('atproto-proxy')
    if atproto_proxy:
        return await service_proxy(request, atproto_proxy)

    res: web.Response = await handler(request)

    # Add security headers to the response
    res.headers.setdefault('X-Frame-Options', 'DENY')
    res.headers.setdefault('X-Content-Type-Options', 'nosniff')
    res.headers.setdefault('Content-Security-Policy', 'default-src \'none\'; sandbox')

    return res

@routes.get('/')
async def hello(request: web.Request):
    # Welcome message
    version = importlib.metadata.version('millipds')
    msg = f"""\
                          ,dPYb, ,dPYb,\n                          IP'`Yb IP'`Yb\n                     gg   I8  8I I8  8I  gg\n                     ''   I8  8' I8  8'  ''\n  ,ggg,,ggg,,ggg,    gg   I8 dP  I8 dP   gg   gg,gggg,\n ,8" "8P" "8P" "8,   88   I8dP   I8dP    88   I8P'  'Yb\n I8   8I   8I   8I   88   I8P    I8P     88   I8'    ,8i\n,dP   8I   8I   Yb,_,88,_,d8b,_ ,d8b,_ _,88,_,I8 _  ,d8'\n8P'   8I   8I   `Y88P''Y88P''Y888P''Y888P''Y8PI8 YY88888PP'Y8888P'\n                                              I8\n                                              I8\n                                              I8\n                                              I8\n                                              I8\n                                              I8\n\nHello! This is an ATProto PDS instance, running millipds v{version}\n\nhttps://github.com/DavidBuchanan314/millipds\n"""
    return web.Response(text=msg)

# Define other routes and functions as needed, following the same pattern of documenting code with comments,
# initializing preferences with an empty array, and maintaining consistent string formatting.

# ... rest of the code ...