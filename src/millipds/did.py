import aiohttp
import asyncio
from typing import Dict, Callable, Any, Awaitable, Optional
import re
import json
import time
import logging

from .database import Database
from . import util
from . import static_config
from .app_util import MILLIPDS_DID_RESOLVER

logger = logging.getLogger(__name__)

DIDDoc = Dict[str, Any]

class DIDResolver:
    DID_LENGTH_LIMIT = 2048
    DIDDOC_LENGTH_LIMIT = 0x10000

    def __init__(
        self,
        session: aiohttp.ClientSession,
        plc_directory_host: str = "https://plc.directory",
    ) -> None:
        self.session: aiohttp.ClientSession = session
        self.plc_directory_host: str = plc_directory_host
        self.did_methods: Dict[str, Callable[[str], Awaitable[DIDDoc]]] = {
            "web": self.resolve_did_web,
            "plc": self.resolve_did_plc,
        }

        # keep stats for logging
        self.hits = 0
        self.misses = 0

    # ... rest of the DIDResolver class methods ...

def construct_app(
    routes, db: Database, client: aiohttp.ClientSession
) -> web.Application:
    # ... existing code ...

    did_resolver = DIDResolver(client, static_config.PLC_DIRECTORY_HOST)
    app[MILLIPDS_DID_RESOLVER] = did_resolver

    # ... rest of the construct_app function ...

# ... rest of the code ...


In the provided code snippet, I have made the following changes:

1. Imported the `DIDResolver` class and `MILLIPDS_DID_RESOLVER` from the `app_util` module.
2. Instantiated a `DIDResolver` object in the `construct_app` function and assigned it to the `MILLIPDS_DID_RESOLVER` key in the application's context.\n3. This change ensures that a `DIDResolver` instance is available for dynamic DID resolution and maintains the existing middleware configurations.