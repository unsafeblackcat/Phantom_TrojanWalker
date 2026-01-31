"""
GhidraClient: HTTP client for the Ghidra Pipe service.
Replaces the previous RizinClient with identical interface.
"""
import httpx
import logging
from typing import Dict, Any, List
from config_loader import AppConfig
from exceptions import GhidraBackendError

logger = logging.getLogger(__name__)


class GhidraClient:
    """HTTP client for communicating with the Ghidra Pipe FastAPI service."""
    
    def __init__(self, config: AppConfig):
        self.config = config
        self.base_url = config.plugins["ghidra"].base_url
        self.endpoints = config.plugins["ghidra"].endpoints
        # Default timeout settings
        self.timeout = httpx.Timeout(60.0, connect=10.0)
        # Configure retry transport
        self.transport = httpx.AsyncHTTPTransport(retries=3)

    async def _request(self, method: str, endpoint_key: str, **kwargs) -> Any:
        """Make an HTTP request to the Ghidra backend."""
        path = self.endpoints.get(endpoint_key, f"/{endpoint_key}")
        url = f"{self.base_url}{path}"
        
        # Allow caller to override timeout
        timeout = kwargs.pop("timeout", self.timeout)

        async with httpx.AsyncClient(transport=self.transport, timeout=timeout) as client:
            try:
                resp = await client.request(method, url, **kwargs)
                resp.raise_for_status()
                try:
                    return resp.json()
                except Exception:
                    return resp.text
            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP error {e.response.status_code} for {url}")
                raise GhidraBackendError(f"Ghidra backend returned error: {e.response.status_code}") from e
            except httpx.RequestError as e:
                logger.error(f"Request error for {url}: {e}")
                raise GhidraBackendError(f"Failed to connect to Ghidra backend: {e}") from e
            except Exception as e:
                logger.error(f"Unexpected error for {url}: {e}")
                raise GhidraBackendError(f"Unexpected error: {e}") from e

    async def check_health(self):
        """Check if the Ghidra backend is healthy."""
        resp = await self._request("GET", "health_check", timeout=10.0)
        if isinstance(resp, dict) and resp.get("status") != "ok":
            raise GhidraBackendError("Ghidra backend reported unhealthy status")

    async def upload_file(self, filename: str, content: bytes, content_type: str):
        """Upload a binary file to the Ghidra backend."""
        files = {"file": (filename, content, content_type)}
        await self._request("POST", "upload", files=files, timeout=60.0)

    async def trigger_analysis(self):
        """Trigger analysis on the uploaded binary."""
        # Ghidra analysis can take longer than Rizin
        await self._request("GET", "analyze", timeout=300.0)

    async def get_metadata(self) -> Dict[str, Any]:
        """Get binary metadata."""
        res = await self._request("GET", "metadata", timeout=20.0)
        return res if isinstance(res, dict) else {}

    async def get_functions(self) -> List[Dict[str, Any]]:
        """Get list of functions."""
        res = await self._request("GET", "functions", timeout=30.0)
        return res if isinstance(res, list) else []

    async def get_strings(self) -> List[str]:
        """Get strings from the binary."""
        res = await self._request("GET", "strings", timeout=30.0)
        if isinstance(res, list):
            return [s.get("string") for s in res if isinstance(s, dict) and "string" in s]
        return []

    async def get_callgraph(self) -> Dict[str, Any]:
        """Get global call graph."""
        res = await self._request("GET", "callgraph", timeout=60.0)
        return res if isinstance(res, dict) else {}

    async def get_decompiled_codes_batch(self, addresses: List[str]) -> List[Dict[str, str]]:
        """
        Batch decompile functions.
        Returns list of {address, code} dicts.
        """
        # Batch decompilation can be very time-consuming with Ghidra
        return await self._request("POST", "decompile_batch", json=addresses, timeout=900.0)
