"""
Shared base collector: token management, paged HTTP helpers, and rate-limit retry.

Security notes
--------------
* ALL HTTP calls in subclasses MUST use `_get`, `_paginate_arm`, or `_paginate_graph`.
  These are strictly GET-only; the tool never writes to Azure or Graph APIs.
* Access tokens are held only in memory (TokenCache); they are never logged or
  persisted to disk.
* The `Authorization` header is constructed inline and never passed to logger calls.
"""
import asyncio
import logging
from typing import Any, Callable, Optional

import httpx
from azure.identity import AzureCliCredential, CredentialUnavailableError

from ..config import settings

logger = logging.getLogger(__name__)

# Azure resource scopes (read-only audience tokens)
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
ARM_SCOPE   = "https://management.azure.com/.default"

# How long (seconds) to wait between retry attempts when no Retry-After header present
_BACKOFF = (1, 4, 16)          # 3 attempts: 1 s, 4 s, 16 s
_MAX_RETRIES = 3
_RETRYABLE_STATUSES = {429, 500, 502, 503, 504}


class TokenCache:
    """In-memory token cache with pre-expiry refresh (60-second buffer).

    Tokens are NEVER written to disk or emitted in log output.
    """

    def __init__(self):
        self._tokens: dict[str, Any] = {}
        self._credential: Optional[AzureCliCredential] = None

    def _get_credential(self) -> AzureCliCredential:
        if self._credential is None:
            self._credential = AzureCliCredential()
        return self._credential

    def get_token(self, scope: str) -> str:
        import time
        cached = self._tokens.get(scope)
        if cached and cached["expires_on"] - time.time() > 60:
            return cached["token"]
        try:
            token_obj = self._get_credential().get_token(scope)
            self._tokens[scope] = {
                "token": token_obj.token,
                "expires_on": token_obj.expires_on,
            }
            return token_obj.token
        except CredentialUnavailableError:
            raise RuntimeError(
                "Azure CLI credentials not available. Run: az login\n"
                "On Windows: open a new terminal after running az login."
            )

    def clear(self):
        self._tokens.clear()
        self._credential = None


# Module-level singleton — one token cache per process
_token_cache = TokenCache()


def get_token_cache() -> TokenCache:
    return _token_cache


def _sanitize_for_log(text: str) -> str:
    """Strip newlines from strings before they reach log output (log-injection guard)."""
    return str(text).replace("\n", " ").replace("\r", " ")[:200]


class BaseCollector:
    """
    Async HTTP helpers for ARM and Graph APIs.

    READ-ONLY GUARANTEE
    -------------------
    This class exposes only GET methods (`_get`, `_paginate_arm`, `_paginate_graph`,
    `_get_arm`, `_get_graph`).  No POST / PUT / PATCH / DELETE methods exist.
    Subclasses must not call `client.post()` or other mutating methods directly.
    """

    def __init__(self, progress_callback: Optional[Callable] = None):
        self.cache = _token_cache
        self.progress_callback = progress_callback or (lambda **kw: None)

    # ── Auth headers (never logged) ────────────────────────────────────────

    def _arm_headers(self) -> dict:
        return {"Authorization": f"Bearer {self.cache.get_token(ARM_SCOPE)}"}

    def _graph_headers(self) -> dict:
        return {"Authorization": f"Bearer {self.cache.get_token(GRAPH_SCOPE)}"}

    # ── Progress ───────────────────────────────────────────────────────────

    def _report(self, phase: str, message: str, current: int = 0, total: int = 0):
        self.progress_callback(phase=phase, message=message, current=current, total=total)

    # ── Core GET with retry + rate-limit handling ──────────────────────────

    async def _get(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict,
        params: Optional[dict] = None,
    ) -> dict:
        """
        Issue a GET request with automatic retry on transient errors.

        Respects `Retry-After` headers from 429 responses.
        Applies exponential back-off for 5xx errors.
        Auth headers are refreshed on each retry in case the token expired.
        """
        last_exc: Optional[Exception] = None

        for attempt, backoff in enumerate(_BACKOFF):
            try:
                # Refresh auth on every attempt (token may have expired mid-scan)
                current_headers = dict(headers)
                if "Authorization" in current_headers:
                    scope = ARM_SCOPE if "management.azure.com" in url else GRAPH_SCOPE
                    current_headers["Authorization"] = f"Bearer {self.cache.get_token(scope)}"

                resp = await client.get(
                    url, headers=current_headers, params=params,
                    timeout=settings.api_timeout,
                )

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", backoff))
                    wait = min(retry_after, 60)
                    logger.debug("Rate-limited by Azure (429). Waiting %ss (attempt %d).", wait, attempt + 1)
                    await asyncio.sleep(wait)
                    params = None  # params already in URL after first attempt
                    continue

                if resp.status_code in _RETRYABLE_STATUSES - {429}:
                    logger.debug(
                        "Transient HTTP %s for %s; retrying in %ss.",
                        resp.status_code, _sanitize_for_log(url), backoff,
                    )
                    await asyncio.sleep(backoff)
                    continue

                resp.raise_for_status()
                return resp.json()

            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                last_exc = exc
                logger.debug(
                    "Network error for %s (attempt %d/%d): %s",
                    _sanitize_for_log(url), attempt + 1, _MAX_RETRIES,
                    _sanitize_for_log(str(exc)),
                )
                await asyncio.sleep(backoff)

        raise last_exc or RuntimeError(
            f"Request failed after {_MAX_RETRIES} attempts: {_sanitize_for_log(url)}"
        )

    # ── Pagination ─────────────────────────────────────────────────────────

    async def _paginate(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict,
        params: Optional[dict] = None,
        next_link_key: str = "@odata.nextLink",
        value_key: str = "value",
    ) -> list[dict]:
        results: list[dict] = []
        current_url: Optional[str] = url
        current_params = params

        while current_url:
            data = await self._get(client, current_url, headers, current_params)
            results.extend(data.get(value_key, []))
            current_url = data.get(next_link_key)
            current_params = None  # nextLink already encodes original params
        return results

    async def _paginate_arm(
        self,
        client: httpx.AsyncClient,
        url: str,
        params: Optional[dict] = None,
    ) -> list[dict]:
        return await self._paginate(
            client, url, self._arm_headers(), params,
            next_link_key="nextLink",
        )

    async def _paginate_graph(
        self,
        client: httpx.AsyncClient,
        url: str,
        params: Optional[dict] = None,
    ) -> list[dict]:
        return await self._paginate(
            client, url, self._graph_headers(), params,
            next_link_key="@odata.nextLink",
        )

    async def _get_arm(
        self, client: httpx.AsyncClient, url: str, params: Optional[dict] = None
    ) -> dict:
        return await self._get(client, url, self._arm_headers(), params)

    async def _get_graph(
        self, client: httpx.AsyncClient, url: str, params: Optional[dict] = None
    ) -> dict:
        return await self._get(client, url, self._graph_headers(), params)
