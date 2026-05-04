"""Per-request authorization check against an external policy engine."""

import httpx

from .config import Settings
from .logging import get_logger

logger = get_logger(__name__)


async def is_allowed(
    user_identity: str | None,
    facility: str,
    path: str,
    method: str,
    http_client: httpx.AsyncClient,
    settings: Settings,
) -> bool:
    """Return True if the request is allowed; queries the policy engine when configured."""
    if not settings.policy_engine_url:
        return True

    try:
        resp = await http_client.post(
            settings.policy_engine_url,
            json={
                "user": user_identity,
                "facility": facility,
                "path": path,
                "method": method,
            },
            timeout=5.0,
        )
        if resp.status_code == 200:
            return resp.json().get("allowed", False)
        logger.warning("Policy engine returned %d, denying", resp.status_code, extra={"facility": facility})
        return False
    except Exception:
        logger.exception("Policy engine unreachable, denying", extra={"facility": facility})
        return False
