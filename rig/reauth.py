"""Workflow-suspend / re-auth event publisher for 401/403 deny paths."""

from __future__ import annotations

import asyncio
import functools
import json
from typing import Any

import boto3

from .logging import get_logger

logger = get_logger(__name__)


class ReauthPublisher:
    """Publish structured re-auth events to SNS and/or SQS.

    This hook is intentionally fail-open: publish failures are logged but never
    block the request path, mirroring rig's revocation philosophy.
    """

    def __init__(
        self,
        *,
        sns_topic_arn: str = "",
        sqs_queue_url: str = "",
        aws_region: str = "us-east-1",
    ) -> None:
        self._sns_topic_arn = sns_topic_arn.strip()
        self._sqs_queue_url = sqs_queue_url.strip()
        self._aws_region = aws_region
        self._sns_client = None
        self._sqs_client = None

    @property
    def enabled(self) -> bool:
        return bool(self._sns_topic_arn or self._sqs_queue_url)

    def _sns(self):
        if self._sns_client is None:
            self._sns_client = boto3.client("sns", region_name=self._aws_region)
        return self._sns_client

    def _sqs(self):
        if self._sqs_client is None:
            self._sqs_client = boto3.client("sqs", region_name=self._aws_region)
        return self._sqs_client

    async def publish_suspend_event(self, event: dict[str, Any]) -> bool:
        """Best-effort publish of a workflow-suspend event to all configured sinks."""
        if not self.enabled:
            return False

        payload = json.dumps(event, separators=(",", ":"), sort_keys=True)
        loop = asyncio.get_running_loop()
        ok = True

        if self._sns_topic_arn:
            try:
                await loop.run_in_executor(
                    None,
                    functools.partial(
                        self._sns().publish,
                        TopicArn=self._sns_topic_arn,
                        Message=payload,
                        Subject="rig-reauth-required",
                    ),
                )
            except Exception:
                ok = False
                logger.exception("reauth: failed to publish SNS suspend event")

        if self._sqs_queue_url:
            try:
                await loop.run_in_executor(
                    None,
                    functools.partial(
                        self._sqs().send_message,
                        QueueUrl=self._sqs_queue_url,
                        MessageBody=payload,
                    ),
                )
            except Exception:
                ok = False
                logger.exception("reauth: failed to publish SQS suspend event")

        if ok:
            logger.info(
                "rig.reauth.publish",
                extra={
                    "audit": True,
                    "event": "reauth_publish",
                    "status": event.get("status"),
                    "facility": event.get("facility"),
                    "sub": event.get("sub"),
                    "project": event.get("project"),
                    "reason": event.get("reason"),
                    "sns": bool(self._sns_topic_arn),
                    "sqs": bool(self._sqs_queue_url),
                },
            )
        return ok
