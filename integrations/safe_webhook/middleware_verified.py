"""
Razorpay payment webhook handler.

Verifies that incoming webhook requests genuinely originated from
Razorpay before processing them, using HMAC-SHA256 signature
verification as documented by Razorpay's Webhooks API.
"""

import hashlib
import hmac
import os
from functools import wraps

# Fail loudly at import time if the secret isn't configured, rather than
# silently accepting unverifiable requests at runtime.
RAZORPAY_WEBHOOK_SECRET = os.environ["RAZORPAY_WEBHOOK_SECRET"]


def verify_razorpay_signature(function):
    """Reject any webhook request that isn't signed by Razorpay.

    BUG (original code): the handler only checked that the
    X-Razorpay-Signature header was *present*, never that it was
    *correct*. That means any request with any non-empty value in that
    header — attacker-controlled, no secret required — passed straight
    through to payment_webhook(). This decorator now recomputes the
    HMAC-SHA256 digest of the raw request body using the webhook secret
    and compares it to the header using a constant-time comparison
    (hmac.compare_digest) to avoid leaking timing information about how
    many bytes matched.
    """

    @wraps(function)
    def wrapper(request):
        signature = request.headers.get("X-Razorpay-Signature")
        if not signature:
            return {"error": "Missing signature"}, 401

        # IMPORTANT: sign the raw body, not the parsed JSON. Re-serializing
        # request.json can reorder keys/whitespace and produce a different
        # byte string than what Razorpay actually signed, causing valid
        # requests to fail verification.
        raw_body = request.get_data()

        expected_signature = hmac.new(
            key=RAZORPAY_WEBHOOK_SECRET.encode("utf-8"),
            msg=raw_body,
            digestmod=hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(expected_signature, signature):
            return {"error": "Invalid signature"}, 401

        return function(request)

    return wrapper


@verify_razorpay_signature
def payment_webhook(request):
    """Handle a verified Razorpay payment webhook event."""

    payload = request.json["payload"]["payment"]["entity"]
    payment_id = payload["id"]

    # NOTE (not fixed here, flagging for your IDEMPOTENCY detector):
    # Razorpay retries webhook delivery on timeout/non-2xx responses, so
    # this handler can be called more than once for the same event. As
    # written it has no idempotency guard — processing side effects
    # (e.g. crediting an account, sending a confirmation) would run
    # again on every retry. A minimal fix is checking/storing
    # `request.json["payload"]["payment"]["entity"]["id"]` (or the
    # top-level event id) in a persistent store before acting on it.

    print(f"Processing payment: {payment_id}")
    return {"status": "processed"}, 200
