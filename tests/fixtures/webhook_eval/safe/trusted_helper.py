import hmac


def process_event(request):
    pass


def webhook_handler(request):
    signature = request.headers.get("X-Webhook-Signature")
    sig = signature
    expected = "expected-signature"

    if hmac.compare_digest(sig, expected):
        process_event(request)
