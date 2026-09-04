import hmac


def process_event(request):
    pass


def webhook_handler(request):
    signature = request.headers.get("X-Webhook-Signature")
    expected = "expected-signature"

    hmac.compare_digest(signature, expected)
    process_event(request)
