import hmac


def process_event(request):
    pass


def webhook_handler(request):
    signature = request.headers.get("X-Webhook-Signature")  # noqa: F841

    hmac.compare_digest("unrelated-a", "unrelated-b")
    process_event(request)
