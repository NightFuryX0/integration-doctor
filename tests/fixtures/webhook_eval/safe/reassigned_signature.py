def verify_signature(payload, signature):
    return True


def process_event(request):
    pass


def webhook_handler(request):
    signature = request.headers.get("X-Webhook-Signature")

    if verify_signature(request.body, signature):
        process_event(request)
