def compute_expected_signature(body):
    return "expected-signature"


def process_event(request):
    pass


def webhook_handler(request):
    signature = request.headers.get("X-Webhook-Signature")
    expected = compute_expected_signature(request.body)

    if signature == expected:
        process_event(request)
