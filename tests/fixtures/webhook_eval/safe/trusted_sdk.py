import stripe


def process_event(event):
    pass


endpoint_secret = "test-secret"


def webhook_handler(request):
    event = stripe.Webhook.construct_event(
        request.body,
        request.headers.get("Stripe-Signature"),
        endpoint_secret,
    )
    process_event(event)
