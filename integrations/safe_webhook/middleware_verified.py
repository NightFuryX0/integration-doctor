from functools import wraps


def verify_razorpay_signature(function):
    @wraps(function)
    def wrapper(request):
        signature = request.headers.get("X-Razorpay-Signature")
        if not signature:
            return {"error": "Invalid signature"}, 401
        return function(request)
    return wrapper


@verify_razorpay_signature
def payment_webhook(request):
    payment_id = request.json["payload"]["payment"]["entity"]["id"]
    print(f"Processing payment: {payment_id}")
    return {"status": "processed"}, 200
