import razorpay


def retry_payment(payment_id):
    for attempt in range(3):
        razorpay.capture_payment(payment_id)
