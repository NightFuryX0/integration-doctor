from flask import Flask, request

app = Flask(__name__)


@app.route("/webhook", methods=["POST"])
def webhook():
    event = request.get_json()

    if event["event"] == "payment.captured":
        payment_id = event["payload"]["payment"]["entity"]["id"]

        # This represents changing the merchant's order/payment state.
        # There is deliberately NO check for whether this event was already processed.
        print(f"Processing payment: {payment_id}")

    return {"status": "ok"}
