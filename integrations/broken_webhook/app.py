from flask import Flask, request, jsonify

app = Flask(__name__)

"""Example payment webhook handler with NO signature verification.

This file exists as a fixture for the detector's test suite — it
deliberately reproduces the class of bug WEBHOOK-001 is meant to catch.
Do not use this handler as a template.
"""


def process_event(request):
    payload = request.body
    print(f"Processing payment event: {payload}")


def webhook_handler(request):
    # No signature is read or checked at all before acting on the payload.
    process_event(request)
    return {"status": "ok"}


def process_event(request):
    payload = request.body
    print(f"Processing payment event: {payload}")


def webhook_handler(request):
    # No signature is read or checked at all before acting on the payload.
    process_event(request)
    return {"status": "ok"}


@app.route("/webhook", methods=["POST"])
def webhook():
    event = request.get_json()

    if event["event"] == "payment.captured":
        payment = event["payload"]["payment"]["entity"]

        print(f"Payment received: {payment['id']}")
        print(f"Amount: {payment['amount']}")

    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(port=5000)
