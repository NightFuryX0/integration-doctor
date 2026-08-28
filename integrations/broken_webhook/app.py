from flask import Flask, request, jsonify

app = Flask(__name__)


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
