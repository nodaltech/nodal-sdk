import json
import os
import logging
from flask import Flask, request

app = Flask(__name__)
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)


@app.route("/report", methods=["POST"])
def report():
    data = request.get_json()
    print(str(data))
    return {}, 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
