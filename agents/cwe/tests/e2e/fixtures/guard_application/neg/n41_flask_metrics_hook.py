from flask import Flask, request
from flask_login import current_user
from prometheus_client import Counter

app = Flask(__name__)
REQUESTS = Counter("requests", "Requests", ["authenticated"])


@app.before_request
def metrics():
    if request.headers.get("X-Prometheus-Scrape"):
        return
    REQUESTS.labels(authenticated=current_user.is_authenticated).inc()
