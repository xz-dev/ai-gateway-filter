from fastapi.testclient import TestClient

from privacy_gateway.main import create_app


def before_all(context):
    context.client = TestClient(create_app())
    context.response = None
    context.last_crypto_response = None
