from behave import then, when


def _json(response):
    return response.json()


@when('I encrypt a text payload "{content}" using crypto key "{crypto_key}"')
def step_encrypt_text(context, content, crypto_key):
    context.response = context.client.post(
        "/encrypt",
        json={"type": "text", "content": content, "crypto_key": crypto_key},
    )
    context.last_crypto_response = _json(context.response)


@when('I encrypt an image payload "{content}" using crypto key "{crypto_key}"')
def step_encrypt_image(context, content, crypto_key):
    context.response = context.client.post(
        "/encrypt",
        json={"type": "image", "content": content, "crypto_key": crypto_key},
    )
    context.last_crypto_response = _json(context.response)


@when("I decrypt the last crypto response")
def step_decrypt_last(context):
    context.response = context.client.post("/decrypt", json=context.last_crypto_response)
    context.last_crypto_response = _json(context.response)


@when('I decrypt a text payload "{content}" using crypto key "{crypto_key}"')
def step_decrypt_text(context, content, crypto_key):
    context.response = context.client.post(
        "/decrypt",
        json={"type": "text", "content": content, "crypto_key": crypto_key},
    )
    context.last_crypto_response = _json(context.response)


@when('I check non-stream text "{text}"')
def step_check_text(context, text):
    context.response = context.client.post("/sensitive-words/text", json={"text": text})


@when("I stream text chunks")
def step_stream_text_chunks(context):
    chunks = [row["chunk"] for row in context.table]

    def body():
        for chunk in chunks:
            yield chunk.encode("utf-8")

    context.response = context.client.post(
        "/sensitive-words/text/stream",
        content=body(),
        headers={"Content-Type": "text/plain"},
    )


@then("the response status should be {status_code:d}")
def step_status(context, status_code):
    assert context.response.status_code == status_code, context.response.text


@then('the response field "{field}" should be "{expected}"')
def step_json_field_equals(context, field, expected):
    actual = _json(context.response)[field]
    if expected == "true":
        expected_value = True
    elif expected == "false":
        expected_value = False
    else:
        expected_value = expected
    assert actual == expected_value, f"expected {field}={expected_value!r}, got {actual!r}"


@then('the response field "{field}" should not be "{unexpected}"')
def step_json_field_not_equals(context, field, unexpected):
    actual = _json(context.response)[field]
    assert actual != unexpected, f"expected {field} to differ from {unexpected!r}"


@then('the response detail should be "{expected}"')
def step_json_detail_equals(context, expected):
    actual = _json(context.response)["detail"]
    assert actual == expected, f"expected detail={expected!r}, got {actual!r}"
