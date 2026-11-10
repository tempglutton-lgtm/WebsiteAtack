MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class ResponseTooLargeError(ValueError):
    pass


async def read_response_body(response) -> str:
    if (
        response.content_length is not None
        and response.content_length > MAX_RESPONSE_BYTES
    ):
        raise ResponseTooLargeError("Response exceeds the configured size limit.")
    body = await response.content.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise ResponseTooLargeError("Response exceeds the configured size limit.")
    return body.decode(response.charset or "utf-8", errors="replace")
