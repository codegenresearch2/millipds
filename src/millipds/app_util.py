
# Corrected the unterminated string literal issue by properly closing the string literal
# with a matching quotation mark.

TOOSLOW_MSG = cbrrr.encode_dag_cbor({"op": -1}) + cbrrr.encode_dag_cbor(
    {"error": "ConsumerTooSlow", "message": "you're not reading my events fast enough :("}
)

FUTURECURSOR_MSG = cbrrr.encode_dag_cbor({"op": -1}) + cbrrr.encode_dag_cbor(
    {"error": "FutureCursor", "message": "woah, are you from the future?"}
)


In the provided code snippet, I have corrected the `SyntaxError` caused by an unterminated string literal in the `app_util.py` file. I have properly closed the string literals with matching quotation marks to ensure that the Python interpreter can correctly parse the code. This should resolve the syntax issues and allow the tests to run without encountering the `SyntaxError`.