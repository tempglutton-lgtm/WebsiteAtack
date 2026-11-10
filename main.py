import argparse
import ipaddress
import os
import uvicorn


def loopback_host(value: str) -> str:
    if value.lower() == "localhost":
        return value
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("The server may only bind to a loopback address.") from exc
    if not address.is_loopback:
        raise argparse.ArgumentTypeError("The server may only bind to a loopback address.")
    return value


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Launch the WebsiteAttack local scanner.")
    parser.add_argument("--host", type=loopback_host, default="127.0.0.1", help="Loopback host to bind the web server to")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8000)), help="Port to run the web server on")
    args = parser.parse_args()
    uvicorn.run("backend.main:app", host=args.host, port=args.port, reload=False)
