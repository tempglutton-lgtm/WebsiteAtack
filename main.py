import argparse
import os
import uvicorn

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Launch the WebsiteAttack local scanner.")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind the web server to")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8000)), help="Port to run the web server on")
    args = parser.parse_args()
    uvicorn.run("backend.main:app", host=args.host, port=args.port, reload=False)
