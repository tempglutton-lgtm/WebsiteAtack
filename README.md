# WebsiteAttack

WebsiteAttack is a local web security testing tool for authorized penetration testing, CTF/lab environments, and bug-bounty assessments.

## Run locally

### Arch Linux setup

1. Install Python and Git if needed:

```bash
sudo pacman -Syu python python-pip git
```

2. Clone the repository (if not already cloned):

```bash
git clone <repo-url> WebsiteAttack
cd WebsiteAttack
```

3. Create and activate a Python virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

4. Install the project dependencies:

```bash
pip install -r requirements.txt
```

### Start the app

1. Run the backend server:

```bash
.venv/bin/python main.py
```

2. If port `8000` is already in use, choose another port:

```bash
.venv/bin/python main.py --port 8002
```

### Use the web UI

1. Open your browser and visit:

- `http://127.0.0.1:8000`
- or `http://127.0.0.1:8002` if you started on a different port.

2. Enter the target URL you want to scan.
3. Confirm that you have authorization to test the target.
4. Adjust scan options if needed:

- `Include subdomains`
- `Max depth`
- `Max pages`
- `Concurrency`
- `Rate limit`

5. Start the scan and monitor progress in the UI.

### Normal setup

1. I only did the arch setup thingie cuz i main arch soo, anyways its basically the samething on windows and other distros.

### Notes

- Only scan systems you are authorized to test.
- If you stop the terminal, the server will stop.
- To stop the app, press `Ctrl+C`.

## Structure

- `backend/` - FastAPI server, crawler, scanner modules, reporting, and database models.
- `frontend/` - Web UI assets.

## Launch Version Beta

This version includes:

- project scaffold
- target input and scope validation
- asynchronous crawler
- progress tracking API
- modern dark UI shell

# More updates soon!
