# DevScan — Website Health & Vulnerability Scanner (MVP)

**Project name:** DevScan
**Purpose:** Lightweight website scanner that checks reachability, basic security headers, mixed content, certificate expiry, and extracts assets/links. Saves files and metadata locally and produces a simple human-readable result for sharing (e.g., Instagram).

**IMPORTANT LEGAL WARNING — READ BEFORE USING**
- **Only** scan websites and domains you own or have **explicit, written permission** to test. Unauthorized scanning of third-party websites can be illegal in many jurisdictions and may be treated as malicious activity.
- Do **not** use this tool to probe, attack, or exfiltrate data from systems you do not control.
- The author and distributor of this tool (you) are responsible for all uses of the software. Use at your own risk.

## What's included
- `app.py` — Flask web UI that accepts a URL and runs the scanner (synchronously for MVP).
- `devscan/scanner.py` — The main scanner module (async) adapted from the user's provided crawler code.
- `templates/index.html` — Minimal modern UI (Tailwind CDN) to paste URL and run a scan; results appear on the page and can be downloaded as an image (html2canvas CDN used).
- `static/js/main.js` — Frontend JS to call the Flask API and render results.
- `requirements.txt` — Python dependencies.
- `README.md` — This file.

## Quick start (local)
1. Create a Python 3.10+ virtualenv and activate it:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the Flask app (development mode):
   ```bash
   python app.py
   ```
   By default it listens on `http://127.0.0.1:5000`.
4. Open the site in your browser, paste a URL you own, and run the scan.

## Notes & limitations
- The scanner is designed as an MVP. Some targets block automated requests or rate-limit clients; in such cases, the scanner may not be able to fetch all pages.
- This project intentionally **does not** include automated brute-force or exploit modules. It extracts links and looks for obvious misconfigurations or missing headers only.
- For advanced performance audits (Lighthouse metrics) you would need headless Chrome / Puppeteer or Playwright; Playwright is optionally referenced but not required for the basic tool.

## How results are stored
- Scanned content and metadata are saved under the `output/` folder inside the project directory. Each saved file is accompanied by a `.meta.txt` describing detected issues.

## Customization
- Edit `devscan/scanner.py` to change settings like concurrency, timeouts, and which heuristics to run.

## License
- This repository is provided "as-is" for educational and authorized security testing purposes.
