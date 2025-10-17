import asyncio
from flask import Flask, render_template, request, jsonify, send_file
from io import BytesIO
import json
from devscan.scanner import run_scan

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json(force=True)
    url = data.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    if not url.startswith('http://') and not url.startswith('https://'):
        return jsonify({'error': 'URL must start with http:// or https://'}), 400

    try:
        report = run_scan(url)
        return jsonify({
            'start_url': url,
            'pages_scanned': len(report),
            'vulnerabilities': report
        })
    except Exception as e:
        return jsonify({'error': f'Scan failed: {e}'}), 500

@app.route('/api/download', methods=['POST'])
def download_report():
    data = request.get_json(force=True)
    report_json = json.dumps(data, indent=2)
    buffer = BytesIO()
    buffer.write(report_json.encode('utf-8'))
    buffer.seek(0)
    return send_file(buffer, mimetype='application/json', as_attachment=True, download_name='DevScan_Report.json')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
