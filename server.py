from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import subprocess, sys, os

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

HERE = os.path.dirname(__file__)
SCRIPT_CANDIDATES = ["DeviceDiscovery.py", "Device Discovery.py"]
SCRIPT_PATH = next((os.path.join(HERE, f) for f in SCRIPT_CANDIDATES if os.path.isfile(os.path.join(HERE, f))), None)

# --- Serve your main HTML website ---
@app.get("/")
def serve_home():
    return send_from_directory('.', 'HomeNetSafe2.0.html')

# --- Serve your static JS and image files (Flask will auto-handle via static_folder) ---

@app.get("/run-script")
def run_script():
    if not SCRIPT_PATH:
        return jsonify({"ok": False, "stdout": "", "stderr": "Device discovery script not found"}), 500
    try:
        result = subprocess.run(
            [sys.executable, SCRIPT_PATH],
            capture_output=True,
            text=True
        )
        return jsonify({
            "ok": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr
        }), (200 if result.returncode == 0 else 500)
    except Exception as e:
        return jsonify({"ok": False, "stdout": "", "stderr": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
