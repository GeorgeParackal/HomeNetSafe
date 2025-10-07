from flask import Flask, jsonify
from flask_cors import CORS
import subprocess, sys, os

app = Flask(__name__)
CORS(app)  # Allow browser requests from your HTML page

SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "Device Discovery.py")

@app.get("/run-script")
def run_script():
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
        })
    except Exception as e:
        return jsonify({"ok": False, "stdout": "", "stderr": str(e)}), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
