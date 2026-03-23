import subprocess
try:
    print("Testing secret-tool...")
    res = subprocess.run(["secret-tool", "lookup", "application", "chromium"], capture_output=True, text=True, timeout=2)
    print("Return code:", res.returncode)
    print("Stdout length:", len(res.stdout))
except subprocess.TimeoutExpired:
    print("Timed out!")
except Exception as e:
    print("Error:", e)
