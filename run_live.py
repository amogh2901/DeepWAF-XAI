"""
run_live.py
--------------------------------------------------------------------------------
Launches DeepWAF-XAI Streamlit Dashboard (Port 8501) and establishes a secure
public tunnel via ngrok.
"""

import os
import sys
import time
import json
import urllib.request
import urllib.error
import subprocess
import signal

# Ensure Windows console doesn't crash on UTF-8 characters
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

def find_ngrok():
    venv_ngrok = os.path.join(os.path.dirname(sys.executable), "ngrok.exe")
    if os.path.exists(venv_ngrok):
        return venv_ngrok
    temp_ngrok = os.path.join(os.environ.get("TEMP", ""), "ngrok.exe")
    if os.path.exists(temp_ngrok):
        return temp_ngrok
    local_ngrok = os.path.join("ngrok-v3-stable-windows-amd64", "ngrok.exe")
    if os.path.exists(local_ngrok):
        return local_ngrok
    return "ngrok"

def check_service_health(url, timeout=1.0):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HealthChecker/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False

def get_ngrok_public_url(max_retries=20, delay=1.0):
    api_url = "http://127.0.0.1:4040/api/tunnels"
    for _ in range(max_retries):
        try:
            req = urllib.request.Request(api_url, headers={"User-Agent": "NgrokChecker/1.0"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                tunnels = data.get("tunnels", [])
                for t in tunnels:
                    pub_url = t.get("public_url", "")
                    if pub_url.startswith("https://"):
                        return pub_url
                if tunnels:
                    return tunnels[0].get("public_url", "")
        except Exception:
            pass
        time.sleep(delay)
    return None

def main():
    print("=" * 70)
    print("[*] STARTING DEEPWAF-XAI SERVICES & PUBLIC NGROK TUNNEL")
    print("=" * 70)

    # 1. Locate executables
    python_exe = sys.executable
    ngrok_exe = find_ngrok()
    print(f"[*] Python interpreter : {python_exe}")
    print(f"[*] ngrok binary       : {ngrok_exe}")

    processes = []

    def cleanup(signum=None, frame=None):
        print("\n[*] Shutting down live services...")
        for p in processes:
            try:
                p.terminate()
            except Exception:
                pass
        time.sleep(1)
        for p in processes:
            try:
                p.kill()
            except Exception:
                pass
        print("[+] All services stopped cleanly.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # 2. Launch Streamlit SOC Dashboard on Port 8501
    print("\n[1/3] Starting Streamlit SOC Dashboard on http://localhost:8501 ...")
    st_cmd = [
        python_exe, "-m", "streamlit", "run", "src/app.py",
        "--server.port", "8501",
        "--server.headless", "true",
        "--server.enableCORS", "false",
        "--server.enableXsrfProtection", "false"
    ]
    st_proc = subprocess.Popen(st_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    processes.append(st_proc)

    # Wait for Streamlit to initialize
    print("      Waiting for Streamlit dashboard to be ready...", end="", flush=True)
    st_ready = False
    for _ in range(25):
        if check_service_health("http://127.0.0.1:8501/_stcore/health") or check_service_health("http://127.0.0.1:8501"):
            st_ready = True
            break
        print(".", end="", flush=True)
        time.sleep(1)
    print()

    if not st_ready:
        print("[!] Warning: Streamlit health check did not return HTTP 200 within 25s, but process is running.")
    else:
        print("      [+] Streamlit SOC Dashboard is active at http://localhost:8501")

    # 3. Launch ngrok tunnel pointing to port 8501
    print("\n[2/3] Starting ngrok tunnel on port 8501 ...")
    ngrok_cmd = [ngrok_exe, "http", "8501", "--log=stdout"]
    ngrok_proc = subprocess.Popen(ngrok_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    processes.append(ngrok_proc)

    # 4. Fetch Public ngrok URL from local ngrok API
    print("      Retrieving public tunnel URL from ngrok client API...", end="", flush=True)
    public_url = get_ngrok_public_url(max_retries=20, delay=1.0)
    print()

    if public_url:
        print("\n" + "=" * 70)
        print("[+] DEEPWAF-XAI IS LIVE AND PUBLICLY ACCESSIBLE!")
        print("=" * 70)
        print(f"[*] Public ngrok URL : {public_url}")
        print(f"[*] Local Dashboard  : http://localhost:8501")
        print(f"[*] ngrok Web Console: http://localhost:4040")
        print("=" * 70)
        print("Press Ctrl+C in this terminal at any time to stop the services.\n")

        with open("live_url.txt", "w", encoding="utf-8") as f:
            f.write(public_url + "\n")
    else:
        print("[!] Could not automatically retrieve public URL from http://127.0.0.1:4040/api/tunnels.")
        print("    Check ngrok console at http://localhost:4040 or run ngrok manually.")

    # 5. Keep alive and monitor child processes
    try:
        while True:
            time.sleep(2)
            if st_proc.poll() is not None:
                print("[!] Streamlit process stopped unexpectedly.")
                break
            if ngrok_proc.poll() is not None:
                print("[!] ngrok process stopped unexpectedly.")
                break
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()

if __name__ == "__main__":
    main()
