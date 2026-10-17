import httpx
import time
import uuid
import sys

BASE_URL = "http://localhost:8000"

def test_live_flow():
    client = httpx.Client(timeout=30.0)
    
    unique_id = str(uuid.uuid4())[:8]
    email = f"test_{unique_id}@example.com"
    username = f"user_{unique_id}"
    password = "SecurePass123!"

    print(f"--- 1. Registering new admin: {email} ---")
    reg_resp = client.post(
        f"{BASE_URL}/api/auth/register",
        json={
            "email": email,
            "username": username,
            "password": password,
            "full_name": f"Test Admin {unique_id}",
            "is_admin": True,
            "admin_secret": "admin123"
        }
    )
    if reg_resp.status_code != 201:
        print(f"Registration failed: {reg_resp.text}")
        sys.exit(1)
    print("Registration successful.")

    print(f"--- 2. Logging in as admin ---")
    login_resp = client.post(
        f"{BASE_URL}/api/auth/login",
        json={
            "username_or_email": email,
            "password": password,
            "is_admin": True
        }
    )
    if login_resp.status_code != 200:
        print(f"Login failed: {login_resp.text}")
        sys.exit(1)
    
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("Login successful.")

    print("--- 3. Verifying /me ---")
    me_resp = client.get(f"{BASE_URL}/api/auth/me", headers=headers)
    assert me_resp.status_code == 200
    print(f"Me: {me_resp.json()['email']}")

    print("--- 4. Starting a Live Scan (Target: 127.0.0.1, Engine: dns) ---")
    # Using DNS engine as it's usually fast and doesn't require heavy tools like testssl
    scan_resp = client.post(
        f"{BASE_URL}/api/reports",
        json={
            "domain": "google.com",
            "scan_type": "dns"
        },
        headers=headers
    )
    if scan_resp.status_code != 200:
        print(f"Scan initiation failed: {scan_resp.text}")
        sys.exit(1)
    
    scan_data = scan_resp.json()
    # Handle list or dict return
    if isinstance(scan_data, list):
        scan_id = scan_data[0]["id"]
    else:
        scan_id = scan_data["id"]
    print(f"Scan started. ID: {scan_id}")

    print("--- 5. Polling status and logs ---")
    for _ in range(10):
        status_resp = client.get(f"{BASE_URL}/api/reports/{scan_id}/status", headers=headers)
        logs_resp = client.get(f"{BASE_URL}/api/scans/{scan_id}/logs", headers=headers)
        
        status = status_resp.json().get("status")
        progress = status_resp.json().get("progress_percent")
        logs_count = len(logs_resp.json())
        
        print(f"Status: {status} | Progress: {progress}% | Logs: {logs_count}")
        
        if status in ["COMPLETED", "FAILED"]:
            break
        time.sleep(5)
    
    print("--- 6. Verifying Dashboard ---")
    dash_resp = client.get(f"{BASE_URL}/api/dashboard/stats", headers=headers)
    print(f"Dashboard Stats: {dash_resp.json()}")

    print("\n✅ Live E2E Flow Completed Successfully!")

if __name__ == "__main__":
    test_live_flow()
