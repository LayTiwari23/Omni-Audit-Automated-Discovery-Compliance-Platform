import pytest
from fastapi import status
from unittest.mock import patch, MagicMock

def test_debug_routes(client):
    from app.main import app
    routes = []
    for route in app.routes:
        methods = getattr(route, "methods", "WS")
        routes.append(f"{route.path} [{methods}]")
    print("\nRegistered Routes:")
    for r in sorted(routes):
        print(r)

def test_api_info(client):
    response = client.get("/api/info")
    assert response.status_code == 200
    print(f"\nAPI Info: {response.json()}")

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_create_scan_success(client, auth_headers):
    """Test starting a new scan."""
    # Mocking celery delay to avoid actual worker task creation
    with patch("workers.scan_worker.run_scan_task.delay") as mock_task:
        mock_task.return_value = MagicMock(id="fake-task-id")
        response = client.post(
            "/api/reports/",
            json={
                "domain": "example.com",
                "scan_type": "web"
            },
            headers=auth_headers
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        # reports.py returns either a list or a single object
        if isinstance(data, list):
            assert data[0]["domain"] == "example.com"
        else:
            assert data["domain"] == "example.com"
        assert mock_task.called

def test_create_scan_invalid_domain(client, auth_headers):
    """Test starting a scan with an invalid domain."""
    # We need to mock validate_domain to fail for this test
    with patch("app.api.endpoints.reports.validate_domain") as mock_val:
        mock_val.return_value = (False, "Invalid domain")
        response = client.post(
            "/api/reports/",
            json={
                "domain": "not-a-domain",
                "scan_type": "web"
            },
            headers=auth_headers
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

def test_list_reports(client, auth_headers, db, test_user):
    """Test listing user reports."""
    # reports.py uses raw SQL, so we need to insert using raw SQL or ensure models match
    from sqlalchemy import text
    from datetime import datetime, timezone
    
    db.execute(
        text("INSERT INTO scans (user_id, domain, scan_type, status, created_at, updated_at) VALUES (:uid, :domain, :type, :status, :now, :now)"),
        {"uid": test_user.id, "domain": "test1.com", "type": "web", "status": "COMPLETED", "now": datetime.now()}
    )
    db.execute(
        text("INSERT INTO scans (user_id, domain, scan_type, status, created_at, updated_at) VALUES (:uid, :domain, :type, :status, :now, :now)"),
        {"uid": test_user.id, "domain": "test2.com", "type": "web", "status": "RUNNING", "now": datetime.now()}
    )
    db.commit()

    response = client.get("/api/reports/", headers=auth_headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert len(data) >= 2

def test_get_scan_status(client, auth_headers, db, test_user):
    """Test getting status of a specific scan."""
    from sqlalchemy import text
    from datetime import datetime, timezone
    
    result = db.execute(
        text("INSERT INTO scans (user_id, domain, scan_type, status, progress_percent, created_at, updated_at) VALUES (:uid, :domain, :type, :status, :progress, :now, :now) RETURNING id"),
        {"uid": test_user.id, "domain": "test.com", "type": "web", "status": "RUNNING", "progress": 45.0, "now": datetime.now()}
    )
    scan_id = result.fetchone()[0]
    db.commit()

    response = client.get(f"/api/reports/{scan_id}/status", headers=auth_headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["status"] == "RUNNING"
    assert response.json()["progress_percent"] == 45.0
