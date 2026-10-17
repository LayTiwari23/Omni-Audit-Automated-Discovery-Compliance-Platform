import pytest
from fastapi import status

def test_user_registration(client):
    """Test standard user registration."""
    response = client.post(
        "/api/auth/register",
        json={
            "email": "newuser@example.com",
            "username": "newuser",
            "password": "securepassword123",
            "full_name": "New User"
        }
    )
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["email"] == "newuser@example.com"
    assert "id" in data
    assert data["is_admin"] is False

def test_admin_registration_success(client):
    """Test admin registration with correct secret."""
    response = client.post(
        "/api/auth/register",
        json={
            "email": "newadmin@example.com",
            "username": "newadmin",
            "password": "adminpassword123",
            "is_admin": True,
            "admin_secret": "admin123"
        }
    )
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["is_admin"] is True

def test_admin_registration_failure(client):
    """Test admin registration with wrong secret."""
    response = client.post(
        "/api/auth/register",
        json={
            "email": "fakeadmin@example.com",
            "username": "fakeadmin",
            "password": "adminpassword123",
            "is_admin": True,
            "admin_secret": "wrong_secret"
        }
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

def test_login_success(client, test_user):
    """Test login with email."""
    response = client.post(
        "/api/auth/login",
        json={
            "username_or_email": "test@example.com",
            "password": "testpass123",
            "is_admin": False
        }
    )
    assert response.status_code == status.HTTP_200_OK
    assert "access_token" in response.json()

def test_login_wrong_role(client, admin_user):
    """Test admin trying to login as a regular user."""
    response = client.post(
        "/api/auth/login",
        json={
            "username_or_email": "admin@example.com",
            "password": "adminpass123",
            "is_admin": False
        }
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Access denied" in response.json()["detail"]

def test_get_me(client, auth_headers, test_user):
    """Test getting current user profile."""
    response = client.get("/api/auth/me", headers=auth_headers)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["email"] == test_user.email
