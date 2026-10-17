import pytest
from typing import Generator
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
import os
import sys

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), 'backend'))

# Use a separate test database (SQLite for speed and isolation in tests)
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

from app.db.session import Base, get_db
from app.core.security import create_access_token, hash_password
from app.models.user import User
from app.main import app

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Create all tables in the test database."""
    Base.metadata.create_all(bind=engine)
    
    yield
    
    # Cleanup after all tests
    if os.path.exists("./test.db"):
        os.remove("./test.db")

@pytest.fixture
def db() -> Generator[Session, None, None]:
    """Provides a clean database session for each test."""
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()

@pytest.fixture
def client(db: Session) -> Generator[TestClient, None, None]:
    """FastAPI test client with overridden database dependency."""
    def override_get_db():
        try:
            yield db
        finally:
            pass
            
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

@pytest.fixture
def test_user(db: Session) -> User:
    """Creates a regular test user."""
    user = User(
        email="test@example.com",
        username="testuser",
        password_hash=hash_password("testpass123"),
        is_admin=False,
        all_access=True # For testing convenience
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@pytest.fixture
def admin_user(db: Session) -> User:
    """Creates an admin test user."""
    user = User(
        email="admin@example.com",
        username="adminuser",
        password_hash=hash_password("adminpass123"),
        is_admin=True,
        all_access=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@pytest.fixture
def auth_headers(test_user: User) -> dict:
    """Returns headers for an authenticated regular user."""
    token = create_access_token(data={"sub": str(test_user.id)})
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def admin_auth_headers(admin_user: User) -> dict:
    """Returns headers for an authenticated admin user."""
    token = create_access_token(data={"sub": str(admin_user.id)})
    return {"Authorization": f"Bearer {token}"}
