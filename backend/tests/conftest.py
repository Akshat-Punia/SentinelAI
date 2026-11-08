try:
    import pytest
    fixture = pytest.fixture
except ImportError:
    pytest = None
    def fixture(*args, **kwargs):
        return lambda fn: fn
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
import app.models
from app.models.user import User, UserRole
from app.core.security import hash_password

# Isolated in-memory SQLite engine for tests
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL,
    connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@fixture(scope="function")
def db_session():
    """Provides a fresh database session for each test function."""
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


@fixture(scope="function")
def admin_user(db_session):
    user = User(
        username="admin_test",
        email="admin@sentinel.test",
        hashed_password=hash_password("AdminPass123!"),
        role=UserRole.ADMIN.value,
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@fixture(scope="function")
def analyst_user(db_session):
    user = User(
        username="analyst_test",
        email="analyst@sentinel.test",
        hashed_password=hash_password("AnalystPass123!"),
        role=UserRole.SECURITY_ANALYST.value,
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@fixture(scope="function")
def viewer_user(db_session):
    user = User(
        username="viewer_test",
        email="viewer@sentinel.test",
        hashed_password=hash_password("ViewerPass123!"),
        role=UserRole.VIEWER.value,
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user
