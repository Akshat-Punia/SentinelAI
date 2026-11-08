from fastapi import Request
from app.models.user import User, UserRole
from app.schemas.user import UserCreate, UserLogin, UserUpdateRole
from app.api.v1.auth import register, login
from app.api.v1.users import list_users, update_user_role, get_audit_logs
from app.core.security import verify_password


def test_user_registration(db_session):
    mock_req = Request({"type": "http", "client": ("127.0.0.1", 12345)})
    user_in = UserCreate(
        username="newuser",
        email="newuser@sentinel.test",
        password="SecurePassword123!",
        role="Viewer"
    )
    user = register(user_in=user_in, request=mock_req, db=db_session)
    assert user.id is not None
    assert user.username == "newuser"
    assert verify_password("SecurePassword123!", user.hashed_password)


def test_user_login_success(db_session, admin_user):
    mock_req = Request({"type": "http", "client": ("127.0.0.1", 12345)})
    login_in = UserLogin(username="admin_test", password="AdminPass123!")
    res = login(login_in=login_in, request=mock_req, db=db_session)
    assert "access_token" in res
    assert res["role"] == UserRole.ADMIN.value


def test_admin_role_modification(db_session, admin_user, viewer_user):
    mock_req = Request({"type": "http", "client": ("127.0.0.1", 12345)})
    updated = update_user_role(
        user_id=viewer_user.id,
        role_in=UserUpdateRole(role=UserRole.SECURITY_ANALYST.value),
        request=mock_req,
        db=db_session,
        current_user=admin_user
    )
    assert updated.role == UserRole.SECURITY_ANALYST.value


def test_audit_log_tracking(db_session, admin_user):
    mock_req = Request({"type": "http", "client": ("127.0.0.1", 12345)})
    login(login_in=UserLogin(username="admin_test", password="AdminPass123!"), request=mock_req, db=db_session)
    logs = get_audit_logs(limit=10, db=db_session, current_user=admin_user)
    assert len(logs) >= 1
    assert any(l.action == "LOGIN_SUCCESS" for l in logs)
