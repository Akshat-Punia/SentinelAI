from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User, UserRole
from app.schemas.user import UserCreate, UserLogin, UserResponse
from app.schemas.token import Token
from app.core.security import hash_password, verify_password, create_access_token
from app.api.deps import get_current_user, record_audit_log

router = APIRouter(prefix="/auth", tags=["Authentication & IAM"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, request: Request, db: Session = Depends(get_db)):
    # Check if username or email already exists
    if db.query(User).filter(User.username == user_in.username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username is already registered"
        )
    if db.query(User).filter(User.email == user_in.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address is already registered"
        )

    # Validate role assignment
    valid_roles = [r.value for r in UserRole]
    assigned_role = user_in.role if user_in.role in valid_roles else UserRole.VIEWER.value

    # First registered user automatically becomes Admin for convenience
    user_count = db.query(User).count()
    if user_count == 0:
        assigned_role = UserRole.ADMIN.value

    new_user = User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=hash_password(user_in.password),
        role=assigned_role,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    client_ip = request.client.host if request.client else "unknown"
    record_audit_log(
        db=db,
        action="USER_REGISTERED",
        resource="AUTH",
        user_id=new_user.id,
        username=new_user.username,
        ip_address=client_ip,
        details=f"User {new_user.username} registered with role '{new_user.role}'"
    )

    return new_user


@router.post("/login", response_model=Token)
def login(login_in: UserLogin, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    user = db.query(User).filter(User.username == login_in.username).first()

    if not user or not verify_password(login_in.password, user.hashed_password):
        record_audit_log(
            db=db,
            action="LOGIN_FAILED",
            resource="AUTH",
            status_str="FAILURE",
            username=login_in.username,
            ip_address=client_ip,
            details=f"Failed login attempt for username '{login_in.username}'"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact an administrator."
        )

    # Successful login
    token = create_access_token(data={"sub": user.username, "role": user.role})
    record_audit_log(
        db=db,
        action="LOGIN_SUCCESS",
        resource="AUTH",
        user_id=user.id,
        username=user.username,
        ip_address=client_ip,
        details=f"User {user.username} authenticated successfully"
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user.role,
        "username": user.username
    }


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Retrieve profile and permissions of the currently authenticated user."""
    return current_user
