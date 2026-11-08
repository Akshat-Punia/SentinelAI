from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User, UserRole
from app.models.audit_log import AuditLog
from app.schemas.user import UserResponse, UserUpdateRole
from app.schemas.audit_log import AuditLogResponse
from app.api.deps import require_roles, record_audit_log

router = APIRouter(prefix="/users", tags=["User & IAM Administration"])


@router.get("", response_model=List[UserResponse])
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN.value]))
):
    """Admin-only: Retrieve all registered system users and their assigned roles."""
    return db.query(User).order_by(User.id.asc()).all()


@router.patch("/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: int,
    role_in: UserUpdateRole,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN.value]))
):
    """Admin-only: Update a user's security role (Admin, Security Analyst, Viewer)."""
    valid_roles = [r.value for r in UserRole]
    if role_in.role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Allowed roles are: {valid_roles}"
        )

    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} was not found"
        )

    old_role = target_user.role
    target_user.role = role_in.role
    db.commit()
    db.refresh(target_user)

    client_ip = request.client.host if request.client else "unknown"
    record_audit_log(
        db=db,
        action="ROLE_MODIFIED",
        resource="IAM",
        user_id=current_user.id,
        username=current_user.username,
        ip_address=client_ip,
        details=f"Admin {current_user.username} changed role of {target_user.username} from '{old_role}' to '{target_user.role}'"
    )

    return target_user


@router.get("/audit-logs", response_model=List[AuditLogResponse])
def get_audit_logs(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN.value, UserRole.SECURITY_ANALYST.value]))
):
    """Admin and Security Analyst: Inspect chronological system audit trails."""
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
