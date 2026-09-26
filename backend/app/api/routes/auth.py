from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.security import create_access_token, verify_password
from app.db.session import get_db
from app.models.user import AdminUser
from app.schemas.auth import LoginRequest, LoginResponse, LoginUser

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    admin = db.query(AdminUser).filter(AdminUser.username == payload.username).first()

    if admin is None or not verify_password(payload.password, admin.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Username or password wrong, please try again.",
        )

    token = create_access_token(subject=admin.username)
    return LoginResponse(
        access_token=token,
        user=LoginUser(username=admin.username, display_name=admin.display_name),
    )
