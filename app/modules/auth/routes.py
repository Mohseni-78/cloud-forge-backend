from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status,Request
from sqlalchemy.orm import Session
import uuid

from app.core.security import create_access_token, create_refresh_token, decode_token, \
    get_token_expire_datetime
from app.db.models import User
from app.db.session import get_db
from app.modules.auth.blacklist import blacklist_access_token
from app.modules.auth.dependencies import get_current_user, \
    get_current_access_token_payload
from app.modules.auth.schemas import (
    AccessTokenResponse,
    LoginRequest,
    RefreshTokenRequest,
    RegisterRequest,
    TokenPair, LogoutRequest, AuthSessionRead,
)
from app.modules.auth.service import (
    authenticate_user,
    create_user,
    get_user_by_email,
    get_user_by_id,
    get_user_by_username, create_auth_session, get_auth_session_by_refresh_jti,
    is_auth_session_valid, rotate_auth_session, revoke_auth_session,
    list_active_auth_sessions, get_user_auth_session_by_id,
)
from app.modules.users.schemas import UserRead

router = APIRouter()


def get_request_ip(request: Request) -> str | None:
    if request.client is None:
        return None

    return request.client.host


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):

    existing_user_by_email = get_user_by_email(db, email=payload.email)
    if existing_user_by_email is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    existing_user_by_username = get_user_by_username(db, payload.username)
    if existing_user_by_username is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        )

    return create_user(db, payload)


@router.post("/login", response_model=TokenPair)
def login(payload: LoginRequest,request:Request, db: Session = Depends(get_db)):

    user = authenticate_user(db, payload)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    access_token = create_access_token(subject=str(user.id))
    refresh_token = create_refresh_token(subject=str(user.id))

    refresh_payload = decode_token(refresh_token)
    refresh_token_jti = str(refresh_payload["jti"])
    refresh_expires_at = get_token_expire_datetime(refresh_payload)

    create_auth_session(
        db=db,
        user_id=user.id,
        refresh_token_jti=refresh_token_jti,
        expires_at=refresh_expires_at,
        user_agent=request.headers.get("user-agent"),
        ip_address=get_request_ip(request),
    )



    return TokenPair(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh", response_model=AccessTokenResponse)
def refresh_token(
    payload: RefreshTokenRequest,
    request:Request,
    db: Session = Depends(get_db),
):
    try:
        token_payload = decode_token(payload.refresh_token)

    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    token_type = token_payload.get("type")
    user_id = token_payload.get("sub")
    refresh_token_jti = token_payload.get("jti")

    if token_type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing token subject",
        )

    if refresh_token_jti is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing token identifier",
        )

    try:
        parsed_user_id = uuid.UUID(str(user_id))

    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token subject",
        )

    user = get_user_by_id(db, parsed_user_id)


    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )

    auth_session = get_auth_session_by_refresh_jti(
        db=db,
        refresh_token_jti=str(refresh_token_jti),
    )

    if not is_auth_session_valid(auth_session):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh session is invalid",
        )

    if auth_session.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh session does not belong to user",
        )


    new_access_token = create_access_token(subject=str(user.id))
    new_refresh_token = create_refresh_token(subject=str(user.id))

    new_refresh_payload = decode_token(new_refresh_token)
    new_refresh_token_jti = str(new_refresh_payload["jti"])
    new_refresh_expires_at = get_token_expire_datetime(new_refresh_payload)

    rotate_auth_session(
        db=db,
        auth_session=auth_session,
        new_refresh_token_jti=new_refresh_token_jti,
        expires_at=new_refresh_expires_at,
        user_agent=request.headers.get("user-agent"),
        ip_address=get_request_ip(request),
    )

    return TokenPair(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
    )

@router.post("/logout")
def logout(
    payload: LogoutRequest,
    current_user: User = Depends(get_current_user),
    access_payload: dict[str, Any] = Depends(get_current_access_token_payload),
    db: Session = Depends(get_db),
):
    try:
        refresh_payload = decode_token(payload.refresh_token)

    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    refresh_token_type = refresh_payload.get("type")
    refresh_token_subject = refresh_payload.get("sub")
    refresh_token_jti = refresh_payload.get("jti")

    if refresh_token_type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token type",
        )

    if refresh_token_subject != str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token does not belong to current user",
        )

    if refresh_token_jti is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing refresh token identifier",
        )

    auth_session = get_auth_session_by_refresh_jti(
        db=db,
        refresh_token_jti=str(refresh_token_jti),
    )

    if auth_session is not None and not auth_session.is_revoked:
        revoke_auth_session(db=db, auth_session=auth_session)

    access_token_jti = access_payload.get("jti")
    access_token_expires_at = get_token_expire_datetime(access_payload)

    if access_token_jti is not None:
        blacklist_access_token(
            jti=str(access_token_jti),
            expires_at=access_token_expires_at,
        )

    return {
        "status": "ok",
        "message": "Logged out successfully",
    }


@router.get("/sessions", response_model=list[AuthSessionRead])
def get_my_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return list_active_auth_sessions(
        db=db,
        user_id=current_user.id,
    )


@router.delete("/sessions/{session_id}")
def revoke_my_session(
    session_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    auth_session = get_user_auth_session_by_id(
        db=db,
        user_id=current_user.id,
        session_id=session_id,
    )

    if auth_session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )

    if not auth_session.is_revoked:
        revoke_auth_session(db=db, auth_session=auth_session)

    return {
        "status": "ok",
        "message": "Session revoked successfully",
    }


@router.get("/me", response_model=UserRead)
def get_me(
    current_user: User = Depends(get_current_user),
):
    return current_user
