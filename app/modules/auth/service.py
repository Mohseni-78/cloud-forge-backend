from sqlalchemy import select
from sqlalchemy.orm import Session

import uuid
from datetime import datetime, UTC

from app.core.security import hash_password, verify_password
from app.db.models import User, AuthSession
from app.modules.auth.schemas import LoginRequest, RegisterRequest


def get_user_by_email(db: Session, email: str) -> User | None:
    statement = select(User).where(User.email == email)
    return db.scalar(statement)


def get_user_by_username(db: Session, username: str) -> User | None:
    statement = select(User).where(User.username == username)
    return db.scalar(statement)


def get_user_by_id(db: Session, user_id: str) -> User | None:
    statement = select(User).where(User.id == user_id)
    return db.scalar(statement)


def create_user(db: Session, payload: RegisterRequest) -> User:
    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def authenticate_user(db: Session, payload: LoginRequest) -> User | None:
    user = get_user_by_email(db, payload.email)

    if user is None:
        return None

    if not verify_password(
        plain_password=payload.password, hashed_password=user.hashed_password
    ):
        return None

    return user

def create_auth_session(
    db: Session,
    user_id: uuid.UUID,
    refresh_token_jti: str,
    expires_at: datetime,
    user_agent: str | None,
    ip_address: str | None,
) -> AuthSession:
    auth_session = AuthSession(
        user_id=user_id,
        refresh_token_jti=refresh_token_jti,
        expires_at=expires_at,
        user_agent=user_agent,
        ip_address=ip_address,
    )

    db.add(auth_session)
    db.commit()
    db.refresh(auth_session)

    return auth_session

def get_auth_session_by_refresh_jti(
    db: Session,
    refresh_token_jti: str,
) -> AuthSession | None:
    statement = select(AuthSession).where(
        AuthSession.refresh_token_jti == refresh_token_jti
    )

    return db.scalar(statement)

def rotate_auth_session(
    db: Session,
    auth_session: AuthSession,
    new_refresh_token_jti: str,
    expires_at: datetime,
    user_agent: str | None,
    ip_address: str | None,
) -> AuthSession:
    auth_session.refresh_token_jti = new_refresh_token_jti
    auth_session.expires_at = expires_at
    auth_session.last_used_at = datetime.now(UTC)
    auth_session.user_agent = user_agent
    auth_session.ip_address = ip_address

    db.add(auth_session)
    db.commit()
    db.refresh(auth_session)

    return auth_session


def revoke_auth_session(
    db: Session,
    auth_session: AuthSession,
) -> AuthSession:
    auth_session.is_revoked = True
    auth_session.revoked_at = datetime.now(UTC)

    db.add(auth_session)
    db.commit()
    db.refresh(auth_session)

    return auth_session

def list_active_auth_sessions(
    db: Session,
    user_id: uuid.UUID,
) -> list[AuthSession]:
    statement = (
        select(AuthSession)
        .where(AuthSession.user_id == user_id)
        .where(AuthSession.is_revoked.is_(False))
        .where(AuthSession.expires_at > datetime.now(UTC))
        .order_by(AuthSession.created_at.desc())
    )

    return list(db.scalars(statement).all())

def get_user_auth_session_by_id(
    db: Session,
    user_id: uuid.UUID,
    session_id: uuid.UUID,
) -> AuthSession | None:
    statement = (
        select(AuthSession)
        .where(AuthSession.id == session_id)
        .where(AuthSession.user_id == user_id)
    )

    return db.scalar(statement)

def is_auth_session_valid(auth_session: AuthSession | None) -> bool:
    if auth_session is None:
        return False

    if auth_session.is_revoked:
        return False

    if auth_session.expires_at <= datetime.now(UTC):
        return False

    return True



