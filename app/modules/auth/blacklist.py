from datetime import datetime, UTC

from app.integrations.redis import redis_client


def _blacklist_key(jti:str) -> str:
    return f"jwt:blacklist:{jti}"

def blacklist_access_token(jti:str,expired_at:datetime)->None:
    now=datetime.now(UTC)
    ttl_seconds=int((expired_at-now).total_seconds())

    if(ttl_seconds <=0):
        return

    redis_client.setex(
        _blacklist_key(jti),
        ttl_seconds,
        "1"
    )

def is_access_token_blacklisted(jti:str) -> bool:
    return bool(redis_client.exists(_blacklist_key(jti)))
