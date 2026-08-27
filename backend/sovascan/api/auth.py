import datetime
import hashlib

from fastapi import Depends, HTTPException, Security, status
from fastapi.security.api_key import APIKeyHeader
from sqlalchemy.orm import Session

from sovascan.models.api_key import ApiKey
from sovascan.models.base import get_db

# Define header key lookup
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_api_key(
    api_key_str: str = Security(api_key_header),
    db: Session = Depends(get_db)
) -> ApiKey:
    """Verifies that the provided X-API-Key header matches an active database key."""
    if not api_key_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API Key. Provide X-API-Key in header."
        )

    # Calculate SHA-256 hash of the incoming key
    key_hash = hashlib.sha256(api_key_str.encode("utf-8")).hexdigest()

    # Query key in database
    db_key = db.query(ApiKey).filter(
        ApiKey.key_hash == key_hash,
        ApiKey.is_active.is_(True),
    ).first()

    if not db_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API Key."
        )

    # Update last_used timestamp asynchronously/safely
    try:
        db_key.last_used = datetime.datetime.utcnow()
        db.commit()
    except Exception:
        db.rollback()

    return db_key
