from pydantic import BaseModel, Field
from typing import Optional


class TokenRequest(BaseModel):
    grant_type: str = Field(...)
    code: str = Field(...)
    redirect_uri: str = Field(...)
    client_id: str = Field(...)
    code_verifier: str = Field(..., min_length=43, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    id_token: Optional[str] = None
    scope: str


class UserInfoResponse(BaseModel):
    sub: str
    preferred_username: Optional[str] = None