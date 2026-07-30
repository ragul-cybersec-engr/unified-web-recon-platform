from pydantic import BaseModel, EmailStr, constr, validator
from typing import List, Literal, Optional


class LoginIn(BaseModel):
    email: EmailStr
    password: constr(min_length=6)


class NewReconIn(BaseModel):
    orgname: constr(min_length=1)
    domains: List[constr(min_length=1)]
    email: Optional[EmailStr] = None
    scan_type: Literal["domain", "extended"] = "extended"

    @validator("orgname")
    def orgname_must_not_be_blank(cls, v):
        cleaned = " ".join(v.split())
        if not cleaned:
            raise ValueError("organization name is required")
        return cleaned

    @validator("domains")
    def domains_must_be_valid(cls, v):
        cleaned = []
        for d in v:
            d = d.strip().lower()
            if not d:
                continue
            if " " in d:
                raise ValueError("invalid domain")
            cleaned.append(d)
        if not cleaned:
            raise ValueError("no valid domains")
        return cleaned


class RegisterIn(BaseModel):
    email: EmailStr
    password: constr(min_length=6)
    name: constr(min_length=1, max_length=120)


class OTPRequestIn(BaseModel):
    email: EmailStr


class OTPVerifyIn(BaseModel):
    email: EmailStr
    otp: constr(min_length=4, max_length=8)


class ExportEmailIn(BaseModel):
    recipient_email: EmailStr
    format: Literal["txt", "docx", "pdf", "xml"] = "pdf"
