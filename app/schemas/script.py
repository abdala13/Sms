from pydantic import BaseModel, Field


class ParseCurlRequest(BaseModel):
    curl: str = Field(min_length=5)
