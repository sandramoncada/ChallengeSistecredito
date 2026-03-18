from pydantic import BaseModel, field_validator


class AnalyzeRequest(BaseModel):
    vector: str

    @field_validator("vector")
    @classmethod
    def validate_vector_format(cls, v: str) -> str:
        if not v.startswith("CVSS:3.1/"):
            raise ValueError("Vector must start with 'CVSS:3.1/'")
        return v
