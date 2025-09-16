from pydantic import BaseModel

class Settings(BaseModel):
    AWS_DEFAULT_REGION: str
    AWS_ACCESS_KEY_ID: str
    AWS_SECRET_ACCESS_KEY: str
    SECRET_KEY: str
