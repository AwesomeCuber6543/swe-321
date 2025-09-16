from pydantic import BaseModel

class Token(BaseModel):
    '''
    Attributes:
        access_token (str): The access token
        token_type (str): The type of the token
        refresh_token (str): The refresh token
    '''
    access_token: str
    token_type: str
    refresh_token: str
