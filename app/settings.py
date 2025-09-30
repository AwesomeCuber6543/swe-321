import os
from dotenv import load_dotenv
from app.schemas.settings import Settings

def get_settings():
    load_dotenv("project.env")
    
    settings_dict = {
        key: value 
        for key, value in os.environ.items() 
        if key in Settings.model_fields.keys()
    }
    
    return Settings(**settings_dict)

if __name__ == "__main__":
    print(get_settings())
