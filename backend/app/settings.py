import os
from pathlib import Path
from dotenv import load_dotenv
from schemas.settings import Settings

def get_settings():
    env_path = Path(__file__).parent.parent.parent / "project.env"
    load_dotenv(env_path)
    
    settings_dict = {
        key: value 
        for key, value in os.environ.items() 
        if key in Settings.model_fields.keys()
    }
    
    return Settings(**settings_dict)

if __name__ == "__main__":
    print(get_settings())
