from datetime import datetime
import pymysql
from app.settings import get_settings
from app.schemas.models import UserInDB

settings = get_settings()

def get_db_connection():
    return pymysql.connect(
        host='yamabiko.proxy.rlwy.net',
        port=18460,
        user='root',
        password=settings.MYSQL_ROOT_PASSWORD,
        database='railway',
        charset='utf8mb4'
    )

def get_db():
    connection = get_db_connection()
    try:
        yield connection
    finally:
        connection.close()

class Database:
    def __init__(self, connection):
        self.connection = connection
        self.users = UserTable(connection)
        self.tokens = TokenTable(connection)

class UserTable:
    def __init__(self, connection):
        self.connection = connection
    
    def put_item(self, Item: dict):
        cursor = self.connection.cursor()
        try:
            sql = """
            INSERT INTO users (email, hashed_password, first_name, last_name, role, is_temporary_password, disabled, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            hashed_password = VALUES(hashed_password),
            first_name = VALUES(first_name),
            last_name = VALUES(last_name),
            role = VALUES(role),
            is_temporary_password = VALUES(is_temporary_password),
            disabled = VALUES(disabled)
            """
            cursor.execute(sql, (
                Item['email'],
                Item['hashed_password'],
                Item['first_name'],
                Item['last_name'],
                Item['role'],
                Item['is_temporary_password'],
                Item['disabled'],
                Item['created_at']
            ))
            self.connection.commit()
            return {"Item": Item}
        finally:
            cursor.close()
    
    def get_item(self, Key: dict):
        cursor = self.connection.cursor(pymysql.cursors.DictCursor)
        try:
            sql = "SELECT * FROM users WHERE email = %s"
            cursor.execute(sql, (Key['email'],))
            user = cursor.fetchone()
            if user:
                return {"Item": user}
            return {}
        finally:
            cursor.close()
    
    def delete_item(self, Key: dict):
        cursor = self.connection.cursor()
        try:
            sql = "DELETE FROM users WHERE email = %s"
            cursor.execute(sql, (Key['email'],))
            self.connection.commit()
            return {}
        finally:
            cursor.close()

class TokenTable:
    def __init__(self, connection):
        self.connection = connection
    
    def put_item(self, Item: dict):
        cursor = self.connection.cursor()
        try:
            expires_at = Item['expires_at']
            if isinstance(expires_at, int):
                expires_at = datetime.fromtimestamp(expires_at)
            
            sql = """
            INSERT INTO tokens (access_token, refresh_token, user_id, expires_at, token_type, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            refresh_token = VALUES(refresh_token),
            user_id = VALUES(user_id),
            expires_at = VALUES(expires_at),
            token_type = VALUES(token_type)
            """
            cursor.execute(sql, (
                Item['access_token'],
                Item['refresh_token'],
                Item['user_id'],
                expires_at,
                Item['token_type'],
                datetime.now()
            ))
            self.connection.commit()
            return {"Item": Item}
        finally:
            cursor.close()
    
    def get_item(self, Key: dict):
        cursor = self.connection.cursor(pymysql.cursors.DictCursor)
        try:
            sql = "SELECT * FROM tokens WHERE access_token = %s"
            cursor.execute(sql, (Key['access_token'],))
            token = cursor.fetchone()
            if token:
                if 'expires_at' in token and hasattr(token['expires_at'], 'timestamp'):
                    token['expires_at'] = int(token['expires_at'].timestamp())
                return {"Item": token}
            return {}
        finally:
            cursor.close()
    
    def delete_item(self, Key: dict):
        cursor = self.connection.cursor()
        try:
            sql = "DELETE FROM tokens WHERE access_token = %s"
            cursor.execute(sql, (Key['access_token'],))
            self.connection.commit()
            return {}
        finally:
            cursor.close()
