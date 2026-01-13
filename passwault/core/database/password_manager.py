from ast import Pass
from typing import Optional
from passwault.core.database.models import SessionLocal, PasswordManager

# save a new password
def save_password(
    resource_name: str,
    password: str,
    username: Optional[str] = None,
    website: Optional[str] = None,
    description: Optional[str] = None) -> None:
    
    session = SessionLocal()
    new_pass = PasswordManager(
        resource_name = resource_name,
        username = username,
        password = password,
        website = website,
        description = description
        
    )
    
    session.add(new_pass)
    session.commit()
    session.refresh(new_pass)
    session.close()

def get_password_by_username(username: str) -> Optional[str]:
    session = SessionLocal()
    data = session.query(PasswordManager).filter_by(username=username).first()
    session.close()
    
    if data:
        return str(data.password)

    return None

def get_password_by_resource_name(resource_name: str) -> Optional[str]:
    session = SessionLocal()
    data = session.query(PasswordManager).filter_by(resource_name=resource_name).first()
    session.close()
    
    if data:
        return str(data.password)

    return None

def get_password_by_website(website: str) -> Optional[str]:
    session = SessionLocal()
    data = session.query(PasswordManager).filter_by(website=website).first()
    session.close()
    
    if data:
        return str(data.password)
    
    return None

def get_all_passwords()-> Optional[list[PasswordManager]]:
    session = SessionLocal()
    data = session.query(PasswordManager).all()
    session.close()
    
    if data:
        return data
    
    return None