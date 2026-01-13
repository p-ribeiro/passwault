from sqlalchemy import Column, Integer, String, Text, ForeignKey, create_engine
from sqlalchemy.orm import relationship, declarative_base, sessionmaker

Base = declarative_base()

class PasswordManager(Base):
    __tablename__ = "password_manager"
    
    id = Column(Integer, primary_key=True)
    resource_name = Column(String(100), nullable=False)
    username = Column(String(50), nullable=True)
    password = Column(String(50), nullable=False)
    website = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    
# Database Setup
engine = create_engine("sqlite:///passwault.db", echo=True)
SessionLocal = sessionmaker(bind=engine)