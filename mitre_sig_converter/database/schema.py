from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime, JSON
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime, UTC

Base = declarative_base()

class Technique(Base):
    __tablename__ = 'techniques'
    
    id = Column(Integer, primary_key=True)
    technique_id = Column(String(50), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    platform = Column(String(50))
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
    updated_at = Column(DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))
    
    signatures = relationship("Signature", back_populates="technique")

class Signature(Base):
    __tablename__ = 'signatures'
    
    id = Column(Integer, primary_key=True)
    technique_id = Column(Integer, ForeignKey('techniques.id'), nullable=False)
    signature_type = Column(String(50), nullable=False)  # YARA, Sigma, KQL
    content = Column(Text, nullable=False)
    signature_metadata = Column(JSON)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
    updated_at = Column(DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))
    
    technique = relationship("Technique", back_populates="signatures")
