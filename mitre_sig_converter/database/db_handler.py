from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from typing import List, Optional, Dict, Any
import logging

from .schema import Base, Technique, Signature

class DatabaseHandler:
    def __init__(self, db_url: str):
        self.engine = create_engine(db_url)
        self.Session = sessionmaker(bind=self.engine)
        self.logger = logging.getLogger(__name__)

    def init_db(self):
        """Initialize the database by creating all tables."""
        try:
            Base.metadata.create_all(self.engine)
            self.logger.info("Database initialized successfully")
        except SQLAlchemyError as e:
            self.logger.error(f"Failed to initialize database: {str(e)}")
            raise

    def add_technique(self, technique_data: Dict[str, Any]) -> Optional[Technique]:
        """Add a new technique to the database."""
        session = self.Session()
        try:
            technique = Technique(**technique_data)
            session.add(technique)
            session.commit()
            return technique
        except SQLAlchemyError as e:
            session.rollback()
            self.logger.error(f"Failed to add technique: {str(e)}")
            return None
        finally:
            session.close()

    def add_signature(self, signature_data: Dict[str, Any]) -> Optional[Signature]:
        """Add a new signature to the database."""
        session = self.Session()
        try:
            signature = Signature(**signature_data)
            session.add(signature)
            session.commit()
            return signature
        except SQLAlchemyError as e:
            session.rollback()
            self.logger.error(f"Failed to add signature: {str(e)}")
            return None
        finally:
            session.close()

    def get_technique(self, technique_id: str) -> Optional[Technique]:
        """Retrieve a technique by its ID."""
        session = self.Session()
        try:
            return session.query(Technique).filter_by(technique_id=technique_id).first()
        except SQLAlchemyError as e:
            self.logger.error(f"Failed to get technique: {str(e)}")
            return None
        finally:
            session.close()

    def get_signatures_by_technique(self, technique_id: str) -> List[Signature]:
        """Retrieve all signatures for a specific technique."""
        session = self.Session()
        try:
            technique = self.get_technique(technique_id)
            if technique:
                return technique.signatures
            return []
        except SQLAlchemyError as e:
            self.logger.error(f"Failed to get signatures: {str(e)}")
            return []
        finally:
            session.close()

    def update_technique(self, technique_id: str, update_data: Dict[str, Any]) -> bool:
        """Update an existing technique."""
        session = self.Session()
        try:
            technique = self.get_technique(technique_id)
            if technique:
                for key, value in update_data.items():
                    setattr(technique, key, value)
                session.commit()
                return True
            return False
        except SQLAlchemyError as e:
            session.rollback()
            self.logger.error(f"Failed to update technique: {str(e)}")
            return False
        finally:
            session.close()

    def delete_technique(self, technique_id: str) -> bool:
        """Delete a technique and its associated signatures."""
        session = self.Session()
        try:
            technique = self.get_technique(technique_id)
            if technique:
                session.delete(technique)
                session.commit()
                return True
            return False
        except SQLAlchemyError as e:
            session.rollback()
            self.logger.error(f"Failed to delete technique: {str(e)}")
            return False
        finally:
            session.close()
