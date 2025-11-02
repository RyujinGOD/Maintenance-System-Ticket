from datetime import datetime
from flask_login import UserMixin
from sqlalchemy import Integer, String, Text, DateTime, Column, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base, UserMixin):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(String(120))
    email = Column(String(120), unique=True, index=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    role = Column(String(20), default='user')  # 'user' or 'admin'
    tickets_created = relationship("Ticket", back_populates="creator", foreign_keys="Ticket.created_by")
    tickets_managed = relationship("Ticket", back_populates="manager", foreign_keys="Ticket.managed_by")

class Ticket(Base):
    __tablename__ = 'tickets'
    id = Column(Integer, primary_key=True)
    date_created = Column(DateTime, default=datetime.utcnow)
    type = Column(String(80))
    description = Column(Text)
    action_done = Column(Text)
    status = Column(String(30), default='open')  # open, in_progress, resolved
    created_by = Column(Integer, ForeignKey('users.id'))
    managed_by = Column(Integer, ForeignKey('users.id'), nullable=True)
    attachment = Column(String(255), nullable=True)  # filename stored
    creator = relationship("User", foreign_keys=[created_by], back_populates="tickets_created")
    manager = relationship("User", foreign_keys=[managed_by], back_populates="tickets_managed")
