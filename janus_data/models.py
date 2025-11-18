from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, LargeBinary
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from .database import Base

# Host model
class Host(Base):
    __tablename__ = 'host'

    # attributes
    id = Column(Integer, primary_key=True, index=True)
    host_ip_address = Column(String, unique=True, index=True, nullable=False)
    host_mac_address = Column(String, unique=True, nullable=False)
    host_name = Column(String, index=True)
    is_gateway = Column(Boolean, default=False)
    last_seen = Column(DateTime, default=datetime.now(timezone.utc))

    # Relationships
    arp_entries_as_target = relationship("ArpEntry", foreign_keys="ARPEntry.target_host_id", back_populates="target_host")
    arp_entries_as_source = relationship("ArpEntry", foreign_keys="ARPEntry.source_host_id", back_populates="source_host")

    def __repr__(self):
        return f"<Host(id={self.id},ip='{self.host_ip_address} ', mac='{self.host_mac_address}')>"

    def __repr__(self):
        return f"<Host(id={self.id},ip='{self.host_ip_address} ', mac='{self.host_mac_address}')>"


class Host(Base):
    __tablename__ = 'host'

    # attributes
    # Relationships