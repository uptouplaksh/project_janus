# janus_data/models.py
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, LargeBinary
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from .database import Base


def utcnow():
    """Helper to always get timezone-aware UTC datetimes."""
    return datetime.now(timezone.utc)


# Host model
class Host(Base):
    __tablename__ = 'host'

    id = Column(Integer, primary_key=True, index=True)
    host_ip_address = Column(String, unique=True, index=True, nullable=False)
    host_mac_address = Column(String, unique=True, nullable=False)
    host_name = Column(String, index=True)
    is_gateway = Column(Boolean, default=False)
    last_seen = Column(DateTime, default=utcnow)

    arp_entries_as_target = relationship(
        "ARPEntry",
        foreign_keys="ARPEntry.target_host_id",
        back_populates="target_host",
    )
    arp_entries_as_source = relationship(
        "ARPEntry",
        foreign_keys="ARPEntry.source_host_id",
        back_populates="source_host",
    )

    def __repr__(self):
        return f"<Host(id={self.id}, ip='{self.host_ip_address}', mac='{self.host_mac_address}')>"


class ARPEntry(Base):
    __tablename__ = 'arp_entry'

    id = Column(Integer, primary_key=True, index=True)
    spoofed_mac_address = Column(String, nullable=False)
    original_mac_address = Column(String, nullable=False)
    timestamp = Column(DateTime, default=utcnow)
    is_active = Column(Boolean, default=True)

    target_host_id = Column(Integer, ForeignKey('host.id'), nullable=False)
    source_host_id = Column(Integer, ForeignKey('host.id'), nullable=False)

    target_host = relationship(
        "Host",
        foreign_keys=[target_host_id],
        back_populates="arp_entries_as_target",
    )
    source_host = relationship(
        "Host",
        foreign_keys=[source_host_id],
        back_populates="arp_entries_as_source",
    )

    def __repr__(self):
        target_ip = self.target_host.host_ip_address if self.target_host else 'N/A'
        return f"<ARPEntry(id={self.id}, target_ip='{target_ip}', spoofed_mac='{self.spoofed_mac_address}')>"


class AttackSession(Base):
    __tablename__ = 'attack_session'

    id = Column(Integer, primary_key=True, index=True)
    start_time = Column(DateTime, default=utcnow)
    end_time = Column(DateTime)
    is_session_active = Column(Boolean, default=False)
    attacker_ip_address = Column(String, nullable=False)
    attacker_mac_address = Column(String, nullable=False)

    victim_host_id = Column(Integer, ForeignKey('host.id'), nullable=False)
    gateway_host_id = Column(Integer, ForeignKey('host.id'), nullable=False)

    victim_host = relationship("Host", foreign_keys=[victim_host_id])
    gateway_host = relationship("Host", foreign_keys=[gateway_host_id])
    packet_data = relationship('PacketData', back_populates="attack_session")

    def __repr__(self):
        victim_ip = self.victim_host.host_ip_address if self.victim_host else 'N/A'
        return f"<AttackSession(id={self.id}, active={self.is_session_active}, victim='{victim_ip}')>"


class PacketData(Base):
    __tablename__ = 'packet_data'

    id = Column(Integer, primary_key=True, index=True)

    # 👇 KEY FIX: make session_id nullable for now so passive sniffing works
    session_id = Column(Integer, ForeignKey("attack_session.id"), nullable=True)

    timestamp = Column(DateTime, default=utcnow)
    source_ip = Column(String, nullable=True)
    source_mac = Column(String, nullable=True)
    dest_ip = Column(String, nullable=True)
    dest_mac = Column(String, nullable=True)
    protocol = Column(String, nullable=True)
    raw_data = Column(LargeBinary, nullable=False)

    attack_session = relationship("AttackSession", back_populates="packet_data")

    def __repr__(self):
        return (
            f"<PacketData(id={self.id}, session='{self.session_id}', "
            f"src_ip='{self.source_ip}', dst_ip='{self.dest_ip}')>"
        )
