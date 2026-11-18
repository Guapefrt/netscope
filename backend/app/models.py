from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String, default="nmap_discovery")
    timestamp = Column(DateTime, default=datetime.utcnow)
    source_file = Column(String)

    assets = relationship("Asset", back_populates="scan", cascade="all, delete-orphan")

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    ip_address = Column(String, index=True)
    mac_address = Column(String, index=True, nullable=True)
    vendor = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    os_estimate = Column(String, nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="assets")
    services = relationship("Service", back_populates="asset", cascade="all, delete-orphan")
    packages = relationship("SoftwarePackage", back_populates="asset", cascade="all, delete-orphan")
    endpoint_security = relationship("EndpointSecurity", back_populates="asset", uselist=False, cascade="all, delete-orphan")

class Service(Base):
    __tablename__ = "services"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    port = Column(Integer)
    protocol = Column(String)
    state = Column(String)
    service_name = Column(String)
    product = Column(String, nullable=True)
    version = Column(String, nullable=True)

    asset = relationship("Asset", back_populates="services")

class SoftwarePackage(Base):
    __tablename__ = "software_packages"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    name = Column(String)
    version = Column(String)
    architecture = Column(String, nullable=True)

    asset = relationship("Asset", back_populates="packages")

class EndpointSecurity(Base):
    __tablename__ = "endpoint_security"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    wazuh_agent_id = Column(String)
    status = Column(String)
    total_checks = Column(Integer)
    passed_checks = Column(Integer)
    failed_checks = Column(Integer)

    asset = relationship("Asset", back_populates="endpoint_security")
