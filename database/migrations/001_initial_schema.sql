-- ============================================================================
-- Migration: 001_initial_schema.sql
-- Description: Core schema for ThreatLens security analytics engine
-- Database: PostgreSQL 16+
-- ============================================================================

-- Enable UUID extension for secure, unique identifiers
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- 1. RAW TELEMETRY TABLE
-- Stores multi-source incoming logs in their original JSON structure.
-- ============================================================================
CREATE TABLE raw_telemetry (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ingested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    source_type VARCHAR(64) NOT NULL, -- e.g., 'sysmon', 'cloudtrail', 'palo_alto_防火墙'
    payload JSONB NOT NULL
);

-- ============================================================================
-- 2. NORMALIZED EVENTS TABLE
-- Structured schema extracted from raw logs for high-performance querying,
-- process lineage tracing, and behavioral baselining.
-- ============================================================================
CREATE TABLE normalized_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    raw_telemetry_id UUID REFERENCES raw_telemetry(id) ON DELETE CASCADE,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    user_name VARCHAR(255),
    process_name VARCHAR(512),
    parent_process_name VARCHAR(512),
    process_id INT,
    parent_process_id INT,
    source_ip INET,
    destination_ip INET,
    destination_port INT,
    action VARCHAR(64), -- e.g., 'process_create', 'network_connect', 'logon'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 3. THREAT INTEL TABLE
-- Known Indicators of Compromise (IOCs) for multi-table correlation anti-joins.
-- ============================================================================
CREATE TABLE threat_intel (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator_type VARCHAR(32) NOT NULL, -- e.g., 'ip', 'domain', 'file_hash'
    indicator_value VARCHAR(512) NOT NULL UNIQUE,
    threat_name VARCHAR(255),
    severity VARCHAR(32) DEFAULT 'HIGH',
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 4. DETECTION RULES METADATA TABLE
-- Maps analytical queries or metadata to framework standards like MITRE ATT&CK.
-- ============================================================================
CREATE TABLE detection_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_name VARCHAR(255) NOT NULL,
    description TEXT,
    mitre_technique_id VARCHAR(32), -- e.g., 'T1059.001'
    severity VARCHAR(32) NOT NULL,
    query_text TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 5. PERFORMANCE INDEXING STRATEGY
-- Crucial for proving scalability when scanning millions of security events.
-- ============================================================================

-- GIN Index on raw JSONB payloads to allow lightning-fast nested property searches
CREATE INDEX idx_raw_telemetry_payload_gin ON raw_telemetry USING GIN (payload);
CREATE INDEX idx_raw_telemetry_source_type ON raw_telemetry (source_type);
CREATE INDEX idx_raw_telemetry_ingested_at ON raw_telemetry (ingested_at);

-- B-Tree Indexes on normalized tables for window functions, temporal queries, and joins
CREATE INDEX idx_normalized_events_timestamp ON normalized_events (timestamp DESC);
CREATE INDEX idx_normalized_events_hostname ON normalized_events (hostname);
CREATE INDEX idx_normalized_events_process ON normalized_events (process_name);
CREATE INDEX idx_normalized_events_parent_process ON normalized_events (parent_process_name);
CREATE INDEX idx_normalized_events_source_ip ON normalized_events (source_ip);
CREATE INDEX idx_normalized_events_dest_ip ON normalized_events (destination_ip);

-- Index on Threat Intel for rapid lookups during anti-joins
CREATE INDEX idx_threat_intel_value ON threat_intel (indicator_value);
