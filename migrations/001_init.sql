-- lumid-identity schema. GORM AutoMigrate creates these on startup;
-- this file is the read-friendly source of truth + ops-friendly
-- bootstrap for a fresh Postgres migration later.
--
-- Phase 1 targets MySQL (trading_mysql) with a dedicated database
-- `lumid_identity`. Run once, as root:
--
--   CREATE DATABASE IF NOT EXISTS lumid_identity
--     CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(36) PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  password_hash VARCHAR(255),
  name VARCHAR(255),
  avatar_url VARCHAR(512),
  role VARCHAR(32) NOT NULL DEFAULT 'user',
  status VARCHAR(16) NOT NULL DEFAULT 'active',
  invitation_code_used VARCHAR(64),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS identities (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id VARCHAR(36) NOT NULL,
  provider VARCHAR(32) NOT NULL,
  provider_sub VARCHAR(255) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_provider_sub (provider, provider_sub),
  INDEX idx_identities_user (user_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS tokens (
  id VARCHAR(36) PRIMARY KEY,
  user_id VARCHAR(36) NOT NULL,
  prefix VARCHAR(16) NOT NULL,
  hash VARCHAR(255) NOT NULL,
  hash_alg VARCHAR(16) NOT NULL DEFAULT 'argon2id',
  name VARCHAR(128),
  scopes TEXT,
  last_used_at TIMESTAMP NULL,
  expires_at TIMESTAMP NULL,
  revoked_at TIMESTAMP NULL,
  source VARCHAR(16) NOT NULL DEFAULT 'native',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_tokens_user (user_id),
  INDEX idx_tokens_prefix (prefix),
  INDEX idx_tokens_hash (hash)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS oauth_clients (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  client_id VARCHAR(64) NOT NULL UNIQUE,
  secret_hash VARCHAR(255),
  name VARCHAR(128) NOT NULL,
  redirect_uris TEXT NOT NULL,
  grant_types VARCHAR(255) NOT NULL,
  allowed_scopes TEXT NOT NULL,
  is_public BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS oauth_codes (
  code VARCHAR(64) PRIMARY KEY,
  client_id VARCHAR(64) NOT NULL,
  user_id VARCHAR(36) NOT NULL,
  redirect_uri VARCHAR(512) NOT NULL,
  scopes TEXT,
  code_challenge VARCHAR(128),
  code_challenge_method VARCHAR(16),
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_oauth_codes_expires (expires_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS sessions (
  id VARCHAR(36) PRIMARY KEY,
  user_id VARCHAR(36) NOT NULL,
  jti VARCHAR(64) NOT NULL UNIQUE,
  client_id VARCHAR(64),
  user_agent VARCHAR(255),
  ip VARCHAR(45),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  revoked_at TIMESTAMP NULL,
  INDEX idx_sessions_user (user_id),
  INDEX idx_sessions_expires (expires_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS signing_keys (
  kid VARCHAR(32) PRIMARY KEY,
  alg VARCHAR(16) NOT NULL DEFAULT 'RS256',
  private_pem TEXT NOT NULL,
  public_jwk TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  rotated_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_signing_keys_active (active)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_log (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id VARCHAR(36),
  token_id VARCHAR(36),
  event VARCHAR(32) NOT NULL,
  source VARCHAR(32),
  method VARCHAR(8),
  path VARCHAR(255),
  status INT,
  duration_ms INT,
  ip VARCHAR(45),
  user_agent VARCHAR(255),
  detail TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_audit_user (user_id),
  INDEX idx_audit_token (token_id),
  INDEX idx_audit_created (created_at)
) ENGINE=InnoDB;
