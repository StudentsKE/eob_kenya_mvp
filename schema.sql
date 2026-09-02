-- e-OB Kenya MVP database structure
-- PostgreSQL target schema. Development design only.
-- Do not load real operational police data until the system has been
-- formally reviewed, authorized, secured and tested.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE user_role AS ENUM (
  'SYSTEM_ADMIN',
  'STATION_ADMIN',
  'OB_OFFICER',
  'SUPERVISOR',
  'INVESTIGATING_OFFICER',
  'READ_ONLY'
);

CREATE TYPE occurrence_status AS ENUM (
  'OPEN',
  'UNDER_REVIEW',
  'ASSIGNED',
  'ACTIONED',
  'CLOSED',
  'REFERRED'
);

CREATE TYPE person_role AS ENUM (
  'REPORTER',
  'COMPLAINANT',
  'VICTIM',
  'SUSPECT',
  'WITNESS',
  'OTHER'
);

CREATE TABLE stations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  station_code VARCHAR(30) NOT NULL UNIQUE,
  station_name VARCHAR(150) NOT NULL,
  county VARCHAR(100) NOT NULL,
  sub_county VARCHAR(100),
  ward VARCHAR(100),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  service_identifier VARCHAR(50) NOT NULL UNIQUE,
  username VARCHAR(80) NOT NULL UNIQUE,
  full_name VARCHAR(180) NOT NULL,
  rank_title VARCHAR(100),
  role user_role NOT NULL,
  station_id UUID REFERENCES stations(id),
  password_hash TEXT NOT NULL,
  mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE occurrence_counters (
  station_id UUID PRIMARY KEY REFERENCES stations(id),
  current_ob_number BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE occurrences (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  station_id UUID NOT NULL REFERENCES stations(id),
  ob_number BIGINT NOT NULL,
  occurrence_date DATE NOT NULL,
  occurrence_time TIME NOT NULL,
  category VARCHAR(100) NOT NULL,
  subcategory VARCHAR(100),
  location_text TEXT NOT NULL,
  narrative TEXT NOT NULL,
  action_taken TEXT,
  status occurrence_status NOT NULL DEFAULT 'OPEN',
  confidentiality_level VARCHAR(30) NOT NULL DEFAULT 'RESTRICTED',
  created_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (station_id, ob_number)
);

CREATE TABLE occurrence_persons (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  occurrence_id UUID NOT NULL REFERENCES occurrences(id) ON DELETE RESTRICT,
  person_role person_role NOT NULL,
  full_name VARCHAR(180) NOT NULL,
  phone VARCHAR(40),
  address TEXT,
  age_years INTEGER CHECK (age_years IS NULL OR age_years BETWEEN 0 AND 130),
  sex VARCHAR(30),
  identification_reference TEXT,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE occurrence_assignments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  occurrence_id UUID NOT NULL REFERENCES occurrences(id) ON DELETE RESTRICT,
  officer_id UUID NOT NULL REFERENCES users(id),
  assigned_by UUID NOT NULL REFERENCES users(id),
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  unassigned_at TIMESTAMPTZ
);

CREATE TABLE occurrence_actions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  occurrence_id UUID NOT NULL REFERENCES occurrences(id) ON DELETE RESTRICT,
  action_type VARCHAR(100) NOT NULL,
  action_text TEXT NOT NULL,
  action_time TIMESTAMPTZ NOT NULL DEFAULT now(),
  performed_by UUID NOT NULL REFERENCES users(id)
);

CREATE TABLE occurrence_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  occurrence_id UUID NOT NULL REFERENCES occurrences(id) ON DELETE RESTRICT,
  version_number INTEGER NOT NULL,
  changed_by UUID NOT NULL REFERENCES users(id),
  changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  change_reason TEXT NOT NULL,
  snapshot JSONB NOT NULL,
  UNIQUE (occurrence_id, version_number)
);

CREATE TABLE approvals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  occurrence_id UUID NOT NULL REFERENCES occurrences(id) ON DELETE RESTRICT,
  decision VARCHAR(30) NOT NULL CHECK (decision IN ('APPROVED','RETURNED','REJECTED')),
  remarks TEXT,
  decided_by UUID NOT NULL REFERENCES users(id),
  decided_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE attachments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  occurrence_id UUID NOT NULL REFERENCES occurrences(id) ON DELETE RESTRICT,
  object_key TEXT NOT NULL,
  original_filename TEXT NOT NULL,
  mime_type VARCHAR(150) NOT NULL,
  file_size_bytes BIGINT NOT NULL,
  sha256_hex CHAR(64) NOT NULL,
  uploaded_by UUID NOT NULL REFERENCES users(id),
  uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
  id BIGSERIAL PRIMARY KEY,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id UUID REFERENCES users(id),
  station_id UUID REFERENCES stations(id),
  action VARCHAR(80) NOT NULL,
  entity_type VARCHAR(80) NOT NULL,
  entity_id UUID,
  ip_address INET,
  user_agent TEXT,
  details JSONB
);

CREATE INDEX idx_occurrences_station_date
  ON occurrences(station_id, occurrence_date DESC);

CREATE INDEX idx_occurrences_status
  ON occurrences(status);

CREATE INDEX idx_occurrence_persons_occurrence
  ON occurrence_persons(occurrence_id);

CREATE INDEX idx_audit_station_time
  ON audit_log(station_id, occurred_at DESC);

-- Important application rule:
-- UPDATE/DELETE of the substantive occurrence record must not silently
-- overwrite history. The application should create an occurrence_versions
-- row containing the previous state and require a reason for every amendment.
-- Hard deletion should be prohibited for operational records.
