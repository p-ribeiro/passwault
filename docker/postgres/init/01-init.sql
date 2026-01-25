-- PostgreSQL initialization script for Passwault
-- This runs automatically on first container start

-- Enable useful extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Grant all privileges to the application user
GRANT ALL PRIVILEGES ON DATABASE passwault TO passwault;
