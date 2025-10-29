-- ==========================
-- Clean Database Schema
-- ==========================

-- Drop existing structures safely
DROP TABLE IF EXISTS expiry_alerts CASCADE;
DROP TABLE IF EXISTS inventory CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TYPE IF EXISTS account_type CASCADE;

-- User account type
CREATE TYPE public.account_type AS ENUM
    ('Client','Employee', 'Admin');
ALTER TYPE public.account_type
    OWNER TO rehaan;
-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    account_type account_type DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Inventory table
CREATE TABLE inventory (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    item_name VARCHAR(100) NOT NULL,
    dsc TEXT,
    category VARCHAR(50),
    qty INTEGER CHECK (qty >= 0),
    unit VARCHAR(20),
    date_added DATE DEFAULT CURRENT_DATE,
    exp_date DATE,
    price NUMERIC(10,2) CHECK (price >= 0),
    UNIQUE (user_id, item_name)
);

-- Expiry alerts table
CREATE TABLE expiry_alerts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    inventory_id INTEGER REFERENCES inventory(id) ON DELETE CASCADE,
    alert_date DATE DEFAULT CURRENT_DATE,
    msg TEXT
);
