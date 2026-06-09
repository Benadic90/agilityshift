-- Fake banking tables with risky fields for PQC migration demo

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    -- Risky field: public key too small for PQC
    public_key VARCHAR(512),
    -- Risky field: certificate too small for PQC
    certificate VARCHAR(2048)
);

CREATE TABLE transactions (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    amount DECIMAL(10, 2),
    -- Risky field: signature too small for PQC
    signature VARCHAR(256)
);

CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    action VARCHAR(255),
    -- Risky field: jwt token might exceed limit with PQC
    jwt_token VARCHAR(512),
    -- Risky field: attestation proof too small
    attestation_proof VARCHAR(256)
);
