-- Add up migration script here

--! postgres
BEGIN;
CREATE TABLE IF NOT EXISTS dag (
    round BIGINT NOT NULL,
    public_key BYTEA NOT NULL,
    vertex BYTEA NOT NULL,
    max_keys BIGINT NOT NULL,
    PRIMARY KEY (round, public_key)
);

CREATE TABLE IF NOT EXISTS consensus_state (
    round BIGINT NOT NULL PRIMARY KEY,
    committed_round BIGINT NOT NULL,
    transactions BYTEA NOT NULL,
    PRIMARY KEY (round)
);
COMMIT;