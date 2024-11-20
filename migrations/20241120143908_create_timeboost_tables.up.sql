-- Add up migration script here

--! postgres
BEGIN;
CREATE TABLE IF NOT EXISTS dag (
    round BIGINT NOT NULL,
    public_key BYTEA NOT NULL,
    vertex BYTEA NOT NULL,
    PRIMARY KEY (round, public_key)
);

CREATE TABLE IF NOT EXISTS timeouts (
    round BIGINT NOT NULL PRIMARY KEY,
    votes BYTEA NOT NULL,
    PRIMARY KEY (round)
);

CREATE TABLE IF NOT EXISTS delivered (
    round BIGINT NOT NULL PRIMARY KEY,
    public_key BYTEA NOT NULL,
    PRIMARY KEY (round, public_key)
);

CREATE TABLE IF NOT EXISTS consensus_state (
    round BIGINT NOT NULL PRIMARY KEY,
    committed_round BIGINT NOT NULL,
    buffer BYTEA NOT NULL,
    delivered BYTEA NOT NULL,
    no_votes BYTEA NOT NULL,
    leader_stack BYTEA NOT NULL,
    transactions BYTEA NOT NULL,
    PRIMARY KEY (round)
);
COMMIT;