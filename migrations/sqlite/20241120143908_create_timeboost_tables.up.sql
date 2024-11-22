-- Add up migration script here

--! sqlite
CREATE TABLE IF NOT EXISTS dag (
    round INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    vertex BLOB NOT NULL,
    max_keys INTEGER NOT NULL,
    PRIMARY KEY (round, public_key)
);

CREATE TABLE IF NOT EXISTS consensus_state (
    round INTEGER NOT NULL,
    committed_round INTEGER NOT NULL,
    transactions BLOB NOT NULL,
    PRIMARY KEY (round)
);