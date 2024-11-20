-- Add down migration script here
BEGIN;
DROP TABLE dag;
DROP TABLE timeouts;
DROP TABLE delivered;
DROP TABLE consensus_state;
COMMIT;