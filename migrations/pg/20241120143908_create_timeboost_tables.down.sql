-- Add down migration script here
BEGIN;
DROP TABLE dag;
DROP TABLE consensus_state;
COMMIT;