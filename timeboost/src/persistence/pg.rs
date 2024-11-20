use anyhow::Result;
use async_trait::async_trait;
use sailfish::consensus::{ConsensusState, Dag};
use sqlx::PgPool;
use timeboost_core::types::{
    committee::StaticCommittee, round_number::RoundNumber, vertex::Vertex, PublicKey,
};
use tracing::debug;

use super::{
    row_types::{ConsensusStatePartialRow, ConsensusStateRaw, DagRow, DeliveredRow, TimeoutsRow},
    traits::Persistence,
};

pub struct PgPersistence {
    pool: PgPool,
}

#[async_trait]
impl Persistence for PgPersistence {
    async fn new(uri: String) -> Result<Self> {
        let pool = PgPool::connect(&uri).await?;
        Ok(Self { pool })
    }

    async fn load_dag(&self, committee: &StaticCommittee) -> Result<Dag> {
        let rows: Vec<DagRow> = sqlx::query_as("SELECT round, public_key, vertex FROM dag")
            .fetch_all(&self.pool)
            .await?;

        if rows.is_empty() {
            return Ok(Dag::new(committee.size()));
        }

        let mut entries = Vec::new();
        for row in rows {
            // It's a BIGINT in postgres, but sqlx only supports i64.
            let round_u64: u64 = row.round.try_into()?;
            let round = RoundNumber::from(round_u64);
            let public_key: PublicKey = bincode::deserialize(&row.public_key)?;
            let vertex: Vertex = bincode::deserialize(&row.vertex)?;
            entries.push((round, public_key, vertex));
        }

        Ok(Dag::from_entries(entries, committee.size()))
    }

    async fn save_vertex(&self, vertex: &Vertex) -> Result<()> {
        let mut conn = self.pool.acquire().await?;
        let round: i64 = vertex.round().i64();
        let vt_serialized = bincode::serialize(vertex)?;
        let pk_serialized = bincode::serialize(&vertex.source())?;

        debug!(
            %round,
            "saving vertex"
        );

        if let Err(e) =
            sqlx::query("INSERT INTO dag (round, public_key, vertex) VALUES ($1, $2, $3)")
                .bind(round)
                .bind(pk_serialized)
                .bind(vt_serialized)
                .execute(&mut *conn)
                .await
        {
            return Err(anyhow::anyhow!("failed to save vertex; error = {e}"));
        }

        Ok(())
    }

    async fn load_consensus_state(&self, committee: &StaticCommittee) -> Result<ConsensusState> {
        let state_partial: ConsensusStatePartialRow =
            sqlx::query_as("SELECT * FROM consensus_state")
                .fetch_one(&self.pool)
                .await?;
        let timeouts: Vec<TimeoutsRow> = sqlx::query_as("SELECT * FROM timeouts")
            .fetch_all(&self.pool)
            .await?;
        let delivered: Vec<DeliveredRow> = sqlx::query_as("SELECT * FROM delivered")
            .fetch_all(&self.pool)
            .await?;
        let dag = self.load_dag(committee).await?;

        ConsensusStateRaw {
            state_partial,
            timeouts,
            delivered,
            dag: Some(dag),
        }
        .into()
    }

    async fn save_consensus_state(&self, state: &ConsensusState) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let timeouts = TimeoutsRow::from_consensus_state(state)?;
        let delivered = DeliveredRow::from_consensus_state(state)?;
        let state_partial = ConsensusStatePartialRow::from_consensus_state(state)?;

        for row in timeouts {
            sqlx::query(
                "INSERT INTO timeouts (round, votes) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(row.round)
            .bind(row.votes)
            .execute(&mut *tx)
            .await?;
        }

        for row in delivered {
            sqlx::query(
                "INSERT INTO delivered (round, public_key) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(row.round)
            .bind(row.public_key)
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query(
            "INSERT INTO consensus_state (round, committed_round, buffer, delivered, no_votes, leader_stack, transactions) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
        )
            .bind(state_partial.round)
            .bind(state_partial.committed_round)
            .bind(state_partial.buffer)
            .bind(state_partial.delivered)
            .bind(state_partial.no_votes)
            .bind(state_partial.leader_stack)
            .bind(state_partial.transactions)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn gc(&self, round: RoundNumber) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM dag WHERE round < $1")
            .bind(round.i64())
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM timeouts WHERE round < $1")
            .bind(round.i64())
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM delivered WHERE round < $1")
            .bind(round.i64())
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM consensus_state WHERE round < $1")
            .bind(round.i64())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}
