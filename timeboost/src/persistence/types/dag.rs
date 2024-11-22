use anyhow::{Context, Result};
use sailfish::consensus::Dag;
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use timeboost_core::types::{round_number::RoundNumber, vertex::Vertex, PublicKey};

use crate::persistence::traits::{Loadable, PgQuery, Savable};

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub(crate) struct DagRow {
    pub round: i64,
    pub public_key: Vec<u8>,
    pub vertex: Vec<u8>,
    pub max_keys: i64,
}

impl Savable for DagRow {
    type Model = Dag;

    fn table_name() -> &'static str {
        "dag"
    }

    fn from_model(model: Self::Model) -> Result<Vec<Self>> {
        model
            .to_entries()
            .map(|(r, s, v)| -> Result<Self> {
                Ok(Self {
                    round: r.i64(),
                    public_key: bincode::serialize(&s)?,
                    vertex: bincode::serialize(&v)?,
                    max_keys: model.max_keys().get() as i64,
                })
            })
            .collect()
    }

    fn column_names() -> &'static [&'static str] {
        &["round", "public_key", "vertex", "max_keys"]
    }

    fn bind_values(self, query: PgQuery<'_>) -> PgQuery<'_> {
        query
            .bind(self.round)
            .bind(self.public_key)
            .bind(self.vertex)
            .bind(self.max_keys)
    }
}

impl Loadable for DagRow {
    type Model = Dag;

    fn table_name() -> &'static str {
        "dag"
    }

    fn into_model(rows: Vec<Self>) -> Result<Self::Model> {
        let max_keys = rows.first().context("no rows found")?.max_keys as usize;

        let entries: Result<Vec<(RoundNumber, PublicKey, Vertex)>> = rows
            .iter()
            .map(|r| {
                Ok((
                    RoundNumber::from(r.round),
                    bincode::deserialize(&r.public_key).context("invalid public key")?,
                    bincode::deserialize(&r.vertex).context("invalid vertex")?,
                ))
            })
            .collect();

        // If any of the rows are invalid, we want to return an error
        let entries = entries?;

        Ok(Dag::from_entries(
            entries,
            NonZeroUsize::new(max_keys).context("invalid max keys")?,
        ))
    }
}
