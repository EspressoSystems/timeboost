#![cfg(feature = "postgres")]

use anyhow::Result;
use async_trait::async_trait;
use serde::Serialize;
use sqlx::PgPool;
use timeboost_core::types::round_number::RoundNumber;

use super::traits::{Loadable, Persistence, Savable};

pub struct PgPersistence {
    pool: PgPool,
}

#[async_trait]
impl Persistence for PgPersistence {
    async fn new(uri: String) -> Result<Self> {
        let pool = PgPool::connect(&uri).await?;
        Ok(Self { pool })
    }

    async fn save<M, S>(&self, model: M, saver: S) -> Result<()>
    where
        M: Serialize + Send + Sync,
        S: Savable<Model = M> + Send + Sync,
    {
        let rows = S::from_model(model)?;
        let query = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            S::table_name(),
            S::column_names().join(", "),
            &format!(
                "({})",
                rows.iter()
                    .enumerate()
                    .map(|(i, _)| format!("${}", i + 1))
                    .collect::<Vec<String>>()
                    .join(", ")
            )
        );
        saver
            .bind_values(sqlx::query(&query))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn load<L>(&self) -> Result<L::Model>
    where
        L: Loadable,
    {
        let query = format!("SELECT * FROM {}", L::table_name());
        let rows = sqlx::query_as::<_, L>(&query).fetch_all(&self.pool).await?;
        L::into_model(rows)
    }

    async fn gc(&self, tables: &[&str], round: RoundNumber) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for table in tables {
            sqlx::query(&format!("DELETE FROM {} WHERE round < $1", table))
                .bind(round.i64())
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
