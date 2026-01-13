use std::{
    env::{self, VarError},
    io,
};

use aws_sdk_dynamodb::{Client, operation::get_item::GetItemOutput, types::AttributeValue};
use tracing::{error, warn};

use crate::env::{TIMEBOOST_DYNAMODB_TABLE, TIMEBOOST_STAMP};

const KEY: &str = "key";
const VAL: &str = "val";
const DEFAULT_TABLE_NAME: &str = "timeboost";

#[derive(Debug)]
pub struct StateIo {
    table: String,
    stamp: String,
    client: Client,
}

impl StateIo {
    pub async fn create() -> io::Result<Self> {
        let Ok(stamp) = env::var(TIMEBOOST_STAMP) else {
            let msg = format!("missing or invalid environment variable {TIMEBOOST_STAMP}");
            return Err(io::Error::new(io::ErrorKind::NotFound, msg));
        };
        let table = match env::var(TIMEBOOST_DYNAMODB_TABLE) {
            Ok(name) => name,
            Err(VarError::NotPresent) => {
                warn!(%stamp, name = %DEFAULT_TABLE_NAME, "using default dynamo-db table");
                String::from(DEFAULT_TABLE_NAME)
            }
            Err(VarError::NotUnicode(_)) => {
                let msg = format!("invalid environment variable {TIMEBOOST_DYNAMODB_TABLE}");
                return Err(io::Error::new(io::ErrorKind::NotFound, msg));
            }
        };
        Ok(Self {
            table,
            stamp,
            client: Client::new(&aws_config::load_from_env().await),
        })
    }

    pub async fn load(&mut self) -> io::Result<Option<Vec<u8>>> {
        let item = self
            .client
            .get_item()
            .table_name(&self.table)
            .key(KEY, AttributeValue::S(self.stamp.clone()))
            .send()
            .await
            .map_err(|e| io::Error::other(e.into_service_error()))?;

        let GetItemOutput {
            item: Some(map), ..
        } = item
        else {
            return Ok(None);
        };

        let Some(AttributeValue::B(val)) = map.get(VAL) else {
            let msg = format!(
                "{}::{} does not contain binary data",
                self.table, self.stamp
            );
            return Err(io::Error::new(io::ErrorKind::InvalidData, msg));
        };

        Ok(Some(val.clone().into_inner()))
    }

    pub async fn store(&mut self, val: &[u8]) -> io::Result<()> {
        let req = self
            .client
            .update_item()
            .table_name(&self.table)
            .key(KEY, AttributeValue::S(self.stamp.clone()))
            .update_expression(format!("SET {VAL} = :b"))
            .expression_attribute_values(":b", AttributeValue::B(val.into()));

        req.send().await.map_err(|err| {
            error!(stamp = %self.stamp, %err, "failed to store stamp item");
            io::Error::other(err)
        })?;

        Ok(())
    }
}
