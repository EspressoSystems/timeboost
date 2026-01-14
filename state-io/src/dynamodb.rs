use std::{
    env::{self, VarError},
    io,
};

use aws_sdk_dynamodb::{Client, operation::get_item::GetItemOutput, types::AttributeValue};
use tracing::{error, warn};

const KEY: &str = "key";
const VAL: &str = "val";
const DEFAULT_TABLE_NAME: &str = "timeboost";
const TIMEBOOST_DYNAMODB_TABLE: &str = "TIMEBOOST_DYNAMODB_TABLE";

#[derive(Debug)]
pub struct StateIo {
    table: String,
    client: Client,
}

impl StateIo {
    pub async fn create() -> io::Result<Self> {
        let table = match env::var(TIMEBOOST_DYNAMODB_TABLE) {
            Ok(name) => name,
            Err(VarError::NotPresent) => {
                warn!(name = %DEFAULT_TABLE_NAME, "using default dynamo-db table");
                String::from(DEFAULT_TABLE_NAME)
            }
            Err(VarError::NotUnicode(_)) => {
                let msg = format!("invalid environment variable {TIMEBOOST_DYNAMODB_TABLE}");
                return Err(io::Error::new(io::ErrorKind::NotFound, msg));
            }
        };
        Ok(Self {
            table,
            client: Client::new(&aws_config::load_from_env().await),
        })
    }

    pub async fn load(&mut self, key: &str) -> io::Result<Option<Vec<u8>>> {
        let item = self
            .client
            .get_item()
            .table_name(&self.table)
            .key(KEY, AttributeValue::S(key.to_string()))
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
            let msg = format!("{}::{} does not contain binary data", self.table, key);
            return Err(io::Error::new(io::ErrorKind::InvalidData, msg));
        };

        Ok(Some(val.clone().into_inner()))
    }

    pub async fn store(&mut self, key: &str, val: &[u8]) -> io::Result<()> {
        let req = self
            .client
            .update_item()
            .table_name(&self.table)
            .key(KEY, AttributeValue::S(key.to_string()))
            .update_expression(format!("SET {VAL} = :b"))
            .expression_attribute_values(":b", AttributeValue::B(val.into()));

        req.send().await.map_err(|err| {
            error!(%key, %err, "failed to store item");
            io::Error::other(err)
        })?;

        Ok(())
    }
}
