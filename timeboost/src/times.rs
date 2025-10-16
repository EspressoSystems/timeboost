use std::env;

use anyhow::{Result, bail};
use multisig::PublicKey;
use times::TimeSeries;
use tokio::fs::write;

use crate::TIMEBOOST_NO_SUBMIT;

#[derive(serde::Serialize)]
struct Durations {
    round: u64,
    msg_validate: u64,
    rbc_proposal: u64,
    delivered: u64,
    decrypt: u64,
    certify: u64,
    total: u64,
    verified: u64,
}

#[derive(serde::Serialize)]
struct Duration {
    round: u64,
    sf_delivered: u64,
    msg_validate: u64,
    rbc_proposal: u64,
}

pub struct TimesWriter {
    label: PublicKey,
    no_submit: bool,
    saved_timeboost: bool,
    saved_sailfish: bool,
}

impl TimesWriter {
    pub fn new(label: PublicKey) -> Self {
        Self {
            label,
            no_submit: env::var(TIMEBOOST_NO_SUBMIT).is_ok(),
            saved_timeboost: false,
            saved_sailfish: false,
        }
    }

    pub fn is_timeboost_saved(&self) -> bool {
        self.saved_timeboost
    }

    pub fn is_sailfish_saved(&self) -> bool {
        self.saved_sailfish
    }

    pub async fn save_timeboost_series(&mut self) -> Result<()> {
        if self.saved_timeboost {
            return Ok(());
        }

        let Some(sf_start) = times::time_series("sf-round-start") else {
            bail!("no time series corresponds to sf-round-start")
        };
        let Some(sf_delivered) = times::time_series("sf-delivered") else {
            bail!("no time series corresponds to sf-delivered")
        };
        let Some(msg_validate_start) = times::take_time_series("validate-msg-start") else {
            bail!("no time series corresponds to validate-msg-start");
        };
        let Some(msg_validate_end) = times::take_time_series("validate-msg-end") else {
            bail!("no time series corresponds to validate-msg-end");
        };
        let Some(rbc_proposed) = times::take_time_series("rbc-proposed") else {
            bail!("no time series corresponds to rbc-proposed");
        };
        let Some(rbc_delivered) = times::take_time_series("rbc-delivered") else {
            bail!("no time series corresponds to rbc-proposed");
        };
        let Some(tb_decrypt_start) = times::time_series("tb-decrypt-start") else {
            bail!("no time series corresponds to tb-decrypt-start")
        };
        let Some(tb_decrypt_end) = times::time_series("tb-decrypt-end") else {
            bail!("no time series corresponds to tb-decrypt-end")
        };
        let Some(tb_cert_start) = times::time_series("tb-certify-start") else {
            bail!("no time series corresponds to tb-certify-start")
        };
        let Some(tb_cert_end) = times::time_series("tb-certify-end") else {
            bail!("no time series corresponds to tb-certify-end")
        };
        let tb_verified = if self.no_submit {
            TimeSeries::default()
        } else if let Some(s) = times::time_series("tb-verified") {
            s
        } else {
            bail!("no time series corresponds to tb-verified")
        };

        let mut csv = csv::Writer::from_writer(Vec::new());

        for (r, sfs) in sf_start.records() {
            let Some(sfd) = sf_delivered.records().get(r) else {
                continue;
            };
            let Some(rs) = rbc_proposed.records().get(r) else {
                continue;
            };
            let Some(re) = rbc_delivered.records().get(r) else {
                continue;
            };
            let Some(vs) = msg_validate_start.records().get(r) else {
                continue;
            };
            let Some(ve) = msg_validate_end.records().get(r) else {
                continue;
            };
            let Some(tbds) = tb_decrypt_start.records().get(r) else {
                continue;
            };
            let Some(tbde) = tb_decrypt_end.records().get(r) else {
                continue;
            };
            let Some(tbcs) = tb_cert_start.records().get(r) else {
                continue;
            };
            let Some(tbce) = tb_cert_end.records().get(r) else {
                continue;
            };
            let ver = if self.no_submit {
                0
            } else if let Some(tbv) = tb_verified.records().get(r) {
                tbv.duration_since(*sfs).as_millis() as u64
            } else {
                continue;
            };
            csv.serialize(Durations {
                round: *r,
                msg_validate: ve.duration_since(*vs).as_millis() as u64,
                rbc_proposal: re.duration_since(*rs).as_millis() as u64,
                delivered: sfd.duration_since(*sfs).as_millis() as u64,
                decrypt: tbde.duration_since(*tbds).as_millis() as u64,
                certify: tbce.duration_since(*tbcs).as_millis() as u64,
                total: tbce.duration_since(*sfs).as_millis() as u64,
                verified: ver,
            })?
        }

        let path = std::path::Path::new("/tmp")
            .join(self.label.to_string())
            .with_extension("csv");

        write(path, csv.into_inner()?).await?;
        self.saved_timeboost = true;

        Ok(())
    }

    pub async fn save_sailfish_series(&mut self) -> Result<()> {
        if self.saved_sailfish {
            return Ok(());
        }

        let Some(start) = times::take_time_series("sf-round-start") else {
            bail!("no time series corresponds to sf-round-start");
        };
        let Some(delivered) = times::take_time_series("sf-delivered") else {
            bail!("no time series corresponds to sf-delivered");
        };
        let Some(msg_validate_start) = times::take_time_series("validate-msg-start") else {
            bail!("no time series corresponds to validate-msg-start");
        };
        let Some(msg_validate_end) = times::take_time_series("validate-msg-end") else {
            bail!("no time series corresponds to validate-msg-end");
        };
        let Some(rbc_proposed) = times::take_time_series("rbc-proposed") else {
            bail!("no time series corresponds to rbc-proposed");
        };
        let Some(rbc_delivered) = times::take_time_series("rbc-delivered") else {
            bail!("no time series corresponds to rbc-proposed");
        };

        let mut csv = csv::Writer::from_writer(Vec::new());

        for (r, ss) in start.records() {
            let Some(se) = delivered.records().get(r) else {
                continue;
            };
            let Some(rs) = rbc_proposed.records().get(r) else {
                continue;
            };
            let Some(re) = rbc_delivered.records().get(r) else {
                continue;
            };
            let Some(vs) = msg_validate_start.records().get(r) else {
                continue;
            };
            let Some(ve) = msg_validate_end.records().get(r) else {
                continue;
            };
            csv.serialize(Duration {
                round: *r,
                sf_delivered: se.duration_since(*ss).as_millis() as u64,
                msg_validate: ve.duration_since(*vs).as_millis() as u64,
                rbc_proposal: re.duration_since(*rs).as_millis() as u64,
            })?
        }

        let path = std::path::Path::new("/tmp")
            .join(self.label.to_string())
            .with_extension("csv");

        write(path, csv.into_inner()?).await?;
        self.saved_sailfish = true;

        Ok(())
    }
}
