use std::{fmt, path::PathBuf};

use jiff::SignedDuration;
use multisig::PublicKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Scenario {
    #[serde(rename = "step")]
    pub steps: Vec<Step>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Step {
    #[serde(default)]
    pub delay: SignedDuration,
    pub action: Action,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum Action {
    Remove { files: Vec<PathBuf> },
    StartNode { node: PublicKey },
    StopNode { node: PublicKey },
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Remove { files } => write!(f, "remove {files:?}"),
            Self::StartNode { node } => write!(f, "start node {node}"),
            Self::StopNode { node } => write!(f, "stop node {node}"),
        }
    }
}
