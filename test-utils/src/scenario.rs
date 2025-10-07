use std::{fmt, path::PathBuf};

use jiff::SignedDuration;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Scenario {
    #[serde(rename = "step")]
    pub steps: Vec<Step>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Step {
    pub label: Option<String>,
    #[serde(default)]
    pub delay: SignedDuration,
    pub action: Action,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum Action {
    Remove { files: Vec<PathBuf> },
    StartNode { node: String, label: Option<String> },
    StopNode { node: String, label: Option<String> },
    Exit,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Remove { files } => write!(f, "remove {files:?}"),
            Self::StartNode {
                node,
                label: Some(l),
            } => write!(f, "start node {node:?} ({l:?})"),
            Self::StartNode { node, label: None } => write!(f, "start node {node:?}"),
            Self::StopNode {
                node,
                label: Some(l),
            } => write!(f, "stop node {node:?} ({l:?})"),
            Self::StopNode { node, label: None } => write!(f, "stop node {node:?}"),
            Self::Exit => f.write_str("exit"),
        }
    }
}
