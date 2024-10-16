use crate::{
    impls::sailfish_types::SailfishTypes,
    types::timeout::{NoVoteData, TimeoutData},
};
use hotshot_types::simple_certificate::{SimpleCertificate, SuccessThreshold};

use super::vertex::Vertex;

pub type VertexCertificate = SimpleCertificate<SailfishTypes, Vertex, SuccessThreshold>;
pub type TimeoutCertificate = SimpleCertificate<SailfishTypes, TimeoutData, SuccessThreshold>;
pub type NoVoteCertificate = SimpleCertificate<SailfishTypes, NoVoteData, SuccessThreshold>;
