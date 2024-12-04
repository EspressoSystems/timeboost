use crate::tests::network::external::Libp2pNetworkTest;
use crate::tests::network::network_tests::*;

#[tokio::test]
async fn test_simple_network_genesis() {
    run_simple_network_genesis_test::<Libp2pNetworkTest>().await
}

#[tokio::test]
async fn test_simple_network_round_progression() {
    run_network_round_progression_test::<Libp2pNetworkTest>().await
}

#[tokio::test]
async fn test_simple_network_round_timeout() {
    run_simple_network_round_timeout_test::<Libp2pNetworkTest>().await
}
