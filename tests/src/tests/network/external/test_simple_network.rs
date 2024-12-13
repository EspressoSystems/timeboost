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

#[tokio::test]
async fn test_simple_network_genesis_round_timeout() {
    run_simple_network_round_timeout_genesis_test::<Libp2pNetworkTest>().await
}

#[tokio::test]
async fn test_simple_network_catchup() {
    run_simple_network_catchup_test::<Libp2pNetworkTest>().await
}

#[tokio::test]
async fn test_simple_network_catchup_missed_round() {
    run_simple_network_catchup_node_missed_round_test::<Libp2pNetworkTest>().await
}
