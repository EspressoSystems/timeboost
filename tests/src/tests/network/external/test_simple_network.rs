use crate::tests::network::{external::basic::BasicNetworkTest, network_tests::*};

#[tokio::test]
async fn test_simple_network_genesis() {
    run_simple_network_genesis_test::<BasicNetworkTest>().await;
}

#[tokio::test]
async fn test_simple_network_round_progression() {
    run_network_round_progression_test::<BasicNetworkTest>().await;
}

#[tokio::test]
async fn test_simple_network_round_timeout() {
    run_simple_network_round_timeout_test::<BasicNetworkTest>().await;
}

#[tokio::test]
async fn test_simple_network_genesis_round_timeout() {
    run_simple_network_round_timeout_genesis_test::<BasicNetworkTest>().await;
}

#[tokio::test]
async fn test_simple_network_catchup() {
    run_simple_network_catchup_test::<BasicNetworkTest>().await;
}

#[tokio::test]
async fn test_simple_network_catchup_missed_round() {
    run_simple_network_catchup_node_missed_round_test::<BasicNetworkTest>().await;
}
