use crate::tests::network::internal::MemoryNetworkTest;
use crate::tests::network::network_tests::*;

#[tokio::test(flavor = "multi_thread")]
async fn test_simple_network_genesis() {
    run_simple_network_genesis_test::<MemoryNetworkTest>().await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_simple_network_round_progression() {
    run_network_round_progression_test::<MemoryNetworkTest>().await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_simple_network_round_timeout() {
    run_simple_network_round_timeout_test::<MemoryNetworkTest>().await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_simple_network_catchup() {
    run_simple_network_catchup_test::<MemoryNetworkTest>().await
}
