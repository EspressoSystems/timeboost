use timeboost_utils::types::logging;

#[tokio::test]
async fn test_timeboost_startup() {
    logging::init_logging();
}
