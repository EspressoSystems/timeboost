use timeboost_core::logging;

#[tokio::test]
async fn test_timeboost_startup() {
    logging::init_logging();
}
