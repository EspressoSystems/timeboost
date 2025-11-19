use timeboost_utils::logging;

#[tokio::test]
async fn test_timeboost_startup() {
    logging::init_logging();
}
