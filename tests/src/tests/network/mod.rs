use sailfish::coordinator::CoordinatorAuditEvent;

pub mod external;
pub mod internal;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TestOutcome {
    Passed,
    Waiting,
}

pub struct TestCondition {
    identifier: String,
    eval: Box<dyn Fn(&CoordinatorAuditEvent) -> TestOutcome>,
}

impl std::fmt::Display for TestCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.identifier)
    }
}

impl TestCondition {
    pub fn new<F>(identifier: String, eval: F) -> Self
    where
        F: for<'a> Fn(&'a CoordinatorAuditEvent) -> TestOutcome + 'static,
    {
        Self {
            identifier,
            eval: Box::new(eval),
        }
    }

    pub fn evaluate(&self, logs: &[CoordinatorAuditEvent]) -> TestOutcome {
        for e in logs.iter() {
            let result = (self.eval)(e);
            if result != TestOutcome::Waiting {
                return result;
            }
        }

        // We have yet to see the event that we're looking for.
        TestOutcome::Waiting
    }
}
