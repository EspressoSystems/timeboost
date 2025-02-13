use crate::types::message::Evidence;

pub use quick_cache::unsync::Cache as QuickCache;

pub trait Cache<T> {
    fn add(&mut self, val: T);
    fn contains(&self, val: &T) -> bool;
}

#[derive(Debug, Copy, Clone)]
pub struct NoCache<T>(std::marker::PhantomData<fn(&T)>);

impl<T> NoCache<T> {
    pub fn new() -> Self {
        NoCache(std::marker::PhantomData)
    }
}

impl<T> Cache<T> for NoCache<T> {
    fn add(&mut self, _: T) {}

    fn contains(&self, _: &T) -> bool {
        false
    }
}

impl Cache<Evidence> for QuickCache<[u8; 32], Vec<Evidence>> {
    fn add(&mut self, val: Evidence) {
        let key = match &val {
            Evidence::Genesis => return (),
            Evidence::Regular(c) => <[u8; 32]>::from(*c.commitment()),
            Evidence::Timeout(c) => <[u8; 32]>::from(*c.commitment()),
        };
        if let Some(mut e) = self.get_mut(&key) {
            e.push(val);
            return;
        }
        self.insert(key, vec![val])
    }

    fn contains(&self, val: &Evidence) -> bool {
        let key = match &val {
            Evidence::Genesis => return false,
            Evidence::Regular(c) => <[u8; 32]>::from(*c.commitment()),
            Evidence::Timeout(c) => <[u8; 32]>::from(*c.commitment()),
        };
        self.get(&key).map(|e| e.contains(val)).unwrap_or(false)
    }
}
