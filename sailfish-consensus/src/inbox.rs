use std::collections::VecDeque;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Inbox<T> {
    items: VecDeque<T>,
}

impl<T> Default for Inbox<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Inbox<T> {
    pub fn new() -> Self {
        Inbox {
            items: VecDeque::new(),
        }
    }

    pub fn first(&self) -> Option<&T> {
        self.items.front()
    }

    pub fn first_mut(&mut self) -> Option<&mut T> {
        self.items.front_mut()
    }

    pub fn insert_first(&mut self, val: T) {
        self.items.push_front(val)
    }

    pub fn take_first(&mut self) -> Option<T> {
        self.items.pop_front()
    }

    pub fn last(&self) -> Option<&T> {
        self.items.back()
    }

    pub fn last_mut(&mut self) -> Option<&mut T> {
        self.items.back_mut()
    }

    pub fn insert_last(&mut self, val: T) {
        self.items.push_back(val)
    }

    pub fn take_last(&mut self) -> Option<T> {
        self.items.pop_back()
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.items.iter_mut()
    }
}

impl<T> Extend<T> for Inbox<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.items.extend(iter)
    }
}
