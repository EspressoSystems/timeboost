use std::collections::VecDeque;
use std::ops::Range;

use crate::RoundNumber;

/// Epochs associate values to non-overlapping intervals of round numbers.
#[derive(Debug)]
pub struct Epochs<T> {
    epochs: VecDeque<(Range<RoundNumber>, T)>,
}

impl<T> Default for Epochs<T> {
    fn default() -> Self {
        Self {
            epochs: VecDeque::new(),
        }
    }
}

impl<T> Epochs<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.epochs.len()
    }

    pub fn intervals(&self) -> impl Iterator<Item = &Range<RoundNumber>> {
        self.epochs.iter().map(|(r, _)| r)
    }

    pub fn first(&self) -> Option<&(Range<RoundNumber>, T)> {
        self.epochs.front()
    }

    pub fn last(&self) -> Option<&(Range<RoundNumber>, T)> {
        self.epochs.back()
    }

    pub fn find<F>(&self, pred: F) -> Option<&(Range<RoundNumber>, T)>
    where
        F: Fn(&Range<RoundNumber>, &T) -> bool,
    {
        self.epochs.iter().rev().find(|(r, v)| pred(r, v))
    }

    pub fn get<N>(&self, r: N) -> Option<&T>
    where
        N: Into<RoundNumber>
    {
        let r = r.into();
        self.find(|range, _| range.contains(&r)).map(|(_, v)| v)
    }

    pub fn add<N>(&mut self, r: Range<N>, v: T) -> &mut Self
    where
        N: Into<RoundNumber>,
    {
        let r = Range {
            start: r.start.into(),
            end: r.end.into(),
        };
        assert!(!r.is_empty());
        for (i, (e, _)) in self.epochs.iter_mut().enumerate().rev() {
            if e.end <= r.start {
                self.epochs.insert(i, (r, v));
                return self;
            }
        }
        self.epochs.push_back((r, v));
        self
    }

    pub fn remove(&mut self, num: usize) {
        if num >= self.epochs.len() {
            self.epochs.clear();
            return;
        }
        for _ in 0..num {
            self.epochs.pop_front();
        }
    }

    pub fn remove_if<F>(&mut self, pred: F)
    where
        F: Fn(&Range<RoundNumber>, &T) -> bool,
    {
        while let Some((r, v)) = self.epochs.front() {
            if pred(r, v) {
                self.epochs.pop_front();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Epochs;

    #[test]
    fn add() {
        let mut e = Epochs::default();
        e.add(10..15, 'c').add(1..2, 'b').add(0..1, 'a');
        let v = e.find(|r, _| r.contains(&1.into()));
        assert!(matches!(v, Some((_, 'b'))))
    }
}
