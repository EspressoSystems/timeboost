use std::ops::{Add, Div};

pub fn median<T, I>(values: I) -> Option<T>
where
    T: Ord + Copy + From<u64> + Add<Output = T> + Div<u64, Output = T>,
    I: Iterator<Item = T>,
{
    let mut sorted_values = values.collect::<Vec<_>>();
    if sorted_values.is_empty() {
        return None;
    }
    sorted_values.sort_unstable();
    let median = if sorted_values.len() % 2 == 0 {
        (sorted_values[sorted_values.len() / 2 - 1] + sorted_values[sorted_values.len() / 2]) / 2
    } else {
        sorted_values[sorted_values.len() / 2]
    };

    Some(median.into())
}

#[cfg(test)]
mod tests {
    use timeboost_core::types::time::Timestamp;

    #[test]
    fn median() {
        use super::median;

        let ts: [Timestamp; 0] = [];
        assert_eq!(None, median(&mut ts.iter().map(|t| *t)));

        let ts = [1.into()];
        assert_eq!(Some(Timestamp::from(1)), median(&mut ts.iter().map(|t| *t)));

        let ts = [1.into(), 2.into()];
        assert_eq!(Some(Timestamp::from(1)), median(&mut ts.iter().map(|t| *t)));

        let ts = [1.into(), 2.into(), 3.into()];
        assert_eq!(Some(Timestamp::from(2)), median(&mut ts.iter().map(|t| *t)));

        let ts = [1.into(), 2.into(), 3.into(), 4.into()];
        assert_eq!(Some(Timestamp::from(2)), median(&mut ts.iter().map(|t| *t)));

        let ts = [1.into(), 2.into(), 3.into(), 4.into(), 5.into()];
        assert_eq!(Some(Timestamp::from(3)), median(&mut ts.iter().map(|t| *t)));
    }
}
