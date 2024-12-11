use std::ops::{Add, Div};

pub fn median<T>(values: &mut [T]) -> Option<T>
where
    T: Ord + Copy + From<u64> + Add<Output = T> + Div<u64, Output = T>,
{
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let median = if values.len() % 2 == 0 {
        (values[values.len() / 2 - 1] + values[values.len() / 2]) / 2
    } else {
        values[values.len() / 2]
    };

    Some(median.into())
}

#[cfg(test)]
mod tests {
    use timeboost_core::types::time::Timestamp;

    #[test]
    fn median() {
        use super::median;

        let mut ts: [Timestamp; 0] = [];
        assert_eq!(None, median(&mut ts));

        let mut ts = [1.into()];
        assert_eq!(Some(Timestamp::from(1)), median(&mut ts));

        let mut ts = [1.into(), 2.into()];
        assert_eq!(Some(Timestamp::from(1)), median(&mut ts));

        let mut ts = [1.into(), 2.into(), 3.into()];
        assert_eq!(Some(Timestamp::from(2)), median(&mut ts));

        let mut ts = [1.into(), 2.into(), 3.into(), 4.into()];
        assert_eq!(Some(Timestamp::from(2)), median(&mut ts));

        let mut ts = [1.into(), 2.into(), 3.into(), 4.into(), 5.into()];
        assert_eq!(Some(Timestamp::from(3)), median(&mut ts));
    }
}
