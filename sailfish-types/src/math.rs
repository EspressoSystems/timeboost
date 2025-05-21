use std::ops::{Add, Div};

pub fn median<T>(values: &mut [T]) -> Option<T>
where
    T: Ord + Copy + Add<Output = T> + Div<u64, Output = T>,
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
    Some(median)
}

#[cfg(test)]
mod tests {

    #[test]
    fn median_time() {
        use super::median;

        let mut xs: [u64; 0] = [];
        assert_eq!(None, median(&mut xs));

        let mut xs = [1];
        assert_eq!(Some(1), median(&mut xs));

        let mut xs = [1, 2];
        assert_eq!(Some(1), median(&mut xs));

        let mut xs = [1, 2, 3];
        assert_eq!(Some(2), median(&mut xs));

        let mut xs = [1, 2, 3, 4];
        assert_eq!(Some(2), median(&mut xs));

        let mut xs = [1, 2, 3, 4, 5];
        assert_eq!(Some(3), median(&mut xs));
    }
}
