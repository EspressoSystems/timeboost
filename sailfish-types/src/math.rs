pub fn median(values: &mut [u64]) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let median = if values.len() % 2 == 0 {
        let a = values[values.len() / 2 - 1];
        let b = values[values.len() / 2];
        a.saturating_add(b) / 2
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
