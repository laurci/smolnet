pub fn lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

pub fn leq(a: u32, b: u32) -> bool {
    a == b || lt(a, b)
}

pub fn gt(a: u32, b: u32) -> bool {
    lt(b, a)
}

pub fn geq(a: u32, b: u32) -> bool {
    leq(b, a)
}

#[cfg(test)]
mod test {
    use crate::proto::tcp::seq::{geq, gt, leq, lt};

    #[test]
    fn ordering_without_wraparound() {
        assert!(lt(1, 2));
        assert!(!lt(2, 1));
        assert!(!lt(1, 1));

        assert!(gt(2, 1));
        assert!(leq(1, 1));
        assert!(geq(1, 1));
    }

    #[test]
    fn ordering_across_the_wraparound() {
        let before = u32::MAX - 4;
        let after = 4u32;

        assert!(lt(before, after));
        assert!(gt(after, before));
        assert!(!lt(after, before));
    }

    #[test]
    fn half_the_space_away_is_the_boundary() {
        let base = 1000u32;

        assert!(lt(base, base.wrapping_add(i32::MAX as u32)));
        assert!(gt(base, base.wrapping_sub(i32::MAX as u32)));
    }
}
