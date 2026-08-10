/// A sliding window of counters we have already accepted.
///
/// UDP reorders and duplicates, so a session cannot simply demand that counters
/// arrive in order. This is the same shape as the anti replay window in RFC 6479
/// and in WireGuard: remember the highest counter seen, and a bitmap of which of
/// the preceding `WINDOW` counters have already been used. Anything older than
/// the window, or already marked, is refused.
pub const WINDOW: u64 = 1024;

const BITS: usize = 64;
const WORDS: usize = (WINDOW as usize).div_ceil(BITS);

#[derive(Debug, Clone)]
pub struct ReplayWindow {
    highest: u64,
    seen: [u64; WORDS],
    started: bool,
}

impl Default for ReplayWindow {
    fn default() -> ReplayWindow {
        ReplayWindow::new()
    }
}

impl ReplayWindow {
    pub fn new() -> ReplayWindow {
        ReplayWindow {
            highest: 0,
            seen: [0; WORDS],
            started: false,
        }
    }

    fn mark(&mut self, counter: u64) {
        let bit = (counter % WINDOW) as usize;

        self.seen[bit / BITS] |= 1u64 << (bit % BITS);
    }

    fn marked(&self, counter: u64) -> bool {
        let bit = (counter % WINDOW) as usize;

        self.seen[bit / BITS] & (1u64 << (bit % BITS)) != 0
    }

    fn clear_between(&mut self, from: u64, to: u64) {
        // Advancing past the whole window is the same as starting fresh.
        if to.saturating_sub(from) >= WINDOW {
            self.seen = [0; WORDS];
            return;
        }

        for counter in (from + 1)..=to {
            let bit = (counter % WINDOW) as usize;

            self.seen[bit / BITS] &= !(1u64 << (bit % BITS));
        }
    }

    /// Returns true when this counter is fresh, and remembers it. Returns false
    /// for a replay or a packet so old we can no longer prove it is not one.
    pub fn accept(&mut self, counter: u64) -> bool {
        if !self.started {
            self.started = true;
            self.highest = counter;
            self.mark(counter);

            return true;
        }

        if counter > self.highest {
            self.clear_between(self.highest, counter);
            self.highest = counter;
            self.mark(counter);

            return true;
        }

        if self.highest - counter >= WINDOW {
            return false;
        }

        if self.marked(counter) {
            return false;
        }

        self.mark(counter);

        true
    }

    pub fn highest(&self) -> u64 {
        self.highest
    }
}

#[cfg(test)]
mod test {
    use crate::replay::{ReplayWindow, WINDOW};

    #[test]
    fn packets_in_order_are_all_accepted() {
        let mut window = ReplayWindow::new();

        for counter in 0..5_000 {
            assert!(window.accept(counter), "counter {counter} should be fresh");
        }
    }

    #[test]
    fn a_repeat_is_always_refused() {
        let mut window = ReplayWindow::new();

        assert!(window.accept(7));
        assert!(!window.accept(7), "the same counter must never be taken twice");

        assert!(window.accept(8));
        assert!(!window.accept(8));
        assert!(!window.accept(7));
    }

    #[test]
    fn reordering_inside_the_window_is_tolerated() {
        let mut window = ReplayWindow::new();

        assert!(window.accept(100));
        assert!(window.accept(98), "a straggler is still fresh");
        assert!(window.accept(99));

        assert!(!window.accept(98), "but only once");
        assert!(!window.accept(100));
    }

    #[test]
    fn anything_older_than_the_window_is_refused() {
        let mut window = ReplayWindow::new();

        assert!(window.accept(WINDOW * 2));

        assert!(
            !window.accept(WINDOW * 2 - WINDOW),
            "exactly a window behind is already too old to prove"
        );
        assert!(!window.accept(0));

        assert!(
            window.accept(WINDOW * 2 - WINDOW + 1),
            "one inside the window is still fine"
        );
    }

    #[test]
    fn a_jump_forward_does_not_leave_stale_bits_behind() {
        let mut window = ReplayWindow::new();

        assert!(window.accept(5));

        // jumping clear of the window must not let counter 5's bit, which now
        // aliases to a much newer counter, refuse a fresh packet
        let far = 5 + WINDOW * 3;
        assert!(window.accept(far));

        assert!(
            window.accept(far - 1),
            "a straggler after a big jump is still fresh"
        );
        assert!(!window.accept(far), "and the jump itself is not replayable");
    }

    #[test]
    fn aliasing_across_the_window_does_not_accept_a_replay() {
        let mut window = ReplayWindow::new();

        assert!(window.accept(1));
        assert!(window.accept(1 + WINDOW));

        assert!(
            !window.accept(1),
            "an old counter that aliases to the same bit must not slip through"
        );
    }

    #[test]
    fn a_session_may_start_anywhere() {
        let mut window = ReplayWindow::new();

        assert!(window.accept(9_000_000), "the first counter seen sets the mark");
        assert_eq!(window.highest(), 9_000_000);
        assert!(!window.accept(9_000_000));
    }

    #[test]
    fn the_whole_window_can_be_filled_then_none_repeat() {
        let mut window = ReplayWindow::new();

        for counter in (0..WINDOW).rev() {
            assert!(window.accept(counter), "counter {counter} arriving backwards");
        }

        for counter in 0..WINDOW {
            assert!(!window.accept(counter), "counter {counter} must not repeat");
        }
    }
}
