pub const TCP_INITIAL_WINDOW_SEGMENTS: usize = 4;
pub const TCP_FAST_RETRANSMIT_THRESHOLD: u8 = 3;

pub struct Congestion {
    cwnd: usize,
    ssthresh: usize,
    dup_acks: u8,
    in_recovery: bool,
}

impl Congestion {
    pub fn new(mss: usize) -> Congestion {
        Congestion {
            cwnd: mss * TCP_INITIAL_WINDOW_SEGMENTS,
            ssthresh: usize::MAX,
            dup_acks: 0,
            in_recovery: false,
        }
    }

    pub fn window(&self) -> usize {
        self.cwnd
    }

    pub fn duplicate_acks(&self) -> u8 {
        self.dup_acks
    }

    pub fn on_mss(&mut self, mss: usize) {
        self.cwnd = mss * TCP_INITIAL_WINDOW_SEGMENTS;
    }

    /// An acknowledgement of data we had not seen acknowledged before. Only new
    /// data opens the window: acknowledging a syn or a fin is not progress.
    pub fn on_new_ack(&mut self, acked_data: usize, mss: usize) {
        self.dup_acks = 0;

        if self.in_recovery {
            self.in_recovery = false;
            self.cwnd = self.ssthresh;

            tracing::debug!(cwnd = self.cwnd, "tcp leaving fast recovery");
            return;
        }

        if acked_data == 0 {
            return;
        }

        if self.cwnd < self.ssthresh {
            self.cwnd += acked_data.min(mss);
        } else {
            self.cwnd += (mss * mss / self.cwnd).max(1);
        }
    }

    /// Returns whether this duplicate is the one that should trigger a
    /// retransmission without waiting for the timer.
    pub fn on_duplicate_ack(&mut self, mss: usize, flight: usize) -> bool {
        self.dup_acks += 1;

        if self.in_recovery {
            self.cwnd += mss;
            return false;
        }

        if self.dup_acks < TCP_FAST_RETRANSMIT_THRESHOLD {
            return false;
        }

        self.ssthresh = (flight / 2).max(2 * mss);
        self.cwnd = self.ssthresh + usize::from(TCP_FAST_RETRANSMIT_THRESHOLD) * mss;
        self.in_recovery = true;

        tracing::debug!(
            ssthresh = self.ssthresh,
            cwnd = self.cwnd,
            "tcp entering fast recovery"
        );

        true
    }

    pub fn on_timeout(&mut self, mss: usize, flight: usize) {
        self.ssthresh = (flight / 2).max(2 * mss);
        self.cwnd = mss;
        self.dup_acks = 0;
        self.in_recovery = false;

        tracing::debug!(
            ssthresh = self.ssthresh,
            cwnd = self.cwnd,
            "tcp timeout, back to slow start"
        );
    }
}

#[cfg(test)]
mod test {
    use crate::proto::tcp::congestion::{
        Congestion, TCP_FAST_RETRANSMIT_THRESHOLD, TCP_INITIAL_WINDOW_SEGMENTS,
    };

    const MSS: usize = 1460;

    #[test]
    fn the_window_opens_at_the_initial_burst_size() {
        let congestion = Congestion::new(MSS);

        assert_eq!(congestion.window(), MSS * TCP_INITIAL_WINDOW_SEGMENTS);
    }

    #[test]
    fn slow_start_adds_a_segment_per_acknowledgement() {
        let mut congestion = Congestion::new(MSS);
        let start = congestion.window();

        congestion.on_new_ack(MSS, MSS);
        assert_eq!(congestion.window(), start + MSS);

        congestion.on_new_ack(MSS * 4, MSS);
        assert_eq!(
            congestion.window(),
            start + MSS * 2,
            "growth per ack is capped at one segment however much was acked"
        );
    }

    #[test]
    fn acknowledging_no_data_does_not_open_the_window() {
        let mut congestion = Congestion::new(MSS);
        let start = congestion.window();

        congestion.on_new_ack(0, MSS);

        assert_eq!(congestion.window(), start);
    }

    #[test]
    fn congestion_avoidance_grows_far_more_slowly() {
        let mut congestion = Congestion::new(MSS);

        congestion.on_timeout(MSS, MSS * 32);
        let ssthresh = MSS * 16;

        while congestion.window() < ssthresh {
            congestion.on_new_ack(MSS, MSS);
        }

        let before = congestion.window();
        congestion.on_new_ack(MSS, MSS);

        let growth = congestion.window() - before;
        assert!(
            growth < MSS / 4,
            "growth of {growth} should be a fraction of a segment, not a whole one"
        );
    }

    #[test]
    fn a_timeout_collapses_to_one_segment_and_halves_the_threshold() {
        let mut congestion = Congestion::new(MSS);

        congestion.on_timeout(MSS, MSS * 10);

        assert_eq!(congestion.window(), MSS);

        while congestion.window() < MSS * 5 {
            congestion.on_new_ack(MSS, MSS);
        }

        let before = congestion.window();
        congestion.on_new_ack(MSS, MSS);
        assert!(
            congestion.window() - before < MSS,
            "past the halved threshold we are in congestion avoidance"
        );
    }

    #[test]
    fn three_duplicates_enter_fast_recovery() {
        let mut congestion = Congestion::new(MSS);
        let flight = MSS * 8;

        for _ in 1..TCP_FAST_RETRANSMIT_THRESHOLD {
            assert!(!congestion.on_duplicate_ack(MSS, flight));
        }

        assert!(congestion.on_duplicate_ack(MSS, flight));

        let ssthresh = flight / 2;
        assert_eq!(
            congestion.window(),
            ssthresh + usize::from(TCP_FAST_RETRANSMIT_THRESHOLD) * MSS
        );
    }

    #[test]
    fn further_duplicates_inflate_but_do_not_retransmit_again() {
        let mut congestion = Congestion::new(MSS);
        let flight = MSS * 8;

        for _ in 0..TCP_FAST_RETRANSMIT_THRESHOLD {
            congestion.on_duplicate_ack(MSS, flight);
        }

        let inflated = congestion.window();
        assert!(!congestion.on_duplicate_ack(MSS, flight));
        assert_eq!(congestion.window(), inflated + MSS);
    }

    #[test]
    fn a_new_ack_deflates_out_of_recovery() {
        let mut congestion = Congestion::new(MSS);
        let flight = MSS * 8;

        for _ in 0..TCP_FAST_RETRANSMIT_THRESHOLD {
            congestion.on_duplicate_ack(MSS, flight);
        }

        congestion.on_new_ack(MSS, MSS);

        assert_eq!(congestion.window(), flight / 2);
        assert_eq!(congestion.duplicate_acks(), 0);
    }
}
