use std::time::{Duration, Instant};

pub const TCP_PACING_GAIN_NUM: u64 = 5;
pub const TCP_PACING_GAIN_DEN: u64 = 4;
pub const TCP_PACING_BURST_SEGMENTS: usize = 16;

pub const TCP_PACING_BURST_MICROS: u64 = 4_000;

#[derive(Debug, Default)]
pub struct Pacer {
    credit: usize,
    last: Option<Instant>,
}

impl Pacer {
    pub fn new() -> Pacer {
        Pacer::default()
    }

    pub fn rate(window: usize, round_trip: Duration) -> u64 {
        let micros = (round_trip.as_micros() as u64).max(1);
        let paced = (window as u64).saturating_mul(TCP_PACING_GAIN_NUM) / TCP_PACING_GAIN_DEN;

        (paced.saturating_mul(1_000_000) / micros).max(1)
    }

    fn burst(rate: u64, mss: usize) -> usize {
        let window = (u128::from(rate) * u128::from(TCP_PACING_BURST_MICROS) / 1_000_000) as usize;

        window.max(mss.saturating_mul(TCP_PACING_BURST_SEGMENTS))
    }

    pub fn allowance(
        &mut self,
        now: Instant,
        window: usize,
        round_trip: Option<Duration>,
        mss: usize,
    ) -> usize {
        let Some(round_trip) = round_trip else {
            self.last = Some(now);
            self.credit = window;

            return self.credit;
        };

        let rate = Pacer::rate(window, round_trip);
        let elapsed = self
            .last
            .map(|last| now.saturating_duration_since(last))
            .unwrap_or(round_trip);

        self.last = Some(now);

        let earned = (u128::from(rate) * elapsed.as_micros() / 1_000_000) as usize;
        self.credit = self
            .credit
            .saturating_add(earned)
            .min(Pacer::burst(rate, mss));

        self.credit
    }

    pub fn consume(&mut self, bytes: usize) {
        self.credit = self.credit.saturating_sub(bytes);
    }

    pub fn ready_at(
        &self,
        now: Instant,
        window: usize,
        round_trip: Option<Duration>,
        mss: usize,
    ) -> Option<Instant> {
        let round_trip = round_trip?;

        if self.credit >= mss {
            return None;
        }

        let missing = (mss - self.credit) as u64;
        let rate = Pacer::rate(window, round_trip);
        let micros = missing.saturating_mul(1_000_000) / rate;

        Some(now + Duration::from_micros(micros.max(1)))
    }
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use crate::proto::tcp::pacing::Pacer;

    const MSS: usize = 1240;

    #[test]
    fn the_rate_spreads_a_window_over_a_round_trip() {
        let rate = Pacer::rate(64 * 1024, Duration::from_millis(10));

        assert_eq!(
            rate,
            65536 * 5 / 4 * 100,
            "a window every rtt, times the gain"
        );
    }

    #[test]
    fn a_connection_without_an_rtt_sample_is_not_paced() {
        let mut pacer = Pacer::new();

        let allowed = pacer.allowance(Instant::now(), 64 * 1024, None, MSS);

        assert_eq!(allowed, 64 * 1024, "we cannot pace before we can measure");
    }

    #[test]
    fn credit_accrues_with_time_and_is_capped_to_a_burst() {
        let base = Instant::now();
        let mut pacer = Pacer::new();
        let rtt = Duration::from_millis(10);

        pacer.allowance(base, 64 * 1024, Some(rtt), MSS);
        pacer.consume(pacer.credit);

        let after_a_millisecond =
            pacer.allowance(base + Duration::from_millis(1), 64 * 1024, Some(rtt), MSS);
        assert!(after_a_millisecond > 0);

        let after_a_second =
            pacer.allowance(base + Duration::from_secs(1), 64 * 1024, Some(rtt), MSS);
        let rate = Pacer::rate(64 * 1024, rtt);

        assert_eq!(
            after_a_second,
            (rate * 4 / 1_000) as usize,
            "credit never accumulates beyond a few milliseconds of sending"
        );
    }

    #[test]
    fn spending_credit_reduces_the_allowance() {
        let base = Instant::now();
        let mut pacer = Pacer::new();
        let rtt = Duration::from_millis(10);

        pacer.allowance(base, 64 * 1024, Some(rtt), MSS);
        let before = pacer.credit;
        pacer.consume(MSS);

        assert_eq!(pacer.credit, before - MSS);
    }

    #[test]
    fn a_burst_is_a_few_milliseconds_of_sending_with_a_floor() {
        let slow = Pacer::burst(1_000, MSS);
        let fast = Pacer::burst(100_000_000, MSS);

        assert_eq!(slow, MSS * 16, "a slow link still gets a useful burst");
        assert_eq!(fast, 400_000, "a fast link gets a few milliseconds of data");
    }

    #[test]
    fn a_drained_pacer_asks_to_be_woken_later() {
        let base = Instant::now();
        let mut pacer = Pacer::new();
        let rtt = Duration::from_millis(10);

        pacer.allowance(base, 64 * 1024, Some(rtt), MSS);
        pacer.consume(pacer.credit);

        let wake = pacer
            .ready_at(base, 64 * 1024, Some(rtt), MSS)
            .expect("a drained pacer has a deadline");

        assert!(wake > base);
        assert!(
            wake < base + Duration::from_millis(10),
            "one segment of credit arrives well within a round trip"
        );
    }

    #[test]
    fn a_pacer_with_credit_does_not_ask_for_a_timer() {
        let base = Instant::now();
        let mut pacer = Pacer::new();

        pacer.allowance(base, 64 * 1024, Some(Duration::from_millis(10)), MSS);

        assert!(
            pacer
                .ready_at(base, 64 * 1024, Some(Duration::from_millis(10)), MSS)
                .is_none()
        );
    }
}
