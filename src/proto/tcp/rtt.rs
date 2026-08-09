use std::time::{Duration, Instant};

use crate::proto::tcp::seq;

pub const TCP_RTO_INITIAL: Duration = Duration::from_secs(1);
pub const TCP_RTO_MIN: Duration = Duration::from_millis(200);
pub const TCP_RTO_MAX: Duration = Duration::from_secs(60);

pub struct RoundTrip {
    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
    sample: Option<(u32, Instant)>,
}

impl Default for RoundTrip {
    fn default() -> Self {
        RoundTrip::new()
    }
}

impl RoundTrip {
    pub fn new() -> RoundTrip {
        RoundTrip {
            srtt: None,
            rttvar: Duration::ZERO,
            rto: TCP_RTO_INITIAL,
            sample: None,
        }
    }

    pub fn rto(&self) -> Duration {
        self.rto
    }

    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    pub fn start_sample(&mut self, covers: u32, now: Instant) {
        if self.sample.is_none() {
            self.sample = Some((covers, now));
        }
    }

    pub fn take_sample(&mut self, acked: u32, now: Instant) {
        let Some((covers, sent_at)) = self.sample else {
            return;
        };

        if seq::lt(acked, covers) {
            return;
        }

        self.sample = None;
        self.update(now.duration_since(sent_at));
    }

    pub fn discard_sample(&mut self) {
        self.sample = None;
    }

    fn update(&mut self, measurement: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(measurement);
                self.rttvar = measurement / 2;
            }
            Some(srtt) => {
                let difference = srtt.abs_diff(measurement);

                self.rttvar = (self.rttvar * 3 + difference) / 4;
                self.srtt = Some((srtt * 7 + measurement) / 8);
            }
        }

        let srtt = self.srtt.unwrap_or(measurement);
        self.rto = (srtt + self.rttvar * 4).clamp(TCP_RTO_MIN, TCP_RTO_MAX);

        tracing::trace!(
            measurement_ms = measurement.as_millis(),
            rto_ms = self.rto.as_millis(),
            "tcp round trip estimate updated"
        );
    }

    pub fn back_off(&mut self) {
        self.rto = (self.rto * 2).min(TCP_RTO_MAX);
        self.sample = None;
    }
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use crate::proto::tcp::rtt::{RoundTrip, TCP_RTO_INITIAL, TCP_RTO_MAX, TCP_RTO_MIN};

    #[test]
    fn the_first_measurement_seeds_the_estimate() {
        let base = Instant::now();
        let mut round_trip = RoundTrip::new();

        assert_eq!(round_trip.rto(), TCP_RTO_INITIAL);

        round_trip.start_sample(100, base);
        round_trip.take_sample(100, base + Duration::from_millis(80));

        assert_eq!(round_trip.srtt(), Some(Duration::from_millis(80)));
        assert_eq!(round_trip.rto(), Duration::from_millis(80 + 4 * 40));
    }

    #[test]
    fn a_steady_link_settles_towards_the_floor() {
        let base = Instant::now();
        let mut round_trip = RoundTrip::new();

        for round in 0..40u32 {
            let sent_at = base + Duration::from_millis(u64::from(round) * 100);

            round_trip.start_sample(round, sent_at);
            round_trip.take_sample(round, sent_at + Duration::from_millis(10));
        }

        assert_eq!(
            round_trip.rto(),
            TCP_RTO_MIN,
            "a fast, stable link is clamped by the minimum"
        );
    }

    #[test]
    fn an_ack_that_does_not_cover_the_sample_is_ignored() {
        let base = Instant::now();
        let mut round_trip = RoundTrip::new();

        round_trip.start_sample(500, base);
        round_trip.take_sample(400, base + Duration::from_millis(50));

        assert_eq!(round_trip.srtt(), None);
        assert_eq!(round_trip.rto(), TCP_RTO_INITIAL);
    }

    #[test]
    fn only_one_sample_is_timed_at_once() {
        let base = Instant::now();
        let mut round_trip = RoundTrip::new();

        round_trip.start_sample(100, base);
        round_trip.start_sample(200, base + Duration::from_millis(50));

        round_trip.take_sample(200, base + Duration::from_millis(60));

        assert_eq!(
            round_trip.srtt(),
            Some(Duration::from_millis(60)),
            "the measurement runs from the first send, not the second"
        );
    }

    #[test]
    fn backing_off_doubles_and_discards_the_sample() {
        let base = Instant::now();
        let mut round_trip = RoundTrip::new();

        round_trip.start_sample(100, base);
        round_trip.back_off();

        assert_eq!(round_trip.rto(), TCP_RTO_INITIAL * 2);

        round_trip.take_sample(100, base + Duration::from_millis(10));
        assert_eq!(
            round_trip.srtt(),
            None,
            "karn's algorithm: a retransmitted segment never yields a measurement"
        );
    }

    #[test]
    fn backing_off_is_capped() {
        let mut round_trip = RoundTrip::new();

        for _ in 0..20 {
            round_trip.back_off();
        }

        assert_eq!(round_trip.rto(), TCP_RTO_MAX);
    }
}
