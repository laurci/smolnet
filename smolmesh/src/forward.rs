use std::future::poll_fn;
use std::io;
use std::task::Poll;

use smolnet::device::{Device, DeviceError, MAX_FRAME_SIZE};

struct Lane {
    buffer: Vec<u8>,
    held: Option<usize>,
    label: &'static str,
}

impl Lane {
    fn new(label: &'static str) -> Lane {
        Lane {
            buffer: vec![0u8; MAX_FRAME_SIZE],
            held: None,
            label,
        }
    }
}

fn pump<F: Device + ?Sized, T: Device + ?Sized>(
    from: &mut F,
    to: &mut T,
    lane: &mut Lane,
) -> io::Result<bool> {
    loop {
        let len = match lane.held.take() {
            Some(len) => len,
            None => match from.read_frame(&mut lane.buffer) {
                Ok(len) => len,
                Err(DeviceError::WouldBlock) => return Ok(false),
                Err(DeviceError::BufferTooSmall { need, got }) => {
                    tracing::warn!(lane = lane.label, need, got, "dropping an oversized packet");
                    continue;
                }
                Err(e) => return Err(io::Error::other(e.to_string())),
            },
        };

        match to.write_frame(&lane.buffer[..len]) {
            Ok(()) => tracing::trace!(lane = lane.label, len, "forwarded a packet"),
            Err(DeviceError::WouldBlock) => {
                lane.held = Some(len);
                tracing::trace!(
                    lane = lane.label,
                    len,
                    "far side is full, holding the packet"
                );

                return Ok(true);
            }
            Err(DeviceError::BufferTooSmall { need, got }) => {
                tracing::warn!(
                    lane = lane.label,
                    need,
                    got,
                    "dropping a packet that will not fit"
                );
            }
            Err(e) => return Err(io::Error::other(e.to_string())),
        }
    }
}

pub async fn forward<A: Device + ?Sized, B: Device + ?Sized>(
    a: &mut A,
    b: &mut B,
) -> io::Result<()> {
    let mut outbound = Lane::new("outbound");
    let mut inbound = Lane::new("inbound");

    let a_mtu = a.capabilities().mtu;
    let b_mtu = b.capabilities().mtu;

    if a_mtu != b_mtu {
        tracing::warn!(
            a_mtu,
            b_mtu,
            "the two sides disagree on mtu, oversized packets will be dropped"
        );
    }

    loop {
        let b_blocked = pump(a, b, &mut outbound)?;
        let a_blocked = pump(b, a, &mut inbound)?;

        poll_fn(|cx| {
            let mut ready = false;

            if !b_blocked && let Poll::Ready(result) = a.poll_readable(cx) {
                result?;
                ready = true;
            }

            if !a_blocked && let Poll::Ready(result) = b.poll_readable(cx) {
                result?;
                ready = true;
            }

            if b_blocked && let Poll::Ready(result) = b.poll_writable(cx) {
                result?;
                ready = true;
            }

            if a_blocked && let Poll::Ready(result) = a.poll_writable(cx) {
                result?;
                ready = true;
            }

            if ready {
                Poll::Ready(io::Result::Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await?;
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use smolnet::device::{Device, Medium, loopback::LoopbackDevice};

    use crate::forward::forward;

    fn packet(src: Ipv4Addr, dst: Ipv4Addr, body: u8) -> Vec<u8> {
        let mut bytes = vec![body; 24];

        bytes[0] = 0x45;
        bytes[12..16].copy_from_slice(&src.octets());
        bytes[16..20].copy_from_slice(&dst.octets());

        bytes
    }

    fn here(body: u8) -> Vec<u8> {
        packet(
            Ipv4Addr::new(10, 77, 0, 2),
            Ipv4Addr::new(10, 77, 0, 3),
            body,
        )
    }

    fn there(body: u8) -> Vec<u8> {
        packet(
            Ipv4Addr::new(10, 77, 0, 3),
            Ipv4Addr::new(10, 77, 0, 2),
            body,
        )
    }

    #[tokio::test]
    async fn packets_cross_in_both_directions() {
        let mut left = LoopbackDevice::new(Medium::Ip);
        let mut right = LoopbackDevice::new(Medium::Ip);

        left.push_rx(&here(0xaa));
        right.push_rx(&there(0xbb));

        let pump = tokio::spawn(async move {
            let _ =
                tokio::time::timeout(Duration::from_millis(200), forward(&mut left, &mut right))
                    .await;

            (left.drain_tx(), right.drain_tx())
        });

        let (left_tx, right_tx) = pump.await.unwrap();

        assert_eq!(right_tx, vec![here(0xaa)], "left to right was forwarded");
        assert_eq!(left_tx, vec![there(0xbb)], "right to left was forwarded");
    }

    #[tokio::test]
    async fn a_blocked_far_side_stops_us_draining_the_source() {
        let mut left = LoopbackDevice::new(Medium::Ip);
        let mut right = LoopbackDevice::new(Medium::Ip);

        right.set_writable(false);

        for body in 0..5u8 {
            left.push_rx(&here(body));
        }

        let pump = tokio::spawn(async move {
            let _ =
                tokio::time::timeout(Duration::from_millis(200), forward(&mut left, &mut right))
                    .await;

            (left.rx_len(), right.tx_len())
        });

        let (waiting, delivered) = pump.await.unwrap();

        assert_eq!(
            delivered, 0,
            "nothing reaches a far side that cannot accept"
        );
        assert_eq!(
            waiting, 4,
            "we hold one packet and leave the rest queued rather than draining and dropping them"
        );
    }

    #[tokio::test]
    async fn a_held_packet_is_delivered_once_the_far_side_drains() {
        let mut left = LoopbackDevice::new(Medium::Ip);
        let mut right = LoopbackDevice::new(Medium::Ip);

        let gate = right.writable_gate();
        gate.set(false);

        for body in 0..3u8 {
            left.push_rx(&here(body));
        }

        let pump = tokio::spawn(async move {
            let _ =
                tokio::time::timeout(Duration::from_millis(500), forward(&mut left, &mut right))
                    .await;

            right.drain_tx()
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        gate.set(true);

        assert_eq!(
            pump.await.unwrap(),
            vec![here(0), here(1), here(2)],
            "everything held or queued during the stall is delivered in order once it clears"
        );
    }

    #[tokio::test]
    async fn one_blocked_direction_does_not_stall_the_other() {
        let mut left = LoopbackDevice::new(Medium::Ip);
        let mut right = LoopbackDevice::new(Medium::Ip);

        right.set_writable(false);

        left.push_rx(&here(0xaa));
        right.push_rx(&there(0xbb));

        let pump = tokio::spawn(async move {
            let _ =
                tokio::time::timeout(Duration::from_millis(200), forward(&mut left, &mut right))
                    .await;

            (left.drain_tx(), right.tx_len())
        });

        let (left_tx, right_tx) = pump.await.unwrap();

        assert_eq!(right_tx, 0, "the blocked direction delivers nothing");
        assert_eq!(
            left_tx,
            vec![there(0xbb)],
            "the healthy direction keeps flowing"
        );
    }

    #[tokio::test]
    async fn mismatched_mtus_are_reported_but_not_fatal() {
        let mut left = LoopbackDevice::new(Medium::Ip).with_mtu(1500);
        let mut right = LoopbackDevice::new(Medium::Ip).with_mtu(1280);

        assert_ne!(left.capabilities().mtu, right.capabilities().mtu);

        let result =
            tokio::time::timeout(Duration::from_millis(100), forward(&mut left, &mut right)).await;

        assert!(result.is_err(), "the forwarder keeps running");
    }
}
