use std::future::poll_fn;
use std::io;
use std::task::Poll;

use smolnet::device::{Device, DeviceError, MAX_FRAME_SIZE};

fn drain<F: Device + ?Sized, T: Device + ?Sized>(
    from: &mut F,
    to: &mut T,
    buffer: &mut [u8],
    direction: &'static str,
) -> io::Result<()> {
    loop {
        let len = match from.read_frame(buffer) {
            Ok(len) => len,
            Err(DeviceError::WouldBlock) => return Ok(()),
            Err(DeviceError::BufferTooSmall { need, got }) => {
                tracing::warn!(direction, need, got, "dropping an oversized packet");
                continue;
            }
            Err(e) => return Err(io::Error::other(e.to_string())),
        };

        match to.write_frame(&buffer[..len]) {
            Ok(()) => tracing::trace!(direction, len, "forwarded a packet"),
            Err(DeviceError::WouldBlock) => {
                tracing::debug!(direction, len, "dropping a packet, the far side is full");
            }
            Err(DeviceError::BufferTooSmall { need, got }) => {
                tracing::warn!(direction, need, got, "dropping a packet that will not fit");
            }
            Err(e) => return Err(io::Error::other(e.to_string())),
        }
    }
}

pub async fn forward<A: Device + ?Sized, B: Device + ?Sized>(
    a: &mut A,
    b: &mut B,
) -> io::Result<()> {
    let mut buffer = vec![0u8; MAX_FRAME_SIZE];

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
        poll_fn(|cx| {
            let mut ready = false;

            if let Poll::Ready(result) = a.poll_readable(cx) {
                result?;
                ready = true;
            }

            if let Poll::Ready(result) = b.poll_readable(cx) {
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

        drain(a, b, &mut buffer, "outbound")?;
        drain(b, a, &mut buffer, "inbound")?;
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use smolnet::device::{Device, Medium, loopback::LoopbackDevice};

    use crate::forward::forward;

    fn packet(src: Ipv4Addr, dst: Ipv4Addr, body: u8) -> Vec<u8> {
        let mut bytes = vec![body; 24];

        bytes[0] = 0x45;
        bytes[12..16].copy_from_slice(&src.octets());
        bytes[16..20].copy_from_slice(&dst.octets());

        bytes
    }

    #[tokio::test]
    async fn packets_cross_in_both_directions() {
        let mut left = LoopbackDevice::new(Medium::Ip);
        let mut right = LoopbackDevice::new(Medium::Ip);

        let outbound = packet(
            Ipv4Addr::new(10, 30, 0, 2),
            Ipv4Addr::new(10, 30, 0, 3),
            0xaa,
        );
        let inbound = packet(
            Ipv4Addr::new(10, 30, 0, 3),
            Ipv4Addr::new(10, 30, 0, 2),
            0xbb,
        );

        left.push_rx(&outbound);
        right.push_rx(&inbound);

        let pump = tokio::spawn(async move {
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                forward(&mut left, &mut right),
            )
            .await;

            (left.drain_tx(), right.drain_tx())
        });

        let (left_tx, right_tx) = pump.await.unwrap();

        assert_eq!(right_tx, vec![outbound], "left to right was forwarded");
        assert_eq!(left_tx, vec![inbound], "right to left was forwarded");
    }

    #[tokio::test]
    async fn a_packet_too_large_for_the_far_side_is_dropped() {
        let mut left = LoopbackDevice::new(Medium::Ip);
        let mut right = LoopbackDevice::new(Medium::Ip);

        right.set_writable(false);

        left.push_rx(&packet(
            Ipv4Addr::new(10, 30, 0, 2),
            Ipv4Addr::new(10, 30, 0, 3),
            0xaa,
        ));

        let pump = tokio::spawn(async move {
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                forward(&mut left, &mut right),
            )
            .await;

            right.drain_tx()
        });

        assert!(
            pump.await.unwrap().is_empty(),
            "the forwarder drops rather than stalling"
        );
    }

    #[tokio::test]
    async fn mismatched_mtus_are_reported_but_not_fatal() {
        let mut left = LoopbackDevice::new(Medium::Ip).with_mtu(1500);
        let mut right = LoopbackDevice::new(Medium::Ip).with_mtu(1280);

        assert_ne!(left.capabilities().mtu, right.capabilities().mtu);

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            forward(&mut left, &mut right),
        )
        .await;

        assert!(result.is_err(), "the forwarder keeps running");
    }
}
