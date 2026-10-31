//! With crypto offloaded to rayon, every driver still delivers every packet.
//!
//! Offloading runs on real threads, so this uses real time rather than the paused clock, and
//! checks delivery as a multiset: batches finishing out of order may reorder packets.

use std::time::Duration;

use sanstun_drivers::Driver;
use sanstun_drivers::net::Network;
use sanstun_drivers::scenario::{Star, ip_packet};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offloaded_crypto_delivers_everything() {
    for driver in Driver::ALL {
        let mut star = Star::new(4, 5);
        for node in &mut star.nodes {
            node.offload = true;
        }
        let mut running = star.spawn(driver, Network::builder());

        let mut sent = Vec::new();
        for round in 0..50u32 {
            for spoke in 1..=4 {
                let up = ip_packet(&[&round.to_be_bytes()[..], &[spoke as u8, 0]].concat());
                let down = ip_packet(&[&round.to_be_bytes()[..], &[spoke as u8, 1]].concat());
                running.handles[spoke].tun_in.send((0, up.clone())).unwrap();
                running.handles[0]
                    .tun_in
                    .send((star.peer(0, spoke), down.clone()))
                    .unwrap();
                sent.push(up);
                sent.push(down);
            }
        }

        let mut received = Vec::new();
        for handle in &mut running.handles {
            let tun_out = handle.tun_out.as_mut().unwrap();
            let expected = if handle.addr == star.addr(0) { 200 } else { 50 };
            for _ in 0..expected {
                let (_, packet) = tokio::time::timeout(Duration::from_secs(5), tun_out.recv())
                    .await
                    .unwrap_or_else(|_| panic!("{} stalled", driver.name()))
                    .unwrap();
                received.push(packet);
            }
        }

        sent.sort();
        received.sort();
        assert_eq!(received, sent, "{}", driver.name());
    }
}
