//! Nodes stop when their TUN device closes, so benchmarks can create them repeatedly.

use std::time::Duration;

use sanstun_drivers::Driver;
use sanstun_drivers::net::Network;
use sanstun_drivers::scenario::{Star, ip_packet};

#[tokio::test(start_paused = true)]
async fn dropping_the_handles_stops_every_task() {
    for driver in Driver::ALL {
        let star = Star::new(4, 1);
        let running = star.spawn(driver, Network::builder());
        for spoke in 1..=4 {
            running.handles[spoke]
                .tun_in
                .send((0, ip_packet(b"hi")))
                .unwrap();
        }
        tokio::time::sleep(Duration::from_secs(1)).await;

        drop(running);
        tokio::time::sleep(Duration::from_secs(1)).await;

        let alive = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        assert_eq!(alive, 0, "{} left tasks running", driver.name());
    }
}
