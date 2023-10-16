// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the metrics system for Network devices.
//!
//! # Metrics format
//! The metrics are flushed in JSON when requested by vmm::logger::metrics::METRICS.write().
//!
//! ## JSON example with metrics:
//! ```json
//! {
//!  "net_eth0": {
//!     "activate_fails": "SharedIncMetric",
//!     "cfg_fails": "SharedIncMetric",
//!     "mac_address_updates": "SharedIncMetric",
//!     "no_rx_avail_buffer": "SharedIncMetric",
//!     "no_tx_avail_buffer": "SharedIncMetric",
//!     ...
//!  }
//!  "net_eth1": {
//!     "activate_fails": "SharedIncMetric",
//!     "cfg_fails": "SharedIncMetric",
//!     "mac_address_updates": "SharedIncMetric",
//!     "no_rx_avail_buffer": "SharedIncMetric",
//!     "no_tx_avail_buffer": "SharedIncMetric",
//!     ...
//!  }
//!  ...
//!  "net_iface_id": {
//!     "activate_fails": "SharedIncMetric",
//!     "cfg_fails": "SharedIncMetric",
//!     "mac_address_updates": "SharedIncMetric",
//!     "no_rx_avail_buffer": "SharedIncMetric",
//!     "no_tx_avail_buffer": "SharedIncMetric",
//!     ...
//!  }
//!  "net": {
//!     "activate_fails": "SharedIncMetric",
//!     "cfg_fails": "SharedIncMetric",
//!     "mac_address_updates": "SharedIncMetric",
//!     "no_rx_avail_buffer": "SharedIncMetric",
//!     "no_tx_avail_buffer": "SharedIncMetric",
//!     ...
//!  }
//! }
//! ```
//! Each `net` field in the example above is a serializable `NetDeviceMetrics` structure
//! collecting metrics such as `activate_fails`, `cfg_fails`, etc. for the network device.
//! `net_eth0` represent metrics for the endpoint "/network-interfaces/eth0",
//! `net_eth1` represent metrics for the endpoint "/network-interfaces/eth1", and
//! `net_iface_id` represent metrics for the endpoint "/network-interfaces/{iface_id}"
//! network device respectively and `net` is the aggregate of all the per device metrics.
//!
//! # Limitations
//! Network device currently do not have `vmm::logger::metrics::StoreMetrics` so aggregate
//! doesn't consider them.
//!
//! # Design
//! The main design goals of this system are:
//! * To improve network device metrics by logging them at per device granularity.
//! * Continue to provide aggregate net metrics to maintain backward compatibility.
//! * Move NetDeviceMetrics out of from logger and decouple it.
//! * Use lockless operations, preferably ones that don't require anything other than simple
//!   reads/writes being atomic.
//! * Rely on `serde` to provide the actual serialization for writing the metrics.
//! * Since all metrics start at 0, we implement the `Default` trait via derive for all of them, to
//!   avoid having to initialize everything by hand.
//!
//! * Devices could be created in any order i.e. the first device created could either be eth0 or
//!   eth1 so if we use a vector for NetDeviceMetrics and call 1st device as net0, then net0 could
//!   sometimes point to eth0 and sometimes to eth1 which doesn't help with analysing the metrics.
//!   So, use Map instead of Vec to help understand which interface the metrics actually belongs to.
//! * We use "net_$iface_id" for the metrics name instead of "net_$tap_name" to be consistent with
//!   the net endpoint "/network-interfaces/{iface_id}".
//!
//! The system implements 1 types of metrics:
//! * Shared Incremental Metrics (SharedIncMetrics) - dedicated for the metrics which need a counter
//! (i.e the number of times an API request failed). These metrics are reset upon flush.
//! We use NET_DEV_METRICS_PVT instead of adding an entry of NetDeviceMetrics
//! in Net so that metrics are accessible to be flushed even from signal handlers.

use std::collections::BTreeMap;
use std::sync::{RwLock, RwLockReadGuard};

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::logger::{IncMetric, SharedIncMetric};

/// returns lock-unwrapped NET_DEV_METRICS_PVT.metrics,
/// we have this function so that we don't have to make
/// NET_DEV_METRICS_PVT public
pub fn get_net_metrics() -> RwLockReadGuard<'static, NetMetricsPerDevice> {
    // lock is always initialized so it is safe the unwrap the lock without a check.
    NET_DEV_METRICS_PVT.read().unwrap()
}

/// map of network interface id and metrics
/// this should be protected by a lock before accessing.
#[derive(Debug)]
pub struct NetMetricsPerDevice {
    /// used to access per net device metrics
    pub metrics: BTreeMap<String, NetDeviceMetrics>,
}

impl NetMetricsPerDevice {
    /// Allocate `NetDeviceMetrics` for net device having
    /// id `iface_id`. Also, allocate only if it doesn't
    /// exist to avoid overwriting previously allocated data.
    /// lock is always initialized so it is safe the unwrap
    /// the lock without a check.
    pub fn alloc(iface_id: String) {
        if NET_DEV_METRICS_PVT
            .read()
            .unwrap()
            .metrics
            .get(&iface_id)
            .is_none()
        {
            NET_DEV_METRICS_PVT
                .write()
                .unwrap()
                .metrics
                .insert(iface_id, NetDeviceMetrics::default());
        }
    }
}

#[macro_export]
// Per device metrics are behind a ref lock and in a map which
// makes it difficult to return the metrics pointer via a function
// This macro is an attempt to make the code more readable and to
// centralize the error handling.
// The macro can be called in below ways where iface_id is String and
// activate_fails is a metric from struct `NetDeviceMetrics`:
//     net_metrics!(&iface_id, activate_fails.inc());
//     net_metrics!(&iface_id, activate_fails.add(5));
//     net_metrics!(&iface_id, activate_fails.count());
macro_rules! net_metrics {
    ($iface_id:expr,$metric:ident.$action:ident($($value:tt)?)) => {{
        if $crate::devices::virtio::net::metrics::get_net_metrics().metrics.get($iface_id).is_some() {
            $crate::devices::virtio::net::metrics::get_net_metrics().metrics.get($iface_id).unwrap().$metric.$action($($value)?)
        }else{
            $crate::devices::virtio::net::metrics::NetMetricsPerDevice::alloc($iface_id.to_string());
            $crate::devices::virtio::net::metrics::get_net_metrics().metrics.get($iface_id).unwrap().$metric.$action($($value)?)
        }
    }}
}

/// Pool of Network-related metrics per device behind a lock to
/// keep things thread safe. Since the lock is initialized here
/// it is safe to unwrap it without any check.
static NET_DEV_METRICS_PVT: RwLock<NetMetricsPerDevice> = RwLock::new(NetMetricsPerDevice {
    metrics: BTreeMap::new(),
});

/// This function facilitates aggregation and serialization of
/// per net device metrics.
pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    let metrics_len = NET_DEV_METRICS_PVT.read().unwrap().metrics.len();
    // +1 to accomodate aggregate net metrics
    let mut seq = serializer.serialize_map(Some(1 + metrics_len))?;

    let mut net_aggregated: NetDeviceMetrics = NetDeviceMetrics::default();

    for metrics in NET_DEV_METRICS_PVT.read().unwrap().metrics.iter() {
        let devn = format!("net_{}", metrics.0);
        // serialization will flush the metrics so aggregate before it.
        net_aggregated.aggregate(metrics.1);
        seq.serialize_entry(&devn, &metrics.1)?;
    }
    seq.serialize_entry("net", &net_aggregated)?;
    seq.end()
}

/// Network-related metrics.
#[derive(Default, Debug, Serialize)]
pub struct NetDeviceMetrics {
    /// Number of times when activate failed on a network device.
    pub activate_fails: SharedIncMetric,
    /// Number of times when interacting with the space config of a network device failed.
    pub cfg_fails: SharedIncMetric,
    /// Number of times the mac address was updated through the config space.
    pub mac_address_updates: SharedIncMetric,
    /// No available buffer for the net device rx queue.
    pub no_rx_avail_buffer: SharedIncMetric,
    /// No available buffer for the net device tx queue.
    pub no_tx_avail_buffer: SharedIncMetric,
    /// Number of times when handling events on a network device failed.
    pub event_fails: SharedIncMetric,
    /// Number of events associated with the receiving queue.
    pub rx_queue_event_count: SharedIncMetric,
    /// Number of events associated with the rate limiter installed on the receiving path.
    pub rx_event_rate_limiter_count: SharedIncMetric,
    /// Number of RX partial writes to guest.
    pub rx_partial_writes: SharedIncMetric,
    /// Number of RX rate limiter throttling events.
    pub rx_rate_limiter_throttled: SharedIncMetric,
    /// Number of events received on the associated tap.
    pub rx_tap_event_count: SharedIncMetric,
    /// Number of bytes received.
    pub rx_bytes_count: SharedIncMetric,
    /// Number of packets received.
    pub rx_packets_count: SharedIncMetric,
    /// Number of errors while receiving data.
    pub rx_fails: SharedIncMetric,
    /// Number of successful read operations while receiving data.
    pub rx_count: SharedIncMetric,
    /// Number of times reading from TAP failed.
    pub tap_read_fails: SharedIncMetric,
    /// Number of times writing to TAP failed.
    pub tap_write_fails: SharedIncMetric,
    /// Number of transmitted bytes.
    pub tx_bytes_count: SharedIncMetric,
    /// Number of malformed TX frames.
    pub tx_malformed_frames: SharedIncMetric,
    /// Number of errors while transmitting data.
    pub tx_fails: SharedIncMetric,
    /// Number of successful write operations while transmitting data.
    pub tx_count: SharedIncMetric,
    /// Number of transmitted packets.
    pub tx_packets_count: SharedIncMetric,
    /// Number of TX partial reads from guest.
    pub tx_partial_reads: SharedIncMetric,
    /// Number of events associated with the transmitting queue.
    pub tx_queue_event_count: SharedIncMetric,
    /// Number of events associated with the rate limiter installed on the transmitting path.
    pub tx_rate_limiter_event_count: SharedIncMetric,
    /// Number of RX rate limiter throttling events.
    pub tx_rate_limiter_throttled: SharedIncMetric,
    /// Number of packets with a spoofed mac, sent by the guest.
    pub tx_spoofed_mac_count: SharedIncMetric,
}

impl NetDeviceMetrics {
    /// Net metrics are SharedIncMetric where the diff of current vs
    /// old is serialized i.e. serialize_u64(current-old).
    /// So to have the aggregate serialized in same way we need to
    /// fetch the diff of current vs old metrics and add it to the
    /// aggregate.
    pub fn aggregate(&mut self, other: &Self) {
        self.activate_fails.add(other.activate_fails.fetch_diff());
        self.cfg_fails.add(other.cfg_fails.fetch_diff());
        self.mac_address_updates
            .add(other.mac_address_updates.fetch_diff());
        self.no_rx_avail_buffer
            .add(other.no_rx_avail_buffer.fetch_diff());
        self.no_tx_avail_buffer
            .add(other.no_tx_avail_buffer.fetch_diff());
        self.event_fails.add(other.event_fails.fetch_diff());
        self.rx_queue_event_count
            .add(other.rx_queue_event_count.fetch_diff());
        self.rx_event_rate_limiter_count
            .add(other.rx_event_rate_limiter_count.fetch_diff());
        self.rx_partial_writes
            .add(other.rx_partial_writes.fetch_diff());
        self.rx_rate_limiter_throttled
            .add(other.rx_rate_limiter_throttled.fetch_diff());
        self.rx_tap_event_count
            .add(other.rx_tap_event_count.fetch_diff());
        self.rx_bytes_count.add(other.rx_bytes_count.fetch_diff());
        self.rx_packets_count
            .add(other.rx_packets_count.fetch_diff());
        self.rx_fails.add(other.rx_fails.fetch_diff());
        self.rx_count.add(other.rx_count.fetch_diff());
        self.tap_read_fails.add(other.tap_read_fails.fetch_diff());
        self.tap_write_fails.add(other.tap_write_fails.fetch_diff());
        self.tx_bytes_count.add(other.tx_bytes_count.fetch_diff());
        self.tx_malformed_frames
            .add(other.tx_malformed_frames.fetch_diff());
        self.tx_fails.add(other.tx_fails.fetch_diff());
        self.tx_count.add(other.tx_count.fetch_diff());
        self.tx_packets_count
            .add(other.tx_packets_count.fetch_diff());
        self.tx_partial_reads
            .add(other.tx_partial_reads.fetch_diff());
        self.tx_queue_event_count
            .add(other.tx_queue_event_count.fetch_diff());
        self.tx_rate_limiter_event_count
            .add(other.tx_rate_limiter_event_count.fetch_diff());
        self.tx_rate_limiter_throttled
            .add(other.tx_rate_limiter_throttled.fetch_diff());
        self.tx_spoofed_mac_count
            .add(other.tx_spoofed_mac_count.fetch_diff());
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_max_net_dev_metrics() {
        // Note: this test has nothing to do with
        // Net structure or IRQs, this is just to allocate
        // metrics for max number of devices that system can have.
        // we have 5-23 irq for net devices so max 19 net devices.
        const MAX_NET_DEVICES: usize = 19;

        assert!(NET_DEV_METRICS_PVT.read().is_ok());
        assert!(NET_DEV_METRICS_PVT.write().is_ok());

        for i in 0..MAX_NET_DEVICES {
            let devn: String = format!("eth{}", i);
            NetMetricsPerDevice::alloc(devn.clone());
            net_metrics!(&devn, activate_fails.inc());
            net_metrics!(&devn, rx_bytes_count.add(10));
            net_metrics!(&devn, tx_bytes_count.add(5));
        }
        for i in 0..MAX_NET_DEVICES {
            let devn: String = format!("eth{}", i);
            assert!(net_metrics!(&devn, activate_fails.count()) >= 1);
            assert!(net_metrics!(&devn, rx_bytes_count.count()) >= 10);
            assert_eq!(net_metrics!(&devn, tx_bytes_count.count()), 5);
        }
    }
    #[test]
    fn test_signle_net_dev_metrics() {
        // Use eth0 so that we can check thread safety with the
        // `test_net_dev_metrics` which also uses the same name.
        let devn = "eth0";

        assert!(NET_DEV_METRICS_PVT.read().is_ok());
        assert!(NET_DEV_METRICS_PVT.write().is_ok());

        NetMetricsPerDevice::alloc(String::from(devn));
        assert!(NET_DEV_METRICS_PVT.read().is_ok());
        assert!(get_net_metrics().metrics.get(devn).is_some());

        net_metrics!(devn, activate_fails.inc());
        assert!(
            net_metrics!(devn, activate_fails.count()) > 0,
            "{}",
            net_metrics!(devn, activate_fails.count())
        );
        // we expect only 2 tests (this and test_max_net_dev_metrics)
        // to update activate_fails count for eth0.
        assert!(
            net_metrics!(devn, activate_fails.count()) <= 2,
            "{}",
            net_metrics!(devn, activate_fails.count())
        );

        net_metrics!(&String::from(devn), activate_fails.inc());
        net_metrics!(&String::from(devn), rx_bytes_count.add(5));
        assert!(net_metrics!(&String::from(devn), rx_bytes_count.count()) >= 5);
    }
}
