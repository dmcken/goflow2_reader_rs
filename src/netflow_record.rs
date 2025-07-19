
// std
use std::net::{IpAddr, Ipv4Addr};

// External
use chrono::{DateTime, TimeZone, Utc};
use ipnet::IpNet;
use serde::Serialize;




#[derive(Serialize, Debug, PartialEq)]
pub struct NetflowRecord {
    pub time_received_ns: DateTime<Utc>,
    pub sequence_num: u64,
    pub time_flow_start_ns: DateTime<Utc>,
    pub time_flow_end_ns: DateTime<Utc>,
    pub etype: u16,
    pub proto: u16,
    pub bytes: u64,
    pub packets: u64,
    pub addr_src: IpAddr,
    pub addr_dst: IpAddr,
    pub addr_sampler: IpAddr,
    pub addr_next_hop: IpAddr,
    pub port_src: u16,
    pub port_dst: u16,
    pub mac_src: Option<u64>,
    pub mac_dst: Option<u64>,
    pub post_nat_src_ipv4_address: Option<IpAddr>,
    pub post_nat_dst_ipv4_address: Option<IpAddr>,
    pub post_napt_src_transport_port: Option<u16>,
    pub  post_napt_dst_transport_port: Option<u16>,
}
impl Default for NetflowRecord {
    fn default() -> Self {
        let default_time = Utc.timestamp_opt(0, 0).unwrap(); // 1970-01-01T00:00:00Z
        let default_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

        NetflowRecord {
            time_received_ns: default_time,
            sequence_num: 0,
            time_flow_start_ns: default_time,
            time_flow_end_ns: default_time,
            etype: 0,
            proto: 0,
            bytes: 0,
            packets: 0,
            addr_src: default_ip,
            addr_dst: default_ip,
            addr_sampler: default_ip,
            addr_next_hop: default_ip,
            port_src: 0,
            port_dst: 0,
            mac_src: None,
            mac_dst: None,
            post_nat_src_ipv4_address: None,
            post_nat_dst_ipv4_address: None,
            post_napt_src_transport_port: None,
            post_napt_dst_transport_port: None,
        }
    }
}
impl NetflowRecord {
    pub fn new_with_defaults() -> Self {
        Self::default()
    }
    pub fn proto(&self) -> i64           {   self.proto as i64          }
    pub fn bytes(&self) -> i64           {   self.bytes as i64          }
    pub fn addr_src_str(&self) -> String {   self.addr_src.to_string()  }
    pub fn addr_dst_str(&self) -> String {   self.addr_dst.to_string()  }
}

// rhai helpers
pub fn option_ip(ip: Option<IpAddr>) -> String {
    ip.map(|v| v.to_string()).unwrap_or_default()
}

pub fn option_u16(v: Option<u16>) -> i64 {
    v.map(|v| v as i64).unwrap_or(-1)
}

pub fn option_dt(dt: Option<DateTime<Utc>>) -> i64 {
    dt.map(|v| v.timestamp()).unwrap_or(0)
}

pub fn ip_in_cidr(ip_str: &str, cidr_str: &str) -> bool {
    match (ip_str.parse::<IpAddr>(), cidr_str.parse::<IpNet>()) {
        (Ok(ip), Ok(net)) => net.contains(&ip),
        _ => false,
    }
}

