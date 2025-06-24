# goflow2_reader_rs
Rust goflow2 protobuf reader.





## CLI Arguments


| Short | Long | Description |
| ----- | ---- | ----------- |
| p | path | File to load |
| f | filter | Filter records |
| l | limit | Limit number of results |
| o | output | Output format to display |

## Filters

You can filter on the following fields:
* bytes
* proto
* addr_src
* addr_dst
* post_nat_src_ipv4_address
* post_napt_src_transport_port
* time_flow_start_ns

Supported operators

| operator | Description |
| -------- | ----------- |
| `==` | Equality |
| `&&` | Logical AND |
| `&#124;&#124;` | Logical OR |
| `ip_in_cidr` | Compare IPs to CIDRs, e.g. ip_in_cidr(addr_src,"10.1.0.0/16") |


