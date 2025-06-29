# Goflow2 Reader (Rust)

Rust goflow2 protobuf record reader.


## CLI Arguments


| Short | Long | Description |
| ----- | ---- | ----------- |
| p | path | File to load |
| f | filter | Filter records |
| l | limit | Limit number of results, defaults to 0 which equals unlimited |
| o | output | Output format to display |
| <none> | no-frame | Omits the header "Searching for" and footer "Matched records: x" lines, useful for allowing output to be piped to other commands |

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
| == | Equality |
| && | Logical AND |
| &#124;&#124; | Logical OR |
| ip_in_cidr | Compare IPs to CIDRs, e.g. ip_in_cidr(addr_src,"10.1.0.0/16") |

### Example filters

* `proto == 17` - Display all UDP flows. For ids see: [Protocol numbers](https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)
* `addr_src == "103.153.238.161"`
* `ip_in_cidr(addr_src,"10.1.0.0/16")`
* `post_napt_src_transport_port == 57068 && post_nat_src_ipv4_address == "8.8.4.3"`

## Input formats

Protobuf files can be read in their raw form or compressed with any of the following (automatically detected from the file extension). Support is purely for decompression so all variants should be supported (raise an issue if you find one that doesn't work).

* 7z - Support currently via 7z subprocess. I have to look at sevenz-rust2.
* bz2
* xz

## Output formats

This program outputs a single line for each matching record to stdout.

| Output format | Description |
| ------------- | ----------- |
| json-pretty | Multi-line pretty printed JSON object. |
| json | Single-line json object. |
| csv | Single-line CSV record. A header is printed once at the start. |
| none | No record output, useful for counting records that match a filter before inspecting the records themselves. Doesn't surpress the "Searching for" or count lines. See no-frame option for that. |
