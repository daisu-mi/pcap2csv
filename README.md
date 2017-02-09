# pcap2csv

PCAP2CSV is a simple command line program which outputs CSV formatted data from raw PCAP packet capture data. Each packet recorded in the PCAP file is transformed to one line data, along with the following format.

| Number | Column  | Type     | Description|
|:------:|:-------:|:--------:|:-----------:|
|1       |tv_sec   |long      |Recorded time (tv_sec) in the PCAP file.|
|2       |tv_usec  |long      |Recorded time (tv_usec) in the PCAP file.|
|3       |counter  |long      |Sequence number in the PCAP file.|
|4       |srcip    |char      |Source IPv4/IPv6 address.|
|5       |dstip    |char      |Destination IPv4/IPv6 address.|
|6       |srcasn   |int       |Source AS Number.|
|7       |dstasn   |int       |Destination AS Number.|
|8       |sport/type |int       |Source TCP or UDP Portnumber, or ICMP type.|
|9       |dport/code |int       |Destination TCP or UDP Portnumber, or ICMP code.|
|10      |proto     |int       |IP Proto (TCP, UDP or ICMP).|

If you want to convert IP address to asnumber, please prepare CAIDA's [Routeviews Prefix to AS mappings Dataset (pfx2as) for IPv4 and IPv6](https://www.caida.org/data/routing/routeviews-prefix2as.xml). The latest version only supports to convert IPv4 addresses to AS Numbers.

# how to compile
* You may need pcap librarly and headers to compile.
- `% ./configure`
- `% ./make`
- `% sudo ./make install`

# how to use
- (example) % p2c -r pcap.cap -l routerview.pfx2as
- `r : read PCAP data`
- `i : read interface directly`
- `l : read routeview dataset`

