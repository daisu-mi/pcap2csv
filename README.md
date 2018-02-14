# pcap2csv

PCAP2CSV is a simple command line program which outputs CSV formatted data from raw PCAP packet capture data. Each packet recorded in the PCAP file is transformed to one line data, aligned by the following format.

| Number | Row Name| Type     | Description|
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
|11-266  |bag-of-Fs |int       |Bag of Fields (x00, x01, x02 .... x0F, x10 .... Xfe, Xff).|

If you want to convert IP address to asnumber, please prepare CAIDA's [Routeviews Prefix to AS mappings Dataset (pfx2as) for IPv4 and IPv6](https://www.caida.org/data/routing/routeviews-prefix2as.xml). The latest version only supports to convert IPv4 addresses to AS Numbers.

## Compile
* You may need pcap librarly and headers to compile.
- `% ./configure`
- `% make`
- `% sudo make install`

## Usage
- `r : read PCAP data`
- `i : read interface directly`
- `c : max number to read`
- `l : lookup AS number from IP address with routeview dataset`
- `x : dump data field with a bag-of-fields (a.k.a, bag-of-words) algorithm`

## Use cases
 1. Read from 100 packets in pcap file  
 `% p2c -r pcap.cap -c 100`
 1. Read from interface directly  
 `% sudo p2c -i eth0`
 1. Aslookup option  
 `% (wget http://data.caida.org/datasets/routing/routeviews-prefix2as/.... && gunzip (filename).pfx2as.gz)`  
 `% p2c -r pcap.cap -l filename.pfx2as`
 1. Bug-of-Field option to analyze layer 7 payloads  
 `% p2c -r pcpa.cap -x 7`
 1. Bug-of-Field option to analyze other portion  
 `% p2c -r pcap.cap -x 0`  # observe L3 Header, L4 Header, and L7 payloads  
 `% p2c -r pcap.cap -x 3`  # observe L3 Header  
 `% p2c -r pcap.cap -x 4`  # observe L4 Header  
 `% p2c -r pcap.cap -x 7`  # observe L7 Payloads  
  
# binary2csv 
Binary2CSV is a BoF parser for any files (as well as txt)

## Use cases
 1. Read from files
 `% b2c -r README.md`
 
