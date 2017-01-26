#ifndef __P2C_ETHER_H__
#define __P2C_ETHER_H__

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN      6
#endif


struct  ether_header {
    u_int8_t    ether_dhost[ETHER_ADDR_LEN];
    u_int8_t    ether_shost[ETHER_ADDR_LEN];
    u_int16_t   ether_type;
};

#ifndef ETHERTYPE_HDRLEN
#define ETHERTYPE_HDRLEN	14
#endif

#ifndef ETHERTYPE_LEN
#define ETHERTYPE_LEN           2
#endif

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP        0x0800  /* IP protocol */
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6      0x86dd
#endif

#ifndef ETHERTYPE_8021Q
#define ETHERTYPE_8021Q     0x8100
#endif

#endif
