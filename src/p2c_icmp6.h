#ifndef __P2C_ICMP6_H__
#define __P2C_ICMP6_H__

struct icmp6hdr {
    u_int8_t    icmp6_type; /* type field */
    u_int8_t    icmp6_code; /* code field */
    u_int16_t   icmp6_cksum;    /* checksum field */
    union {
        u_int32_t   icmp6_un_data32[1]; /* type-specific field */
        u_int16_t   icmp6_un_data16[2]; /* type-specific field */
        u_int8_t    icmp6_un_data8[4];  /* type-specific field */
    } icmp6_dataun;
};

#endif

