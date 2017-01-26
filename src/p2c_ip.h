#ifndef __P2C_IP4_H__
#define __P2C_IP4_H__

#ifndef IPVERSION	
#define IPVERSION	 4
#endif

struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN
		u_int		ip_hl:4,				/* header length */
						ip_v:4;					/* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
		u_int		ip_v:4,				 	/* version */
						ip_hl:4;				/* header length */
#endif
		u_int8_t		ip_tos;		 	/* type of service */
		u_int16_t	 ip_len;		 	/* total length */
		u_int16_t	 ip_id;				/* identification */
		u_int16_t	 ip_off;		 	/* fragment offset field */
#define IP_DF 0x4000				/* dont fragment flag */
#define IP_MF 0x2000				/* more fragments flag */
#define IP_OFFMASK 0x1fff		 /* mask for fragmenting bits */
		u_int8_t		ip_ttl;		 	/* time to live */
		u_int8_t		ip_p;			 	/* protocol */
		u_int16_t	 ip_sum;		 	/* checksum */
		struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

#endif
