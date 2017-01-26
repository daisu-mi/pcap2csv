#ifndef __P2C_ICMP_H__
#define __P2C_ICMP_H__

struct icmphdr {
	u_int8_t  icmp_type;		/* type of message, see below */
	u_int8_t  icmp_code;		/* type sub code */
	u_int16_t icmp_cksum;		/* ones complement cksum of struct */
	union {
		u_int8_t ih_pptr;			/* ICMP_PARAMPROB */
		struct in_addr ih_gwaddr;	/* ICMP_REDIRECT */
		struct ih_idseq {
			u_int16_t icd_id;
			u_int16_t icd_seq;
		} ih_idseq;
		u_int32_t ih_void;

		/* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
		struct ih_pmtu {
			u_int16_t ipm_void;
			u_int16_t ipm_nextmtu;
		} ih_pmtu;
	} icmp_hun;
#define	icmp_pptr	icmp_hun.ih_pptr
#define	icmp_gwaddr	icmp_hun.ih_gwaddr
#define	icmp_id		icmp_hun.ih_idseq.icd_id
#define	icmp_seq	icmp_hun.ih_idseq.icd_seq
#define	icmp_void	icmp_hun.ih_void
#define	icmp_pmvoid	icmp_hun.ih_pmtu.ipm_void
#define	icmp_nextmtu	icmp_hun.ih_pmtu.ipm_nextmtu
	union {
		struct id_ts {
			u_int32_t its_otime;
			u_int32_t its_rtime;
			u_int32_t its_ttime;
		} id_ts;
		struct id_ip  {
			struct ip idi_ip;
			/* options and then 64 bits of data */
		} id_ip;
                struct mpls_ext {
                    u_int8_t legacy_header[128]; /* extension header starts 128 bytes after ICMP header */
                    u_int8_t version_res[2];
                    u_int8_t checksum[2];
                    u_int8_t data[1];
                } mpls_ext;
		u_int32_t id_mask;
		u_int8_t id_data[1];
	} icmp_dun;
#define	icmp_otime	icmp_dun.id_ts.its_otime
#define	icmp_rtime	icmp_dun.id_ts.its_rtime
#define	icmp_ttime	icmp_dun.id_ts.its_ttime
#define	icmp_ip		icmp_dun.id_ip.idi_ip
#define	icmp_mask	icmp_dun.id_mask
#define	icmp_data	icmp_dun.id_data
#define	icmp_mpls_ext_version	icmp_dun.mpls_ext.version_res
#define	icmp_mpls_ext_checksum	icmp_dun.mpls_ext.checksum
#define	icmp_mpls_ext_data	icmp_dun.mpls_ext.data
};

#endif
