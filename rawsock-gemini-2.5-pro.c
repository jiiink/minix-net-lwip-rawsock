/* LWIP service - rawsock.c - RAW sockets */
/*
 * For IPv6 sockets, this module attempts to implement a part of RFC 3542, but
 * currently not more than what is supported by lwIP and/or what is expected by
 * a handful of standard utilities (dhcpcd, ping6, traceroute6..).
 *
 * For general understanding, be aware that IPv4 raw sockets always receive
 * packets including the IP header, and may be used to send packets including
 * the IP header if IP_HDRINCL is set, while IPv6 raw sockets always send and
 * receive actual payloads only, using ancillary (control) data to set and
 * retrieve per-packet IP header fields.
 *
 * For packet headers we follow general BSD semantics.  For example, some IPv4
 * header fields are swapped both when sending and when receiving.  Also, like
 * on NetBSD, IPPROTO_RAW is not a special value in any way.
 */

#include "lwip.h"
#include "ifaddr.h"
#include "pktsock.h"

#include "lwip/raw.h"
#include "lwip/inet_chksum.h"

#include <net/route.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>

/* The number of RAW sockets.  Inherited from the lwIP configuration. */
#define NR_RAWSOCK	MEMP_NUM_RAW_PCB

/*
 * Outgoing packets are not getting buffered, so the send buffer size simply
 * determines the maximum size for sent packets.  The send buffer maximum is
 * therefore limited to the maximum size of a single packet (64K-1 bytes),
 * which is already enforced by lwIP's 16-bit length parameter to pbuf_alloc().
 *
 * The actual transmission may enforce a lower limit, though.  The full packet
 * size must not exceed the same 64K-1 limit, and that includes any headers
 * that still have to be prepended to the given packet.  The size of those
 * headers depends on the socket type (IPv4/IPv6) and the IP_HDRINCL setting.
 *
 * The default is equal to the maximum here, because if a (by definition,
 * privileged) application wishes to send large raw packets, it probably has a
 * good reason, and we do not want to get in its way.
 */
#define RAW_MAX_PAYLOAD	(UINT16_MAX)

#define RAW_SNDBUF_MIN	1		/* minimum RAW send buffer size */
#define RAW_SNDBUF_DEF	RAW_MAX_PAYLOAD	/* default RAW send buffer size */
#define RAW_SNDBUF_MAX	RAW_MAX_PAYLOAD	/* maximum RAW send buffer size */
#define RAW_RCVBUF_MIN	MEMPOOL_BUFSIZE	/* minimum RAW receive buffer size */
#define RAW_RCVBUF_DEF	32768		/* default RAW receive buffer size */
#define RAW_RCVBUF_MAX	65536		/* maximum RAW receive buffer size */

static struct rawsock {
	struct pktsock raw_pktsock;		/* packet socket object */
	struct raw_pcb *raw_pcb;		/* lwIP RAW control block */
	TAILQ_ENTRY(rawsock) raw_next;		/* next in active/free list */
	struct icmp6_filter raw_icmp6filter;	/* ICMPv6 type filter */
} raw_array[NR_RAWSOCK];

static TAILQ_HEAD(, rawsock) raw_freelist;	/* list of free RAW sockets */
static TAILQ_HEAD(, rawsock) raw_activelist;	/* list, in-use RAW sockets */

static const struct sockevent_ops rawsock_ops;

#define rawsock_get_sock(raw)	(ipsock_get_sock(rawsock_get_ipsock(raw)))
#define rawsock_get_ipsock(raw)	(pktsock_get_ipsock(&(raw)->raw_pktsock))
#define rawsock_is_ipv6(raw)	(ipsock_is_ipv6(rawsock_get_ipsock(raw)))
#define rawsock_is_v6only(raw)	(ipsock_is_v6only(rawsock_get_ipsock(raw)))
#define rawsock_is_conn(raw)	\
	(raw_flags((raw)->raw_pcb) & RAW_FLAGS_CONNECTED)
#define rawsock_is_hdrincl(raw)	\
	(raw_flags((raw)->raw_pcb) & RAW_FLAGS_HDRINCL)

static ssize_t rawsock_pcblist(struct rmib_call *, struct rmib_node *,
	struct rmib_oldp *, struct rmib_newp *);

/* The CTL_NET {PF_INET,PF_INET6} IPPROTO_RAW subtree. */
/* All dynamically numbered; the sendspace/recvspace entries are ours. */
static struct rmib_node net_inet_raw_table[] = {
	RMIB_INT(RMIB_RO, RAW_SNDBUF_DEF, "sendspace",
	    "Default RAW send buffer size"),
	RMIB_INT(RMIB_RO, RAW_RCVBUF_DEF, "recvspace",
	    "Default RAW receive buffer size"),
	RMIB_FUNC(RMIB_RO | CTLTYPE_NODE, 0, rawsock_pcblist, "pcblist",
	    "RAW IP protocol control block list"),
};

static struct rmib_node net_inet_raw_node =
    RMIB_NODE(RMIB_RO, net_inet_raw_table, "raw", "RAW IPv4 settings");
static struct rmib_node net_inet6_raw6_node =
    RMIB_NODE(RMIB_RO, net_inet_raw_table, "raw6", "RAW IPv6 settings");

/*
 * Initialize the raw sockets module.
 */
void
rawsock_init(void)
{
	TAILQ_INIT(&raw_freelist);

	for (size_t slot = 0; slot < (sizeof(raw_array) / sizeof(raw_array[0])); slot++) {
		TAILQ_INSERT_TAIL(&raw_freelist, &raw_array[slot], raw_next);
	}

	TAILQ_INIT(&raw_activelist);

	if (mibtree_register_inet(PF_INET, IPPROTO_RAW, &net_inet_raw_node) != 0) {
		panic("rawsock_init: cannot register IPv4 MIB tree");
	}
	if (mibtree_register_inet(PF_INET6, IPPROTO_RAW, &net_inet6_raw6_node) != 0) {
		panic("rawsock_init: cannot register IPv6 MIB tree");
	}
}

/*
 * Check whether the given arrived IPv6 packet is fit to be received on the
 * given raw socket.
 */
static int
rawsock_check_v6(struct rawsock *raw, struct pbuf *pbuf)
{
	struct raw_pcb * const pcb = raw->raw_pcb;

	assert(rawsock_is_ipv6(raw));

	if (pcb->protocol == IPPROTO_ICMPV6) {
		if (pbuf->len < offsetof(struct icmp6_hdr, icmp6_dataun)) {
			return FALSE;
		}
		const struct icmp6_hdr *icmp6_hdr =
		    (const struct icmp6_hdr *)pbuf->payload;
		if (!ICMP6_FILTER_WILLPASS(icmp6_hdr->icmp6_type,
		    &raw->raw_icmp6filter)) {
			return FALSE;
		}
	}

	if (pcb->chksum_reqd) {
		if (pbuf->tot_len < pcb->chksum_offset + sizeof(uint16_t)) {
			return FALSE;
		}
		if (ip6_chksum_pseudo(pbuf, pcb->protocol, pbuf->tot_len,
		    ip6_current_src_addr(), ip6_current_dest_addr()) != 0) {
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * Adjust the given arrived IPv4 packet by changing the length and offset
 * fields to host-byte order, as is done by the BSDs.  This effectively mirrors
 * the swapping part of the preparation done on IPv4 packets being sent if the
 * IP_HDRINCL socket option is enabled.
 */
static void
rawsock_adjust_v4(struct pbuf *pbuf)
{
	if (pbuf == NULL || pbuf->payload == NULL || pbuf->len < sizeof(struct ip_hdr)) {
		return;
	}

	struct ip_hdr *iphdr = (struct ip_hdr *)pbuf->payload;

	IPH_LEN(iphdr) = htons(IPH_LEN(iphdr));
	IPH_OFFSET(iphdr) = htons(IPH_OFFSET(iphdr));
}

/*
 * A packet has arrived on a raw socket.  Since the same packet may have to be
 * delivered to multiple raw sockets, we always return 0 (= not consumed) from
 * this function.  As such, we must make a copy of the given packet if we want
 * to keep it, and never free it.
 */
static uint8_t
rawsock_input(void *arg, struct raw_pcb *pcb __unused, struct pbuf *psrc,
              const ip_addr_t *srcaddr)
{
    struct rawsock *raw = (struct rawsock *)arg;
    struct pbuf *pbuf;
    int off = 0;
    int hdrlen;

    assert(raw->raw_pcb == pcb);

    hdrlen = pktsock_test_input(&raw->raw_pktsock, psrc);
    if (hdrlen < 0) {
        return 0;
    }

    if (ip_current_is_v6()) {
        off = ip_current_header_tot_len();
        util_pbuf_header(psrc, -off);

        if (!rawsock_check_v6(raw, psrc)) {
            util_pbuf_header(psrc, off);
            return 0;
        }
    } else {
        if (rawsock_is_ipv6(raw)) {
            if (raw->raw_pcb->chksum_reqd) {
                return 0;
            }
            off = IP_HLEN;
            util_pbuf_header(psrc, -off);
        }
    }

    pbuf = pchain_alloc(PBUF_RAW, hdrlen + psrc->tot_len);
    if (pbuf == NULL) {
        if (off > 0) {
            util_pbuf_header(psrc, off);
        }
        return 0;
    }

    util_pbuf_header(pbuf, -hdrlen);

    err_t err = pbuf_copy(pbuf, psrc);

    if (off > 0) {
        util_pbuf_header(psrc, off);
    }

    if (err != ERR_OK) {
        pbuf_free(pbuf);
        return 0;
    }

    pbuf->flags |= psrc->flags & (PBUF_FLAG_LLMCAST | PBUF_FLAG_LLBCAST);

    if (!rawsock_is_ipv6(raw)) {
        rawsock_adjust_v4(pbuf);
    }

    pktsock_input(&raw->raw_pktsock, pbuf, srcaddr, 0);

    return 0;
}

/*
 * Create a raw socket.
 */
sockid_t
rawsock_socket(int domain, int protocol, struct sock ** sockp,
	const struct sockevent_ops ** ops)
{
	if (protocol < 0 || protocol > UINT8_MAX) {
		return EPROTONOSUPPORT;
	}

	if (TAILQ_EMPTY(&raw_freelist)) {
		return ENOBUFS;
	}

	struct rawsock *raw = TAILQ_FIRST(&raw_freelist);
	TAILQ_REMOVE(&raw_freelist, raw, raw_next);

	uint8_t ip_type = pktsock_socket(&raw->raw_pktsock, domain, RAW_SNDBUF_DEF,
	    RAW_RCVBUF_DEF, sockp);

	raw->raw_pcb = raw_new_ip_type(ip_type, protocol);
	if (raw->raw_pcb == NULL) {
		TAILQ_INSERT_HEAD(&raw_freelist, raw, raw_next);
		return ENOBUFS;
	}

	raw_recv(raw->raw_pcb, rawsock_input, (void *)raw);

	raw_set_multicast_ttl(raw->raw_pcb, 1);
	unsigned int flags = raw_flags(raw->raw_pcb);
	raw_setflags(raw->raw_pcb, flags | RAW_FLAGS_MULTICAST_LOOP);

	raw->raw_pcb->chksum_reqd = 0;
	if (rawsock_is_ipv6(raw) && protocol == IPPROTO_ICMPV6) {
		raw->raw_pcb->chksum_reqd = 1;
		raw->raw_pcb->chksum_offset =
		    offsetof(struct icmp6_hdr, icmp6_cksum);
		ICMP6_FILTER_SETPASSALL(&raw->raw_icmp6filter);
	}

	TAILQ_INSERT_TAIL(&raw_activelist, raw, raw_next);

	*ops = &rawsock_ops;
	return SOCKID_RAW | (sockid_t)(raw - raw_array);
}

/*
 * Bind a raw socket to a local address.
 */
static int
rawsock_bind(struct sock *sock, const struct sockaddr *addr,
	socklen_t addr_len, endpoint_t user_endpt)
{
	struct rawsock *raw = (struct rawsock *)sock;

	if (rawsock_is_conn(raw)) {
		return EINVAL;
	}

	ip_addr_t ipaddr;
	int r = ipsock_get_src_addr(rawsock_get_ipsock(raw), addr, addr_len,
	    user_endpt, &raw->raw_pcb->local_ip, 0, TRUE, &ipaddr, NULL);

	if (r != OK) {
		return r;
	}

	const err_t err = raw_bind(raw->raw_pcb, &ipaddr);

	return util_convert_err(err);
}

/*
 * Connect a raw socket to a remote address.
 */
static int
rawsock_connect(struct sock * sock, const struct sockaddr * addr,
	socklen_t addr_len, endpoint_t user_endpt __unused)
{
	struct rawsock *raw = (struct rawsock *)sock;

	if (addr_is_unspec(addr, addr_len)) {
		raw_disconnect(raw->raw_pcb);
		return OK;
	}

	ip_addr_t dst_addr;
	int r = ipsock_get_dst_addr(rawsock_get_ipsock(raw), addr, addr_len,
	    &raw->raw_pcb->local_ip, &dst_addr, NULL);
	if (r != OK) {
		return r;
	}

	if (ip_addr_isany(&raw->raw_pcb->local_ip)) {
		struct ifdev *ifdev = NULL;
		if (ip_addr_ismulticast(&dst_addr)) {
			uint32_t ifindex = pktsock_get_ifindex(&raw->raw_pktsock);
			if (ifindex == 0) {
				ifindex = raw_get_multicast_netif_index(
				    raw->raw_pcb);
			}

			if (ifindex != 0) {
				ifdev = ifdev_get_by_index(ifindex);
				if (ifdev == NULL) {
					return ENXIO;
				}
			}
		}

		const ip_addr_t *src_addr = ifaddr_select(&dst_addr, ifdev, NULL);
		if (src_addr == NULL) {
			return EHOSTUNREACH;
		}

		err_t err = raw_bind(raw->raw_pcb, src_addr);
		if (err != ERR_OK) {
			return util_convert_err(err);
		}
	}

	err_t err = raw_connect(raw->raw_pcb, &dst_addr);
	if (err != ERR_OK) {
		return util_convert_err(err);
	}

	return OK;
}

/*
 * Perform preliminary checks on a send request.
 */
static int
rawsock_pre_send(struct sock *sock, size_t len, socklen_t ctl_len __unused,
	const struct sockaddr *addr, socklen_t addr_len __unused,
	endpoint_t user_endpt __unused, int flags)
{
	struct rawsock *raw = (struct rawsock *)sock;

	if ((flags & ~MSG_DONTROUTE) != 0) {
		return EOPNOTSUPP;
	}

	if (!rawsock_is_conn(raw) && addr == NULL) {
		return EDESTADDRREQ;
	}

	const struct ipsock *ip_sock = rawsock_get_ipsock(raw);
	const size_t sndbuf = ipsock_get_sndbuf(ip_sock);

	if (len > sndbuf) {
		return EMSGSIZE;
	}

	return OK;
}

/*
 * Swap IP-level options between the RAW PCB and the packet options structure,
 * for all options that have their flag set in the packet options structure.
 * This function is called twice when sending a packet.  The result is that the
 * flagged options are overridden for only the packet being sent.
 */
static void
rawsock_swap_opt(struct rawsock *raw, struct pktopt *pkto)
{
	if (!raw || !pkto || !raw->raw_pcb) {
		return;
	}

	if (pkto->pkto_flags & PKTOF_TOS) {
		const uint8_t temp_tos = raw->raw_pcb->tos;
		raw->raw_pcb->tos = pkto->pkto_tos;
		pkto->pkto_tos = temp_tos;
	}

	if (pkto->pkto_flags & PKTOF_TTL) {
		const uint8_t temp_ttl = raw->raw_pcb->ttl;
		const uint8_t temp_mcast_ttl = raw_get_multicast_ttl(raw->raw_pcb);

		raw->raw_pcb->ttl = pkto->pkto_ttl;
		raw_set_multicast_ttl(raw->raw_pcb, pkto->pkto_ttl);

		pkto->pkto_ttl = temp_ttl;
		pkto->pkto_mcast_ttl = temp_mcast_ttl;
	}
}

/*
 * We are about to send the given packet that already includes an IPv4 header,
 * because the IP_HDRINCL option is enabled on a raw IPv4 socket.  Prepare the
 * IPv4 header for sending, by modifying a few fields in it, as expected by
 * userland.
 */
static int
rawsock_prepare_hdrincl(struct rawsock *raw, struct pbuf *pbuf,
	const ip_addr_t *src_addr)
{
	(void)raw;

	if (pbuf->len < sizeof(struct ip_hdr)) {
		return EINVAL;
	}

	struct ip_hdr *iphdr = (struct ip_hdr *)pbuf->payload;
	const size_t hlen = (size_t)IPH_HL(iphdr) << 2;

	if (hlen < sizeof(struct ip_hdr) || pbuf->len < hlen) {
		return OK;
	}

	if (iphdr->src.addr == PP_HTONL(INADDR_ANY)) {
		assert(IP_IS_V4(src_addr));
		iphdr->src.addr = ip_addr_get_ip4_u32(src_addr);
	}

	IPH_LEN(iphdr) = htons(IPH_LEN(iphdr));
	IPH_OFFSET(iphdr) = htons(IPH_OFFSET(iphdr));
	IPH_CHKSUM(iphdr) = 0;

	IPH_CHKSUM(iphdr) = inet_chksum(iphdr, hlen);

	return OK;
}

/*
 * Send a packet on a raw socket.
 */
static int
rawsock_send(struct sock * sock, const struct sockdriver_data * data,
	size_t len, size_t * off, const struct sockdriver_data * ctl __unused,
	socklen_t ctl_len __unused, socklen_t * ctl_off __unused,
	const struct sockaddr * addr, socklen_t addr_len,
	endpoint_t user_endpt __unused, int flags, size_t min __unused)
{
	struct rawsock *raw = (struct rawsock *)sock;
	ip_addr_t src_addr, dst_addr;
	const ip_addr_t *src_addrp, *dst_addrp;
	struct ifdev *ifdev;
	struct pbuf *pbuf;
	int r;

	struct pktopt pktopt = { .pkto_flags = 0 };
	if ((r = pktsock_get_ctl(&raw->raw_pktsock, ctl, ctl_len, &pktopt)) != OK)
		return r;

	if ((r = pktsock_get_pktinfo(&raw->raw_pktsock, &pktopt, &ifdev,
	    &src_addr)) != OK)
		return r;

	if (ifdev != NULL && !ip_addr_isany(&src_addr)) {
		src_addrp = &src_addr;
	} else {
		src_addrp = &raw->raw_pcb->local_ip;
		if (ip_addr_ismulticast(src_addrp))
			src_addrp = IP46_ADDR_ANY(IP_GET_TYPE(src_addrp));
	}

	if (!rawsock_is_conn(raw)) {
		assert(addr != NULL);
		if ((r = ipsock_get_dst_addr(rawsock_get_ipsock(raw), addr,
		    addr_len, src_addrp, &dst_addr, NULL)) != OK)
			return r;
		dst_addrp = &dst_addr;
	} else {
		dst_addrp = &raw->raw_pcb->remote_ip;
	}

	if (ifdev == NULL && ip_addr_ismulticast(dst_addrp)) {
		uint32_t ifindex = raw_get_multicast_netif_index(raw->raw_pcb);
		if (ifindex != NETIF_NO_INDEX)
			ifdev = ifdev_get_by_index(ifindex);
	}

	if (ifdev == NULL) {
		if (!(flags & MSG_DONTROUTE)) {
			const ip_addr_t *route_src = IP_IS_ANY_TYPE_VAL(*src_addrp) ?
			    IP46_ADDR_ANY(IP_GET_TYPE(dst_addrp)) : src_addrp;
			struct netif *netif = ip_route(route_src, dst_addrp);
			if (netif == NULL)
				return EHOSTUNREACH;
			ifdev = netif_get_ifdev(netif);
		} else {
			ifdev = ifaddr_map_by_subnet(dst_addrp);
			if (ifdev == NULL)
				return EHOSTUNREACH;
		}
	}

	assert(ifdev != NULL);
	if ((IP_IS_V6(dst_addrp) && ifaddr_is_zone_mismatch(ip_2_ip6(dst_addrp), ifdev)) ||
	    (IP_IS_V6(src_addrp) && ifaddr_is_zone_mismatch(ip_2_ip6(src_addrp), ifdev)))
		return EHOSTUNREACH;

	if (ip_addr_isany(src_addrp)) {
		src_addrp = ifaddr_select(dst_addrp, ifdev, NULL);
		if (src_addrp == NULL)
			return EHOSTUNREACH;
	}

	assert(len <= RAW_MAX_PAYLOAD);
	size_t hdrlen = rawsock_is_hdrincl(raw) ? 0 :
	    (IP_IS_V6(dst_addrp) ? IP6_HLEN : IP_HLEN);

	if (hdrlen + len > RAW_MAX_PAYLOAD)
		return EMSGSIZE;

	if ((pbuf = pchain_alloc(PBUF_IP, len)) == NULL)
		return ENOBUFS;

	if ((r = pktsock_get_data(&raw->raw_pktsock, data, len, pbuf)) != OK) {
		pbuf_free(pbuf);
		return r;
	}

	if (raw->raw_pcb->chksum_reqd) {
		if (pbuf->len < raw->raw_pcb->chksum_offset + sizeof(uint16_t)) {
			pbuf_free(pbuf);
			return EINVAL;
		}
		memset((char *)pbuf->payload + raw->raw_pcb->chksum_offset, 0,
		    sizeof(uint16_t));
	}

	if (rawsock_is_hdrincl(raw)) {
		if ((r = rawsock_prepare_hdrincl(raw, pbuf, src_addrp)) != OK) {
			pbuf_free(pbuf);
			return r;
		}
	}

	if (ip_addr_ismulticast(dst_addrp))
		pbuf->flags |= PBUF_FLAG_LLMCAST;
	else if (ip_addr_isbroadcast(dst_addrp, ifdev_get_netif(ifdev)))
		pbuf->flags |= PBUF_FLAG_LLBCAST;

	assert(!ip_addr_isany(src_addrp));
	assert(!ip_addr_ismulticast(src_addrp));

	rawsock_swap_opt(raw, &pktopt);
	err_t err = raw_sendto_if_src(raw->raw_pcb, pbuf, dst_addrp,
	    ifdev_get_netif(ifdev), src_addrp);
	rawsock_swap_opt(raw, &pktopt);

	pbuf_free(pbuf);

	if ((r = util_convert_err(err)) == OK)
		*off = len;
	return r;
}

/*
 * Update the set of flag-type socket options on a raw socket.
 */
static void
rawsock_setsockmask(struct sock *sock, unsigned int mask)
{
    if (!sock) {
        return;
    }

    struct rawsock *raw = (struct rawsock *)sock;
    if (!raw->raw_pcb) {
        return;
    }

    if (mask & SO_BROADCAST) {
        ip_set_option(raw->raw_pcb, SOF_BROADCAST);
    } else {
        ip_reset_option(raw->raw_pcb, SOF_BROADCAST);
    }
}

/*
 * Prepare a helper structure for IP-level option processing.
 */
static void
rawsock_get_ipopts(struct rawsock *raw, struct ipopts *ipopts)
{
    if (!raw || !ipopts || !raw->raw_pcb) {
        return;
    }

    ipopts->local_ip = &raw->raw_pcb->local_ip;
    ipopts->remote_ip = &raw->raw_pcb->remote_ip;
    ipopts->tos = &raw->raw_pcb->tos;
    ipopts->ttl = &raw->raw_pcb->ttl;
    ipopts->sndmin = RAW_SNDBUF_MIN;
    ipopts->sndmax = RAW_SNDBUF_MAX;
    ipopts->rcvmin = RAW_RCVBUF_MIN;
    ipopts->rcvmax = RAW_RCVBUF_MAX;
}

/*
 * Set socket options on a raw socket.
 */
static void
update_raw_flags(struct raw_pcb *pcb, unsigned int flag, int enable)
{
	unsigned int flags = raw_flags(pcb);

	if (enable)
		flags |= flag;
	else
		flags &= ~flag;

	raw_setflags(pcb, flags);
}

static int
rawsock_setsockopt_ip(struct rawsock *raw, int name,
    const struct sockdriver_data *data, socklen_t len)
{
	int r;

	switch (name) {
	case IP_HDRINCL: {
		int val;
		if ((r = sockdriver_copyin_opt(data, &val, sizeof(val),
		    len)) != OK)
			return r;
		update_raw_flags(raw->raw_pcb, RAW_FLAGS_HDRINCL, val);
		return OK;
	}
	case IP_MULTICAST_IF: {
		struct in_addr in_addr;
		ip_addr_t ipaddr;
		struct ifdev *ifdev;

		pktsock_set_mcaware(&raw->raw_pktsock);
		if ((r = sockdriver_copyin_opt(data, &in_addr,
		    sizeof(in_addr), len)) != OK)
			return r;
		ip_addr_set_ip4_u32(&ipaddr, in_addr.s_addr);
		ifdev = ifaddr_map_by_addr(&ipaddr);
		if (ifdev == NULL)
			return EADDRNOTAVAIL;
		raw_set_multicast_netif_index(raw->raw_pcb,
		    ifdev_get_index(ifdev));
		return OK;
	}
	case IP_MULTICAST_LOOP: {
		uint8_t byte;
		pktsock_set_mcaware(&raw->raw_pktsock);
		if ((r = sockdriver_copyin_opt(data, &byte, sizeof(byte),
		    len)) != OK)
			return r;
		update_raw_flags(raw->raw_pcb, RAW_FLAGS_MULTICAST_LOOP, byte);
		return OK;
	}
	case IP_MULTICAST_TTL: {
		uint8_t byte;
		pktsock_set_mcaware(&raw->raw_pktsock);
		if ((r = sockdriver_copyin_opt(data, &byte, sizeof(byte),
		    len)) != OK)
			return r;
		raw_set_multicast_ttl(raw->raw_pcb, byte);
		return OK;
	}
	default:
		return EOPNOTSUPP;
	}
}

static int
rawsock_setsockopt_ipv6(struct rawsock *raw, int name,
    const struct sockdriver_data *data, socklen_t len)
{
	int r;

	switch (name) {
	case IPV6_CHECKSUM: {
		int val;
		if (raw->raw_pcb->protocol == IPPROTO_ICMPV6)
			return EINVAL;
		if ((r = sockdriver_copyin_opt(data, &val, sizeof(val),
		    len)) != OK)
			return r;
		if (val == -1) {
			raw->raw_pcb->chksum_reqd = 0;
		} else if (val >= 0 && (val & 1) == 0) {
			raw->raw_pcb->chksum_reqd = 1;
			raw->raw_pcb->chksum_offset = (uint16_t)val;
		} else {
			return EINVAL;
		}
		return OK;
	}
	case IPV6_MULTICAST_IF: {
		int val;
		uint32_t ifindex;
		pktsock_set_mcaware(&raw->raw_pktsock);
		if ((r = sockdriver_copyin_opt(data, &val, sizeof(val),
		    len)) != OK)
			return r;
		if (val != 0) {
			ifindex = (uint32_t)val;
			if (ifdev_get_by_index(ifindex) == NULL)
				return ENXIO;
		} else {
			ifindex = NETIF_NO_INDEX;
		}
		raw_set_multicast_netif_index(raw->raw_pcb, ifindex);
		return OK;
	}
	case IPV6_MULTICAST_LOOP: {
		int val;
		pktsock_set_mcaware(&raw->raw_pktsock);
		if ((r = sockdriver_copyin_opt(data, &val, sizeof(val),
		    len)) != OK)
			return r;
		if (val < 0 || val > 1)
			return EINVAL;
		update_raw_flags(raw->raw_pcb, RAW_FLAGS_MULTICAST_LOOP, val);
		return OK;
	}
	case IPV6_MULTICAST_HOPS: {
		int val;
		pktsock_set_mcaware(&raw->raw_pktsock);
		if ((r = sockdriver_copyin_opt(data, &val, sizeof(val),
		    len)) != OK)
			return r;
		if (val < -1 || val > UINT8_MAX)
			return EINVAL;
		raw_set_multicast_ttl(raw->raw_pcb,
		    (val == -1) ? 1 : (uint8_t)val);
		return OK;
	}
	default:
		return EOPNOTSUPP;
	}
}

static int
rawsock_setsockopt_icmpv6(struct rawsock *raw, int name,
    const struct sockdriver_data *data, socklen_t len)
{
	switch (name) {
	case ICMP6_FILTER: {
		struct icmp6_filter filter;
		int r;
		if (len == 0) {
			ICMP6_FILTER_SETPASSALL(&raw->raw_icmp6filter);
			return OK;
		}
		if ((r = sockdriver_copyin_opt(data, &filter, sizeof(filter),
		    len)) != OK)
			return r;
		memcpy(&raw->raw_icmp6filter, &filter, sizeof(filter));
		return OK;
	}
	default:
		return EOPNOTSUPP;
	}
}

static int
rawsock_setsockopt(struct sock *sock, int level, int name,
    const struct sockdriver_data *data, socklen_t len)
{
	struct rawsock *raw = (struct rawsock *)sock;
	int r = EOPNOTSUPP;

	switch (level) {
	case IPPROTO_IP:
		if (!rawsock_is_ipv6(raw))
			r = rawsock_setsockopt_ip(raw, name, data, len);
		break;
	case IPPROTO_IPV6:
		if (rawsock_is_ipv6(raw))
			r = rawsock_setsockopt_ipv6(raw, name, data, len);
		break;
	case IPPROTO_ICMPV6:
		if (rawsock_is_ipv6(raw) &&
		    raw->raw_pcb->protocol == IPPROTO_ICMPV6)
			r = rawsock_setsockopt_icmpv6(raw, name, data, len);
		break;
	}

	if (r != EOPNOTSUPP)
		return r;

	struct ipopts ipopts;
	rawsock_get_ipopts(raw, &ipopts);
	return pktsock_setsockopt(&raw->raw_pktsock, level, name, data, len,
	    &ipopts);
}

/*
 * Retrieve socket options on a raw socket.
 */
static void
get_ip4_multicast_if_addr(const struct raw_pcb *pcb, struct in_addr *in_addr)
{
	uint32_t ifindex = raw_get_multicast_netif_index(pcb);
	struct ifdev *ifdev = ifdev_get_by_index(ifindex);

	if (ifdev != NULL) {
		const ip4_addr_t *ip4addr = netif_ip4_addr(ifdev_get_netif(ifdev));
		in_addr->s_addr = ip4_addr_get_u32(ip4addr);
	} else {
		in_addr->s_addr = PP_HTONL(INADDR_ANY);
	}
}

static int
rawsock_getsockopt(struct sock * sock, int level, int name,
	const struct sockdriver_data * data, socklen_t * len)
{
	struct rawsock *raw = (struct rawsock *)sock;
	struct ipopts ipopts;

	switch (level) {
	case IPPROTO_IP:
		if (rawsock_is_ipv6(raw)) {
			break;
		}

		switch (name) {
		case IP_HDRINCL: {
			int val = !!rawsock_is_hdrincl(raw);
			return sockdriver_copyout_opt(data, &val, sizeof(val),
			    len);
		}
		case IP_MULTICAST_IF: {
			struct in_addr in_addr;
			get_ip4_multicast_if_addr(raw->raw_pcb, &in_addr);
			return sockdriver_copyout_opt(data, &in_addr,
			    sizeof(in_addr), len);
		}
		case IP_MULTICAST_LOOP: {
			uint8_t byte =
			    !!(raw_flags(raw->raw_pcb) & RAW_FLAGS_MULTICAST_LOOP);
			return sockdriver_copyout_opt(data, &byte,
			    sizeof(byte), len);
		}
		case IP_MULTICAST_TTL: {
			uint8_t byte = raw_get_multicast_ttl(raw->raw_pcb);
			return sockdriver_copyout_opt(data, &byte,
			    sizeof(byte), len);
		}
		}
		break;

	case IPPROTO_IPV6:
		if (!rawsock_is_ipv6(raw)) {
			break;
		}

		switch (name) {
		case IPV6_CHECKSUM: {
			int val = raw->raw_pcb->chksum_reqd ?
			    raw->raw_pcb->chksum_offset : -1;
			return sockdriver_copyout_opt(data, &val, sizeof(val),
			    len);
		}
		case IPV6_MULTICAST_IF: {
			int val =
			    (int)raw_get_multicast_netif_index(raw->raw_pcb);
			return sockdriver_copyout_opt(data, &val, sizeof(val),
			    len);
		}
		case IPV6_MULTICAST_LOOP: {
			int val =
			    !!(raw_flags(raw->raw_pcb) & RAW_FLAGS_MULTICAST_LOOP);
			return sockdriver_copyout_opt(data, &val, sizeof(val),
			    len);
		}
		case IPV6_MULTICAST_HOPS: {
			int val = raw_get_multicast_ttl(raw->raw_pcb);
			return sockdriver_copyout_opt(data, &val, sizeof(val),
			    len);
		}
		}
		break;

	case IPPROTO_ICMPV6:
		if (!rawsock_is_ipv6(raw) ||
		    raw->raw_pcb->protocol != IPPROTO_ICMPV6) {
			break;
		}

		if (name == ICMP6_FILTER) {
			return sockdriver_copyout_opt(data,
			    &raw->raw_icmp6filter,
			    sizeof(raw->raw_icmp6filter), len);
		}
		break;
	}

	rawsock_get_ipopts(raw, &ipopts);
	return pktsock_getsockopt(&raw->raw_pktsock, level, name, data, len,
	    &ipopts);
}

/*
 * Retrieve the local socket address of a raw socket.
 */
static int
rawsock_getsockname(struct sock *sock, struct sockaddr *addr,
                      socklen_t *addr_len)
{
    if (!sock || !addr || !addr_len) {
        return -1;
    }

    struct rawsock *raw = (struct rawsock *)sock;
    struct raw_pcb *pcb = raw->raw_pcb;

    if (!pcb) {
        return -1;
    }

    ipsock_put_addr(rawsock_get_ipsock(raw), addr, addr_len,
                    &pcb->local_ip, 0);

    return 0;
}

/*
 * Retrieve the remote socket address of a raw socket.
 */
static int
rawsock_getpeername(struct sock * sock, struct sockaddr * addr,
	socklen_t * addr_len)
{
	if (!sock || !addr || !addr_len) {
		return EINVAL;
	}

	struct rawsock *raw = (struct rawsock *)sock;

	if (!raw->raw_pcb) {
		return EFAULT;
	}

	if (!rawsock_is_conn(raw)) {
		return ENOTCONN;
	}

	return ipsock_put_addr(rawsock_get_ipsock(raw), addr, addr_len,
	    &raw->raw_pcb->remote_ip, 0);
}

/*
 * Shut down a raw socket for reading and/or writing.
 */
static int
rawsock_shutdown(struct sock *sock, unsigned int mask)
{
	if (sock == NULL) {
		return OK;
	}

	struct rawsock * const raw = (struct rawsock *)sock;

	if ((mask & SFL_SHUT_RD) != 0) {
		raw_recv(raw->raw_pcb, NULL, NULL);
	}

	pktsock_shutdown(&raw->raw_pktsock, mask);

	return OK;
}

/*
 * Close a raw socket.
 */
static int
rawsock_close(struct sock *sock, int force __unused)
{
	if (!sock) {
		return OK;
	}

	struct rawsock *raw = (struct rawsock *)sock;

	if (raw->raw_pcb) {
		raw_recv(raw->raw_pcb, NULL, NULL);
		raw_remove(raw->raw_pcb);
		raw->raw_pcb = NULL;
	}

	pktsock_close(&raw->raw_pktsock);

	return OK;
}

/*
 * Free up a closed raw socket.
 */
static void
rawsock_free(struct sock *sock)
{
    if (sock == NULL) {
        return;
    }

    struct rawsock *raw = (struct rawsock *)sock;

    assert(raw->raw_pcb == NULL);

    TAILQ_REMOVE(&raw_activelist, raw, raw_next);
    TAILQ_INSERT_HEAD(&raw_freelist, raw, raw_next);
}

/*
 * Fill the given kinfo_pcb sysctl(7) structure with information about the RAW
 * PCB identified by the given pointer.
 */
static void
rawsock_get_info(struct kinfo_pcb *ki, const void *ptr)
{
	if (ki == NULL || ptr == NULL) {
		return;
	}

	const struct raw_pcb *pcb = (const struct raw_pcb *)ptr;
	struct rawsock *raw = (struct rawsock *)pcb->recv_arg;

	if (raw == NULL) {
		return;
	}

	/* We iterate our own list so we can't find "strange" PCBs. */
	assert(raw >= raw_array &&
	    raw < &raw_array[__arraycount(raw_array)]);

	ki->ki_type = SOCK_RAW;
	ki->ki_protocol = pcb->protocol;

	ipsock_get_info(ki, &pcb->local_ip, 0 /*local_port*/,
	    &pcb->remote_ip, 0 /*remote_port*/);

	/* TODO: change this so that sockstat(1) may work one day. */
	ki->ki_sockaddr = (uint64_t)(uintptr_t)rawsock_get_sock(raw);

	ki->ki_rcvq = pktsock_get_recvlen(&raw->raw_pktsock);

	if (rawsock_is_hdrincl(raw)) {
		ki->ki_pflags |= INP_HDRINCL;
	}
}

/*
 * Given either NULL or a previously returned RAW PCB pointer, return the first
 * or next RAW PCB pointer, or NULL if there are no more.  lwIP does not expose
 * 'raw_pcbs', but other modules in this service may also use RAW PCBs (which
 * should then stay hidden), so we iterate through our own list instead.
 */
static const void *
rawsock_enum(const void * last)
{
	struct rawsock *raw;

	if (last == NULL) {
		raw = TAILQ_FIRST(&raw_activelist);
	} else {
		const struct raw_pcb * const pcb = (const struct raw_pcb *)last;
		raw = (struct rawsock *)pcb->recv_arg;

		assert(raw >= raw_array &&
		       raw < &raw_array[__arraycount(raw_array)]);

		raw = TAILQ_NEXT(raw, raw_next);
	}

	return raw ? raw->raw_pcb : NULL;
}

/*
 * Obtain the list of RAW protocol control blocks, for sysctl(7).
 */
static ssize_t
rawsock_pcblist(struct rmib_call *call, struct rmib_node *node __unused,
    struct rmib_oldp *oldp, struct rmib_newp *newp __unused)
{
	return util_pcblist(call, oldp, rawsock_enum, rawsock_get_info);
}

static const struct sockevent_ops rawsock_ops = {
	.sop_bind		= rawsock_bind,
	.sop_connect		= rawsock_connect,
	.sop_pre_send		= rawsock_pre_send,
	.sop_send		= rawsock_send,
	.sop_pre_recv		= pktsock_pre_recv,
	.sop_recv		= pktsock_recv,
	.sop_test_recv		= pktsock_test_recv,
	.sop_ioctl		= ifconf_ioctl,
	.sop_setsockmask	= rawsock_setsockmask,
	.sop_setsockopt		= rawsock_setsockopt,
	.sop_getsockopt		= rawsock_getsockopt,
	.sop_getsockname	= rawsock_getsockname,
	.sop_getpeername	= rawsock_getpeername,
	.sop_shutdown		= rawsock_shutdown,
	.sop_close		= rawsock_close,
	.sop_free		= rawsock_free
};
