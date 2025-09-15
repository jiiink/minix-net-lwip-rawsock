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
void rawsock_init(void)
{
    unsigned int slot;

    TAILQ_INIT(&raw_freelist);
    for (slot = 0; slot < __arraycount(raw_array); ++slot) {
        TAILQ_INSERT_TAIL(&raw_freelist, &raw_array[slot], raw_next);
    }

    TAILQ_INIT(&raw_activelist);

    if (mibtree_register_inet(PF_INET, IPPROTO_RAW, &net_inet_raw_node) != 0) {
        /* Handle registration error if needed */
        return;
    }

    if (mibtree_register_inet(PF_INET6, IPPROTO_RAW, &net_inet6_raw6_node) != 0) {
        /* Handle registration error if needed */
        return;
    }
}

/*
 * Check whether the given arrived IPv6 packet is fit to be received on the
 * given raw socket.
 */
static int rawsock_check_v6(struct rawsock *raw, struct pbuf *pbuf)
{
    uint8_t type;

    if (!rawsock_is_ipv6(raw))
        return FALSE;

    if (raw->raw_pcb->protocol == IPPROTO_ICMPV6) {
        if (pbuf->len < offsetof(struct icmp6_hdr, icmp6_dataun))
            return FALSE;

        type = ((struct icmp6_hdr *)pbuf->payload)->icmp6_type;

        if (!ICMP6_FILTER_WILLPASS((int)type, &raw->raw_icmp6filter))
            return FALSE;
    }

    if (raw->raw_pcb->chksum_reqd) {
        size_t required_len = raw->raw_pcb->chksum_offset + sizeof(uint16_t);

        if (pbuf->tot_len < required_len)
            return FALSE;

        if (ip6_chksum_pseudo(pbuf, raw->raw_pcb->protocol, pbuf->tot_len,
                              ip6_current_src_addr(), ip6_current_dest_addr()) != 0)
            return FALSE;
    }

    return TRUE;
}

/*
 * Adjust the given arrived IPv4 packet by changing the length and offset
 * fields to host-byte order, as is done by the BSDs.  This effectively mirrors
 * the swapping part of the preparation done on IPv4 packets being sent if the
 * IP_HDRINCL socket option is enabled.
 */
static void rawsock_adjust_v4(struct pbuf *pbuf)
{
    if (pbuf == NULL || pbuf->payload == NULL || pbuf->len < sizeof(struct ip_hdr))
        return;

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
static uint8_t rawsock_input(void *arg, struct raw_pcb *pcb, struct pbuf *psrc, const ip_addr_t *srcaddr)
{
    struct rawsock *raw = (struct rawsock *)arg;
    struct pbuf *pbuf = NULL;
    int off = 0, hdrlen = 0;

    if (!raw || raw->raw_pcb != pcb || !psrc || !srcaddr) {
        return 0;
    }

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
    if (!pbuf) {
        if (off > 0) {
            util_pbuf_header(psrc, off);
        }
        return 0;
    }

    util_pbuf_header(pbuf, -hdrlen);

    if (pbuf_copy(pbuf, psrc) != ERR_OK) {
        if (off > 0) {
            util_pbuf_header(psrc, off);
        }
        pbuf_free(pbuf);
        return 0;
    }

    pbuf->flags |= psrc->flags & (PBUF_FLAG_LLMCAST | PBUF_FLAG_LLBCAST);

    if (off > 0) {
        util_pbuf_header(psrc, off);
    }

    if (!rawsock_is_ipv6(raw)) {
        rawsock_adjust_v4(pbuf);
    }

    pktsock_input(&raw->raw_pktsock, pbuf, srcaddr, 0);

    return 0;
}

/*
 * Create a raw socket.
 */
sockid_t rawsock_socket(int domain, int protocol, struct sock **sockp, const struct sockevent_ops **ops) {
	struct rawsock *raw;
	unsigned int flags;
	uint8_t ip_type;

	if (protocol < 0 || protocol > UINT8_MAX)
		return EPROTONOSUPPORT;

	if (TAILQ_EMPTY(&raw_freelist))
		return ENOBUFS;

	raw = TAILQ_FIRST(&raw_freelist);
	if (!raw)
		return ENOBUFS;

	ip_type = pktsock_socket(&raw->raw_pktsock, domain, RAW_SNDBUF_DEF, RAW_RCVBUF_DEF, sockp);

	raw->raw_pcb = raw_new_ip_type(ip_type, protocol);
	if (!raw->raw_pcb)
		return ENOBUFS;

	raw_recv(raw->raw_pcb, rawsock_input, (void *)raw);

	raw_set_multicast_ttl(raw->raw_pcb, 1);

	flags = raw_flags(raw->raw_pcb);
	raw_setflags(raw->raw_pcb, flags | RAW_FLAGS_MULTICAST_LOOP);

	if (rawsock_is_ipv6(raw) && protocol == IPPROTO_ICMPV6) {
		raw->raw_pcb->chksum_reqd = 1;
		raw->raw_pcb->chksum_offset = offsetof(struct icmp6_hdr, icmp6_cksum);
		ICMP6_FILTER_SETPASSALL(&raw->raw_icmp6filter);
	} else {
		raw->raw_pcb->chksum_reqd = 0;
	}

	TAILQ_REMOVE(&raw_freelist, raw, raw_next);
	TAILQ_INSERT_TAIL(&raw_activelist, raw, raw_next);

	if (!ops)
		return EINVAL;
	*ops = &rawsock_ops;
	return SOCKID_RAW | (sockid_t)(raw - raw_array);
}

/*
 * Bind a raw socket to a local address.
 */
static int rawsock_bind(struct sock *sock, const struct sockaddr *addr, socklen_t addr_len, endpoint_t user_endpt)
{
    struct rawsock *raw;
    ip_addr_t ipaddr;
    err_t err;
    int r;

    if (!sock || !addr)
        return EINVAL;

    raw = (struct rawsock *)sock;

    if (rawsock_is_conn(raw))
        return EINVAL;

    r = ipsock_get_src_addr(rawsock_get_ipsock(raw), addr, addr_len, user_endpt,
                            &raw->raw_pcb->local_ip, 0, TRUE, &ipaddr, NULL);
    if (r != OK)
        return r;

    err = raw_bind(raw->raw_pcb, &ipaddr);
    return util_convert_err(err);
}

/*
 * Connect a raw socket to a remote address.
 */
static int rawsock_connect(struct sock *sock, const struct sockaddr *addr,
                          socklen_t addr_len, endpoint_t user_endpt __unused)
{
    struct rawsock *raw = (struct rawsock *)sock;
    const ip_addr_t *src_addr;
    ip_addr_t dst_addr;
    struct ifdev *ifdev = NULL;
    uint32_t ifindex = 0, ifindex2 = 0;
    err_t err;
    int r;

    if (addr_is_unspec(addr, addr_len)) {
        raw_disconnect(raw->raw_pcb);
        return OK;
    }

    r = ipsock_get_dst_addr(rawsock_get_ipsock(raw), addr, addr_len,
                            &raw->raw_pcb->local_ip, &dst_addr, NULL);
    if (r != OK)
        return r;

    if (ip_addr_isany(&raw->raw_pcb->local_ip)) {
        if (ip_addr_ismulticast(&dst_addr)) {
            ifindex = pktsock_get_ifindex(&raw->raw_pktsock);
            ifindex2 = raw_get_multicast_netif_index(raw->raw_pcb);
            if (ifindex == 0)
                ifindex = ifindex2;
            if (ifindex != 0) {
                ifdev = ifdev_get_by_index(ifindex);
                if (!ifdev)
                    return ENXIO;
            }
        }
        src_addr = ifaddr_select(&dst_addr, ifdev, NULL);
        if (!src_addr)
            return EHOSTUNREACH;
        err = raw_bind(raw->raw_pcb, src_addr);
        if (err != ERR_OK)
            return util_convert_err(err);
    }

    err = raw_connect(raw->raw_pcb, &dst_addr);
    if (err != ERR_OK)
        return util_convert_err(err);

    return OK;
}

/*
 * Perform preliminary checks on a send request.
 */
static int rawsock_pre_send(struct sock *sock, size_t len, socklen_t ctl_len __unused,
                            const struct sockaddr *addr, socklen_t addr_len __unused,
                            endpoint_t user_endpt __unused, int flags)
{
    struct rawsock *raw = (struct rawsock *)sock;

    if ((flags & ~MSG_DONTROUTE) != 0)
        return EOPNOTSUPP;

    if (!rawsock_is_conn(raw) && addr == NULL)
        return EDESTADDRREQ;

    size_t sndbuf = ipsock_get_sndbuf(rawsock_get_ipsock(raw));
    if (len > sndbuf)
        return EMSGSIZE;

    return OK;
}

/*
 * Swap IP-level options between the RAW PCB and the packet options structure,
 * for all options that have their flag set in the packet options structure.
 * This function is called twice when sending a packet.  The result is that the
 * flagged options are overridden for only the packet being sent.
 */
static void rawsock_swap_opt(struct rawsock *raw, struct pktopt *pkto)
{
    if (!raw || !raw->raw_pcb || !pkto) {
        return;
    }

    if (pkto->pkto_flags & PKTOF_TOS) {
        uint8_t temp_tos = raw->raw_pcb->tos;
        raw->raw_pcb->tos = pkto->pkto_tos;
        pkto->pkto_tos = temp_tos;
    }

    if (pkto->pkto_flags & PKTOF_TTL) {
        uint8_t orig_ttl = raw->raw_pcb->ttl;
        uint8_t orig_mcast_ttl = raw_get_multicast_ttl(raw->raw_pcb);

        raw->raw_pcb->ttl = pkto->pkto_ttl;
        raw_set_multicast_ttl(raw->raw_pcb, pkto->pkto_ttl);

        pkto->pkto_ttl = orig_ttl;
        pkto->pkto_mcast_ttl = orig_mcast_ttl;
    }
}

/*
 * We are about to send the given packet that already includes an IPv4 header,
 * because the IP_HDRINCL option is enabled on a raw IPv4 socket.  Prepare the
 * IPv4 header for sending, by modifying a few fields in it, as expected by
 * userland.
 */
static int rawsock_prepare_hdrincl(struct rawsock *raw, struct pbuf *pbuf, const ip_addr_t *src_addr)
{
	if (!raw || !pbuf || !src_addr)
		return EINVAL;

	if (pbuf->len < sizeof(struct ip_hdr))
		return EINVAL;

	struct ip_hdr *iphdr = (struct ip_hdr *)pbuf->payload;
	size_t hlen = (size_t)IPH_HL(iphdr) << 2;

	if (pbuf->len < hlen)
		return OK;

	if (iphdr->src.addr == PP_HTONL(INADDR_ANY)) {
		if (!IP_IS_V4(src_addr))
			return EINVAL;
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
rawsock_send(struct sock *sock, const struct sockdriver_data *data,
	size_t len, size_t *off, const struct sockdriver_data *ctl,
	socklen_t ctl_len, socklen_t *ctl_off,
	const struct sockaddr *addr, socklen_t addr_len,
	endpoint_t user_endpt, int flags, size_t min)
{
	struct rawsock *raw = (struct rawsock *)sock;
	struct pktopt pktopt = {0};
	struct pbuf *pbuf = NULL;
	struct ifdev *ifdev = NULL;
	struct netif *netif;
	const ip_addr_t *dst_addrp = NULL, *src_addrp = NULL;
	ip_addr_t src_addr, dst_addr;
	size_t hdrlen;
	uint32_t ifindex;
	err_t err;
	int r;

	r = pktsock_get_ctl(&raw->raw_pktsock, ctl, ctl_len, &pktopt);
	if (r != OK)
		return r;

	r = pktsock_get_pktinfo(&raw->raw_pktsock, &pktopt, &ifdev, &src_addr);
	if (r != OK)
		return r;

	if (ifdev && !ip_addr_isany(&src_addr)) {
		src_addrp = &src_addr;
	} else {
		src_addrp = &raw->raw_pcb->local_ip;
		if (ip_addr_ismulticast(src_addrp))
			src_addrp = IP46_ADDR_ANY(IP_GET_TYPE(src_addrp));
	}

	if (!rawsock_is_conn(raw)) {
		if (!addr) return EINVAL;
		r = ipsock_get_dst_addr(rawsock_get_ipsock(raw), addr, addr_len, src_addrp, &dst_addr, NULL);
		if (r != OK)
			return r;
		dst_addrp = &dst_addr;
	} else {
		dst_addrp = &raw->raw_pcb->remote_ip;
	}

	if (ifdev == NULL && ip_addr_ismulticast(dst_addrp)) {
		ifindex = raw_get_multicast_netif_index(raw->raw_pcb);
		if (ifindex != NETIF_NO_INDEX)
			ifdev = ifdev_get_by_index(ifindex);
	}

	if (ifdev && IP_IS_V6(dst_addrp)) {
		if (ifaddr_is_zone_mismatch(ip_2_ip6(dst_addrp), ifdev))
			return EHOSTUNREACH;
		if (IP_IS_V6(src_addrp) && ifaddr_is_zone_mismatch(ip_2_ip6(src_addrp), ifdev))
			return EHOSTUNREACH;
	}

	if (ifdev == NULL) {
		if (!(flags & MSG_DONTROUTE)) {
			if (IP_IS_ANY_TYPE_VAL(*src_addrp))
				src_addrp = IP46_ADDR_ANY(IP_GET_TYPE(dst_addrp));
			netif = ip_route(src_addrp, dst_addrp);
			if (!netif)
				return EHOSTUNREACH;
			ifdev = netif_get_ifdev(netif);
		} else {
			ifdev = ifaddr_map_by_subnet(dst_addrp);
			if (!ifdev)
				return EHOSTUNREACH;
		}
	}

	if (!ifdev)
		return EHOSTUNREACH;

	if (ip_addr_isany(src_addrp)) {
		src_addrp = ifaddr_select(dst_addrp, ifdev, NULL);
		if (!src_addrp)
			return EHOSTUNREACH;
	}

	if (len > RAW_MAX_PAYLOAD)
		return EMSGSIZE;

	if (rawsock_is_hdrincl(raw))
		hdrlen = 0;
	else if (IP_IS_V6(dst_addrp))
		hdrlen = IP6_HLEN;
	else
		hdrlen = IP_HLEN;

	if (hdrlen + len > RAW_MAX_PAYLOAD)
		return EMSGSIZE;

	pbuf = pchain_alloc(PBUF_IP, len);
	if (!pbuf)
		return ENOBUFS;

	r = pktsock_get_data(&raw->raw_pktsock, data, len, pbuf);
	if (r != OK) {
		pbuf_free(pbuf);
		return r;
	}

	if (raw->raw_pcb->chksum_reqd) {
		if (pbuf->len < raw->raw_pcb->chksum_offset + sizeof(uint16_t)) {
			pbuf_free(pbuf);
			return EINVAL;
		}
		memset((char *)pbuf->payload + raw->raw_pcb->chksum_offset, 0, sizeof(uint16_t));
	}

	if (rawsock_is_hdrincl(raw)) {
		r = rawsock_prepare_hdrincl(raw, pbuf, src_addrp);
		if (r != OK) {
			pbuf_free(pbuf);
			return r;
		}
	}

	if (ip_addr_ismulticast(dst_addrp))
		pbuf->flags |= PBUF_FLAG_LLMCAST;
	else if (ip_addr_isbroadcast(dst_addrp, ifdev_get_netif(ifdev)))
		pbuf->flags |= PBUF_FLAG_LLBCAST;

	rawsock_swap_opt(raw, &pktopt);

	if (ip_addr_isany(src_addrp) || ip_addr_ismulticast(src_addrp)) {
		pbuf_free(pbuf);
		return EINVAL;
	}

	err = raw_sendto_if_src(raw->raw_pcb, pbuf, dst_addrp, ifdev_get_netif(ifdev), src_addrp);

	rawsock_swap_opt(raw, &pktopt);

	pbuf_free(pbuf);

	r = util_convert_err(err);
	if (r == OK)
		*off = len;
	return r;
}

/*
 * Update the set of flag-type socket options on a raw socket.
 */
static void rawsock_setsockmask(struct sock *sock, unsigned int mask) {
    struct rawsock *raw = (struct rawsock *)sock;

    if (!raw || !raw->raw_pcb)
        return;

    if (mask & SO_BROADCAST)
        ip_set_option(raw->raw_pcb, SOF_BROADCAST);
    else
        ip_reset_option(raw->raw_pcb, SOF_BROADCAST);
}

/*
 * Prepare a helper structure for IP-level option processing.
 */
static void rawsock_get_ipopts(struct rawsock *raw, struct ipopts *ipopts) {
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
static int rawsock_setsockopt(struct sock *sock, int level, int name,
    const struct sockdriver_data *data, socklen_t len)
{
    struct rawsock *raw = (struct rawsock *)sock;
    struct ipopts ipopts;
    struct icmp6_filter filter;
    ip_addr_t ipaddr;
    struct in_addr in_addr;
    struct ifdev *ifdev;
    unsigned int flags;
    uint32_t ifindex;
    uint8_t byte;
    int r, val;

    switch (level) {
        case IPPROTO_IP:
            if (rawsock_is_ipv6(raw))
                break;

            switch (name) {
                case IP_HDRINCL:
                    r = sockdriver_copyin_opt(data, &val, sizeof(val), len);
                    if (r != OK)
                        return r;
                    flags = raw_flags(raw->raw_pcb);
                    if (val)
                        flags |= RAW_FLAGS_HDRINCL;
                    else
                        flags &= ~RAW_FLAGS_HDRINCL;
                    raw_setflags(raw->raw_pcb, flags);
                    return OK;

                case IP_MULTICAST_IF:
                    pktsock_set_mcaware(&raw->raw_pktsock);
                    r = sockdriver_copyin_opt(data, &in_addr, sizeof(in_addr), len);
                    if (r != OK)
                        return r;
                    ip_addr_set_ip4_u32(&ipaddr, in_addr.s_addr);
                    ifdev = ifaddr_map_by_addr(&ipaddr);
                    if (ifdev == NULL)
                        return EADDRNOTAVAIL;
                    raw_set_multicast_netif_index(raw->raw_pcb, ifdev_get_index(ifdev));
                    return OK;

                case IP_MULTICAST_LOOP:
                    pktsock_set_mcaware(&raw->raw_pktsock);
                    r = sockdriver_copyin_opt(data, &byte, sizeof(byte), len);
                    if (r != OK)
                        return r;
                    flags = raw_flags(raw->raw_pcb);
                    if (byte)
                        flags |= RAW_FLAGS_MULTICAST_LOOP;
                    else
                        flags &= ~RAW_FLAGS_MULTICAST_LOOP;
                    raw_setflags(raw->raw_pcb, flags);
                    return OK;

                case IP_MULTICAST_TTL:
                    pktsock_set_mcaware(&raw->raw_pktsock);
                    r = sockdriver_copyin_opt(data, &byte, sizeof(byte), len);
                    if (r != OK)
                        return r;
                    raw_set_multicast_ttl(raw->raw_pcb, byte);
                    return OK;
                default:
                    break;
            }
            break;

        case IPPROTO_IPV6:
            if (!rawsock_is_ipv6(raw))
                break;

            switch (name) {
                case IPV6_CHECKSUM:
                    if (raw->raw_pcb->protocol == IPPROTO_ICMPV6)
                        return EINVAL;
                    r = sockdriver_copyin_opt(data, &val, sizeof(val), len);
                    if (r != OK)
                        return r;
                    if (val == -1) {
                        raw->raw_pcb->chksum_reqd = 0;
                        return OK;
                    }
                    if (val >= 0 && !(val & 1)) {
                        raw->raw_pcb->chksum_reqd = 1;
                        raw->raw_pcb->chksum_offset = val;
                        return OK;
                    }
                    return EINVAL;

                case IPV6_MULTICAST_IF:
                    pktsock_set_mcaware(&raw->raw_pktsock);
                    r = sockdriver_copyin_opt(data, &val, sizeof(val), len);
                    if (r != OK)
                        return r;
                    ifindex = (val != 0) ? (uint32_t)val : NETIF_NO_INDEX;
                    if (val != 0) {
                        ifdev = ifdev_get_by_index(ifindex);
                        if (ifdev == NULL)
                            return ENXIO;
                    }
                    raw_set_multicast_netif_index(raw->raw_pcb, ifindex);
                    return OK;

                case IPV6_MULTICAST_LOOP:
                    pktsock_set_mcaware(&raw->raw_pktsock);
                    r = sockdriver_copyin_opt(data, &val, sizeof(val), len);
                    if (r != OK)
                        return r;
                    if (val < 0 || val > 1)
                        return EINVAL;
                    flags = raw_flags(raw->raw_pcb);
                    if (val)
                        flags |= RAW_FLAGS_MULTICAST_LOOP;
                    else
                        flags &= ~RAW_FLAGS_MULTICAST_LOOP;
                    raw_setflags(raw->raw_pcb, flags);
                    return OK;

                case IPV6_MULTICAST_HOPS:
                    pktsock_set_mcaware(&raw->raw_pktsock);
                    r = sockdriver_copyin_opt(data, &val, sizeof(val), len);
                    if (r != OK)
                        return r;
                    if (val < -1 || val > UINT8_MAX)
                        return EINVAL;
                    if (val == -1)
                        val = 1;
                    raw_set_multicast_ttl(raw->raw_pcb, val);
                    return OK;
                default:
                    break;
            }
            break;

        case IPPROTO_ICMPV6:
            if (!rawsock_is_ipv6(raw) || raw->raw_pcb->protocol != IPPROTO_ICMPV6)
                break;

            switch (name) {
                case ICMP6_FILTER:
                    if (len == 0) {
                        ICMP6_FILTER_SETPASSALL(&raw->raw_icmp6filter);
                        return OK;
                    }
                    r = sockdriver_copyin_opt(data, &filter, sizeof(filter), len);
                    if (r != OK)
                        return r;
                    memcpy(&raw->raw_icmp6filter, &filter, sizeof(filter));
                    return OK;
                default:
                    break;
            }
            break;

        default:
            break;
    }

    rawsock_get_ipopts(raw, &ipopts);
    return pktsock_setsockopt(&raw->raw_pktsock, level, name, data, len, &ipopts);
}


/*
 * Retrieve socket options on a raw socket.
 */
static int rawsock_getsockopt(struct sock *sock, int level, int name, const struct sockdriver_data *data, socklen_t *len) {
    struct rawsock *raw = (struct rawsock *)sock;
    struct ipopts ipopts;
    const ip4_addr_t *ip4addr = NULL;
    struct in_addr in_addr;
    struct ifdev *ifdev = NULL;
    unsigned int flags;
    uint32_t ifindex;
    uint8_t byte;
    int val;

    if (!raw || !data || !len)
        return -1;

    if (level == IPPROTO_IP && !rawsock_is_ipv6(raw)) {
        switch (name) {
            case IP_HDRINCL:
                val = rawsock_is_hdrincl(raw) ? 1 : 0;
                return sockdriver_copyout_opt(data, &val, sizeof(val), len);

            case IP_MULTICAST_IF:
                ifindex = raw_get_multicast_netif_index(raw->raw_pcb);
                if (ifindex != NETIF_NO_INDEX) {
                    ifdev = ifdev_get_by_index(ifindex);
                }
                if (ifdev) {
                    ip4addr = netif_ip4_addr(ifdev_get_netif(ifdev));
                    if (ip4addr)
                        in_addr.s_addr = ip4_addr_get_u32(ip4addr);
                    else
                        in_addr.s_addr = PP_HTONL(INADDR_ANY);
                } else {
                    in_addr.s_addr = PP_HTONL(INADDR_ANY);
                }
                return sockdriver_copyout_opt(data, &in_addr, sizeof(in_addr), len);

            case IP_MULTICAST_LOOP:
                flags = raw_flags(raw->raw_pcb);
                byte = (flags & RAW_FLAGS_MULTICAST_LOOP) ? 1 : 0;
                return sockdriver_copyout_opt(data, &byte, sizeof(byte), len);

            case IP_MULTICAST_TTL:
                byte = raw_get_multicast_ttl(raw->raw_pcb);
                return sockdriver_copyout_opt(data, &byte, sizeof(byte), len);
        }
    } else if (level == IPPROTO_IPV6 && rawsock_is_ipv6(raw)) {
        switch (name) {
            case IPV6_CHECKSUM:
                val = raw->raw_pcb->chksum_reqd ? raw->raw_pcb->chksum_offset : -1;
                return sockdriver_copyout_opt(data, &val, sizeof(val), len);

            case IPV6_MULTICAST_IF:
                ifindex = raw_get_multicast_netif_index(raw->raw_pcb);
                val = (int)ifindex;
                return sockdriver_copyout_opt(data, &val, sizeof(val), len);

            case IPV6_MULTICAST_LOOP:
                flags = raw_flags(raw->raw_pcb);
                val = (flags & RAW_FLAGS_MULTICAST_LOOP) ? 1 : 0;
                return sockdriver_copyout_opt(data, &val, sizeof(val), len);

            case IPV6_MULTICAST_HOPS:
                val = raw_get_multicast_ttl(raw->raw_pcb);
                return sockdriver_copyout_opt(data, &val, sizeof(val), len);
        }
    } else if (level == IPPROTO_ICMPV6 && rawsock_is_ipv6(raw) && raw->raw_pcb->protocol == IPPROTO_ICMPV6) {
        if (name == ICMP6_FILTER) {
            return sockdriver_copyout_opt(data, &raw->raw_icmp6filter, sizeof(raw->raw_icmp6filter), len);
        }
    }

    rawsock_get_ipopts(raw, &ipopts);
    return pktsock_getsockopt(&raw->raw_pktsock, level, name, data, len, &ipopts);
}

/*
 * Retrieve the local socket address of a raw socket.
 */
static int rawsock_getsockname(struct sock *sock, struct sockaddr *addr, socklen_t *addr_len) {
    if (!sock || !addr || !addr_len) {
        return ERR_INVALID_ARG;
    }

    struct rawsock *raw = (struct rawsock *)sock;
    if (!raw || !raw->raw_pcb) {
        return ERR_INTERNAL;
    }

    if (ipsock_put_addr(rawsock_get_ipsock(raw), addr, addr_len, &raw->raw_pcb->local_ip, 0) != 0) {
        return ERR_INTERNAL;
    }

    return OK;
}

/*
 * Retrieve the remote socket address of a raw socket.
 */
static int rawsock_getpeername(struct sock *sock, struct sockaddr *addr, socklen_t *addr_len)
{
    if (!sock || !addr || !addr_len) {
        return EINVAL;
    }

    struct rawsock *raw = (struct rawsock *)sock;

    if (!rawsock_is_conn(raw)) {
        return ENOTCONN;
    }

    int ret = ipsock_put_addr(rawsock_get_ipsock(raw), addr, addr_len, &raw->raw_pcb->remote_ip, 0);
    if (ret != OK) {
        return ret;
    }

    return OK;
}

/*
 * Shut down a raw socket for reading and/or writing.
 */
static int rawsock_shutdown(struct sock *sock, unsigned int mask)
{
    if (sock == NULL) {
        return -1;
    }

    struct rawsock *raw = (struct rawsock *)sock;

    if ((mask & SFL_SHUT_RD) != 0) {
        if (raw->raw_pcb != NULL) {
            raw_recv(raw->raw_pcb, NULL, NULL);
        }
    }

    pktsock_shutdown(&raw->raw_pktsock, mask);

    return 0;
}

/*
 * Close a raw socket.
 */
static int rawsock_close(struct sock *sock, int force)
{
    if (!sock) {
        return -1;
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
static void rawsock_free(struct sock *sock) {
    struct rawsock *raw;

    if (sock == NULL) {
        return;
    }

    raw = (struct rawsock *)sock;

    if (raw->raw_pcb != NULL) {
        return;
    }

    TAILQ_REMOVE(&raw_activelist, raw, raw_next);
    TAILQ_INSERT_HEAD(&raw_freelist, raw, raw_next);
}

/*
 * Fill the given kinfo_pcb sysctl(7) structure with information about the RAW
 * PCB identified by the given pointer.
 */
static void rawsock_get_info(struct kinfo_pcb *ki, const void *ptr)
{
    const struct raw_pcb *pcb = (const struct raw_pcb *)ptr;
    struct rawsock *raw;

    if (pcb == NULL || ki == NULL) {
        return;
    }

    raw = (struct rawsock *)pcb->recv_arg;
    if (raw < raw_array || raw >= &raw_array[__arraycount(raw_array)]) {
        return;
    }

    ki->ki_type = SOCK_RAW;
    ki->ki_protocol = pcb->protocol;

    ipsock_get_info(ki, &pcb->local_ip, 0, &raw->raw_pcb->remote_ip, 0);

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
rawsock_enum(const void *last)
{
    const struct raw_pcb *pcb;
    struct rawsock *raw = NULL;

    if (last) {
        pcb = (const struct raw_pcb *)last;

        raw = (struct rawsock *)pcb->recv_arg;
        if (raw < raw_array || raw >= &raw_array[__arraycount(raw_array)]) {
            return NULL;
        }

        raw = TAILQ_NEXT(raw, raw_next);
    } else {
        raw = TAILQ_FIRST(&raw_activelist);
    }

    return raw ? (const void *)raw->raw_pcb : NULL;
}

/*
 * Obtain the list of RAW protocol control blocks, for sysctl(7).
 */
static ssize_t rawsock_pcblist(struct rmib_call *call, struct rmib_node *node, struct rmib_oldp *oldp, struct rmib_newp *newp)
{
	if (!call || !oldp) {
		return -1;
	}
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
