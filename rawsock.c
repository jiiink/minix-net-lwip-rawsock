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
	initialize_free_list();
	initialize_active_list();
	register_mib_subtrees();
}

static void
initialize_free_list(void)
{
	unsigned int slot;

	TAILQ_INIT(&raw_freelist);

	for (slot = 0; slot < __arraycount(raw_array); slot++)
		TAILQ_INSERT_TAIL(&raw_freelist, &raw_array[slot], raw_next);
}

static void
initialize_active_list(void)
{
	TAILQ_INIT(&raw_activelist);
}

static void
register_mib_subtrees(void)
{
	mibtree_register_inet(PF_INET, IPPROTO_RAW, &net_inet_raw_node);
	mibtree_register_inet(PF_INET6, IPPROTO_RAW, &net_inet6_raw6_node);
}

/*
 * Check whether the given arrived IPv6 packet is fit to be received on the
 * given raw socket.
 */
static int is_icmpv6_packet_too_small(struct pbuf *pbuf)
{
    return pbuf->len < offsetof(struct icmp6_hdr, icmp6_dataun);
}

static int is_icmpv6_type_filtered(struct rawsock *raw, struct pbuf *pbuf)
{
    uint8_t type;
    
    memcpy(&type, &((struct icmp6_hdr *)pbuf->payload)->icmp6_type,
        sizeof(type));
    
    return !ICMP6_FILTER_WILLPASS((int)type, &raw->raw_icmp6filter);
}

static int should_filter_icmpv6(struct rawsock *raw, struct pbuf *pbuf)
{
    if (raw->raw_pcb->protocol != IPPROTO_ICMPV6)
        return FALSE;
    
    if (is_icmpv6_packet_too_small(pbuf))
        return TRUE;
    
    return is_icmpv6_type_filtered(raw, pbuf);
}

static int is_checksum_invalid(struct raw_pcb *pcb, struct pbuf *pbuf)
{
    if (pbuf->tot_len < pcb->chksum_offset + sizeof(uint16_t))
        return TRUE;
    
    return ip6_chksum_pseudo(pbuf, pcb->protocol, pbuf->tot_len,
        ip6_current_src_addr(), ip6_current_dest_addr()) != 0;
}

static int should_verify_checksum(struct rawsock *raw, struct pbuf *pbuf)
{
    if (!raw->raw_pcb->chksum_reqd)
        return FALSE;
    
    return is_checksum_invalid(raw->raw_pcb, pbuf);
}

static int
rawsock_check_v6(struct rawsock *raw, struct pbuf *pbuf)
{
    assert(rawsock_is_ipv6(raw));
    
    if (should_filter_icmpv6(raw, pbuf))
        return FALSE;
    
    if (should_verify_checksum(raw, pbuf))
        return FALSE;
    
    return TRUE;
}

/*
 * Adjust the given arrived IPv4 packet by changing the length and offset
 * fields to host-byte order, as is done by the BSDs.  This effectively mirrors
 * the swapping part of the preparation done on IPv4 packets being sent if the
 * IP_HDRINCL socket option is enabled.
 */
static void swap_ip_header_fields(struct ip_hdr *iphdr)
{
    IPH_LEN(iphdr) = htons(IPH_LEN(iphdr));
    IPH_OFFSET(iphdr) = htons(IPH_OFFSET(iphdr));
}

static void rawsock_adjust_v4(struct pbuf * pbuf)
{
    if (pbuf->len < sizeof(struct ip_hdr))
        return;

    struct ip_hdr *iphdr = (struct ip_hdr *)pbuf->payload;
    swap_ip_header_fields(iphdr);
}

/*
 * A packet has arrived on a raw socket.  Since the same packet may have to be
 * delivered to multiple raw sockets, we always return 0 (= not consumed) from
 * this function.  As such, we must make a copy of the given packet if we want
 * to keep it, and never free it.
 */
static uint8_t
restore_header_if_needed(struct pbuf *psrc, int off)
{
	if (off > 0)
		util_pbuf_header(psrc, off);
	return 0;
}

static int
validate_input_buffer(struct rawsock *raw, struct pbuf *psrc)
{
	int hdrlen = pktsock_test_input(&raw->raw_pktsock, psrc);
	if (hdrlen < 0)
		return -1;
	return hdrlen;
}

static int
process_ipv6_packet(struct rawsock *raw, struct pbuf *psrc)
{
	int off = ip_current_header_tot_len();
	util_pbuf_header(psrc, -off);

	if (!rawsock_check_v6(raw, psrc)) {
		util_pbuf_header(psrc, off);
		return -1;
	}
	return off;
}

static int
process_ipv4_packet_on_ipv6_socket(struct rawsock *raw)
{
	if (raw->raw_pcb->chksum_reqd)
		return -1;
	return IP_HLEN;
}

static int
determine_header_offset(struct rawsock *raw, struct pbuf *psrc)
{
	if (ip_current_is_v6())
		return process_ipv6_packet(raw, psrc);

	if (rawsock_is_ipv6(raw))
		return process_ipv4_packet_on_ipv6_socket(raw);

	return 0;
}

static struct pbuf *
create_packet_copy(struct pbuf *psrc, int hdrlen)
{
	struct pbuf *pbuf = pchain_alloc(PBUF_RAW, hdrlen + psrc->tot_len);
	if (pbuf == NULL)
		return NULL;

	util_pbuf_header(pbuf, -hdrlen);

	if (pbuf_copy(pbuf, psrc) != ERR_OK)
		panic("unexpected pbuf copy failure");

	pbuf->flags |= psrc->flags & (PBUF_FLAG_LLMCAST | PBUF_FLAG_LLBCAST);
	return pbuf;
}

static void
adjust_header_for_ipv4(struct rawsock *raw, struct pbuf *psrc, int off)
{
	if (off > 0 && rawsock_is_ipv6(raw))
		util_pbuf_header(psrc, -off);
}

static uint8_t
rawsock_input(void * arg, struct raw_pcb * pcb __unused, struct pbuf * psrc,
	const ip_addr_t * srcaddr)
{
	struct rawsock *raw = (struct rawsock *)arg;
	struct pbuf *pbuf;
	int off, hdrlen;

	assert(raw->raw_pcb == pcb);

	hdrlen = validate_input_buffer(raw, psrc);
	if (hdrlen < 0)
		return 0;

	off = determine_header_offset(raw, psrc);
	if (off < 0)
		return 0;

	adjust_header_for_ipv4(raw, psrc, off);

	pbuf = create_packet_copy(psrc, hdrlen);
	if (pbuf == NULL)
		return restore_header_if_needed(psrc, off);

	if (off > 0)
		util_pbuf_header(psrc, off);

	if (!rawsock_is_ipv6(raw))
		rawsock_adjust_v4(pbuf);

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
	struct rawsock *raw;
	uint8_t ip_type;

	if (protocol < 0 || protocol > UINT8_MAX)
		return EPROTONOSUPPORT;

	if (TAILQ_EMPTY(&raw_freelist))
		return ENOBUFS;

	raw = TAILQ_FIRST(&raw_freelist);

	ip_type = pktsock_socket(&raw->raw_pktsock, domain, RAW_SNDBUF_DEF,
	    RAW_RCVBUF_DEF, sockp);

	if (rawsock_init_pcb(raw, ip_type, protocol) != 0)
		return ENOBUFS;

	rawsock_configure_multicast(raw);

	if (rawsock_is_ipv6(raw) && protocol == IPPROTO_ICMPV6)
		rawsock_setup_icmpv6(raw);
	else
		raw->raw_pcb->chksum_reqd = 0;

	rawsock_activate(raw);

	*ops = &rawsock_ops;
	return SOCKID_RAW | (sockid_t)(raw - raw_array);
}

static int
rawsock_init_pcb(struct rawsock *raw, uint8_t ip_type, int protocol)
{
	raw->raw_pcb = raw_new_ip_type(ip_type, protocol);
	if (raw->raw_pcb == NULL)
		return -1;
	
	raw_recv(raw->raw_pcb, rawsock_input, (void *)raw);
	return 0;
}

static void
rawsock_configure_multicast(struct rawsock *raw)
{
	unsigned int flags;
	
	raw_set_multicast_ttl(raw->raw_pcb, 1);
	flags = raw_flags(raw->raw_pcb);
	raw_setflags(raw->raw_pcb, flags | RAW_FLAGS_MULTICAST_LOOP);
}

static void
rawsock_setup_icmpv6(struct rawsock *raw)
{
	raw->raw_pcb->chksum_reqd = 1;
	raw->raw_pcb->chksum_offset = offsetof(struct icmp6_hdr, icmp6_cksum);
	ICMP6_FILTER_SETPASSALL(&raw->raw_icmp6filter);
}

static void
rawsock_activate(struct rawsock *raw)
{
	TAILQ_REMOVE(&raw_freelist, raw, raw_next);
	TAILQ_INSERT_TAIL(&raw_activelist, raw, raw_next);
}

/*
 * Bind a raw socket to a local address.
 */
static int validate_connection_state(struct rawsock *raw)
{
	if (rawsock_is_conn(raw))
		return EINVAL;
	return OK;
}

static int get_binding_address(struct rawsock *raw, const struct sockaddr *addr,
	socklen_t addr_len, endpoint_t user_endpt, ip_addr_t *ipaddr)
{
	return ipsock_get_src_addr(rawsock_get_ipsock(raw), addr, addr_len,
	    user_endpt, &raw->raw_pcb->local_ip, 0,
	    TRUE, ipaddr, NULL);
}

static int
rawsock_bind(struct sock *sock, const struct sockaddr *addr,
	socklen_t addr_len, endpoint_t user_endpt)
{
	struct rawsock *raw = (struct rawsock *)sock;
	ip_addr_t ipaddr;
	err_t err;
	int r;

	r = validate_connection_state(raw);
	if (r != OK)
		return r;

	r = get_binding_address(raw, addr, addr_len, user_endpt, &ipaddr);
	if (r != OK)
		return r;

	err = raw_bind(raw->raw_pcb, &ipaddr);

	return util_convert_err(err);
}

/*
 * Connect a raw socket to a remote address.
 */
static int handle_unspec_address(struct rawsock *raw, const struct sockaddr *addr, socklen_t addr_len)
{
    if (addr_is_unspec(addr, addr_len)) {
        raw_disconnect(raw->raw_pcb);
        return OK;
    }
    return -1;
}

static struct ifdev* get_multicast_interface(struct rawsock *raw, const ip_addr_t *dst_addr)
{
    uint32_t ifindex, ifindex2;
    
    if (!ip_addr_ismulticast(dst_addr))
        return NULL;
    
    ifindex = pktsock_get_ifindex(&raw->raw_pktsock);
    ifindex2 = raw_get_multicast_netif_index(raw->raw_pcb);
    
    if (ifindex == 0)
        ifindex = ifindex2;
    
    if (ifindex != 0)
        return ifdev_get_by_index(ifindex);
    
    return NULL;
}

static int bind_to_source_address(struct rawsock *raw, const ip_addr_t *dst_addr)
{
    const ip_addr_t *src_addr;
    struct ifdev *ifdev;
    err_t err;
    
    if (!ip_addr_isany(&raw->raw_pcb->local_ip))
        return OK;
    
    ifdev = get_multicast_interface(raw, dst_addr);
    
    if (ifdev != NULL && ifdev_get_by_index(pktsock_get_ifindex(&raw->raw_pktsock)) == NULL)
        return ENXIO;
    
    src_addr = ifaddr_select(dst_addr, ifdev, NULL);
    
    if (src_addr == NULL)
        return EHOSTUNREACH;
    
    err = raw_bind(raw->raw_pcb, src_addr);
    
    if (err != ERR_OK)
        return util_convert_err(err);
    
    return OK;
}

static int
rawsock_connect(struct sock * sock, const struct sockaddr * addr,
    socklen_t addr_len, endpoint_t user_endpt __unused)
{
    struct rawsock *raw = (struct rawsock *)sock;
    ip_addr_t dst_addr;
    err_t err;
    int r;
    
    r = handle_unspec_address(raw, addr, addr_len);
    if (r >= 0)
        return r;
    
    r = ipsock_get_dst_addr(rawsock_get_ipsock(raw), addr, addr_len,
        &raw->raw_pcb->local_ip, &dst_addr, NULL);
    if (r != OK)
        return r;
    
    r = bind_to_source_address(raw, &dst_addr);
    if (r != OK)
        return r;
    
    err = raw_connect(raw->raw_pcb, &dst_addr);
    
    if (err != ERR_OK)
        return util_convert_err(err);
    
    return OK;
}

/*
 * Perform preliminary checks on a send request.
 */
static int validate_flags(int flags)
{
	if ((flags & ~MSG_DONTROUTE) != 0)
		return EOPNOTSUPP;
	return OK;
}

static int validate_destination(struct rawsock *raw, const struct sockaddr *addr)
{
	if (!rawsock_is_conn(raw) && addr == NULL)
		return EDESTADDRREQ;
	return OK;
}

static int validate_buffer_size(struct rawsock *raw, size_t len)
{
	if (len > ipsock_get_sndbuf(rawsock_get_ipsock(raw)))
		return EMSGSIZE;
	return OK;
}

static int
rawsock_pre_send(struct sock * sock, size_t len, socklen_t ctl_len __unused,
	const struct sockaddr * addr, socklen_t addr_len __unused,
	endpoint_t user_endpt __unused, int flags)
{
	struct rawsock *raw = (struct rawsock *)sock;
	int result;

	result = validate_flags(flags);
	if (result != OK)
		return result;

	result = validate_destination(raw, addr);
	if (result != OK)
		return result;

	return validate_buffer_size(raw, len);
}

/*
 * Swap IP-level options between the RAW PCB and the packet options structure,
 * for all options that have their flag set in the packet options structure.
 * This function is called twice when sending a packet.  The result is that the
 * flagged options are overridden for only the packet being sent.
 */
static void swap_tos(struct rawsock * raw, struct pktopt * pkto)
{
	uint8_t tos = raw->raw_pcb->tos;
	raw->raw_pcb->tos = pkto->pkto_tos;
	pkto->pkto_tos = tos;
}

static void swap_ttl(struct rawsock * raw, struct pktopt * pkto)
{
	uint8_t ttl = raw->raw_pcb->ttl;
	uint8_t mcast_ttl = raw_get_multicast_ttl(raw->raw_pcb);
	raw->raw_pcb->ttl = pkto->pkto_ttl;
	raw_set_multicast_ttl(raw->raw_pcb, pkto->pkto_ttl);
	pkto->pkto_ttl = ttl;
	pkto->pkto_mcast_ttl = mcast_ttl;
}

static void
rawsock_swap_opt(struct rawsock * raw, struct pktopt * pkto)
{
	if (pkto->pkto_flags & PKTOF_TOS) {
		swap_tos(raw, pkto);
	}

	if (pkto->pkto_flags & PKTOF_TTL) {
		swap_ttl(raw, pkto);
	}
}

/*
 * We are about to send the given packet that already includes an IPv4 header,
 * because the IP_HDRINCL option is enabled on a raw IPv4 socket.  Prepare the
 * IPv4 header for sending, by modifying a few fields in it, as expected by
 * userland.
 */
static int validate_ip_header(struct pbuf *pbuf)
{
    if (pbuf->len < sizeof(struct ip_hdr))
        return EINVAL;
    return OK;
}

static void set_source_address_if_blank(struct ip_hdr *iphdr, const ip_addr_t *src_addr)
{
    if (iphdr->src.addr == PP_HTONL(INADDR_ANY)) {
        assert(IP_IS_V4(src_addr));
        iphdr->src.addr = ip_addr_get_ip4_u32(src_addr);
    }
}

static void prepare_ip_header_fields(struct ip_hdr *iphdr, size_t hlen)
{
    IPH_LEN(iphdr) = htons(IPH_LEN(iphdr));
    IPH_OFFSET(iphdr) = htons(IPH_OFFSET(iphdr));
    IPH_CHKSUM(iphdr) = 0;
    IPH_CHKSUM(iphdr) = inet_chksum(iphdr, hlen);
}

static int rawsock_prepare_hdrincl(struct rawsock *raw, struct pbuf *pbuf,
    const ip_addr_t *src_addr)
{
    struct ip_hdr *iphdr;
    size_t hlen;
    int result;

    result = validate_ip_header(pbuf);
    if (result != OK)
        return result;

    iphdr = (struct ip_hdr *)pbuf->payload;
    hlen = (size_t)IPH_HL(iphdr) << 2;

    if (pbuf->len >= hlen) {
        set_source_address_if_blank(iphdr, src_addr);
        prepare_ip_header_fields(iphdr, hlen);
    }

    return OK;
}

/*
 * Send a packet on a raw socket.
 */
static int validate_send_parameters(struct rawsock *raw, size_t len, size_t hdrlen)
{
	if (hdrlen + len > RAW_MAX_PAYLOAD)
		return EMSGSIZE;
	return OK;
}

static int setup_source_address(struct rawsock *raw, struct pktopt *pktopt,
	struct ifdev **ifdev, ip_addr_t *src_addr, const ip_addr_t **src_addrp)
{
	int r;

	if ((r = pktsock_get_pktinfo(&raw->raw_pktsock, pktopt, ifdev,
	    src_addr)) != OK)
		return r;

	if (*ifdev != NULL && !ip_addr_isany(src_addr)) {
		*src_addrp = src_addr;
	} else {
		*src_addrp = &raw->raw_pcb->local_ip;

		if (ip_addr_ismulticast(*src_addrp))
			*src_addrp = IP46_ADDR_ANY(IP_GET_TYPE(*src_addrp));
	}
	return OK;
}

static int setup_destination_address(struct rawsock *raw, const struct sockaddr *addr,
	socklen_t addr_len, const ip_addr_t *src_addrp, ip_addr_t *dst_addr,
	const ip_addr_t **dst_addrp)
{
	int r;

	if (!rawsock_is_conn(raw)) {
		assert(addr != NULL);

		if ((r = ipsock_get_dst_addr(rawsock_get_ipsock(raw), addr,
		    addr_len, src_addrp, dst_addr, NULL)) != OK)
			return r;

		*dst_addrp = dst_addr;
	} else {
		*dst_addrp = &raw->raw_pcb->remote_ip;
	}
	return OK;
}

static void setup_multicast_interface(struct rawsock *raw, struct ifdev **ifdev,
	const ip_addr_t *dst_addrp)
{
	uint32_t ifindex;

	if (*ifdev == NULL && ip_addr_ismulticast(dst_addrp)) {
		ifindex = raw_get_multicast_netif_index(raw->raw_pcb);

		if (ifindex != NETIF_NO_INDEX)
			*ifdev = ifdev_get_by_index(ifindex);
	}
}

static int check_zone_violations(struct ifdev *ifdev, const ip_addr_t *dst_addrp,
	const ip_addr_t *src_addrp)
{
	if (ifdev != NULL && IP_IS_V6(dst_addrp)) {
		if (ifaddr_is_zone_mismatch(ip_2_ip6(dst_addrp), ifdev))
			return EHOSTUNREACH;

		if (IP_IS_V6(src_addrp) &&
		    ifaddr_is_zone_mismatch(ip_2_ip6(src_addrp), ifdev))
			return EHOSTUNREACH;
	}
	return OK;
}

static int perform_route_lookup(struct ifdev **ifdev, const ip_addr_t **src_addrp,
	const ip_addr_t *dst_addrp, int flags)
{
	struct netif *netif;

	if (*ifdev == NULL) {
		if (!(flags & MSG_DONTROUTE)) {
			if (IP_IS_ANY_TYPE_VAL(**src_addrp))
				*src_addrp = IP46_ADDR_ANY(IP_GET_TYPE(dst_addrp));

			if ((netif = ip_route(*src_addrp, dst_addrp)) == NULL)
				return EHOSTUNREACH;

			*ifdev = netif_get_ifdev(netif);
		} else {
			if ((*ifdev = ifaddr_map_by_subnet(dst_addrp)) == NULL)
				return EHOSTUNREACH;
		}
	}
	return OK;
}

static int finalize_source_address(const ip_addr_t **src_addrp,
	const ip_addr_t *dst_addrp, struct ifdev *ifdev)
{
	assert(ifdev != NULL);

	if (ip_addr_isany(*src_addrp)) {
		*src_addrp = ifaddr_select(dst_addrp, ifdev, NULL);

		if (*src_addrp == NULL)
			return EHOSTUNREACH;
	}
	return OK;
}

static size_t calculate_header_length(struct rawsock *raw, const ip_addr_t *dst_addrp)
{
	if (rawsock_is_hdrincl(raw))
		return 0;
	else if (IP_IS_V6(dst_addrp))
		return IP6_HLEN;
	else
		return IP_HLEN;
}

static int prepare_checksum(struct rawsock *raw, struct pbuf *pbuf)
{
	if (raw->raw_pcb->chksum_reqd) {
		if (pbuf->len < raw->raw_pcb->chksum_offset + sizeof(uint16_t))
			return EINVAL;

		memset((char *)pbuf->payload + raw->raw_pcb->chksum_offset, 0,
		    sizeof(uint16_t));
	}
	return OK;
}

static void set_packet_flags(struct pbuf *pbuf, const ip_addr_t *dst_addrp,
	struct ifdev *ifdev)
{
	if (ip_addr_ismulticast(dst_addrp))
		pbuf->flags |= PBUF_FLAG_LLMCAST;
	else if (ip_addr_isbroadcast(dst_addrp, ifdev_get_netif(ifdev)))
		pbuf->flags |= PBUF_FLAG_LLBCAST;
}

static int allocate_and_fill_pbuf(struct rawsock *raw,
	const struct sockdriver_data *data, size_t len,
	const ip_addr_t *src_addrp, struct pbuf **pbuf_out)
{
	struct pbuf *pbuf;
	int r;

	if ((pbuf = pchain_alloc(PBUF_IP, len)) == NULL)
		return ENOBUFS;

	if ((r = pktsock_get_data(&raw->raw_pktsock, data, len, pbuf)) != OK) {
		pbuf_free(pbuf);
		return r;
	}

	if ((r = prepare_checksum(raw, pbuf)) != OK) {
		pbuf_free(pbuf);
		return r;
	}

	if (rawsock_is_hdrincl(raw) &&
	    (r = rawsock_prepare_hdrincl(raw, pbuf, src_addrp)) != OK) {
		pbuf_free(pbuf);
		return r;
	}

	*pbuf_out = pbuf;
	return OK;
}

static int
rawsock_send(struct sock * sock, const struct sockdriver_data * data,
	size_t len, size_t * off, const struct sockdriver_data * ctl __unused,
	socklen_t ctl_len __unused, socklen_t * ctl_off __unused,
	const struct sockaddr * addr, socklen_t addr_len,
	endpoint_t user_endpt __unused, int flags, size_t min __unused)
{
	struct rawsock *raw = (struct rawsock *)sock;
	struct pktopt pktopt;
	struct pbuf *pbuf;
	struct ifdev *ifdev;
	const ip_addr_t *dst_addrp, *src_addrp;
	ip_addr_t src_addr, dst_addr;
	size_t hdrlen;
	err_t err;
	int r;

	pktopt.pkto_flags = 0;

	if ((r = pktsock_get_ctl(&raw->raw_pktsock, ctl, ctl_len,
	    &pktopt)) != OK)
		return r;

	if ((r = setup_source_address(raw, &pktopt, &ifdev, &src_addr,
	    &src_addrp)) != OK)
		return r;

	if ((r = setup_destination_address(raw, addr, addr_len, src_addrp,
	    &dst_addr, &dst_addrp)) != OK)
		return r;

	setup_multicast_interface(raw, &ifdev, dst_addrp);

	if ((r = check_zone_violations(ifdev, dst_addrp, src_addrp)) != OK)
		return r;

	if ((r = perform_route_lookup(&ifdev, &src_addrp, dst_addrp,
	    flags)) != OK)
		return r;

	if ((r = finalize_source_address(&src_addrp, dst_addrp, ifdev)) != OK)
		return r;

	assert(len <= RAW_MAX_PAYLOAD);

	hdrlen = calculate_header_length(raw, dst_addrp);

	if ((r = validate_send_parameters(raw, len, hdrlen)) != OK)
		return r;

	if ((r = allocate_and_fill_pbuf(raw, data, len, src_addrp,
	    &pbuf)) != OK)
		return r;

	set_packet_flags(pbuf, dst_addrp, ifdev);

	rawsock_swap_opt(raw, &pktopt);

	assert(!ip_addr_isany(src_addrp));
	assert(!ip_addr_ismulticast(src_addrp));

	err = raw_sendto_if_src(raw->raw_pcb, pbuf, dst_addrp,
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
rawsock_setsockmask(struct sock * sock, unsigned int mask)
{
	struct rawsock *raw = (struct rawsock *)sock;

	if (mask & SO_BROADCAST)
		ip_set_option(raw->raw_pcb, SOF_BROADCAST);
	else
		ip_reset_option(raw->raw_pcb, SOF_BROADCAST);
}

/*
 * Prepare a helper structure for IP-level option processing.
 */
static void
rawsock_get_ipopts(struct rawsock * raw, struct ipopts * ipopts)
{
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
static int copy_and_validate_int(const struct sockdriver_data *data, socklen_t len, int *val)
{
	return sockdriver_copyin_opt(data, val, sizeof(*val), len);
}

static int copy_and_validate_byte(const struct sockdriver_data *data, socklen_t len, uint8_t *byte)
{
	return sockdriver_copyin_opt(data, byte, sizeof(*byte), len);
}

static void update_raw_flags(struct raw_pcb *pcb, unsigned int flag, int enable)
{
	unsigned int flags = raw_flags(pcb);
	
	if (enable)
		flags |= flag;
	else
		flags &= ~flag;
	
	raw_setflags(pcb, flags);
}

static int handle_ip_hdrincl(struct rawsock *raw, const struct sockdriver_data *data, socklen_t len)
{
	int val, r;
	
	if ((r = copy_and_validate_int(data, len, &val)) != OK)
		return r;
	
	update_raw_flags(raw->raw_pcb, RAW_FLAGS_HDRINCL, val);
	return OK;
}

static int handle_ip_multicast_if(struct rawsock *raw, const struct sockdriver_data *data, socklen_t len)
{
	struct in_addr in_addr;
	ip_addr_t ipaddr;
	struct ifdev *ifdev;
	int r;
	
	pktsock_set_mcaware(&raw->raw_pktsock);
	
	if ((r = sockdriver_copyin_opt(data, &in_addr, sizeof(in_addr), len)) != OK)
		return r;
	
	ip_addr_set_ip4_u32(&ipaddr, in_addr.s_addr);
	
	if ((ifdev = ifaddr_map_by_addr(&ipaddr)) == NULL)
		return EADDRNOTAVAIL;
	
	raw_set_multicast_netif_index(raw->raw_pcb, ifdev_get_index(ifdev));
	return OK;
}

static int handle_multicast_loop(struct rawsock *raw, const struct sockdriver_data *data, socklen_t len, int is_ipv6)
{
	uint8_t byte;
	int val, r;
	
	pktsock_set_mcaware(&raw->raw_pktsock);
	
	if (!is_ipv6) {
		if ((r = copy_and_validate_byte(data, len, &byte)) != OK)
			return r;
		val = byte;
	} else {
		if ((r = copy_and_validate_int(data, len, &val)) != OK)
			return r;
		if (val < 0 || val > 1)
			return EINVAL;
	}
	
	update_raw_flags(raw->raw_pcb, RAW_FLAGS_MULTICAST_LOOP, val);
	return OK;
}

static int handle_multicast_ttl(struct rawsock *raw, const struct sockdriver_data *data, socklen_t len)
{
	uint8_t byte;
	int r;
	
	pktsock_set_mcaware(&raw->raw_pktsock);
	
	if ((r = copy_and_validate_byte(data, len, &byte)) != OK)
		return r;
	
	raw_set_multicast_ttl(raw->raw_pcb, byte);
	return OK;
}

static int handle_ipv6_checksum(struct rawsock *raw, const struct sockdriver_data *data, socklen_t len)
{
	int val, r;
	
	if (raw->raw_pcb->protocol == IPPROTO_ICMPV6)
		return EINVAL;
	
	if ((r = copy_and_validate_int(data, len, &val)) != OK)
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
}

static int handle_ipv6_multicast_if(struct rawsock *raw, const struct sockdriver_data *data, socklen_t len)
{
	struct ifdev *ifdev;
	uint32_t ifindex;
	int val, r;
	
	pktsock_set_mcaware(&raw->raw_pktsock);
	
	if ((r = copy_and_validate_int(data, len, &val)) != OK)
		return r;
	
	if (val != 0) {
		ifindex = (uint32_t)val;
		ifdev = ifdev_get_by_index(ifindex);
		if (ifdev == NULL)
			return ENXIO;
	} else {
		ifindex = NETIF_NO_INDEX;
	}
	
	raw_set_multicast_netif_index(raw->raw_pcb, ifindex);
	return OK;
}

static int handle_ipv6_multicast_hops(struct rawsock *raw, const struct sockdriver_data *data, socklen_t len)
{
	int val, r;
	
	pktsock_set_mcaware(&raw->raw_pktsock);
	
	if ((r = copy_and_validate_int(data, len, &val)) != OK)
		return r;
	
	if (val < -1 || val > UINT8_MAX)
		return EINVAL;
	
	if (val == -1)
		val = 1;
	
	raw_set_multicast_ttl(raw->raw_pcb, val);
	return OK;
}

static int handle_icmp6_filter(struct rawsock *raw, const struct sockdriver_data *data, socklen_t len)
{
	struct icmp6_filter filter;
	int r;
	
	if (len == 0) {
		ICMP6_FILTER_SETPASSALL(&raw->raw_icmp6filter);
		return OK;
	}
	
	if ((r = sockdriver_copyin_opt(data, &filter, sizeof(filter), len)) != OK)
		return r;
	
	memcpy(&raw->raw_icmp6filter, &filter, sizeof(filter));
	return OK;
}

static int handle_ip_options(struct rawsock *raw, int name, const struct sockdriver_data *data, socklen_t len)
{
	switch (name) {
	case IP_HDRINCL:
		return handle_ip_hdrincl(raw, data, len);
	case IP_MULTICAST_IF:
		return handle_ip_multicast_if(raw, data, len);
	case IP_MULTICAST_LOOP:
		return handle_multicast_loop(raw, data, len, 0);
	case IP_MULTICAST_TTL:
		return handle_multicast_ttl(raw, data, len);
	}
	return -1;
}

static int handle_ipv6_options(struct rawsock *raw, int name, const struct sockdriver_data *data, socklen_t len)
{
	switch (name) {
	case IPV6_CHECKSUM:
		return handle_ipv6_checksum(raw, data, len);
	case IPV6_MULTICAST_IF:
		return handle_ipv6_multicast_if(raw, data, len);
	case IPV6_MULTICAST_LOOP:
		return handle_multicast_loop(raw, data, len, 1);
	case IPV6_MULTICAST_HOPS:
		return handle_ipv6_multicast_hops(raw, data, len);
	}
	return -1;
}

static int rawsock_setsockopt(struct sock *sock, int level, int name,
	const struct sockdriver_data *data, socklen_t len)
{
	struct rawsock *raw = (struct rawsock *)sock;
	struct ipopts ipopts;
	int result;
	
	if (level == IPPROTO_IP && !rawsock_is_ipv6(raw)) {
		result = handle_ip_options(raw, name, data, len);
		if (result >= 0)
			return result;
	}
	
	if (level == IPPROTO_IPV6 && rawsock_is_ipv6(raw)) {
		result = handle_ipv6_options(raw, name, data, len);
		if (result >= 0)
			return result;
	}
	
	if (level == IPPROTO_ICMPV6 && rawsock_is_ipv6(raw) &&
	    raw->raw_pcb->protocol == IPPROTO_ICMPV6 && name == ICMP6_FILTER) {
		return handle_icmp6_filter(raw, data, len);
	}
	
	rawsock_get_ipopts(raw, &ipopts);
	return pktsock_setsockopt(&raw->raw_pktsock, level, name, data, len, &ipopts);
}

/*
 * Retrieve socket options on a raw socket.
 */
static int get_ip_hdrincl(struct rawsock *raw, const struct sockdriver_data *data, socklen_t *len)
{
	int val = !!rawsock_is_hdrincl(raw);
	return sockdriver_copyout_opt(data, &val, sizeof(val), len);
}

static int get_ip_multicast_if(struct rawsock *raw, const struct sockdriver_data *data, socklen_t *len)
{
	uint32_t ifindex = raw_get_multicast_netif_index(raw->raw_pcb);
	struct ifdev *ifdev;
	const ip4_addr_t *ip4addr;
	struct in_addr in_addr;

	if (ifindex != NETIF_NO_INDEX && (ifdev = ifdev_get_by_index(ifindex)) != NULL) {
		ip4addr = netif_ip4_addr(ifdev_get_netif(ifdev));
		in_addr.s_addr = ip4_addr_get_u32(ip4addr);
	} else {
		in_addr.s_addr = PP_HTONL(INADDR_ANY);
	}

	return sockdriver_copyout_opt(data, &in_addr, sizeof(in_addr), len);
}

static int get_multicast_loop(struct rawsock *raw, const struct sockdriver_data *data, socklen_t *len, int is_ipv6)
{
	unsigned int flags = raw_flags(raw->raw_pcb);
	
	if (is_ipv6) {
		int val = !!(flags & RAW_FLAGS_MULTICAST_LOOP);
		return sockdriver_copyout_opt(data, &val, sizeof(val), len);
	} else {
		uint8_t byte = !!(flags & RAW_FLAGS_MULTICAST_LOOP);
		return sockdriver_copyout_opt(data, &byte, sizeof(byte), len);
	}
}

static int get_multicast_ttl(struct rawsock *raw, const struct sockdriver_data *data, socklen_t *len, int is_ipv6)
{
	if (is_ipv6) {
		int val = raw_get_multicast_ttl(raw->raw_pcb);
		return sockdriver_copyout_opt(data, &val, sizeof(val), len);
	} else {
		uint8_t byte = raw_get_multicast_ttl(raw->raw_pcb);
		return sockdriver_copyout_opt(data, &byte, sizeof(byte), len);
	}
}

static int get_ipv6_checksum(struct rawsock *raw, const struct sockdriver_data *data, socklen_t *len)
{
	int val = raw->raw_pcb->chksum_reqd ? raw->raw_pcb->chksum_offset : -1;
	return sockdriver_copyout_opt(data, &val, sizeof(val), len);
}

static int get_ipv6_multicast_if(struct rawsock *raw, const struct sockdriver_data *data, socklen_t *len)
{
	uint32_t ifindex = raw_get_multicast_netif_index(raw->raw_pcb);
	int val = (int)ifindex;
	return sockdriver_copyout_opt(data, &val, sizeof(val), len);
}

static int handle_ipv4_options(struct rawsock *raw, int name, const struct sockdriver_data *data, socklen_t *len)
{
	switch (name) {
	case IP_HDRINCL:
		return get_ip_hdrincl(raw, data, len);
	case IP_MULTICAST_IF:
		return get_ip_multicast_if(raw, data, len);
	case IP_MULTICAST_LOOP:
		return get_multicast_loop(raw, data, len, 0);
	case IP_MULTICAST_TTL:
		return get_multicast_ttl(raw, data, len, 0);
	}
	return -1;
}

static int handle_ipv6_options(struct rawsock *raw, int name, const struct sockdriver_data *data, socklen_t *len)
{
	switch (name) {
	case IPV6_CHECKSUM:
		return get_ipv6_checksum(raw, data, len);
	case IPV6_MULTICAST_IF:
		return get_ipv6_multicast_if(raw, data, len);
	case IPV6_MULTICAST_LOOP:
		return get_multicast_loop(raw, data, len, 1);
	case IPV6_MULTICAST_HOPS:
		return get_multicast_ttl(raw, data, len, 1);
	}
	return -1;
}

static int handle_icmpv6_options(struct rawsock *raw, int name, const struct sockdriver_data *data, socklen_t *len)
{
	if (name == ICMP6_FILTER) {
		return sockdriver_copyout_opt(data, &raw->raw_icmp6filter,
		    sizeof(raw->raw_icmp6filter), len);
	}
	return -1;
}

static int rawsock_getsockopt(struct sock *sock, int level, int name,
	const struct sockdriver_data *data, socklen_t *len)
{
	struct rawsock *raw = (struct rawsock *)sock;
	struct ipopts ipopts;
	int result = -1;

	switch (level) {
	case IPPROTO_IP:
		if (!rawsock_is_ipv6(raw))
			result = handle_ipv4_options(raw, name, data, len);
		break;

	case IPPROTO_IPV6:
		if (rawsock_is_ipv6(raw))
			result = handle_ipv6_options(raw, name, data, len);
		break;

	case IPPROTO_ICMPV6:
		if (rawsock_is_ipv6(raw) && raw->raw_pcb->protocol == IPPROTO_ICMPV6)
			result = handle_icmpv6_options(raw, name, data, len);
		break;
	}

	if (result != -1)
		return result;

	rawsock_get_ipopts(raw, &ipopts);
	return pktsock_getsockopt(&raw->raw_pktsock, level, name, data, len, &ipopts);
}

/*
 * Retrieve the local socket address of a raw socket.
 */
static int
rawsock_getsockname(struct sock * sock, struct sockaddr * addr,
	socklen_t * addr_len)
{
	struct rawsock *raw = (struct rawsock *)sock;

	ipsock_put_addr(rawsock_get_ipsock(raw), addr, addr_len,
	    &raw->raw_pcb->local_ip, 0);

	return OK;
}

/*
 * Retrieve the remote socket address of a raw socket.
 */
static int
rawsock_getpeername(struct sock * sock, struct sockaddr * addr,
	socklen_t * addr_len)
{
	struct rawsock *raw = (struct rawsock *)sock;

	if (!rawsock_is_conn(raw))
		return ENOTCONN;

	ipsock_put_addr(rawsock_get_ipsock(raw), addr, addr_len,
	    &raw->raw_pcb->remote_ip, 0);

	return OK;
}

/*
 * Shut down a raw socket for reading and/or writing.
 */
static int rawsock_shutdown(struct sock *sock, unsigned int mask)
{
	struct rawsock *raw = (struct rawsock *)sock;

	if (mask & SFL_SHUT_RD) {
		raw_recv(raw->raw_pcb, NULL, NULL);
	}

	pktsock_shutdown(&raw->raw_pktsock, mask);

	return OK;
}

/*
 * Close a raw socket.
 */
static int
rawsock_close(struct sock * sock, int force __unused)
{
	struct rawsock *raw = (struct rawsock *)sock;

	raw_recv(raw->raw_pcb, NULL, NULL);

	raw_remove(raw->raw_pcb);
	raw->raw_pcb = NULL;

	pktsock_close(&raw->raw_pktsock);

	return OK;
}

/*
 * Free up a closed raw socket.
 */
static void
rawsock_free(struct sock * sock)
{
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
rawsock_get_info(struct kinfo_pcb * ki, const void * ptr)
{
	const struct raw_pcb *pcb = (const struct raw_pcb *)ptr;
	struct rawsock *raw;

	raw = (struct rawsock *)pcb->recv_arg;
	assert(raw >= raw_array &&
	    raw < &raw_array[__arraycount(raw_array)]);

	ki->ki_type = SOCK_RAW;
	ki->ki_protocol = pcb->protocol;

	ipsock_get_info(ki, &pcb->local_ip, 0,
	    &raw->raw_pcb->remote_ip, 0);

	ki->ki_sockaddr = (uint64_t)(uintptr_t)rawsock_get_sock(raw);

	ki->ki_rcvq = pktsock_get_recvlen(&raw->raw_pktsock);

	if (rawsock_is_hdrincl(raw))
		ki->ki_pflags |= INP_HDRINCL;
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
	if (last == NULL)
		return get_first_active_pcb();

	return get_next_active_pcb(last);
}

static const void *
get_first_active_pcb(void)
{
	struct rawsock *raw = TAILQ_FIRST(&raw_activelist);
	return raw != NULL ? raw->raw_pcb : NULL;
}

static const void *
get_next_active_pcb(const void *last)
{
	const struct raw_pcb *pcb = (const struct raw_pcb *)last;
	struct rawsock *raw = (struct rawsock *)pcb->recv_arg;
	
	assert(raw >= raw_array &&
	    raw < &raw_array[__arraycount(raw_array)]);

	raw = TAILQ_NEXT(raw, raw_next);
	return raw != NULL ? raw->raw_pcb : NULL;
}

/*
 * Obtain the list of RAW protocol control blocks, for sysctl(7).
 */
static ssize_t
rawsock_pcblist(struct rmib_call * call, struct rmib_node * node,
	struct rmib_oldp * oldp, struct rmib_newp * newp __unused)
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
