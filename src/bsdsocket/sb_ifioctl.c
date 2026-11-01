/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Interface query ioctls (SIOCGIFCONF, SIOCGIFFLAGS, SIOCGIFADDR,
 * SIOCGIFDSTADDR, SIOCGIFBRDADDR, SIOCGIFNETMASK, SIOCGIFMETRIC and the
 * 4.3BSD O* variants) — the AmiTCP-era way to read the interface list and
 * addresses, used by clients that predate Roadshow's QueryInterfaceTagList
 * (e.g. GetIPAddress, ifconfig-style tools). Read-only: the SIOCSIF* set
 * requests stay unsupported (interfaces are configured through
 * AddNetInterface). Answers come from the live lwIP netif under the core
 * lock, the same source as sb_ifquery.c, and interfaces carry the same names
 * as in ObtainInterfaceList (sb_if_name), so a name from SIOCGIFCONF can be
 * passed back to the other requests. The argument structs mirror the
 * netinclude layouts and are asserted to the wire sizes below.
 */

#include "sb_base.h"

#ifdef __INTELLISENSE__
#include <clib/exec_protos.h>
#else
#include <proto/exec.h>
#endif

#include <debug.h>
#include <memory.h>
#include <netstack_ctl.h>

#include <lwip/ip4_addr.h>
#include <lwip/netif.h>

#include "netstack.h"

/* --- netinclude net/if.h mirrors ------------------------------------------ */

#define SB_IFNAMSIZ 16

struct sb_ifreq
{
    char ifr_name[SB_IFNAMSIZ];
    union
    {
        struct sb_sockaddr_in ifru_addr; /* struct sockaddr: 16 bytes */
        WORD ifru_flags;
        LONG ifru_metric;
        APTR ifru_data;
    } ifr_ifru;
};

struct sb_ifconf
{
    LONG ifc_len; /* in: buffer size; out: bytes filled */
    struct sb_ifreq *ifc_req;
};

/* m68k only: host IntelliSense sees 64-bit LONG/pointers */
#ifndef __INTELLISENSE__
_Static_assert(sizeof(struct sb_ifreq) == 32, "ifreq wire ABI");
_Static_assert(sizeof(struct sb_ifconf) == 8, "ifconf wire ABI");
_Static_assert(SB_IFNAMSIZ == NETCTL_IFNAME_MAX, "sb_if_name() fills ifr_name");
#endif

/* --- helpers (core lock held) --------------------------------------------- */

static WORD sb_ifioctl_flags(const struct netif *nif)
{
    WORD flags = 0;
    if (netif_is_up(nif))
    {
        flags |= SB_IFF_UP;
        if (netif_is_link_up(nif))
            flags |= SB_IFF_RUNNING;
    }
    if (sb_if_is_loopback(nif))
        flags |= SB_IFF_LOOPBACK;
    if (nif->flags & NETIF_FLAG_BROADCAST)
        flags |= SB_IFF_BROADCAST;
    if (nif->flags & NETIF_FLAG_IGMP)
        flags |= SB_IFF_MULTICAST;
    return flags;
}

/* The 4.3BSD O* requests return an osockaddr: a 16-bit family in place of
 * the sa_len/sa_family byte pair, the rest as in sockaddr_in. */
static void sb_ifioctl_set_addr(struct sb_ifreq *ifr, ULONG addr, BOOL old)
{
    sb_if_set_sockaddr(&ifr->ifr_ifru.ifru_addr, addr);
    if (old)
        *(UWORD *)&ifr->ifr_ifru.ifru_addr = SB_AF_INET;
}

static LONG sb_ifioctl_conf(struct SocketBase *base, struct sb_ifconf *ifc, BOOL old)
{
    if (ifc->ifc_len < 0 || (ifc->ifc_len > 0 && ifc->ifc_req == NULL))
        return sb_fail(base, SB_EINVAL);

    LONG room = ifc->ifc_len / (LONG)sizeof(struct sb_ifreq);
    LONG n = 0;
    struct sb_ifreq *ifr = ifc->ifc_req;

    netstack_lock();
    struct netif *nif;
    NETIF_FOREACH(nif)
    {
        if (n == room)
            break;
        memset(ifr, 0, sizeof(*ifr));
        sb_if_name(nif, ifr->ifr_name);
        /* no address yet (DHCP pending): the entry keeps a zeroed sockaddr,
         * family included, so clients testing sa_family skip it, as on BSD */
        ULONG addr = ip4_addr_get_u32(netif_ip4_addr(nif));
        if (addr != 0)
            sb_ifioctl_set_addr(ifr, addr, old);
        ifr++;
        n++;
    }
    netstack_unlock();

    ifc->ifc_len = n * (LONG)sizeof(struct sb_ifreq);
    return 0;
}

/* --- the requests ----------------------------------------------------------- */

/* cold: a rare control path; keeping it (and sb_if_name) out of the hot
 * text stops LTO from re-partitioning the TX/RX code around it, which cost
 * 6-12 % of TCP send throughput on a 68080 in a plain build */
__attribute__((cold)) LONG sb_ifioctl(struct SocketBase *base, ULONG req, APTR argp)
{
    KprintfT("[bsdsocket] %s: req 0x%lx\n", __func__, req);

    if (req == SB_SIOCGIFCONF || req == SB_OSIOCGIFCONF)
        return sb_ifioctl_conf(base, argp, req == SB_OSIOCGIFCONF);

    struct sb_ifreq *ifr = argp;
    char name[SB_IFNAMSIZ];
    memcpy(name, ifr->ifr_name, SB_IFNAMSIZ);
    name[SB_IFNAMSIZ - 1] = '\0';

    netstack_lock();
    struct netif *nif = sb_if_find(name);
    if (nif == NULL)
    {
        netstack_unlock();
        return sb_fail(base, SB_ENXIO);
    }
    ULONG addr = ip4_addr_get_u32(netif_ip4_addr(nif));
    ULONG mask = ip4_addr_get_u32(netif_ip4_netmask(nif));
    /* no address yet (DHCP pending): EADDRNOTAVAIL as on BSD, never 0.0.0.0 */
    if (addr == 0 && req != SB_SIOCGIFFLAGS && req != SB_SIOCGIFMETRIC)
    {
        netstack_unlock();
        return sb_fail(base, SB_EADDRNOTAVAIL);
    }
    LONG rc = 0;

    switch (req)
    {
    case SB_SIOCGIFFLAGS:
        ifr->ifr_ifru.ifru_flags = sb_ifioctl_flags(nif);
        break;
    case SB_SIOCGIFADDR:
    case SB_OSIOCGIFADDR:
    case SB_SIOCGIFDSTADDR: /* not point-to-point: same as the address, */
    case SB_OSIOCGIFDSTADDR: /* as IFQ_DestinationAddress answers */
        sb_ifioctl_set_addr(ifr, addr, req == SB_OSIOCGIFADDR || req == SB_OSIOCGIFDSTADDR);
        break;
    case SB_SIOCGIFBRDADDR:
    case SB_OSIOCGIFBRDADDR:
        if (nif->flags & NETIF_FLAG_BROADCAST)
            sb_ifioctl_set_addr(ifr, addr | ~mask, req == SB_OSIOCGIFBRDADDR);
        else
            rc = SB_EINVAL; /* BSD: no broadcast address on this interface */
        break;
    case SB_SIOCGIFNETMASK:
    case SB_OSIOCGIFNETMASK:
        sb_ifioctl_set_addr(ifr, mask, req == SB_OSIOCGIFNETMASK);
        break;
    case SB_SIOCGIFMETRIC:
        ifr->ifr_ifru.ifru_metric = 0; /* single-homed host, as IFQ_Metric */
        break;
    default:
        rc = SB_EINVAL;
        break;
    }
    netstack_unlock();

    return rc != 0 ? sb_fail(base, rc) : 0;
}
