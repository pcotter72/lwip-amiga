/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * The DNS resolver surface: gethostbyname/byaddr (lwIP DNS, blocking on the
 * opener's signal; reverse lookups via the sb_rdns.c PTR resolver), their
 * reentrant _r variants, and gethostname/gethostid. Forward lookups retry an
 * unqualified name once with the configured search domain appended.
 */

#include "sb_base.h"

#include <lwip/dns.h>
#include <lwip/ip4_addr.h>
#include <lwip/netif.h>

#include <debug.h>

#include "netstack.h"

/* lwIP's answer for one ticket (stack task, core lock held). An abandoned
 * ticket - its waiter gave up, closed the library or died - is only freed:
 * the base it belonged to may be gone, or busy with a newer lookup. */
static void sb_dns_cb(const char *name, const ip_addr_t *ipaddr, void *arg)
{
    KprintfT("[bsdsocket] %s: name=%s found=%ld\n", __func__, (ULONG)name, (LONG)(ipaddr != NULL));
    struct sb_dns_ticket *t = arg;
    (void)name;

    struct SocketBase *base = t->base;
    if (base == NULL)
    {
        FreeMem(t, sizeof(*t));
        return;
    }
    if (ipaddr != NULL)
    {
        t->addr = *ipaddr;
        t->err = 0;
    }
    else
    {
        t->err = SB_HOST_NOT_FOUND;
    }
    t->done = TRUE;
    if (base->task != NULL) /* NULL: the opener ended without closing the library */
        Signal(base->task, 1UL << base->sigBit);
}

static struct sb_hostent *sb_host_fill(struct SocketBase *base, const char *name, ULONG addr)
{
    KprintfT("[bsdsocket] %s: name=%s addr=0x%08lx\n", __func__, (ULONG)name, addr);
    strlcpy(base->hostName, name, sizeof(base->hostName));
    base->hostAddr = addr;
    base->hostAddrList[0] = (char *)&base->hostAddr;
    base->hostAddrList[1] = NULL;
    base->hostAliases[0] = NULL;
    base->host.h_name = base->hostName;
    base->host.h_aliases = base->hostAliases;
    base->host.h_addrtype = SB_AF_INET;
    base->host.h_length = 4;
    base->host.h_addr_list = base->hostAddrList;
    return &base->host;
}

/* One blocking forward-DNS lookup of @name. Returns 0 with *addr filled on
 * success; SB_TRY_AGAIN if interrupted (errno already set); or
 * SB_HOST_NOT_FOUND on a negative or failed answer. */
static LONG sb_dns_query(struct SocketBase *base, const char *name, ULONG *addr)
{
    KprintfT("[bsdsocket] %s: name=%s\n", __func__, (ULONG)name);
    /* a ticket per lookup, see struct sb_dns_ticket */
    struct sb_dns_ticket *t = AllocMem(sizeof(*t), MEMF_PUBLIC | MEMF_CLEAR);
    if (t == NULL)
    {
        sb_set_errno(base, SB_ENOMEM);
        return SB_TRY_AGAIN;
    }
    t->base = base;

    netstack_lock();
    /* ERR_INPROGRESS: lwIP stored the callback and will call it exactly once
     * (answer, or NULL after its retries). Any other result: no callback
     * (ERR_OK filled t->addr from the cache or a literal; dns_enqueue clears
     * the request again before it returns ERR_MEM). */
    err_t r = dns_gethostbyname(name, &t->addr, sb_dns_cb, t);
    if (r == ERR_INPROGRESS)
    {
        base->dnsTicket = t;
        while (!t->done)
        {
            LONG we = sb_wait(base);
            if (we != 0)
            {
                /* sb_wait reports the break even when the answer's signal came
                 * in the same Wait: if the callback has already run it will not
                 * run again and the ticket is ours to free; otherwise give it to
                 * the callback, which frees it */
                base->dnsTicket = NULL;
                if (t->done)
                    FreeMem(t, sizeof(*t));
                else
                    t->base = NULL;
                netstack_unlock();
                sb_set_errno(base, we);
                return SB_TRY_AGAIN;
            }
        }
        base->dnsTicket = NULL;
        r = t->err == 0 ? ERR_OK : ERR_VAL;
    }
    netstack_unlock();

    if (r == ERR_OK)
        *addr = ip4_addr_get_u32(ip_2_ip4(&t->addr));
    FreeMem(t, sizeof(*t)); /* done, or never handed to lwIP: no callback can follow */
    return r == ERR_OK ? 0 : SB_HOST_NOT_FOUND;
}

/* If @name is unqualified (contains no dot) and @domain is set, compose
 * "name.domain" into @out and return TRUE; otherwise FALSE. A dotted name is
 * already qualified (or a literal) and is left alone. */
static BOOL sb_qualify(const char *name, const char *domain, char *out, ULONG outmax)
{
    if (name == NULL || name[0] == '\0' || domain == NULL || domain[0] == '\0')
        return FALSE;

    ULONG nlen = 0;
    while (name[nlen] != '\0')
    {
        if (name[nlen] == '.')
            return FALSE; /* already qualified */
        nlen++;
    }
    ULONG dlen = strlen(domain);
    if (nlen + 1 + dlen + 1 > outmax)
        return FALSE; /* would not fit */

    ULONG o = 0;
    for (ULONG i = 0; i < nlen; i++)
        out[o++] = name[i];
    out[o++] = '.';
    for (ULONG i = 0; i < dlen; i++)
        out[o++] = domain[i];
    out[o] = '\0';
    return TRUE;
}

/* Blocking resolver core shared with gethostbyname_r: resolves @name, fills
 * the per-base hostent, and reports the address/h_errno through the out
 * parameters. An unqualified name that misses is retried once as
 * "name.<search-domain>" (Roadshow order: bare first, qualified fallback).
 * Returns the per-base hostent or NULL. */
struct sb_hostent *sb_host_resolve(struct SocketBase *base, const char *name, ULONG *addrOut, LONG *herrOut)
{
    KprintfT("[bsdsocket] %s: name=%s\n", __func__, name != NULL ? (ULONG)name : (ULONG)"(null)");

    if (name == NULL)
    {
        if (herrOut != NULL)
            *herrOut = SB_HOST_NOT_FOUND;
        sb_set_herrno(base, SB_HOST_NOT_FOUND);
        return NULL;
    }

    ULONG addr = 0;
    LONG rc = sb_dns_query(base, name, &addr);

    const char *canon = name;
    char qbuf[256]; /* DNS names are <= 253 chars */
    if (rc == SB_HOST_NOT_FOUND &&
        sb_qualify(name, SB_ROOT(base)->defaultDomain, qbuf, sizeof(qbuf)))
    {
        /* take the retry's verdict as-is: an interrupted retry must surface
         * as TRY_AGAIN, not as the bare lookup's definitive NOT_FOUND */
        rc = sb_dns_query(base, qbuf, &addr);
        if (rc == 0)
            canon = qbuf; /* report the name that actually resolved */
    }

    if (rc != 0)
    {
        sb_set_herrno(base, rc); /* SB_TRY_AGAIN or SB_HOST_NOT_FOUND */
        if (herrOut != NULL)
            *herrOut = rc;
        return NULL;
    }

    if (addrOut != NULL)
        *addrOut = addr;
    if (herrOut != NULL)
        *herrOut = 0;
    return sb_host_fill(base, canon, addr);
}

APTR bsd_gethostbyname(STRPTR name asm("a0"), struct SocketBase *base asm("a6"))
{
    KprintfT("[bsdsocket] %s: name=%s\n", __func__, name != NULL ? (ULONG)name : (ULONG)"(null)");
    return sb_host_resolve(base, (const char *)name, NULL, NULL);
}

APTR bsd_gethostbyaddr(STRPTR addr asm("a0"), LONG len asm("d0"), LONG type asm("d1"),
                       struct SocketBase *base asm("a6"))
{
    KprintfT("[bsdsocket] %s: addr=0x%08lx len=%ld\n", __func__, (ULONG)addr, len);
    if (addr == NULL || len != 4 || type != SB_AF_INET)
    {
        sb_set_herrno(base, SB_HOST_NOT_FOUND);
        return NULL;
    }
    ULONG a = *(ULONG *)addr;
    char nameBuf[SB_HOSTNAME_MAX];
    if (sb_ptr_resolve(base, a, nameBuf, sizeof(nameBuf)) != 0)
    {
        /* no PTR record (or no resolver / timeout): BSD reports not-found */
        sb_set_herrno(base, SB_HOST_NOT_FOUND);
        return NULL;
    }
    return sb_host_fill(base, nameBuf, a);
}

LONG bsd_gethostname(STRPTR name asm("a0"), LONG namelen asm("d0"),
                     struct SocketBase *base asm("a6"))
{
    KprintfT("[bsdsocket] %s: namelen=%ld\n", __func__, namelen);
    const char *hostname = SB_ROOT(base)->netCfg.cfg_Hostname;
    if (name == NULL || namelen <= 0)
        return -1;
    strlcpy((char *)name, hostname, (ULONG)namelen);
    return 0;
}

ULONG bsd_gethostid(struct SocketBase *base asm("a6"))
{
    KprintfT("[bsdsocket] %s\n", __func__);
    (void)base;
    /* BSD convention: the host identifier is the primary IP address;
     * unconfigured hosts still answer non-zero with the loopback address */
    ULONG id = 0;
    netstack_lock();
    if (netif_default != NULL)
        id = ip4_addr_get_u32(netif_ip4_addr(netif_default));
    netstack_unlock();
    if (id == 0)
        id = 0x7F000001UL;
    return id;
}

/* ------------------------------------------------- reentrant resolvers --- */

static struct sb_hostent *sb_host_to_caller(struct sb_hostent *src, struct sb_hostent *hp,
                                            char *buf, ULONG buflen)
{
    KprintfT("[bsdsocket] %s: buflen=%lu\n", __func__, buflen);
    /* layout in the caller's buffer: addr (4) + addr_list (8) + aliases (4)
     * + name string */
    ULONG need = 4 + 2 * sizeof(char *) + sizeof(char *) + 1;
    const char *name = src->h_name;
    ULONG namelen = strlen(name);
    if (hp == NULL || buf == NULL || buflen < need + namelen)
        return NULL;

    char *addr = buf;
    char **addrList = (char **)(buf + 4);
    char **aliases = (char **)(buf + 4 + 2 * sizeof(char *));
    char *nameDst = buf + 4 + 3 * sizeof(char *);

    *(ULONG *)addr = *(ULONG *)src->h_addr_list[0];
    addrList[0] = addr;
    addrList[1] = NULL;
    aliases[0] = NULL;
    strlcpy(nameDst, name, namelen + 1);

    hp->h_name = nameDst;
    hp->h_aliases = aliases;
    hp->h_addrtype = SB_AF_INET;
    hp->h_length = 4;
    hp->h_addr_list = addrList;
    return hp;
}

APTR bsd_gethostbyname_r(STRPTR name asm("a0"), APTR hp asm("a1"), APTR buf asm("a2"),
                         ULONG buflen asm("d0"), LONG *he asm("a3"),
                         struct SocketBase *base asm("a6"))
{
    KprintfT("[bsdsocket] %s: name=%s buflen=%lu\n", __func__, name != NULL ? (ULONG)name : (ULONG)"(null)", buflen);
    LONG herr = 0;
    struct sb_hostent *res = sb_host_resolve(base, (const char *)name, NULL, &herr);

    if (he != NULL)
        *he = herr;
    if (res == NULL)
        return NULL;
    return sb_host_to_caller(res, hp, buf, buflen);
}

APTR bsd_gethostbyaddr_r(STRPTR addr asm("a0"), LONG len asm("d0"), LONG type asm("d1"),
                         APTR hp asm("a1"), APTR buf asm("a2"), ULONG buflen asm("d2"),
                         LONG *he asm("a3"), struct SocketBase *base asm("a6"))
{
    KprintfT("[bsdsocket] %s: len=%ld type=%ld\n", __func__, len, type);
    struct sb_hostent *res = (struct sb_hostent *)bsd_gethostbyaddr(addr, len, type, base);

    if (he != NULL)
        *he = res != NULL ? 0 : SB_HOST_NOT_FOUND;
    if (res == NULL)
        return NULL;
    return sb_host_to_caller(res, hp, buf, buflen);
}
