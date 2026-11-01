/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * ENV:netstack.prefs reader — see sb_config.h for the schema. The same
 * defaults-then-override pattern as genet's runtime config: a missing or
 * unreadable file is not an error, it is the default configuration.
 */

#include "sb_base.h"

#include <debug.h>
#include <strutil.h>
#include <prefs.h>

/* Cut the leading blank-delimited word off *rest, in place: the word is
 * NUL-terminated and *rest is left on the first character after it, blanks
 * skipped. Whatever remains is the caller's — a value whose last field is
 * free text (an mDNS instance name) just stops calling this. Both the word
 * and the remainder are "" once the value is exhausted, never NULL. */
static char *sb_cfg_word(char **rest)
{
    char *word = *rest;
    char *p = word;

    while (*p != '\0' && *p != ' ' && *p != '\t')
        p++;
    if (*p != '\0')
    {
        *p++ = '\0';
        while (*p == ' ' || *p == '\t')
            p++;
    }
    *rest = p;
    return word;
}

/* /etc/networks notation: 1..4 dot-separated octets, most significant first —
 * "127" = 127, "192.168.6" = 0xC0A806. NOT an IP address (inet_addr pads the
 * missing octets differently). */
static BOOL sb_cfg_parse_netnum(const char *s, ULONG *out)
{
    ULONG net = 0;
    ULONG parts = 0;
    while (*s != '\0')
    {
        ULONG octet = 0;
        ULONG digits = 0;
        while (*s >= '0' && *s <= '9')
        {
            octet = octet * 10 + (ULONG)(*s - '0');
            if (octet > 255)
                return FALSE;
            s++;
            digits++;
        }
        if (digits == 0 || ++parts > 4)
            return FALSE;
        net = (net << 8) | octet;
        if (*s == '.')
            s++;
        else if (*s != '\0')
            return FALSE;
    }
    if (parts == 0)
        return FALSE;
    *out = net;
    return TRUE;
}

static void sb_cfg_defaults(struct SbNetConfig *cfg)
{
    for (ULONG i = 0; i < sizeof(*cfg); i++)
        ((UBYTE *)cfg)[i] = 0;
    strlcpy(cfg->cfg_Hostname, "amiga", sizeof(cfg->cfg_Hostname));
    cfg->cfg_Mdns = TRUE;    /* HOSTNAME.local costs one multicast group */
}

/* The previous model interface keys: recognized so a stale prefs file
 * gets one clear notice instead of silent misconfiguration. Interfaces are
 * configured in DEVS:NetInterfaces/ via AddNetInterface now. */
static BOOL sb_cfg_key_obsolete(const char *key)
{
    static const char *const obsolete[] = {
        "DEVICE", "UNIT", "MODE", "ADDRESS", "NETMASK", "GATEWAY", "VLAN",
    };
    for (ULONG i = 0; i < sizeof(obsolete) / sizeof(obsolete[0]); i++)
    {
        if (_Stricmp((CONST_STRPTR)key, (CONST_STRPTR)obsolete[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

void sb_config_load(struct SbNetConfig *cfg)
{
    sb_cfg_defaults(cfg);

    struct prefs_file f;
    if (!prefs_open(&f, SysBase, "ENV:netstack.prefs"))
        return;
    KprintfT("[bsdsocket] %s: reading ENV:netstack.prefs\n", __func__);

    BOOL warnedObsolete = FALSE;
    char *key, *val;
    while (prefs_next(&f, &key, &val))
    {
        if (sb_cfg_key_obsolete(key))
        {
            if (!warnedObsolete)
            {
                SB_LOG(NS_LOG_WARNING, "netstack.prefs: DEVICE/UNIT/MODE/ADDRESS/"
                       "NETMASK/GATEWAY/VLAN are obsolete, interfaces are "
                       "configured in DEVS:NetInterfaces/ (see AddNetInterface)");
                warnedObsolete = TRUE;
            }
        }
        else if (_Stricmp((CONST_STRPTR)key, (CONST_STRPTR) "DNS1") == 0)
        {
            if (!ip4addr_aton(val, &cfg->cfg_Dns[0]))
                SB_LOG(NS_LOG_WARNING, "netstack.prefs: bad DNS1 '%s'", val);
        }
        else if (_Stricmp((CONST_STRPTR)key, (CONST_STRPTR) "DNS2") == 0)
        {
            if (!ip4addr_aton(val, &cfg->cfg_Dns[1]))
                SB_LOG(NS_LOG_WARNING, "netstack.prefs: bad DNS2 '%s'", val);
        }
        else if (_Stricmp((CONST_STRPTR)key, (CONST_STRPTR) "HOSTNAME") == 0)
        {
            if (!strfit(cfg->cfg_Hostname, val, sizeof(cfg->cfg_Hostname)))
                SB_LOG(NS_LOG_WARNING, "netstack.prefs: HOSTNAME too long '%s'", val);
        }
        else if (_Stricmp((CONST_STRPTR)key, (CONST_STRPTR) "DOMAIN") == 0)
        {
            if (!strfit(cfg->cfg_Domain, val, sizeof(cfg->cfg_Domain)))
                SB_LOG(NS_LOG_WARNING, "netstack.prefs: DOMAIN too long '%s'", val);
        }
        else if (_Stricmp((CONST_STRPTR)key, (CONST_STRPTR) "MDNS") == 0)
        {
            if (!prefs_bool(val, &cfg->cfg_Mdns))
                SB_LOG(NS_LOG_WARNING, "netstack.prefs: bad MDNS '%s'", val);
        }
        else if (_Stricmp((CONST_STRPTR)key, (CONST_STRPTR) "MDNS_SERVICE") == 0)
        {
            /* MDNS_SERVICE = <_type._proto> <port> [instance name]  (repeatable).
             * The name is the rest of the line, spaces included ("Amiga 1200");
             * the type is validated where it is registered (sb_mdns.c). */
            char *rest = val;
            char *type = sb_cfg_word(&rest);
            char *portStr = sb_cfg_word(&rest);
            char *name = rest;

            LONG port;
            if (*type == '\0' || !prefs_number(portStr, 1, 65535, &port))
                SB_LOG(NS_LOG_WARNING, "netstack.prefs: bad MDNS_SERVICE '%s'", type);
            else if (cfg->cfg_NumMdnsServices >= SB_CFG_MDNS_MAX)
                SB_LOG(NS_LOG_WARNING, "netstack.prefs: MDNS_SERVICE table full (max %ld)",
                       (LONG)SB_CFG_MDNS_MAX);
            else
            {
                struct SbCfgMdnsService *s = &cfg->cfg_MdnsServices[cfg->cfg_NumMdnsServices];
                if (strfit(s->type, type, sizeof(s->type)) && strfit(s->name, name, sizeof(s->name)))
                {
                    s->port = (UWORD)port;
                    cfg->cfg_NumMdnsServices++;
                }
                else
                    SB_LOG(NS_LOG_WARNING, "netstack.prefs: MDNS_SERVICE too long '%s'", type);
            }
        }
        else if (_Stricmp((CONST_STRPTR)key, (CONST_STRPTR) "NETWORK") == 0)
        {
            /* NETWORK = <name> <number>  (repeatable): extra networks-database
             * entries for getnetbyname/getnetbyaddr, shadowing the built-ins */
            char *num = val;
            char *name = sb_cfg_word(&num);

            ULONG netnum;
            if (*name == '\0' || !sb_cfg_parse_netnum(num, &netnum))
                SB_LOG(NS_LOG_WARNING, "netstack.prefs: bad NETWORK '%s'", name);
            else if (cfg->cfg_NumNetworks >= SB_CFG_NETWORKS_MAX)
                SB_LOG(NS_LOG_WARNING, "netstack.prefs: NETWORK table full (max %ld)",
                       (LONG)SB_CFG_NETWORKS_MAX);
            else
            {
                struct SbCfgNetwork *n = &cfg->cfg_Networks[cfg->cfg_NumNetworks];
                if (strfit(n->name, name, sizeof(n->name)))
                {
                    n->net = netnum;
                    cfg->cfg_NumNetworks++;
                }
                else
                    SB_LOG(NS_LOG_WARNING, "netstack.prefs: NETWORK too long '%s'", name);
            }
        }
        /* unknown keys are ignored */
    }

    prefs_close(&f);
}
