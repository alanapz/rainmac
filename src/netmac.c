#include <linux/socket.h>                                       /* AF_, PF_, SOL (IPPROTO) constants */
#include <linux/in.h>                                           /* struct sockaddr_in */
#include <linux/un.h>                                           /* struct sockaddr_un */
#include "netmac.h"
#include "ruleset.h"
#include "lookup.h"
#include "utils.h"

#define PERM_NET_CONNECT    1
#define PERM_NET_BIND       2

#define UNIX_OBJECT         struct unix_object
#define IPV4_OBJECT         struct ipv4_object

struct unix_object
{
    char path[255];
};

struct ipv4_object
{
    short proto;
    char addr[16];
    int port;
};

// Declarations

static int r_unix_rule_implies(const RDATA*, const OBJECT*);

static const char* r_unix_object_print(const OBJECT*, IOBUFF*);

static RDATA* r_unix_rdata_import(const char*);

static void r_unix_rdata_export(const RDATA*, IOBUFF*);

static int r_ipv4_rule_implies(const RDATA*, const OBJECT*);

static const char* r_ipv4_object_print(const OBJECT*, IOBUFF*);

static RDATA* r_ipv4_rdata_import(const char*);

static void r_ipv4_rdata_export(const RDATA*, IOBUFF*);

static char* lookup_protocol_name(short);

// Members

static RULESET *unix_ruleset, *ipv4_ruleset;

static const char *net_perm_names[] = { "connect" , "listen" };

extern SECURITY_OPERATIONS secondary_ops;

// Definitions

int netmac_init(void)
{
    unix_ruleset = alloc_ruleset("net_unix", net_perm_names, 2);
    ipv4_ruleset = alloc_ruleset("net_ipv4", net_perm_names, 2);
    if (!unix_ruleset || !ipv4_ruleset)
    {
        return -EIO;
    }
    unix_ruleset->rule_implies = r_unix_rule_implies;
    unix_ruleset->object_print = r_unix_object_print;
    unix_ruleset->rdata_import = r_unix_rdata_import;
    unix_ruleset->rdata_export = r_unix_rdata_export;
    unix_ruleset->rdata_destroy = kfree;
    ipv4_ruleset->rule_implies = r_ipv4_rule_implies;
    ipv4_ruleset->object_print = r_ipv4_object_print;
    ipv4_ruleset->rdata_import = r_ipv4_rdata_import;
    ipv4_ruleset->rdata_export = r_ipv4_rdata_export;
    ipv4_ruleset->rdata_destroy = kfree;
    return 0;
}

void netmac_cleanup(void)
{
    if (unix_ruleset)
    {
        release_ruleset(unix_ruleset);
    }
    if (ipv4_ruleset)
    {
        release_ruleset(ipv4_ruleset);
    }
}

int socket_connect_hook(SOCKET *sock, SOCKADDR *address, int addrlen)
{
    int result = secondary_ops.socket_connect(sock, address, addrlen);
    if (result)
    {
        return result;
    }
    if (!current->pid || current->pid == 1) 
    {
        return 0;
    }    
    const SUBJECT* subject = alloc_subject(current);
    if (address->sa_family == AF_INET)
    {
        IPV4_OBJECT object;
        struct sockaddr_in *in_addr = (struct sockaddr_in*) address;
        object.proto = sock->sk->sk_protocol;
        sprintf(object.addr, "%d.%d.%d.%d", NIPQUAD(in_addr->sin_addr.s_addr));
        object.port = ntohs(in_addr->sin_port);
        result = resolve_access(ipv4_ruleset, PERM_NET_CONNECT, subject, &object);
    }
    else if (address->sa_family == AF_INET6)
    {
        /// TODO: Implement IPv6 support
    }
    else if (address->sa_family == AF_UNIX)
    {
        UNIX_OBJECT object;
        struct sockaddr_un *un_addr = (struct sockaddr_un*) address;
        strncpy(object.path, un_addr->sun_path, sizeof(object.path));
        result = resolve_access(unix_ruleset, PERM_NET_CONNECT, subject, &object);
    }
    else if (address->sa_family == AF_NETLINK)
    {
        /// TODO: Implement Netlink support
    }
    else
    {
        // Unsupported address family - nothing we can do here
    }
    release_subject(subject);
    return result;
}

int socket_bind_hook(SOCKET *sock, SOCKADDR *address, int addrlen)
{
    int result = secondary_ops.socket_bind(sock, address, addrlen);
    if (result)
    {
        return result;
    }
    if (!current->pid || current->pid == 1) 
    {
        return 0;
    }    
    const SUBJECT* subject = alloc_subject(current);
    if (address->sa_family == AF_INET)
    {
        IPV4_OBJECT object;
        struct sockaddr_in *in_addr = (struct sockaddr_in*) address;
        object.proto = sock->sk->sk_protocol;
        sprintf(object.addr, "%d.%d.%d.%d", NIPQUAD(in_addr->sin_addr.s_addr));
        object.port = ntohs(in_addr->sin_port);
        result = resolve_access(ipv4_ruleset, PERM_NET_BIND, subject, &object);
    }
    else if (address->sa_family == AF_INET6)
    {
        /// TODO: Implement IPv6 support
    }
    else if (address->sa_family == AF_UNIX)
    {
        UNIX_OBJECT object;
        struct sockaddr_un *un_addr = (struct sockaddr_un*) address;
        strncpy(object.path, un_addr->sun_path, sizeof(object.path));
        result = resolve_access(unix_ruleset, PERM_NET_BIND, subject, &object);
    }
    else if (address->sa_family == AF_NETLINK)
    {
        /// TODO: Implement Netlink support
    }
    else
    {
        // Unsupported address family - nothing we can do here
    }
    release_subject(subject);
    return result;
}

int socket_accept_hook(SOCKET *sock, SOCKET *newsock)
{
    int result = secondary_ops.socket_accept(sock, newsock);
    if (result)
    {
        return result;
    }
    if (!current->pid || current->pid == 1) 
    {
        return 0;
    }    
    /// TODO: Implement support for acceptance checking
    return result;
}

static int r_unix_rule_implies(const RDATA *rdata_v, const OBJECT *object_v)
{
    const UNIX_OBJECT *rdata = rdata_v;
    const UNIX_OBJECT *object = object_v;
    if (rdata->path && object->path)
    {
        const char *rpath = rdata->path;
        const char *opath = object->path;
        // See explanation in fsmac implies for how this works
        if ((rpath[strlen(rpath) - 1] != '/' && strcmp(rpath, opath))
                || (rpath[strlen(rpath) - 1] == '/' && strncmp(rpath, opath, strlen(rpath) - 1)))
        {
            return 0;
        }
    }
    return 1;
}

static const char* r_unix_object_print(const OBJECT *object_v, IOBUFF *buff)
{
    return ((const UNIX_OBJECT*) object_v)->path;
}

static RDATA* r_unix_rdata_import(const char *rdata)
{
    UNIX_OBJECT *object = kmalloc(sizeof(UNIX_OBJECT), GFP_KERNEL);
    strncpy(object->path, rdata, sizeof(object->path));
    object->path[sizeof(object->path) - 1] = '\0';
    return object; 
}

static void r_unix_rdata_export(const RDATA *rdata_v, IOBUFF *buff)
{
    iobuff_write_chars(buff, ((const UNIX_OBJECT*) rdata_v)->path);
}

static int r_ipv4_rule_implies(const RDATA *rdata_v, const OBJECT *object_v)
{
    const IPV4_OBJECT *rdata = rdata_v;
    const IPV4_OBJECT *object = object_v;
    if (rdata->proto != -1 && rdata->proto != object->proto)
    {
        return 0;
    }
    if (rdata->port != -1 && rdata->port != object->port)
    {
        return 0;
    }
    if (rdata->addr && object->addr)
    {
        const char *raddr = rdata->addr;
        const char *oaddr = object->addr;
        // See explanation in fsmac implies for how this works
        if ((raddr[strlen(raddr) - 1] != '/' && strcmp(raddr, oaddr))
                || (raddr[strlen(raddr) - 1] == '/' && strncmp(raddr, oaddr, strlen(raddr) - 1)))
        {
            return 0;
        }
    }
    return 1;
}

static const char* r_ipv4_object_print(const OBJECT *object_v, IOBUFF *buff)
{
    const IPV4_OBJECT *object = object_v;
    iobuff_sprintf(buff, "%s %s:%d", lookup_protocol_name(object->proto), object->addr, object->port);
    return buff->data;
}

static RDATA* r_ipv4_rdata_import(const char *rdata)
{
    IPV4_OBJECT *object = kmalloc(sizeof(IPV4_OBJECT), GFP_KERNEL);
    object->proto = -1;
    char *delim = strchr(rdata, ':');
    if (!delim)
    {
        strncpy(object->addr, rdata, sizeof(object->addr));
        object->addr[sizeof(object->addr) - 1] = '\0';
        object->port = -1;
    }
    else
    {
        strncpy(object->addr, rdata, delim - rdata);
        object->addr[delim - rdata] = '\0';
        object->port = simple_strtol(delim + 1, NULL, 10);
    }
    return object; 
}

static void r_ipv4_rdata_export(const RDATA *rdata_v, IOBUFF *buff)
{
    const IPV4_OBJECT *rdata = rdata_v;
    iobuff_write_chars(buff, rdata->addr);
    if (rdata->port != -1)
    {
        iobuff_csprintf(buff, ":%d", rdata->port);
    }
}

static char* lookup_protocol_name(short proto)
{
    if (proto == SOL_TCP)
    {
        return "tcp";
    }
    else if (proto == SOL_UDP)
    {
        return "udp";
    }
    else if (proto == SOL_RAW)
    {
        return "raw";
    }
    else if (proto == SOL_NETLINK)
    {
        return "netlink";
    }
    else
    {
        return "other";
    }
}
