#ifndef NETMAC_H
#define	NETMAC_H

#include <net/sock.h>                                           /* struct sock */
#include <linux/net.h>                                          /* struct socket */
#include "shared.h"

#define SOCKET struct socket
#define SOCKADDR struct sockaddr

int netmac_init(void);

void netmac_cleanup(void);

int socket_connect_hook(SOCKET *sock, SOCKADDR *address, int addrlen);

int socket_bind_hook(SOCKET *sock, SOCKADDR *address, int addrlen);

int socket_accept_hook(SOCKET *sock, SOCKET *newsock);

#endif
