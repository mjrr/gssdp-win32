/* 
 * Copyright (C) 2006, 2007, 2008 OpenedHand Ltd.
 * Copyright (C) 2009 Nokia Corporation, all rights reserved.
 *
 * Author: Jorn Baayen <jorn@openedhand.com>
 *         Zeeshan Ali (Khattak) <zeeshanak@gnome.org>
 *                               <zeeshan.ali@nokia.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <config.h>
#include <glib.h>
#ifdef G_OS_WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef int socklen_t;
#else
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "gssdp-socket-source.h"
#include "gssdp-protocol.h"

#ifdef G_OS_WIN32
static int
inet_aton (const gchar *src, struct in_addr *addr)

{
        int ret = inet_addr (src);
        if (ret == INADDR_NONE) {
                if(strcmp( "255.255.255.255", src))
                        return 0;
                addr->s_addr = ret;
                return 1;
        }
        addr->s_addr = ret;
        return 1;
}
#endif

/**
 * gssdp_socket_source_new
 *
 * Return value: A new #GSSDPSocketSource
 **/
GSSDPSocketSource *
gssdp_socket_source_new (GSSDPSocketSourceType type,
                         const char           *host_ip)
{
        GSSDPSocketSource *socket_source;
        struct sockaddr_in bind_addr;
        struct in_addr iface_addr;
        struct ip_mreq mreq;
        gboolean boolean = TRUE;
        guchar ttl = 4;
        int res;

        /* Create source */
        socket_source = g_slice_new0(GSSDPSocketSource);

        /* Create socket */
        socket_source->poll_fd.fd = socket (AF_INET,
                                            SOCK_DGRAM,
                                            IPPROTO_UDP);
        if (socket_source->poll_fd.fd == -1)
                goto error;

        socket_source->poll_fd.events = G_IO_IN | G_IO_ERR;

        /* Enable broadcasting */
        res = setsockopt (socket_source->poll_fd.fd, 
                          SOL_SOCKET,
                          SO_BROADCAST,
                          (char *) &boolean,
                          sizeof (boolean));
        if (res == -1)
                goto error;

        /* TTL */
        res = setsockopt (socket_source->poll_fd.fd,
                          IPPROTO_IP,
                          IP_MULTICAST_TTL,
                          &ttl,
                          sizeof (ttl));
        if (res == -1)
                goto error;

        memset (&bind_addr, 0, sizeof (bind_addr));
        bind_addr.sin_family = AF_INET;

        res = inet_aton (host_ip, &iface_addr);
        if (res == 0)
                goto error;

        /* Set up additional things according to the type of socket desired */
        if (type == GSSDP_SOCKET_SOURCE_TYPE_MULTICAST) {
                /* Allow multiple sockets to use the same PORT number */
                res = setsockopt (socket_source->poll_fd.fd,
                                  SOL_SOCKET,
                                  SO_REUSEADDR,
                                  (char *) &boolean,
                                  sizeof (boolean));
                if (res == -1)
                        goto error;

                /* Enable multicast loopback */
                res = setsockopt (socket_source->poll_fd.fd,
                                  IPPROTO_IP,
                                  IP_MULTICAST_LOOP,
                                  (char *) &boolean,
                                  sizeof (boolean));
                if (res == -1)
                       goto error;

                bind_addr.sin_port = htons (SSDP_PORT);
#ifdef G_OS_WIN32
                /* On windows we apparently cannot bind to multicast adresses */
                memcpy (&(bind_addr.sin_addr),
                        &iface_addr,
                        sizeof (struct in_addr));
#else
                res = inet_aton (SSDP_ADDR, &(bind_addr.sin_addr));
                if (res == 0)
                        goto error;
#endif
        } else {
                bind_addr.sin_port = 0;
                memcpy (&(bind_addr.sin_addr),
                        &iface_addr,
                        sizeof (struct in_addr));
        }

        /* Bind to requested port and address */
        res = bind (socket_source->poll_fd.fd,
                    (struct sockaddr *) &bind_addr,
                    sizeof (bind_addr));
        if (res == -1)
                goto error;
        /* on windows, joining multicast groups has to happen after
         * the call to bind */

        if (type == GSSDP_SOCKET_SOURCE_TYPE_MULTICAST) {
                /* Set the interface */
                /* on windows needs to be done after bind to get an IGMP
                 * message */
                res = setsockopt (socket_source->poll_fd.fd,
                                  IPPROTO_IP,
                                  IP_MULTICAST_IF,
                                  (char *) &iface_addr,
                                  sizeof (struct in_addr));
                if (res == -1)
                        goto error;

                /* Subscribe to multicast channel */
                res = inet_aton (SSDP_ADDR, &(mreq.imr_multiaddr));
                if (res == 0)
                        goto error;

                memcpy (&(mreq.imr_interface),
                        &iface_addr,
                        sizeof (struct in_addr));

                res = setsockopt (socket_source->poll_fd.fd,
                                  IPPROTO_IP,
                                  IP_ADD_MEMBERSHIP,
                                  (char *) &mreq,
                                  sizeof (mreq));
                if (res == -1)
                        goto error;
        }

#ifdef G_OS_WIN32
        socket_source->channel = g_io_channel_win32_new_socket(socket_source->poll_fd.fd);
#else
        socket_source->channel = g_io_channel_unix_new(socket_source->poll_fd.fd);
#endif
        socket_source->source = g_io_create_watch(socket_source->channel, socket_source->poll_fd.events);

        return socket_source;

error:
        return NULL;
}

/**
 * gssdp_socket_source_get_fd
 *
 * Return value: The socket's FD.
 **/
int
gssdp_socket_source_get_fd (GSSDPSocketSource *socket_source)
{
        g_return_val_if_fail (socket_source != NULL, -1);
        
        return socket_source->poll_fd.fd;
}

void
gssdp_socket_source_destroy(GSSDPSocketSource *socket_source)
{
        g_return_if_fail (socket_source != NULL);
        g_source_destroy(socket_source->source);
        g_io_channel_shutdown(socket_source->channel, TRUE, NULL);
        g_io_channel_unref(socket_source->channel);
        g_slice_free(GSSDPSocketSource, socket_source);
}
