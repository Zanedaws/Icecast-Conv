/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2000-2004, Jack Moffitt <jack@xiph.org, 
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>
 *                      and others (see AUTHORS for details).
 */

#ifndef __CONNECTION_H__
#define __CONNECTION_H__

#include <sys/types.h>
#include <time.h>
#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include "compat.h"
#include "httpp/httpp.h"
#include "thread/thread.h"
#include "net/sock.h"

struct _client_tag;
struct source_tag;
struct ice_config_tag;

typedef struct connection_tag
{
    unsigned long id;

    time_t con_time;
    time_t discon_time;
    uint64_t sent_bytes;

    sock_t sock;
    sock_t serversock;
    int error;

#ifdef HAVE_OPENSSL
    SSL *ssl;   /* SSL handler */
#endif
    int ((*send)(struct connection_tag * handle, const void * buf, size_t len)) : itype(_Ptr<int (_Ptr<struct connection_tag> handle, const void *buf, size_t len)>);
    int ((*read)(struct connection_tag * handle, void * buf, size_t len)) : itype(_Ptr<int (_Ptr<struct connection_tag> handle, void *buf, size_t len)>);

    char *ip;
    char *host : itype(_Ptr<char>);

} connection_t;

void connection_initialize(void);
void connection_shutdown(void);
void connection_accept_loop(void);
int  connection_setup_sockets (struct ice_config_tag *config : itype(_Ptr<struct ice_config_tag>));
void connection_close(connection_t *con : itype(_Ptr<connection_t>));
connection_t *connection_create(sock_t sock, sock_t serversock, char *ip : itype(_Nt_array_ptr<char>)) : itype(_Ptr<connection_t>);
int connection_complete_source (struct source_tag *source : itype(_Ptr<struct source_tag>), int response);

int connection_check_pass (http_parser_t *parser : itype(_Ptr<http_parser_t>), const char *user : itype(_Nt_array_ptr<const char>) byte_count(6), const char *pass : itype(_Nt_array_ptr<const char>));
int connection_check_relay_pass(http_parser_t *parser : itype(_Ptr<http_parser_t>));
int connection_check_admin_pass(http_parser_t *parser : itype(_Ptr<http_parser_t>));

extern rwlock_t _source_shutdown_rwlock;

#endif  /* __CONNECTION_H__ */
