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
 * Copyright 2011-2012, Philipp "ph3-der-loewe" Schafft <lion@lion.leolix.org>,
 */

/* client.h
**
** client data structions and function definitions
**
*/
#ifndef __CLIENT_H__
#define __CLIENT_H__

#include "connection.h"
#include "refbuf.h"
#include "httpp/httpp.h"

typedef struct _client_tag
{
    /* the client's connection */
    connection_t *con : itype(_Ptr<connection_t>);
    /* the client's http headers */
    http_parser_t *parser : itype(_Ptr<http_parser_t>);

    /* http response code for this client */
    int respcode;

    /* auth completed, 0 not yet, 1 passed */
    int authenticated;

    /* is client getting intro data */
    long intro_offset;

    /* where in the queue the client is */
    refbuf_t *refbuf : itype(_Ptr<refbuf_t>);

    /* position in first buffer */
    unsigned int pos;

    /* auth used for this client */
    struct auth_tag *auth : itype(_Ptr<struct auth_tag>);

    /* Client username, if authenticated */
    char *username : itype(_Nt_array_ptr<char>);

    /* Client password, if authenticated */
    char *password : itype(_Nt_array_ptr<char>);

    /* Format-handler-specific data for this client */
    void *format_data : itype(_Array_ptr<void>);

    /* function to call to release format specific resources */
    void ((*free_client_data)(struct _client_tag * client)) : itype(_Ptr<void (_Ptr<struct _client_tag> client)>);

    /* write out data associated with client */
    int ((*write_to_client)(struct _client_tag * client)) : itype(_Ptr<int (_Ptr<struct _client_tag> client)>);

    /* function to check if refbuf needs updating */
    int ((*check_buffer)(struct source_tag * source, struct _client_tag * client)) : itype(_Ptr<int (_Ptr<struct source_tag> source, _Ptr<struct _client_tag> client)>);

} client_t;

int client_create (client_t **c_ptr : itype(_Ptr<_Ptr<client_t>>), connection_t *con : itype(_Ptr<connection_t>), http_parser_t *parser : itype(_Ptr<http_parser_t>));
void client_destroy(client_t *client : itype(_Ptr<client_t>));
void client_send_100(client_t *client : itype(_Ptr<client_t>));
void client_send_404(client_t *client : itype(_Ptr<client_t>), const char *message : itype(_Nt_array_ptr<const char>));
void client_send_401(client_t *client : itype(_Ptr<client_t>));
void client_send_403(client_t *client : itype(_Ptr<client_t>), const char *message : itype(_Nt_array_ptr<const char>));
void client_send_400(client_t *client : itype(_Ptr<client_t>), const char *message : itype(_Nt_array_ptr<const char>));
void client_send_500(client_t *client : itype(_Ptr<client_t>), const char *message : itype(_Nt_array_ptr<const char>) count(20));
_Itype_for_any(T) int client_send_bytes (client_t *client : itype(_Ptr<client_t>), const void *buf : itype(_Array_ptr<const T>) count(20), unsigned len);
int client_read_bytes (client_t *client : itype(_Ptr<client_t>), void *buf : itype(_Array_ptr<void>), unsigned len);
void client_set_queue (client_t *client : itype(_Ptr<client_t>), refbuf_t *refbuf : itype(_Ptr<refbuf_t>));
int client_check_source_auth (client_t *client : itype(_Ptr<client_t>), const char *mount : itype(_Nt_array_ptr<const char>));
void client_send_error(client_t *client : itype(_Ptr<client_t>), int status, int plain, const char *message : itype(_Nt_array_ptr<const char>));

#endif  /* __CLIENT_H__ */
