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

/* format.h
**
** format plugin header
**
*/
#ifndef __FORMAT_H__
#define __FORMAT_H__

#include "client.h"
#include "refbuf.h"
#include "httpp/httpp.h"

struct source_tag;
struct _mount_proxy;

typedef enum _format_type_tag
{
    FORMAT_ERROR, /* No format, source not processable */
    FORMAT_TYPE_OGG,
    FORMAT_TYPE_EBML,
    FORMAT_TYPE_GENERIC
} format_type_t;

typedef struct _format_plugin_tag
{
    format_type_t type;

    /* we need to know the mount to report statistics */
    char *mount : itype(_Ptr<char>);

    const char *contenttype : itype(_Nt_array_ptr<const char>);
    char *charset : itype(_Nt_array_ptr<char>);
    uint64_t read_bytes;
    uint64_t sent_bytes;

    refbuf_t * ((*get_buffer)(struct source_tag *)) : itype(_Ptr<_Ptr<refbuf_t> (_Ptr<struct source_tag>)>);
    int ((*write_buf_to_client)(client_t * client)) : itype(_Ptr<int (_Ptr<client_t> client)>);
    void ((*write_buf_to_file)(struct source_tag * source, refbuf_t * refbuf : itype(_Ptr<refbuf_t>))) : itype(_Ptr<void (_Ptr<struct source_tag> source, _Ptr<refbuf_t> refbuf)>);
    int ((*create_client_data)(struct source_tag * source, client_t * client)) : itype(_Ptr<int (_Ptr<struct source_tag> source, _Ptr<client_t> client)>);
    void ((*set_tag)(struct _format_plugin_tag * plugin, const char * tag, const char * value, const char * charset)) : itype(_Ptr<void (_Ptr<struct _format_plugin_tag> plugin, _Nt_array_ptr<const char> tag, _Nt_array_ptr<const char> value, _Nt_array_ptr<const char> charset)>);
    void ((*free_plugin)(struct _format_plugin_tag * self)) : itype(_Ptr<void (_Ptr<struct _format_plugin_tag> self)>);
    void ((*apply_settings)(client_t * client, struct _format_plugin_tag * format, struct _mount_proxy * mount)) : itype(_Ptr<void (_Ptr<client_t> client, _Ptr<struct _format_plugin_tag> format, _Ptr<struct _mount_proxy> mount)>);

    /* for internal state management */
    void *_state : itype(_Ptr<void>);
} format_plugin_t;

format_type_t format_get_type(const char *contenttype : itype(_Nt_array_ptr<const char>));
char *format_get_mimetype(format_type_t type);
int format_get_plugin(format_type_t type, struct source_tag *source : itype(_Ptr<struct source_tag>));

int format_generic_write_to_client (client_t *client : itype(_Ptr<client_t>));
int format_advance_queue (struct source_tag *source : itype(_Ptr<struct source_tag>), client_t *client : itype(_Ptr<client_t>));
int format_check_http_buffer (struct source_tag *source : itype(_Ptr<struct source_tag>), client_t *client : itype(_Ptr<client_t>));
int format_check_file_buffer (struct source_tag *source : itype(_Ptr<struct source_tag>), client_t *client : itype(_Ptr<client_t>));

void format_send_general_headers(format_plugin_t *format, 
        struct source_tag *source, client_t *client);

#endif  /* __FORMAT_H__ */

