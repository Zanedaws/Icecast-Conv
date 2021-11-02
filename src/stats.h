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

#ifndef __STATS_H__
#define __STATS_H__

#include "cfgfile.h"
#include "connection.h"
#include "httpp/httpp.h"
#include "client.h"
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>


typedef struct _stats_node_tag
{
    char *name;
    char *value;
    int hidden;
} stats_node_t;

typedef struct _stats_event_tag
{
    char *source : itype(_Nt_array_ptr<char>);
    char *name : itype(_Nt_array_ptr<char>);
    char *value;
    int  hidden;
    int  action;

    struct _stats_event_tag *next : itype(_Ptr<struct _stats_event_tag>);
} stats_event_t;

typedef struct _stats_source_tag
{
    char *source;
    int  hidden;
    avl_tree *stats_tree : itype(_Ptr<avl_tree>);
} stats_source_t;

typedef struct _stats_tag
{
    avl_tree *global_tree : itype(_Ptr<avl_tree>);

    /* global stats
    start_time
    total_users
    max_users
    total_sources
    max_sources
    total_user_connections
    total_source_connections
    */

    avl_tree *source_tree : itype(_Ptr<avl_tree>);

    /* stats by source, and for stats
    start_time
    total_users
    max_users
    */

} stats_t;

void stats_initialize(void);
void stats_shutdown(void);

void stats_global(ice_config_t *config : itype(_Ptr<ice_config_t>));
stats_t *stats_get_stats(void) : itype(_Ptr<stats_t>);
refbuf_t *stats_get_streams(void) : itype(_Ptr<refbuf_t>);
void stats_clear_virtual_mounts (void);

void stats_event(const char *source : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>), const char *value : itype(_Nt_array_ptr<const char>));
void stats_event_conv(const char *mount : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>), const char *value : itype(_Nt_array_ptr<const char>), const char *charset : itype(_Nt_array_ptr<const char>));
void stats_event_args(const char *source : itype(_Nt_array_ptr<const char>), char *name : itype(_Nt_array_ptr<char>), char *format : itype(_Ptr<char>), ...);
void stats_event_inc(const char *source : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>) count(9));
void stats_event_add(const char *source : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>) count(9), unsigned long value);
void stats_event_sub(const char *source : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>) count(9), unsigned long value);
void stats_event_dec(const char *source : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>) count(9));
void stats_event_hidden (const char *source : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>) count(9), int hidden);
void stats_event_time (const char *mount : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>) count(12));
void stats_event_time_iso8601 (const char *mount : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>) count(20));

void *stats_connection(void *arg);
_Itype_for_any(T) void stats_callback (client_t *client : itype(_Ptr<client_t>), void *notused : itype(_Ptr<T>));

void stats_transform_xslt(client_t *client : itype(_Ptr<client_t>), const char *uri : itype(_Nt_array_ptr<const char>));
void stats_sendxml(client_t *client);
xmlDocPtr stats_get_xml(int show_hidden, const char *show_mount : itype(_Nt_array_ptr<const char>)) : itype(_Ptr<struct _xmlDoc>);
char *stats_get_value(const char *source : itype(_Nt_array_ptr<const char>), const char *name : itype(_Nt_array_ptr<const char>)) : itype(_Ptr<char>);

#endif  /* __STATS_H__ */

