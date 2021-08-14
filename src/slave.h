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

#ifndef __SLAVE_H__
#define __SLAVE_H__

#include "thread/thread.h"

typedef struct _relay_server {
    char *server : itype(_Nt_array_ptr<char>);
    int port;
    char *mount : itype(_Nt_array_ptr<char>);
    char *username : itype(_Nt_array_ptr<char>);
    char *password : itype(_Nt_array_ptr<char>);
    char *localmount : itype(_Nt_array_ptr<char>);
    char *bind : itype(_Nt_array_ptr<char>);
    struct source_tag *source : itype(_Ptr<struct source_tag>);
    int mp3metadata;
    int on_demand;
    int running;
    int cleanup;
    time_t start;
    thread_type *thread : itype(_Ptr<thread_type>);
    struct _relay_server *next : itype(_Ptr<struct _relay_server>);
} relay_server;


void slave_initialize(void);
void slave_shutdown(void);
void slave_update_all_mounts (void);
void slave_rebuild_mounts (void);
relay_server *relay_free (relay_server *relay : itype(_Ptr<relay_server>)) : itype(_Ptr<relay_server>);

#endif  /* __SLAVE_H__ */
