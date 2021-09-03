/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2000-2004, Jack Moffitt <jack@xiph.org>, 
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>
 *                      and others (see AUTHORS for details).
 * Copyright 2011,      Dave 'justdave' Miller <justdave@mozilla.com>.
 * Copyright 2011-2014, Philipp "ph3-der-loewe" Schafft <lion@lion.leolix.org>,
 */

#ifndef __CFGFILE_H__
#define __CFGFILE_H__

#define CONFIG_EINSANE -1
#define CONFIG_ENOROOT -2
#define CONFIG_EBADROOT -3
#define CONFIG_EPARSE -4

#define MAX_YP_DIRECTORIES 25

struct _mount_proxy;

#include "thread/thread.h"
#include "avl/avl.h"
#include "auth.h"
#include "global.h"
#include "connection.h"

#define XMLSTR(str) ((xmlChar *)(str)) 

typedef enum _http_header_type {
 /* static: headers are passed as is to the client. */
 HTTP_HEADER_TYPE_STATIC
} http_header_type;

typedef struct ice_config_http_header_tag {
    /* type of this header. See http_header_type */
    http_header_type type;

    /* name and value of the header */
    char *name : itype(_Nt_array_ptr<char>);
    char *value : itype(_Nt_array_ptr<char>);

    /* filters */
    int status;

    /* link to the next list element */
    struct ice_config_http_header_tag *next : itype(_Ptr<struct ice_config_http_header_tag>);
} ice_config_http_header_t;

typedef struct ice_config_dir_tag {
    char *host;
    int touch_interval;
    struct ice_config_dir_tag *next : itype(_Ptr<struct ice_config_dir_tag>);
} ice_config_dir_t;

typedef struct _config_options {
    char *name;
    char *value;
    struct _config_options *next : itype(_Ptr<struct _config_options>);
} config_options_t;

typedef enum _mount_type {
 MOUNT_TYPE_NORMAL,
 MOUNT_TYPE_DEFAULT
} mount_type;

typedef struct _mount_proxy {
    char *mountname : itype(_Nt_array_ptr<char>); /* The mountpoint this proxy is used for */

    mount_type mounttype; /* The type of the mount point */

    char *username : itype(_Nt_array_ptr<char>); /* Username and password for this mountpoint. If unset, */
    char *password : itype(_Nt_array_ptr<char>); /* falls back to global source password */

    char *dumpfile : itype(_Nt_array_ptr<char>); /* Filename to dump this stream to (will be appended). NULL
                       to not dump. */
    char *intro_filename : itype(_Nt_array_ptr<char>);   /* Send contents of file to client before the stream */
    int fallback_when_full; /* switch new listener to fallback source
                               when max listeners reached */
    int max_listeners; /* Max listeners for this mountpoint only. -1 to not 
                          limit here (i.e. only use the global limit) */
    char *fallback_mount : itype(_Nt_array_ptr<char>); /* Fallback mountname */

    int fallback_override; /* When this source arrives, do we steal back
                              clients from the fallback? */
    int no_mount; /* Do we permit direct requests of this mountpoint? (or only
                     indirect, through fallbacks) */
    int burst_size; /* amount to send to a new client if possible, -1 take
                     * from global setting */
    unsigned int queue_size_limit;
    int hidden; /* Do we list this on the xsl pages */
    unsigned int source_timeout;  /* source timeout in seconds */
    char *charset : itype(_Nt_array_ptr<char>);  /* character set if not utf8 */
    int mp3_meta_interval; /* outgoing per-stream metadata interval */

    ice_config_http_header_t *http_headers : itype(_Ptr<ice_config_http_header_t>); /* additional HTTP headers */

    char *auth_type : itype(_Nt_array_ptr<char>); /* Authentication type */
    struct auth_tag *auth : itype(_Ptr<struct auth_tag>);
    char *cluster_password : itype(_Nt_array_ptr<char>);
    config_options_t *auth_options : itype(_Ptr<config_options_t>); /* Options for this type */
    char *on_connect : itype(_Nt_array_ptr<char>);
    char *on_disconnect : itype(_Nt_array_ptr<char>);
    unsigned int max_listener_duration;

    char *stream_name : itype(_Nt_array_ptr<char>);
    char *stream_description : itype(_Nt_array_ptr<char>);
    char *stream_url : itype(_Nt_array_ptr<char>);
    char *stream_genre : itype(_Nt_array_ptr<char>);
    char *bitrate : itype(_Nt_array_ptr<char>);
    char *type : itype(_Nt_array_ptr<char>);
    char *subtype : itype(_Nt_array_ptr<char>);
    int yp_public;

    struct _mount_proxy *next : itype(_Ptr<struct _mount_proxy>);
} mount_proxy;

typedef struct _aliases {
    char *source : itype(_Nt_array_ptr<char>);
    char *destination : itype(_Nt_array_ptr<char>);
    int port;
    char *bind_address : itype(_Nt_array_ptr<char>);
    struct _aliases *next : itype(_Ptr<struct _aliases>);
} aliases;

typedef struct _listener_t {
    struct _listener_t *next : itype(_Ptr<struct _listener_t>);
    int port;
    int so_sndbuf;
    char *bind_address : itype(_Nt_array_ptr<char>);
    int shoutcast_compat;
    char *shoutcast_mount : itype(_Nt_array_ptr<char>);
    int ssl;
} listener_t;

typedef struct ice_config_tag {
    char *config_filename : itype(_Nt_array_ptr<char>);

    char *location : itype(_Nt_array_ptr<char>);
    char *admin : itype(_Nt_array_ptr<char>);

    int client_limit;
    int source_limit;
    unsigned int queue_size_limit;
    int threadpool_size;
    unsigned int burst_size;
    int client_timeout;
    int header_timeout;
    int source_timeout;
    int ice_login;
    int fileserve;
    int on_demand; /* global setting for all relays */

    char *shoutcast_mount : itype(_Nt_array_ptr<char>);
    char *source_password : itype(_Nt_array_ptr<char>);
    char *admin_username : itype(_Nt_array_ptr<char>);
    char *admin_password : itype(_Nt_array_ptr<char>);
    char *relay_username : itype(_Nt_array_ptr<char>);
    char *relay_password : itype(_Nt_array_ptr<char>);

    int touch_interval;
    ice_config_dir_t *dir_list : itype(_Ptr<ice_config_dir_t>);

    char *hostname : itype(_Nt_array_ptr<char>);
    int port;
    char *mimetypes_fn : itype(_Nt_array_ptr<char>);

    listener_t *listen_sock : itype(_Ptr<listener_t>);
    unsigned int listen_sock_count;

    char *master_server : itype(_Nt_array_ptr<char>);
    int master_server_port;
    int master_update_interval;
    char *master_username : itype(_Nt_array_ptr<char>);
    char *master_password : itype(_Nt_array_ptr<char>);

    ice_config_http_header_t *http_headers : itype(_Ptr<ice_config_http_header_t>);

    relay_server *relay : itype(_Ptr<relay_server>);

    mount_proxy *mounts : itype(_Ptr<mount_proxy>);

    char *server_id : itype(_Nt_array_ptr<char>);
    char *base_dir : itype(_Nt_array_ptr<char>);
    char *log_dir : itype(_Nt_array_ptr<char>);
    char *pidfile : itype(_Nt_array_ptr<char>);
    char *banfile : itype(_Nt_array_ptr<char>);
    char *allowfile : itype(_Nt_array_ptr<char>);
    char *cert_file : itype(_Nt_array_ptr<char>);
    char *cipher_list : itype(_Nt_array_ptr<char>);
    char *webroot_dir : itype(_Nt_array_ptr<char>);
    char *adminroot_dir : itype(_Nt_array_ptr<char>);
    aliases *aliases : itype(_Ptr<aliases>);

    char *access_log : itype(_Nt_array_ptr<char>);
    char *error_log : itype(_Nt_array_ptr<char>);
    char *playlist_log : itype(_Nt_array_ptr<char>);
    int loglevel;
    int logsize;
    int logarchive;

    int chroot;
    int chuid;
    char *user : itype(_Nt_array_ptr<char>);
    char *group : itype(_Nt_array_ptr<char>);
    char * yp_url[25] : itype(char * _Checked[MAX_YP_DIRECTORIES]);
    int yp_url_timeout[25] : itype(int _Checked[MAX_YP_DIRECTORIES]);
    int yp_touch_interval[25] : itype(int _Checked[MAX_YP_DIRECTORIES]);
    int num_yp_directories;
} ice_config_t;

typedef struct {
    rwlock_t config_lock;
    mutex_t relay_lock;
} ice_config_locks;

void config_initialize(void);
void config_shutdown(void);

int config_parse_file(const char *filename : itype(_Nt_array_ptr<const char>) count(512), ice_config_t *configuration : itype(_Array_ptr<ice_config_t>));
int config_initial_parse_file(const char *filename : itype(_Nt_array_ptr<const char>) count(512));
int config_parse_cmdline(int arg, char **argv : itype(_Ptr<_Nt_array_ptr<char>>));
void config_set_config(ice_config_t *config : itype(_Array_ptr<ice_config_t>));
listener_t *config_clear_listener(listener_t *listener : itype(_Ptr<listener_t>)) : itype(_Ptr<listener_t>);
void config_clear(ice_config_t *config : itype(_Array_ptr<ice_config_t>));
mount_proxy *config_find_mount(ice_config_t *config : itype(_Ptr<ice_config_t>), const char *mount : itype(_Nt_array_ptr<const char>), mount_type type) : itype(_Ptr<mount_proxy>);
listener_t *config_get_listen_sock(ice_config_t *config : itype(_Ptr<ice_config_t>), connection_t *con : itype(_Ptr<connection_t>)) : itype(_Ptr<listener_t>);

int config_rehash(void);

ice_config_locks *config_locks(void) : itype(_Ptr<ice_config_locks>);

ice_config_t *config_get_config(void) : itype(_Ptr<ice_config_t>);
ice_config_t *config_grab_config(void) : itype(_Ptr<ice_config_t>);
void config_release_config(void);

/* To be used ONLY in one-time startup code */
ice_config_t *config_get_config_unlocked(void) : itype(_Ptr<ice_config_t>);

#endif  /* __CFGFILE_H__ */
