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
 * Copyright 2011,      Philipp "ph3-der-loewe" Schafft <lion@lion.leolix.org>.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef HAVE_POLL
#include <sys/poll.h>
#endif

#ifndef _WIN32
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#define SCN_OFF_T SCNdMAX
#define PRI_OFF_T PRIdMAX
#else
#include <winsock2.h>
#include <windows.h>
#define fseeko fseek
#define SCN_OFF_T "ld"
#define PRI_OFF_T "ld"
#define snprintf _snprintf
#define strncasecmp _strnicmp
#ifndef S_ISREG
#define S_ISREG(mode)  ((mode) & _S_IFREG)
#endif
#endif

#include "thread/thread.h"
#include "avl/avl.h"
#include "httpp/httpp.h"
#include "net/sock.h"

#include "connection.h"
#include "global.h"
#include "refbuf.h"
#include "client.h"
#include "stats.h"
#include "format.h"
#include "logging.h"
#include "cfgfile.h"
#include "util.h"
#include "admin.h"
#include "compat.h"

#include "fserve.h"

#undef CATMODULE
#define CATMODULE "fserve"

#define BUFSIZE 4096

#pragma CHECKED_SCOPE on

static volatile int __inited = 0;

static _Ptr<fserve_t> active_list = NULL;
static _Ptr<fserve_t> pending_list = NULL;

static spin_t pending_lock;
static _Ptr<avl_tree> mimetypes = NULL;

static volatile int run_fserv = 0;
static unsigned int fserve_clients;
static int client_tree_changed=0;

#ifdef HAVE_POLL
static _Array_ptr<struct pollfd> ufds : count(fserve_clients) = NULL;
#else
static fd_set fds;
static sock_t fd_max = SOCK_ERROR;
#endif

typedef struct {
    char *ext : itype(_Nt_array_ptr<char>);
    char *type : itype(_Nt_array_ptr<char>);
} mime_type;

static void fserve_client_destroy(_Ptr<fserve_t> fclient);
static int _delete_mapping(void *mapping : itype(_Ptr<void>));
static void *fserv_thread_function(void *arg : itype(_Ptr<void>)) : itype(_Ptr<void>);

void fserve_initialize(void)
{
    _Ptr<ice_config_t> config = config_get_config();

    mimetypes = NULL;
    active_list = NULL;
    pending_list = NULL;
    thread_spin_create (&pending_lock);

    fserve_recheck_mime_types (config);
    config_release_config();

    __inited = 1;

    stats_event (NULL, "file_connections", "0");
    _Unchecked {ICECAST_LOG_INFO("file serving started");}
}

void fserve_shutdown(void)
{
    if (!__inited)
        return;

    thread_spin_lock (&pending_lock);
    run_fserv = 0;
    while (pending_list)
    {
        _Ptr<fserve_t> to_go = (_Ptr<fserve_t>)pending_list;
        pending_list = to_go->next;

        fserve_client_destroy (to_go);
    }
    while (active_list)
    {
        _Ptr<fserve_t> to_go = active_list;
        active_list = to_go->next;
        fserve_client_destroy (to_go);
    }

    if (mimetypes)
        _Unchecked {avl_tree_free<avl_tree>(mimetypes, _delete_mapping);}

    thread_spin_unlock (&pending_lock);
    thread_spin_destroy (&pending_lock);
    _Unchecked {ICECAST_LOG_INFO("file serving stopped");}
}

#ifdef HAVE_POLL
int fserve_client_waiting (void)
{
    _Ptr<fserve_t> fclient = NULL;
    unsigned int i = 0;

    /* only rebuild ufds if there are clients added/removed */
    if (client_tree_changed)
    {
        client_tree_changed = 0;
        ufds = realloc<struct pollfd>(ufds, fserve_clients * sizeof(struct pollfd));
        fclient = active_list;
        while (fclient)
        {
            ufds[i].fd = fclient->client->con->sock;
            ufds[i].events = POLLOUT;
            ufds[i].revents = 0;
            fclient = fclient->next;
            i++;
        }
    }
    int tmpRet;
    _Unchecked {if (!ufds)
    _Checked {
        thread_spin_lock (&pending_lock);
        run_fserv = 0;
        thread_spin_unlock (&pending_lock);
        return -1;
    }
    else if (poll((struct pollfd*)ufds, fserve_clients, 200) > 0)
    {
        /* mark any clients that are ready */
        _Checked {
        fclient = active_list;
        for (i=0; i<fserve_clients; i++)
        {
            if (ufds[i].revents & (POLLOUT|POLLHUP|POLLERR))
                fclient->ready = 1;
            fclient = fclient->next;
        }
        return 1;
        }
    }}
    return 0;
}
#else
int fserve_client_waiting (void)
{
    fserve_t *fclient;
    fd_set realfds;

    /* only rebuild fds if there are clients added/removed */
    if(client_tree_changed) {
        client_tree_changed = 0;
        FD_ZERO(&fds);
        fd_max = SOCK_ERROR;
        fclient = active_list;
        while (fclient) {
            FD_SET (fclient->client->con->sock, &fds);
            if (fclient->client->con->sock > fd_max || fd_max == SOCK_ERROR)
                fd_max = fclient->client->con->sock;
            fclient = fclient->next;
        }
    }
    /* hack for windows, select needs at least 1 descriptor */
    if (fd_max == SOCK_ERROR)
    {
        thread_spin_lock (&pending_lock);
        run_fserv = 0;
        thread_spin_unlock (&pending_lock);
        return -1;
    }
    else
    {
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        /* make a duplicate of the set so we do not have to rebuild it
         * each time around */
        memcpy(&realfds, &fds, sizeof(fd_set));
        if(select(fd_max+1, NULL, &realfds, NULL, &tv) > 0)
        {
            /* mark any clients that are ready */
            fclient = active_list;
            while (fclient)
            {
                if (FD_ISSET (fclient->client->con->sock, &realfds))
                    fclient->ready = 1;
                fclient = fclient->next;
            }
            return 1;
        }
    }
    return 0;
}
#endif

static int wait_for_fds(void)
{
    _Ptr<fserve_t> fclient = NULL;
    int ret;

    while (run_fserv)
    {
        /* add any new clients here */
        if (pending_list)
        {
            thread_spin_lock (&pending_lock);

            fclient = _Dynamic_bounds_cast<_Ptr<fserve_t>>(pending_list);
            while (fclient)
            {
                _Ptr<fserve_t> to_move = fclient;
                fclient = fclient->next;
                to_move->next = active_list;
                active_list = to_move;
                client_tree_changed = 1;
                fserve_clients++;
            }
            pending_list = NULL;
            thread_spin_unlock (&pending_lock);
        }
        /* drop out of here if someone is ready */
        ret = fserve_client_waiting();
        if (ret)
            return ret;
    }
    return -1;
}

static void *fserv_thread_function(void *arg : itype(_Ptr<void>)) : itype(_Ptr<void>)
{
    _Ptr<fserve_t> fclient = NULL;
    _Ptr<_Ptr<fserve_t>> trail = NULL;
    size_t bytes;

    while (1)
    {
        if (wait_for_fds() < 0)
            break;

        fclient = active_list;
        trail = &active_list;

        while (fclient)
        {
            /* process this client, if it is ready */
            if (fclient->ready)
            {
                _Ptr<client_t> client = fclient->client;
                _Ptr<refbuf_t> refbuf = client->refbuf;
                fclient->ready = 0;
                if (client->pos == refbuf->len)
                {
                    /* Grab a new chunk */
                    if (fclient->file)
                        bytes = fread (refbuf->data, 1, BUFSIZE, fclient->file);
                    else
                        bytes = 0;
                    if (bytes == 0)
                    {
                        if (refbuf->next == NULL)
                        {
                            _Ptr<fserve_t> to_go = fclient;
                            fclient = fclient->next;
                            *trail = fclient;
                            fserve_client_destroy (to_go);
                            fserve_clients--;
                            client_tree_changed = 1;
                            continue;
                        }
                        refbuf = refbuf->next;
                        client->refbuf->next = NULL;
                        refbuf_release (client->refbuf);
                        client->refbuf = refbuf;
                        bytes = refbuf->len;
                    }
                    refbuf->len = (unsigned int)bytes;
                    client->pos = 0;
                }

                /* Now try and send current chunk. */
                format_generic_write_to_client (client);

                if (client->con->error)
                {
                    _Ptr<fserve_t> to_go = fclient;
                    fclient = fclient->next;
                    *trail = fclient;
                    fserve_clients--;
                    fserve_client_destroy (to_go);
                    client_tree_changed = 1;
                    continue;
                }
            }
            trail = _Dynamic_bounds_cast<_Ptr<_Ptr<fserve_t>>>(&fclient->next);
            fclient = fclient->next;
        }
    }
    _Unchecked {ICECAST_LOG_DEBUG("fserve handler exit");}
    return NULL;
}

/* string returned needs to be free'd */
char *fserve_content_type(const char *path : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<char>)
{
    _Nt_array_ptr<char> ext = util_get_extension(path);
    mime_type exttype = {ext, NULL};
    _Ptr<void> result = NULL;
    _Nt_array_ptr<char> type = ((void *)0);

    thread_spin_lock (&pending_lock);
    if (mimetypes && !avl_get_by_key (mimetypes, _Dynamic_bounds_cast<_Ptr<void>>(&exttype), &result))
    {
        _Ptr<mime_type> mime = _Dynamic_bounds_cast<_Ptr<mime_type>>(result);
        type = ((_Nt_array_ptr<char> )strdup (mime->type));
    }
    else _Checked {
        /* Fallbacks for a few basic ones */
        if(!strcmp(ext, "ogg"))
            type = ((_Nt_array_ptr<char> )strdup ("application/ogg"));
        else if(!strcmp(ext, "mp3"))
            type = ((_Nt_array_ptr<char> )strdup ("audio/mpeg"));
        else if(!strcmp(ext, "html"))
            type = ((_Nt_array_ptr<char> )strdup ("text/html"));
        else if(!strcmp(ext, "css"))
            type = ((_Nt_array_ptr<char> )strdup ("text/css"));
        else if(!strcmp(ext, "txt"))
            type = ((_Nt_array_ptr<char> )strdup ("text/plain"));
        else if(!strcmp(ext, "jpg"))
            type = ((_Nt_array_ptr<char> )strdup ("image/jpeg"));
        else if(!strcmp(ext, "png"))
            type = ((_Nt_array_ptr<char> )strdup ("image/png"));
        else if(!strcmp(ext, "m3u"))
            type = ((_Nt_array_ptr<char> )strdup ("audio/x-mpegurl"));
        else if(!strcmp(ext, "aac"))
            type = ((_Nt_array_ptr<char> )strdup ("audio/aac"));
        else
            type = ((_Nt_array_ptr<char> )strdup ("application/octet-stream"));
    }
    thread_spin_unlock (&pending_lock);
    return type;
}

static void fserve_client_destroy(_Ptr<fserve_t> fclient)
{
    if (fclient)
    {
        if (fclient->file)
            fclose (fclient->file);
        _Unchecked {
        if (fclient->callback)
            fclient->callback (fclient->client, fclient->arg);
        else
            if (fclient->client)
                client_destroy (fclient->client);
        }
        free<fserve_t> (fclient);
    }
}


/* client has requested a file, so check for it and send the file.  Do not
 * refer to the client_t afterwards.  return 0 for success, -1 on error.
 */
int fserve_client_create (client_t *httpclient : itype(_Ptr<client_t>), const char *path : itype(_Nt_array_ptr<const char>))
{
    int bytes;
    struct stat file_buf;
    _Nt_array_ptr<const char> range = NULL;
    off_t new_content_len = 0;
    off_t rangenumber = 0, content_length;
    int rangeproblem = 0;
    int ret = 0;
    _Nt_array_ptr<char> fullpath = ((void *)0);
    int m3u_requested = 0, m3u_file_available = 1;
    _Nt_array_ptr<const char> xslt_playlist_requested : byte_count(8) = NULL;
    int xslt_playlist_file_available = 1;
    _Ptr<ice_config_t> config = ((void *)0);
    _Ptr<FILE> file = NULL;

    fullpath = util_get_path_from_normalised_uri (path);
    _Unchecked{ICECAST_LOG_INFO("checking for file %H (%H)", path, fullpath);}

    if (strcmp (util_get_extension (fullpath), "m3u") == 0)
        m3u_requested = 1;

    if (strcmp (util_get_extension (fullpath), "xspf") == 0)
        xslt_playlist_requested = "xspf.xsl";

    if (strcmp (util_get_extension (fullpath), "vclt") == 0)
        xslt_playlist_requested = "vclt.xsl";

    /* check for the actual file */
    if (stat (fullpath, &file_buf) != 0)
    {
        /* the m3u can be generated, but send an m3u file if available */
        if (m3u_requested == 0 && xslt_playlist_requested == NULL)
        {
            _Unchecked {ICECAST_LOG_WARN("req for file \"%H\" %s", fullpath, strerror (errno));}
            client_send_404 (httpclient, "The file you requested could not be found");
            free<char> (fullpath);
            return -1;
        }
        m3u_file_available = 0;
        xslt_playlist_file_available = 0;
    }

    httpclient->refbuf->len = PER_CLIENT_REFBUF_SIZE;

    if (m3u_requested && m3u_file_available == 0)
    {
        _Nt_array_ptr<const char> host = httpp_getvar (httpclient->parser, "host");
        _Nt_array_ptr<char> sourceuri = ((_Nt_array_ptr<char> )strdup (path));
        _Nt_array_ptr<char> dot = strrchr(sourceuri, '.');

        /* at least a couple of players (fb2k/winamp) are reported to send a 
         * host header but without the port number. So if we are missing the
         * port then lets treat it as if no host line was sent */
        if (host && strchr (host, ':') == NULL)
            host = NULL;

        *dot = 0;
        httpclient->respcode = 200;
        ret = util_http_build_header (httpclient->refbuf->data, BUFSIZE, 0,
	                              0, 200, NULL,
				      "audio/x-mpegurl", NULL, "", NULL);
        if (ret == -1 || ret >= (BUFSIZE - 512)) { /* we want at least 512 bytes left for the content of the playlist */
            _Unchecked {ICECAST_LOG_ERROR("Dropping client as we can not build response headers.");}
            client_send_500(httpclient, "Header generation failed.");
            return -1;
        }
        if (host == NULL)
        {
	    config = config_get_config();
            _Unchecked {snprintf (httpclient->refbuf->data + ret, BUFSIZE - ret,
                    "http://%s:%d%s\r\n", 
                    config->hostname, config->port,
                    sourceuri
                    );}
            config_release_config();
        }
        else
        {
	    _Unchecked {snprintf (httpclient->refbuf->data + ret, BUFSIZE - ret,
                    "http://%s%s\r\n", 
                    host, 
                    sourceuri
                    );}
        }
        httpclient->refbuf->len = strlen (httpclient->refbuf->data);
        fserve_add_client (httpclient, NULL);
        free<char> (sourceuri);
        free<char> (fullpath);
        return 0;
    }
    if (xslt_playlist_requested && xslt_playlist_file_available == 0)
    {
        _Ptr<struct _xmlDoc> doc = NULL;
        _Nt_array_ptr<char> reference = ((_Nt_array_ptr<char> )strdup (path));
        _Nt_array_ptr<char> eol = strrchr (reference, '.');
        if (eol)
            *eol = '\0';
        doc = stats_get_xml (0, reference);
        free<char> (reference);
        admin_send_response (doc, httpclient, TRANSFORMED, xslt_playlist_requested);
        _Unchecked {xmlFreeDoc((xmlDocPtr)doc);}
        return 0;
    }

    /* on demand file serving check */
    config = config_get_config();
    if (config->fileserve == 0)
    {
        _Unchecked {ICECAST_LOG_DEBUG("on demand file \"%H\" refused. Serving static files has been disabled in the config", fullpath);}
        client_send_404 (httpclient, "The file you requested could not be found");
        config_release_config();
        free<char> (fullpath);
        return -1;
    }
    config_release_config();

    if (S_ISREG (file_buf.st_mode) == 0)
    {
        client_send_404 (httpclient, "The file you requested could not be found");
        _Unchecked {ICECAST_LOG_WARN("found requested file but there is no handler for it: %H", fullpath);}
        free<char> (fullpath);
        return -1;
    }

    file = fopen (fullpath, "rb");
    if (file == NULL)
    {
        _Unchecked {ICECAST_LOG_WARN("Problem accessing file \"%H\"", fullpath);}
        client_send_404 (httpclient, "File not readable");
        free<char> (fullpath);
        return -1;
    }
    free<char> (fullpath);

    content_length = file_buf.st_size;
    range = httpp_getvar (httpclient->parser, "range");

    /* full http range handling is currently not done but we deal with the common case */
    if (range != NULL) {
        ret = 0;
        if (strncasecmp (range, "bytes=", 6) == 0)
            _Unchecked {ret = sscanf (range+6, "%" SCN_OFF_T "-", &rangenumber);}

        if (ret != 1) _Checked {
            /* format not correct, so lets just assume
               we start from the beginning */
            rangeproblem = 1;
        }
        if (rangenumber < 0) _Checked {
            rangeproblem = 1;
        }
        if (!rangeproblem) {
            _Unchecked {ret = fseeko ((FILE*)file, rangenumber, SEEK_SET);}
            if (ret != -1) _Checked {
                new_content_len = content_length - rangenumber;
                if (new_content_len < 0) {
                    rangeproblem = 1;
                }
            }
            else _Checked {
                rangeproblem = 1;
            }
            if (!rangeproblem) {
                off_t endpos = rangenumber+new_content_len-1;
                _Nt_array_ptr<char> type = ((void *)0);

                if (endpos < 0) _Checked {
                    endpos = 0;
                }
                httpclient->respcode = 206;
                type = fserve_content_type (path);
		bytes = util_http_build_header (httpclient->refbuf->data, BUFSIZE, 0,
		                                0, 206, NULL,
						type, NULL,
						NULL, NULL);
                if (bytes == -1 || bytes >= (BUFSIZE - 512)) { /* we want at least 512 bytes left */
                    _Unchecked {ICECAST_LOG_ERROR("Dropping client as we can not build response headers.");}
                    client_send_500(httpclient, "Header generation failed.");
                    return -1;
                }
                _Unchecked {bytes += snprintf (httpclient->refbuf->data + bytes, BUFSIZE - bytes,
                    "Accept-Ranges: bytes\r\n"
                    "Content-Length: %" PRI_OFF_T "\r\n"
                    "Content-Range: bytes %" PRI_OFF_T \
                    "-%" PRI_OFF_T "/%" PRI_OFF_T "\r\n\r\n",
                    new_content_len,
                    rangenumber,
                    endpos,
                    content_length);}
                free<char> (type);
            }
            else _Checked {
                goto fail;
            }
        }
        else _Checked {
            goto fail;
        }
    }
    else {
        _Nt_array_ptr<char> type = fserve_content_type(path);
        httpclient->respcode = 200;
	bytes = util_http_build_header (httpclient->refbuf->data, BUFSIZE, 0,
	                                0, 200, NULL,
					type, NULL,
					NULL, NULL);
        if (bytes == -1 || bytes >= (BUFSIZE - 512)) { /* we want at least 512 bytes left */
            _Unchecked {ICECAST_LOG_ERROR("Dropping client as we can not build response headers.");}
            client_send_500(httpclient, "Header generation failed.");
            return -1;
        }
        _Unchecked {bytes += snprintf (httpclient->refbuf->data + bytes, BUFSIZE - bytes,
            "Accept-Ranges: bytes\r\n"
            "Content-Length: %" PRI_OFF_T "\r\n\r\n",
            content_length);}
        free<char> (type);
    }
    httpclient->refbuf->len = bytes;
    httpclient->pos = 0;

    stats_event_inc (NULL, "file_connections");
    fserve_add_client (httpclient, file);

    return 0;

fail:
    fclose (file);
    client_send_error(httpclient, 416, 1, "Request Range Not Satisfiable\r\n");
    return -1;
}


/* Routine to actually add pre-configured client structure to pending list and
 * then to start off the file serving thread if it is not already running
 */
static void fserve_add_pending (_Ptr<fserve_t> fclient)
{
    thread_spin_lock (&pending_lock);
    fclient->next = (_Ptr<fserve_t>)pending_list;
    pending_list = fclient;
    if (run_fserv == 0)
    {
        run_fserv = 1;
        _Unchecked {ICECAST_LOG_DEBUG("fserve handler waking up");}
        _Unchecked {thread_create("File Serving Thread", fserv_thread_function, NULL, THREAD_DETACHED);}
    }
    thread_spin_unlock (&pending_lock);
}


/* Add client to fserve thread, client needs to have refbuf set and filled
 * but may provide a NULL file if no data needs to be read
 */
int fserve_add_client (client_t *client : itype(_Ptr<client_t>), FILE *file : itype(_Ptr<FILE>))
{
    _Ptr<fserve_t> fclient = calloc<fserve_t> (1, sizeof(fserve_t));

    _Unchecked {ICECAST_LOG_DEBUG("Adding client to file serving engine");}
    if (fclient == NULL)
    {
        client_send_404 (client, "memory exhausted");
        return -1;
    }
    fclient->file = file;
    fclient->client = client;
    fclient->ready = 0;
    fserve_add_pending (fclient);

    return 0;
}


/* add client to file serving engine, but just write out the buffer contents,
 * then pass the client to the callback with the provided arg
 */
_Unchecked _Itype_for_any(T) void fserve_add_client_callback (client_t *client : itype(_Ptr<client_t>), fserve_callback_t callback : itype(_Ptr<void (_Ptr<client_t>, void *)>), void *arg : itype(_Ptr<T>))
{
    _Ptr<fserve_t> fclient = calloc<fserve_t> (1, sizeof(fserve_t));

    ICECAST_LOG_DEBUG("Adding client to file serving engine");
    if (fclient == NULL)
    {
        client_send_404 (client, "memory exhausted");
        return;
    }
    fclient->file = NULL;
    fclient->client = client;
    fclient->ready = 0;
    fclient->callback = callback;
    fclient->arg = arg;

    fserve_add_pending (fclient);
}


static int _delete_mapping(void *mapping : itype(_Ptr<void>)) {
    _Ptr<mime_type> map = _Dynamic_bounds_cast<_Ptr<mime_type>>(mapping);
    free<char>(map->ext);
    free<char>(map->type);
    free<mime_type>(map);

    return 1;
}

static int _compare_mappings(void *arg : itype(_Ptr<void>), void *a : itype(_Ptr<void>), void *b : itype(_Ptr<void>))
{   
    int res; 
    res = strcmp((_Dynamic_bounds_cast<_Ptr<mime_type>>(a))->ext, (_Dynamic_bounds_cast<_Ptr<mime_type>>(b))->ext);
    return res;
}

void fserve_recheck_mime_types (ice_config_t *config : itype(_Ptr<ice_config_t>))
{
    _Ptr<FILE> mimefile = ((void *)0);
    char line _Nt_checked[4096 + 1];
    _Nt_array_ptr<char> type : count(4096) = ((void *)0);
_Nt_array_ptr<char> ext = ((void *)0);
_Nt_array_ptr<char> cur = ((void *)0);

    _Ptr<mime_type> mapping = NULL;
    _Ptr<avl_tree> new_mimetypes = ((void *)0);

    if (config->mimetypes_fn == NULL)
        return;
    mimefile = fopen (config->mimetypes_fn, "r");
    if (mimefile == NULL)
    _Checked {
        _Unchecked {ICECAST_LOG_WARN("Cannot open mime types file %s", config->mimetypes_fn);}
        return;
    }

    _Unchecked {new_mimetypes = avl_tree_new(_compare_mappings, NULL);}

    while(fgets(line, 4096, mimefile))
    _Checked {
        line[4095] = 0;

        if(*line == 0 || *line == '#')
            continue;

        type = line;

        cur = line;

        while(*cur != ' ' && *cur != '\t' && *cur)
            cur++;
        if(*cur == 0)
            continue;

        *cur++ = 0;

        while(1) {
            while(*cur == ' ' || *cur == '\t')
                cur++;
            if(*cur == 0)
                break;

            ext = cur;
            while(*cur != ' ' && *cur != '\t' && *cur != '\n' && *cur)
                cur++;
            *cur++ = 0;
            if(*ext)
            _Unchecked {
                _Ptr<void> tmp = NULL;
                /* Add a new extension->type mapping */
                mapping = malloc<mime_type>(sizeof(mime_type));
                mapping->ext = ((_Nt_array_ptr<char> )strdup(ext));
                mapping->type = ((_Nt_array_ptr<char> )strdup(type));
                if (!avl_get_by_key (new_mimetypes, mapping, &tmp))
                    avl_delete (new_mimetypes, mapping, _delete_mapping);
                avl_insert (new_mimetypes, mapping);
            }
        }
    }
    fclose(mimefile);

    thread_spin_lock (&pending_lock);
    if (mimetypes)
        _Unchecked {avl_tree_free(mimetypes, _delete_mapping);}
    mimetypes = new_mimetypes;
    thread_spin_unlock (&pending_lock);
}

