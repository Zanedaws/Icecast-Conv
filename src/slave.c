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

/* -*- c-basic-offset: 4; indent-tabs-mode: nil; -*- */
/* slave.c
 * by Ciaran Anscomb <ciaran.anscomb@6809.org.uk>
 *
 * Periodically requests a list of streams from a master server
 * and creates source threads for any it doesn't already have.
 * */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#define snprintf _snprintf
define strcasecmp stricmp
#define strncasecmp strnicmp
#endif

#include "compat.h"

#include <libxml/uri.h>
#include "thread/thread.h"
#include "avl/avl.h"
#include "net/sock.h"
#include "httpp/httpp.h"

#include "cfgfile.h"
#include "global.h"
#include "util.h"
#include "connection.h"
#include "refbuf.h"
#include "client.h"
#include "stats.h"
#include "logging.h"
#include "source.h"
#include "format.h"
#include "event.h"

#define CATMODULE "slave"

#pragma CHECKED_SCOPE on

static void *_slave_thread(void *arg : itype(_Ptr<void>)) : itype(_Ptr<void>);
static _Ptr<thread_type> _slave_thread_id;
static int slave_running = 0;
static volatile int update_settings = 0;
static volatile int update_all_mounts = 0;
static volatile unsigned int max_interval = 0;
static mutex_t _slave_mutex; // protects update_settings, update_all_mounts, max_interval

relay_server *relay_free(relay_server *relay : itype(_Ptr<relay_server>)) : itype(_Ptr<relay_server>)
{
    _Ptr<relay_server> next = relay->next;
    _Unchecked {ICECAST_LOG_DEBUG("freeing relay %s", relay->localmount);}
    if (relay->source)
       source_free_source ((relay->source));
    _Unchecked {xmlFree ((void*)relay->server);
    xmlFree ((void*)relay->mount);
    xmlFree ((void*)relay->localmount);}
    if (relay->username)
        _Unchecked {xmlFree ((void*)relay->username);}
    if (relay->password)
        _Unchecked {xmlFree ((void*)relay->password);}
    free<relay_server> (relay);
    return next;
}


relay_server *relay_copy(relay_server *r : itype(_Ptr<relay_server>)) : itype(_Ptr<relay_server>)
{
    _Ptr<relay_server> copy = calloc<relay_server> (1, sizeof (relay_server));

    if (copy)
    {
        _Unchecked {copy->server = _Assume_bounds_cast<_Nt_array_ptr<char>>(xmlCharStrdup (r->server), byte_count(4096));
        copy->mount = _Assume_bounds_cast<_Nt_array_ptr<char>>(xmlCharStrdup (r->mount), byte_count(4096));;
        copy->localmount = _Assume_bounds_cast<_Nt_array_ptr<char>>(xmlCharStrdup (r->localmount), byte_count(4096));
        if (r->username)
            copy->username = _Assume_bounds_cast<_Nt_array_ptr<char>>(xmlCharStrdup (r->username), byte_count(4096));
        if (r->password)
            copy->password = _Assume_bounds_cast<_Nt_array_ptr<char>>(xmlCharStrdup (r->password), byte_count(4096));}
        copy->port = r->port;
        copy->mp3metadata = r->mp3metadata;
        copy->on_demand = r->on_demand;
    }
    return copy;
}


/* force a recheck of the relays. This will recheck the master server if
 * this is a slave and rebuild all mountpoints in the stats tree
 */
void slave_update_all_mounts (void)
{
    thread_mutex_lock(&_slave_mutex);
    max_interval = 0;
    update_all_mounts = 1;
    update_settings = 1;
    thread_mutex_unlock(&_slave_mutex);
}


/* Request slave thread to check the relay list for changes and to
 * update the stats for the current streams.
 */
void slave_rebuild_mounts (void)
{
    thread_mutex_lock(&_slave_mutex);
    update_settings = 1;
    thread_mutex_unlock(&_slave_mutex);
}


void slave_initialize(void)
{
    if (slave_running)
        return;

    slave_running = 1;
    max_interval = 0;
    thread_mutex_create (&_slave_mutex);
    _Unchecked {_slave_thread_id = thread_create("Slave Thread", _slave_thread, NULL, THREAD_ATTACHED);}
}


void slave_shutdown(void)
{
    if (!slave_running)
        return;
    slave_running = 0;
    _Unchecked {ICECAST_LOG_DEBUG("waiting for slave thread");}
    thread_join (_slave_thread_id);
}


/* Actually open the connection and do some http parsing, handle any 302
 * responses within here.
 */
static _Ptr<client_t> open_relay_connection(_Ptr<relay_server> relay)
{
    int redirects = 0;
    _Nt_array_ptr<char> server_id = NULL;
    _Ptr<ice_config_t> config = ((void *)0);
    _Ptr<http_parser_t> parser = NULL;
    _Ptr<connection_t> con =NULL;
    _Nt_array_ptr<char> server = strdup (relay->server);
    _Nt_array_ptr<char> mount = strdup (relay->mount);
    int port = relay->port;
    _Nt_array_ptr<char> auth_header = NULL;
    char header _Nt_checked[4096 + 1];

    config = config_get_config ();
    server_id = strdup (config->server_id);
    config_release_config ();

    /* build any authentication header before connecting */
    if (relay->username && relay->password)
    {
        _Nt_array_ptr<char> esc_authorisation = ((void *)0);
        unsigned len = strlen(relay->username) + strlen(relay->password) + 2;

        auth_header = _Dynamic_bounds_cast<_Nt_array_ptr<char>> (malloc<char> (len + 1), byte_count(len + 1));
        _Unchecked {snprintf ((char*)auth_header, len, "%s:%s", relay->username, relay->password);}
        esc_authorisation = util_base64_encode(auth_header);
        free<char>(auth_header);
        len = strlen (esc_authorisation) + 24;
        auth_header = _Dynamic_bounds_cast<_Nt_array_ptr<char>> (malloc<char> (len + 1), byte_count(len + 1));
        _Unchecked {snprintf ((char*)auth_header, len,
                "Authorization: Basic %s\r\n", esc_authorisation);}
        free<char>(esc_authorisation);
    }
    else
        auth_header = strdup ("");

    while (redirects < 10)
    {
        sock_t streamsock;

        _Unchecked {ICECAST_LOG_INFO("connecting to %s:%d", server, port);}

        streamsock = sock_connect_wto_bind (server, port, relay->bind, 10);
        if (streamsock == SOCK_ERROR)
        {
            _Unchecked {ICECAST_LOG_WARN("Failed to connect to %s:%d", server, port);}
            break;
        }
        con = connection_create (streamsock, -1, ((_Nt_array_ptr<char> )strdup (server)));

        /* At this point we may not know if we are relaying an mp3 or vorbis
         * stream, but only send the icy-metadata header if the relay details
         * state so (the typical case).  It's harmless in the vorbis case. If
         * we don't send in this header then relay will not have mp3 metadata.
         */
        _Unchecked {sock_write(streamsock, "GET %s HTTP/1.0\r\n"
                "User-Agent: %s\r\n"
                "Host: %s\r\n"
                "%s"
                "%s"
                "\r\n",
                mount,
                server_id,
                server,
                relay->mp3metadata?"Icy-MetaData: 1\r\n":"",
                auth_header);}
        memset (header, 0, 4096);
        if (util_read_header (con->sock, header, 4096, READ_ENTIRE_HEADER) == 0)
        _Checked {
            _Unchecked {ICECAST_LOG_ERROR("Header read failed for %s (%s:%d%s)", relay->localmount, server, port, mount);}
            break;
        }
        parser = httpp_create_parser();
        httpp_initialize (parser, NULL);
        if (! httpp_parse_response (parser, header, strlen(header), relay->localmount))
        _Checked {
            _Unchecked {ICECAST_LOG_ERROR("Error parsing relay request for %s (%s:%d%s)", relay->localmount,
                    server, port, mount);}
            break;
        }
        if (strcmp (httpp_getvar (parser, HTTPP_VAR_ERROR_CODE), "302") == 0)
        {
            /* better retry the connection again but with different details */
            _Nt_array_ptr<const char> uri = ((void *)0);
_Nt_array_ptr<const char> mountpoint = ((void *)0);

            int len;

            uri = httpp_getvar (parser, "location");
            _Unchecked {ICECAST_LOG_INFO("redirect received %s", uri);}
            if (strncmp (uri, "http://", 7) != 0)
                break;
            uri += 7;
            mountpoint = ((_Nt_array_ptr<char> )strchr (uri, '/'));
            free<char> (mount);
            if (mountpoint)
                mount = strdup (mountpoint);
            else
                mount = strdup ("/");

            len = strcspn (uri, ":/");
            port = 80;
            if (uri [len] == ':')
                port = atoi (uri+len+1);
            free<char> (server);
            server = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(calloc<char> (1, len+1), byte_count(10));
            _Unchecked {strncpy ((char*)server, (char*)uri, len);} //unchecked due to dynamic copy length
            connection_close (con);
            httpp_destroy (parser);
            con = NULL;
            parser = NULL;
        }
        else
        {
            _Ptr<client_t> client = NULL;

            if (httpp_getvar (parser, HTTPP_VAR_ERROR_MESSAGE))
            _Checked {
                _Unchecked {ICECAST_LOG_ERROR("Error from relay request: %s (%s)", relay->localmount,
                        httpp_getvar(parser, HTTPP_VAR_ERROR_MESSAGE));}
                break;
            }
            global_lock ();
            if (client_create (&client, con, parser) < 0)
            {
                global_unlock ();
                /* make sure only the client_destory frees these */
                con = NULL;
                parser = NULL;
                client_destroy (client);
                break;
            }
            global_unlock ();
            sock_set_blocking (streamsock, 0);
            client_set_queue (client, NULL);
            free<char> (server);
            free<char> (mount);
            free<char> (server_id);
            free<char> (auth_header);

            return client;
        }
        redirects++;
    }
    /* failed, better clean up */
    free<char> (server);
    free<char> (mount);
    free<char> (server_id);
    free<char> (auth_header);
    if (con)
        connection_close (con);
    if (parser)
        httpp_destroy (parser);
    return NULL;
}


/* This does the actual connection for a relay. A thread is
 * started off if a connection can be acquired
 */
static void *start_relay_stream (void *arg : itype(_Ptr<void>)) : itype(_Ptr<void>)
{
    _Ptr<relay_server> relay = _Dynamic_bounds_cast<_Ptr<relay_server>>(arg);
    _Ptr<source_t> src = relay->source;
    _Ptr<client_t> client = NULL;

    _Unchecked {ICECAST_LOG_INFO("Starting relayed source at mountpoint \"%s\"", relay->localmount);}
    do
    {
        client = open_relay_connection (relay);

        if (client == NULL)
            continue;

        src->client = client;
        src->parser = client->parser;
        src->con = client->con;

        if (connection_complete_source (src, 0) < 0)
        {
            _Unchecked {ICECAST_LOG_INFO("Failed to complete source initialisation");}
            client_destroy (client);
            src->client = NULL;
            continue;
        }
        stats_event_inc(NULL, "source_relay_connections");
        stats_event (relay->localmount, "source_ip", client->con->ip);

        source_main (relay->source);

        if (relay->on_demand == 0)
        {
            /* only keep refreshing YP entries for inactive on-demand relays */
            yp_remove (relay->localmount);
            relay->source->yp_public = -1;
            relay->start = time(NULL) + 10; /* prevent busy looping if failing */
            slave_update_all_mounts();
        }

        /* we've finished, now get cleaned up */
        relay->cleanup = 1;
        slave_rebuild_mounts();

        return NULL;
    } while (0);  /* TODO allow looping through multiple servers */

    if (relay->source->fallback_mount)
    {
        _Ptr<source_t> fallback_source = ((void *)0);

        _Unchecked {ICECAST_LOG_DEBUG("failed relay, fallback to %s", relay->source->fallback_mount);}
        avl_tree_rlock(global.source_tree);
        fallback_source = source_find_mount (relay->source->fallback_mount);

        if (fallback_source != NULL)
            source_move_clients (relay->source, fallback_source);

        avl_tree_unlock (global.source_tree);
    }

    source_clear_source (relay->source);

    /* cleanup relay, but prevent this relay from starting up again too soon */
    thread_mutex_lock(&_slave_mutex);
    thread_mutex_lock(&(config_locks()->relay_lock));
    relay->source->on_demand = 0;
    relay->start = time(NULL) + max_interval;
    relay->cleanup = 1;
    thread_mutex_unlock(&(config_locks()->relay_lock));
    thread_mutex_unlock(&_slave_mutex);

    return NULL;
}


/* wrapper for starting the provided relay stream */
static void check_relay_stream (relay_server *relay : itype(_Ptr<relay_server>))
{
    if (relay->source == NULL)
    {
        if (relay->localmount[0] != '/')
        _Checked {
            _Unchecked {ICECAST_LOG_WARN("relay mountpoint \"%s\" does not start with /, skipping",
                    relay->localmount);}
            return;
        }
        /* new relay, reserve the name */
        relay->source = source_reserve (relay->localmount);
        if (relay->source)
        {
            _Unchecked {ICECAST_LOG_DEBUG("Adding relay source at mountpoint \"%s\"", relay->localmount);}
            if (relay->on_demand)
            {
                _Ptr<ice_config_t> config = config_get_config ();
                _Ptr<mount_proxy> mountinfo = config_find_mount (config, relay->localmount, MOUNT_TYPE_NORMAL);
                if (mountinfo == NULL)
                    source_update_settings (config, relay->source, mountinfo);
                config_release_config ();
                stats_event (relay->localmount, "listeners", "0");
                slave_update_all_mounts();
            }
        }
        else
        {
            if (relay->start == 0)
            {
                _Unchecked {ICECAST_LOG_WARN("new relay but source \"%s\" already exists", relay->localmount);}
                relay->start = 1;
            }
            return;
        }
    }
    do
    {
        _Ptr<source_t> source = relay->source;
        /* skip relay if active, not configured or just not time yet */
        if (relay->source == NULL || relay->running || relay->start > time(NULL))
            break;
        /* check if an inactive on-demand relay has a fallback that has listeners */
        if (relay->on_demand && source->on_demand_req == 0)
        {
            relay->source->on_demand = relay->on_demand;

            if (source->fallback_mount && source->fallback_override)
            {
                _Ptr<source_t> fallback = ((void *)0);
                avl_tree_rlock (global.source_tree);
                fallback = source_find_mount (source->fallback_mount);
                if (fallback && fallback->running && fallback->listeners)
                {
                   _Unchecked {ICECAST_LOG_DEBUG("fallback running %d with %lu listeners", fallback->running, fallback->listeners);}
                   source->on_demand_req = 1;
                }
                avl_tree_unlock (global.source_tree);
            }
            if (source->on_demand_req == 0)
                break;
        }

        relay->start = time(NULL) + 5;
        relay->running = 1;
        _Unchecked {relay->thread = thread_create ("Relay Thread", start_relay_stream,
                relay, THREAD_ATTACHED);}
        return;

    } while (0);
    /* the relay thread may of shut down itself */
    if (relay->cleanup)
    {
        if (relay->thread)
        {
            _Unchecked {ICECAST_LOG_DEBUG("waiting for relay thread for \"%s\"", relay->localmount);}
            thread_join (_Dynamic_bounds_cast<_Ptr<thread_type>>(relay->thread));
            relay->thread = NULL;
        }
        relay->cleanup = 0;
        relay->running = 0;

        if (relay->on_demand && relay->source)
        {
            _Ptr<ice_config_t> config = config_get_config ();
            _Ptr<mount_proxy> mountinfo = config_find_mount (config, relay->localmount, MOUNT_TYPE_NORMAL);
            source_update_settings (config, relay->source, mountinfo);
            config_release_config ();
            stats_event (relay->localmount, "listeners", "0");
        }
    }
}


/* compare the 2 relays to see if there are any changes, return 1 if
 * the relay needs to be restarted, 0 otherwise
 */
static int relay_has_changed (_Ptr<relay_server> new, _Ptr<relay_server> old)
{
    do
    {
        if (strcmp (new->mount, old->mount) != 0)
            break;
        if (strcmp (new->server, old->server) != 0)
            break;
        if (new->port != old->port)
            break;
        if (new->mp3metadata != old->mp3metadata)
            break;
        if (new->on_demand != old->on_demand)
            old->on_demand = new->on_demand;
        return 0;
    } while (0);
    return 1;
}


/* go through updated looking for relays that are different configured. The
 * returned list contains relays that should be kept running, current contains
 * the list of relays to shutdown
 */
static _Ptr<relay_server> update_relay_set(_Ptr<_Ptr<relay_server>> current, _Ptr<relay_server> updated)
{
    _Ptr<relay_server> relay = updated;
    _Ptr<relay_server> existing_relay = NULL; 
    _Ptr<_Ptr<relay_server>> existing_p = NULL;
    _Ptr<relay_server> new_list = NULL;

    while (relay)
    {
        _Checked {
          existing_relay = *current;
          existing_p = current;
        }

        while (existing_relay)
        {
            /* break out if keeping relay */
            if (strcmp (relay->localmount, existing_relay->localmount) == 0)
                if (relay_has_changed (relay, existing_relay) == 0)
                    break;
            _Checked {existing_p = &existing_relay->next;}
            existing_relay = existing_relay->next;
        }
        if (existing_relay == NULL)
        {
            /* new one, copy and insert */
            existing_relay = relay_copy (relay);
        }
        else
        {
            *existing_p = existing_relay->next;
        }
        existing_relay->next = new_list;
        new_list = existing_relay;
        relay = relay->next;
    }
    return new_list;
}


/* update the relay_list with entries from new_relay_list. Any new relays
 * are added to the list, and any not listed in the provided new_relay_list
 * are separated and returned in a separate list
 */
static _Ptr<relay_server> update_relays(_Ptr<_Ptr<relay_server>> relay_list, _Ptr<relay_server> new_relay_list)
{
    _Ptr<relay_server> active_relays = ((void *)0);
_Ptr<relay_server> cleanup_relays = ((void *)0);


    active_relays = update_relay_set (relay_list, new_relay_list);

    cleanup_relays = *relay_list;
    /* re-assign new set */
    *relay_list = active_relays;

    return cleanup_relays;
}


static void relay_check_streams (relay_server *to_start : itype(_Ptr<relay_server>) , relay_server* to_free : itype(_Ptr<relay_server>) , int skip_timer)
{
    _Ptr<relay_server> relay = NULL;

    while (to_free)
    {
        if (to_free->source)
        {
            if (to_free->running)
            {
                /* relay has been removed from xml, shut down active relay */
                _Unchecked {ICECAST_LOG_DEBUG("source shutdown request on \"%s\"", to_free->localmount);}
                to_free->running = 0;
                to_free->source->running = 0;
                thread_join (_Dynamic_bounds_cast<_Ptr<thread_type>>(to_free->thread));
            }
            else
                stats_event (to_free->localmount, NULL, NULL);
        }
        to_free = relay_free (to_free);
    }

    relay = to_start;
    while (relay)
    {
        if (skip_timer)
            relay->start = 0;
        check_relay_stream (relay);
        relay = relay->next;
    }
}


static int update_from_master(_Ptr<ice_config_t> config)
{
    _Nt_array_ptr<char> master = NULL;
_Nt_array_ptr<char> password = NULL;
_Nt_array_ptr<char> username = NULL;

    int port;
    sock_t mastersock;
    int ret = 0;
    char buf _Checked[256];
    do
    {
        _Nt_array_ptr<char> authheader = NULL;
        _Nt_array_ptr<char> data = NULL;

        _Ptr<relay_server> new_relays = NULL; 
        _Ptr<relay_server> cleanup_relays = ((void *)0);
        int len, count = 1;
        int on_demand;

        username = ((_Nt_array_ptr<char> )strdup (config->master_username));
        if (config->master_password)
            password = ((_Nt_array_ptr<char> )strdup (config->master_password));

        if (config->master_server)
            master = ((_Nt_array_ptr<char> )strdup (config->master_server));

        port = config->master_server_port;

        if (password == NULL || master == NULL || port == 0)
            break;
        on_demand = config->on_demand;
        ret = 1;
        config_release_config();
        mastersock = sock_connect_wto (master, port, 10);

        if (mastersock == SOCK_ERROR)
        _Checked {
            _Unchecked {ICECAST_LOG_WARN("Relay slave failed to contact master server to fetch stream list");}
            break;
        }

        len = strlen(username) + strlen(password) + 2;
        authheader = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(malloc<char>(len), byte_count(4096));
        _Unchecked {snprintf ((char*)authheader, len, "%s:%s", username, password);}
        data = util_base64_encode(authheader);
        _Unchecked {sock_write (mastersock,
                "GET /admin/streamlist.txt HTTP/1.0\r\n"
                "Authorization: Basic %s\r\n"
                "\r\n", data);}
        free<char>(authheader);
        free<char>(data);

        if (sock_read_line(mastersock, buf, sizeof(buf)) == 0 ||
                ((strncmp (_Dynamic_bounds_cast<_Nt_array_ptr<char>>(buf, byte_count(256)), "HTTP/1.0 200", 12) != 0) && (strncmp (_Dynamic_bounds_cast<_Nt_array_ptr<char>>(buf, byte_count(256)), "HTTP/1.1 200", 12) != 0)))
        _Checked {
            sock_close (mastersock);
            _Unchecked {ICECAST_LOG_WARN("Master rejected streamlist request");}
            break;
        } else {
            _Unchecked {ICECAST_LOG_INFO("Master accepted streamlist request");}
        }

        while (sock_read_line(mastersock, buf, sizeof(buf)))
        {
            if (!strlen(_Dynamic_bounds_cast<_Nt_array_ptr<char>>(buf, byte_count(256))))
                break;
        }
        while (sock_read_line(mastersock, _Dynamic_bounds_cast<_Nt_array_ptr<char>>(buf, byte_count(256)), sizeof(buf)))
        {
            _Ptr<relay_server> r = NULL;
            if (!strlen(_Dynamic_bounds_cast<_Nt_array_ptr<char>>(buf, byte_count(256))))
                continue;
            _Unchecked {ICECAST_LOG_DEBUG("read %d from master \"%s\"", count++, buf);}
            _Ptr<struct _xmlURI>  parsed_uri = NULL;
            _Unchecked { parsed_uri = _Assume_bounds_cast<_Ptr<struct _xmlURI>>(xmlParseURI((char*)buf));}
            if (parsed_uri == NULL) _Checked {
                _Unchecked {ICECAST_LOG_DEBUG("Error while parsing line from master. Ignoring line.");}
                continue;
            }
            r = calloc<relay_server> (1, sizeof (relay_server));
            if (r)
            {
                int tmpRet;
                _Unchecked {tmpRet = parsed_uri->server != NULL;}
                if (tmpRet)
                {
                  _Unchecked {r->server = ((_Nt_array_ptr<char> )strdup(parsed_uri->server));}
                  if (parsed_uri->port == 0)
                    r->port = 80;
                  else
                    r->port = parsed_uri->port;
                }
                else
                {
                  //r->server = (char *)xmlCharStrdup (master);
                  r->port = port;
                }

                _Unchecked {r->mount = ((_Nt_array_ptr<char> )strdup(parsed_uri->path));}
                _Unchecked {r->localmount = ((_Nt_array_ptr<char> )strdup(parsed_uri->path));}
                r->mp3metadata = 1;
                r->on_demand = on_demand;
                r->next = new_relays;
                _Unchecked {ICECAST_LOG_DEBUG("Added relay host=\"%s\", port=%d, mount=\"%s\"", r->server, r->port, r->mount);}
                new_relays = r;
            }
            //xmlFreeURI(parsed_uri);
        }
        sock_close (mastersock);

        thread_mutex_lock (&(config_locks()->relay_lock));
        cleanup_relays = update_relays (&global.master_relays, new_relays);
        
        relay_check_streams ((_Dynamic_bounds_cast<_Ptr<relay_server>>(global.master_relays)), cleanup_relays, 0);
        relay_check_streams (NULL, new_relays, 0);

        thread_mutex_unlock (&(config_locks()->relay_lock));

    } while(0);

    if (master)
        free<char> (master);
    if (username)
        free<char> (username);
    if (password)
        free<char> (password);

    return ret;
}


static void *_slave_thread(void *arg : itype(_Ptr<void>)) : itype(_Ptr<void>)
{
    _Ptr<ice_config_t> config = ((void *)0);
    unsigned int interval = 0;

    thread_mutex_lock(&_slave_mutex);
    update_settings = 0;
    update_all_mounts = 0;
    thread_mutex_unlock(&_slave_mutex);

    config = config_get_config();
    stats_global (config);
    config_release_config();
    source_recheck_mounts (1);

    while (1)
    {
        _Ptr<relay_server> cleanup_relays = NULL;
        int skip_timer = 0;

        /* re-read xml file if requested */
        global_lock();
        if (global . schedule_config_reread)
        {
            global.schedule_config_reread = 0;
            _Unchecked {ICECAST_LOG_INFO("Caught config reload request, re-reading config...");}
            event_config_read(NULL);
        }
        global_unlock();

        thread_sleep (1000000);
        if (slave_running == 0)
            break;

        ++interval;

        /* only update relays lists when required */
        thread_mutex_lock(&_slave_mutex);
        if (max_interval <= interval)
        {
            _Unchecked {ICECAST_LOG_DEBUG("checking master stream list");}
            config = config_get_config();

            if (max_interval == 0)
                skip_timer = 1;
            interval = 0;
            max_interval = config->master_update_interval;
            thread_mutex_unlock(&_slave_mutex);

            /* the connection could take some time, so the lock can drop */
            if (update_from_master (config))
                config = config_get_config();

            thread_mutex_lock (&(config_locks()->relay_lock));

            cleanup_relays = update_relays (&global.relays, config->relay);

            config_release_config();
        }
        else
        {
            thread_mutex_unlock(&_slave_mutex);
            thread_mutex_lock (&(config_locks()->relay_lock));
        }

        relay_check_streams ((_Dynamic_bounds_cast<_Ptr<relay_server>>(global.relays)), cleanup_relays, skip_timer);
        relay_check_streams ((_Dynamic_bounds_cast<_Ptr<relay_server>>(global.master_relays)), NULL, skip_timer);
        thread_mutex_unlock (&(config_locks()->relay_lock));

        thread_mutex_lock(&_slave_mutex);
        if (update_settings)
        _Checked {
            source_recheck_mounts (update_all_mounts);
            update_settings = 0;
            update_all_mounts = 0;
        }
        thread_mutex_unlock(&_slave_mutex);
    }
    _Unchecked {ICECAST_LOG_INFO("shutting down current relays");}
    relay_check_streams (NULL, global.relays, 0);
    relay_check_streams (NULL, global.master_relays, 0);

    _Unchecked {ICECAST_LOG_INFO("Slave thread shutdown complete");}

    return NULL;
}

