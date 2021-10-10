/* Icecast
 *
 * This program is distributed under the GNU General Public License, version 2.
 * A copy of this license is included with this source.
 *
 * Copyright 2000-2004, Jack Moffitt <jack@xiph.org, 
 *                      Michael Smith <msmith@xiph.org>,
 *                      oddsock <oddsock@xiph.org>,
 *                      Karl Heyes <karl@xiph.org>,
 *                      and others (see AUTHORS for details).
 * Copyright 2011-2014, Philipp "ph3-der-loewe" Schafft <lion@lion.leolix.org>,
 * Copyright 2014,      Thomas B. Ruecker <thomas@ruecker.fi>.
 */

/* -*- c-basic-offset: 4; indent-tabs-mode: nil; -*- */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef WIN32
#define _WIN32_WINNT 0x0400
/* For getpid() */
#include <process.h>
#include <windows.h>
#define snprintf _snprintf
#define getpid _getpid
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_CURL
#include <curl/curl.h>
#endif

#include "thread/thread.h"
#include "avl/avl.h"
#include "net/sock.h"
#include "net/resolver.h"
#include "httpp/httpp.h"

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_GRP_H
#include <grp.h>
#endif
#if HAVE_PWD_H
#include <pwd.h>
#endif

#include "cfgfile.h"
#include "sighandler.h"

#include "global.h"
#include "compat.h"
#include "connection.h"
#include "refbuf.h"
#include "client.h"
#include "slave.h"
#include "stats.h"
#include "logging.h"
#include "xslt.h"
#include "fserve.h"
#include "yp.h"
#include "auth.h"

#include <libxml/xmlmemory.h>

#undef CATMODULE
#define CATMODULE "main"

#pragma CHECKED_SCOPE on

static int background;
static _Nt_array_ptr<char> pidfile = NULL;

static void _fatal_error(_Nt_array_ptr<const char> perr)
_Checked {
#ifdef WIN32_SERVICE
    MessageBox(NULL, perr, "Error", MB_SERVICE_NOTIFICATION);
#elif defined(WIN32)
    MessageBox(NULL, perr, "Error", MB_OK);
#else
    _Unchecked {fprintf(stdout, "%s\n", perr);}
#endif
}

static void _print_usage(void)
_Checked {
    _Unchecked { printf("%s\n\n", ICECAST_VERSION_STRING); };
    _Unchecked { printf("usage: icecast [-b] -c <file>\n"); };
    _Unchecked { printf("or   : icecast {-v|--version}\n"); };
    _Unchecked { printf("options:\n"); };
    _Unchecked { printf("\t-c <file>       Specify configuration file\n"); };
    _Unchecked { printf("\t-v or --version Display version info\n"); };
    _Unchecked { printf("\t-b              Run icecast in the background\n"); };
    _Unchecked { printf("\n"); };
}

static void _stop_logging(void)
_Checked {
    log_close(errorlog);
    log_close(accesslog);
    log_close(playlistlog);
}

void initialize_subsystems(void)
_Checked {
    log_initialize();
    thread_initialize();
    sock_initialize();
    resolver_initialize();
    config_initialize();
    connection_initialize();
    global_initialize();
    refbuf_initialize();

    xslt_initialize();
#ifdef HAVE_CURL_GLOBAL_INIT
    curl_global_init (CURL_GLOBAL_ALL);
#endif
}

void shutdown_subsystems(void)
_Checked {
    fserve_shutdown();
    refbuf_shutdown();
    slave_shutdown();
    auth_shutdown();
    yp_shutdown();
    stats_shutdown();

    global_shutdown();
    connection_shutdown();
    config_shutdown();
    resolver_shutdown();
    sock_shutdown();
    thread_shutdown();

#ifdef HAVE_CURL
    curl_global_cleanup();
#endif

    /* Now that these are done, we can stop the loggers. */
    _stop_logging();
    log_shutdown();
    xslt_shutdown();
}

static int _parse_config_opts(int argc, _Array_ptr<_Nt_array_ptr<char>> argv : count(argc), _Array_ptr<char> filename : count(size), int size)
_Checked {
    int i = 1;
    int config_ok = 0;

    background = 0;
    if (argc < 2) return -1;

    while (i < argc) {
        if (strcmp(argv[i], "-b") == 0) {
#ifndef WIN32
            pid_t pid;
            _Unchecked {fprintf(stdout, "Starting icecast2\nDetaching from the console\n");}

            pid = fork();

            if (pid > 0) {
                /* exit the parent */
                exit(0);
            }
            else if(pid < 0) {
                _Unchecked {fprintf(stderr, "FATAL: Unable to fork child!");}
                exit(1);
            }
            background = 1;
#endif
        }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            _Unchecked {fprintf(stdout, "%s\n", ICECAST_VERSION_STRING);}
            exit(0);
        }

        if (strcmp(argv[i], "-c") == 0) {
            if (i + 1 < argc) {
                _Unchecked {strncpy(filename, (char*)argv[i + 1], size-1);}
                filename[size-1] = 0;
                config_ok = 1;
            } else {
                return -1;
            }
        }
        i++;
    }

    if(config_ok)
        return 1;
    else
        return -1;
}

static int _start_logging_stdout(void) {
    errorlog = log_open_file(stderr);
    if ( errorlog < 0 )
        return 0;

    log_set_level(errorlog, 2 /* WARN */);

    return 1;
}

static int _start_logging(void)
{
    char fn_error _Nt_checked[FILENAME_MAX];
    char fn_access _Nt_checked[FILENAME_MAX];
    char fn_playlist _Nt_checked[FILENAME_MAX];
    char buf _Nt_checked[1024];
    int log_to_stderr;

    _Ptr<ice_config_t> config = config_get_config_unlocked();

    if(strcmp(config->error_log, "-")) {
        _Unchecked {snprintf(fn_error, FILENAME_MAX, "%s%s%s", config->log_dir, PATH_SEPARATOR, config->error_log);}
        errorlog = log_open(_Dynamic_bounds_cast<_Nt_array_ptr<char>>(fn_error, count(FILENAME_MAX)));
        log_to_stderr = 0;
        if (config->logsize)
            log_set_trigger (errorlog, config->logsize);
        log_set_archive_timestamp(errorlog, config->logarchive);
    } else _Checked {
        /* this is already in place because of _start_logging_stdout() */
    }

    if (errorlog < 0) _Checked {
        buf[sizeof(buf)-1] = 0;
        _Unchecked { snprintf(buf, sizeof(buf)-1, 
                "FATAL: could not open error logging (%s): %s",
                log_to_stderr?"standard error":fn_error,
                ((_Nt_array_ptr<char> )strerror(errno))); };
        _fatal_error(buf);
    }
    log_set_level(errorlog, config->loglevel);

    if(strcmp(config->access_log, "-")) {
        _Unchecked {snprintf(fn_access, FILENAME_MAX, "%s%s%s", config->log_dir, PATH_SEPARATOR, config->access_log);}
        accesslog = log_open(_Dynamic_bounds_cast<_Nt_array_ptr<char>>(fn_access, count(FILENAME_MAX)));
        log_to_stderr = 0;
        if (config->logsize)
            log_set_trigger (accesslog, config->logsize);
        log_set_archive_timestamp(accesslog, config->logarchive);
    } else {
        accesslog = log_open_file(stderr);
        log_to_stderr = 1;
    }

    if (accesslog < 0) _Checked {
        buf[sizeof(buf)-1] = 0;
        _Unchecked { snprintf(buf, sizeof(buf)-1, 
                "FATAL: could not open access logging (%s): %s",
                log_to_stderr?"standard error":fn_access,
                ((_Nt_array_ptr<char> )strerror(errno))); };
        _fatal_error(buf);
    }

    if(config->playlist_log) {
        _Unchecked {snprintf(fn_playlist, FILENAME_MAX, "%s%s%s", config->log_dir, PATH_SEPARATOR, config->playlist_log);}
        playlistlog = log_open(_Dynamic_bounds_cast<_Nt_array_ptr<char>>(fn_playlist, count(FILENAME_MAX)));
        if (playlistlog < 0) _Checked {
            buf[sizeof(buf)-1] = 0;
            _Unchecked { snprintf(buf, sizeof(buf)-1, 
                "FATAL: could not open playlist logging (%s): %s",
                log_to_stderr?"standard error":fn_playlist,
                ((_Nt_array_ptr<char> )strerror(errno))); };
            _fatal_error(buf);
        }
        log_to_stderr = 0;
        if (config->logsize)
            log_set_trigger (playlistlog, config->logsize);
        log_set_archive_timestamp(playlistlog, config->logarchive);
    } else _Checked {
        playlistlog = -1;
    }

    log_set_level(errorlog, config->loglevel);
    log_set_level(accesslog, 4);
    log_set_level(playlistlog, 4);

    if (errorlog >= 0 && accesslog >= 0) return 1;
    
    return 0;
}


static int _start_listening(void)
{
    int i;
    for(i=0; i < global.server_sockets; i++) {
        if (sock_listen(global.serversock[i], ICECAST_LISTEN_QUEUE) == SOCK_ERROR)
            return 0;

        sock_set_blocking(global.serversock[i], 0);
    }

    return 1;
}

/* bind the socket and start listening */
static int _server_proc_init(void)
{
    _Ptr<ice_config_t> config = config_get_config_unlocked();

    if (connection_setup_sockets (config) < 1)
        return 0;

    if (!_start_listening()) _Checked {
        _fatal_error("Failed trying to listen on server socket");
        return 0;
    }

    /* recreate the pid file */
    if (config->pidfile)
    {
        _Ptr<FILE> f = ((void *)0);
        pidfile = ((_Nt_array_ptr<char> )strdup (config->pidfile));
        if (pidfile && (f = fopen (config->pidfile, "w")) != NULL)
        {
            _Unchecked {fprintf (f, "%d\n", (int)getpid());}
            fclose (f);
        }
    }

    return 1;
}

/* this is the heart of the beast */
static void _server_proc(void)
{
    if (background)
    {
        fclose (stdin);
        fclose (stdout);
        fclose (stderr);
    }
    connection_accept_loop();

    _Unchecked {ICECAST_LOG_INFO("Caught halt request, shutting down...");}

    connection_setup_sockets (NULL);
}

/* chroot the process. Watch out - we need to do this before starting other
 * threads. Change uid as well, after figuring out uid _first_ */
#if defined(HAVE_SETUID) || defined(HAVE_CHROOT) || defined(HAVE_SETUID)
static void _ch_root_uid_setup(void)
{
   _Ptr<ice_config_t> conf = config_get_config_unlocked();
#ifdef HAVE_SETUID
   _Ptr<struct passwd> user = ((void *)0);
   _Ptr<struct group> group = NULL;
   uid_t uid=-1;
   gid_t gid=-1;

   if(conf->chuid)
   {
       if(conf->user) {
           user = getpwnam(conf->user);
           if(user)
               uid = user->pw_uid;
           else
               _Unchecked {fprintf(stderr, "Couldn't find user \"%s\" in password file\n", conf->user);}
       }
       if(conf->group) {
           _Unchecked {group = _Assume_bounds_cast<_Ptr<struct group>>(getgrnam(((const char *)conf->group)));}

           if(group)
               gid = group->gr_gid;
           else
               _Unchecked {fprintf(stderr, "Couldn't find group \"%s\" in groups file\n", conf->group);}
       }
   }
#endif

#if HAVE_CHROOT
   if (conf->chroot)
   {
       if(getuid()) /* root check */
       {
            _Unchecked {fprintf(stderr, "WARNING: Cannot change server root unless running as root.\n");}
           return;
       }
       if(chroot(conf->base_dir))
       _Checked {
           _Unchecked {fprintf(stderr,"WARNING: Couldn't change server root: %s\n", ((_Nt_array_ptr<char> )strerror(errno)));}
           return;
       }
       else
           _Unchecked {fprintf(stdout, "Changed root successfully to \"%s\".\n", conf->base_dir);}

   }   
#endif

#if HAVE_SETUID
   if(conf->chuid)
   {
       if(getuid()) /* root check */
       {
           _Unchecked {fprintf(stderr, "WARNING: Can't change user id unless you are root.\n");}
           return;
       }

       if(uid != (uid_t)-1 && gid != (gid_t)-1) {
           if(!setgid(gid))
               _Unchecked {fprintf(stdout, "Changed groupid to %i.\n", (int)gid);}
           else
               _Unchecked {fprintf(stdout, "Error changing groupid: %s.\n", ((_Nt_array_ptr<char> )strerror(errno)));}
           if(!initgroups(conf->user, gid))
               _Unchecked {fprintf(stdout, "Changed supplementary groups based on user: %s.\n", conf->user);}
	   else
               _Unchecked {fprintf(stdout, "Error changing supplementary groups: %s.\n", ((_Nt_array_ptr<char> )strerror(errno)));}
           if(!setuid(uid))
               _Unchecked {fprintf(stdout, "Changed userid to %i.\n", (int)uid);}
           else
               _Unchecked {fprintf(stdout, "Error changing userid: %s.\n", ((_Nt_array_ptr<char> )strerror(errno)));}
       }
   }
#endif
}
#endif

#ifdef WIN32_SERVICE
int mainService(int argc, char **argv)
#else
int main(int argc, char **argv : itype(_Array_ptr<_Nt_array_ptr<char>>) count(argc))
#endif
{
    int res, ret;
    char filename _Nt_checked[512];
    char pbuf _Nt_checked[1024];

    /* parse the '-c icecast.xml' option
    ** only, so that we can read a configfile
    */
    res = _parse_config_opts(argc, argv, _Dynamic_bounds_cast<_Nt_array_ptr<char>>(filename, count(512)), 512);
    if (res == 1) {
#if !defined(_WIN32) || defined(_CONSOLE) || defined(__MINGW32__) || defined(__MINGW64__)
        /* startup all the modules */
        initialize_subsystems();
        if (!_start_logging_stdout()) _Checked {
            _fatal_error("FATAL: Could not start logging on stderr.");
            shutdown_subsystems();
            return 1;
        }
#endif
        /* parse the config file */
        config_get_config();
        ret = config_initial_parse_file(_Dynamic_bounds_cast<_Nt_array_ptr<char>>(filename, count(512)));
        config_release_config();
        if (ret < 0) {
            memset(_Dynamic_bounds_cast<_Array_ptr<char>>(pbuf, count(1024)), '\000', sizeof(pbuf));
            _Unchecked {snprintf(pbuf, sizeof(pbuf)-1, 
                "FATAL: error parsing config file (%s)", filename);}
            _fatal_error(pbuf);
            switch (ret) _Checked {
            case CONFIG_EINSANE:
                _fatal_error("filename was null or blank");
                break;
            case CONFIG_ENOROOT:
                _fatal_error("no root element found");
                break;
            case CONFIG_EBADROOT:
                _fatal_error("root element is not <icecast>");
                break;
            default:
                _fatal_error("XML config parsing error");
                break;
            }
#if !defined(_WIN32) || defined(_CONSOLE) || defined(__MINGW32__) || defined(__MINGW64__)
            shutdown_subsystems();
#endif
            return 1;
        }
    } else if (res == -1) _Checked {
        _print_usage();
        return 1;
    }
    
    /* override config file options with commandline options */
    config_parse_cmdline(argc, argv);

    /* Bind socket, before we change userid */
    if(!_server_proc_init()) _Checked {
        _fatal_error("Server startup failed. Exiting");
        shutdown_subsystems();
        return 1;
    }

#if defined(HAVE_SETUID) || defined(HAVE_CHROOT) || defined(HAVE_SETUID)
    _ch_root_uid_setup(); /* Change user id and root if requested/possible */
#endif

    stats_initialize(); /* We have to do this later on because of threading */
    fserve_initialize(); /* This too */

#ifdef HAVE_SETUID 
    /* We'll only have getuid() if we also have setuid(), it's reasonable to
     * assume */
    if(!getuid()) /* Running as root! Don't allow this */
    _Checked {
        _Unchecked {fprintf(stderr, "ERROR: You should not run icecast2 as root\n");}
        _Unchecked {fprintf(stderr, "Use the changeowner directive in the config file\n");}
        shutdown_subsystems();
        return 1;
    }
#endif

    /* setup default signal handlers */
    sighandler_initialize();

    if (!_start_logging()) _Checked {
        _fatal_error("FATAL: Could not start logging");
        shutdown_subsystems();
        return 1;
    }

    _Unchecked {ICECAST_LOG_INFO("%s server started", ICECAST_VERSION_STRING);}

    /* REM 3D Graphics */

    /* let her rip */
    global.running = ICECAST_RUNNING;

    /* Startup yp thread */
    _Unchecked {yp_initialize();}

    /* Do this after logging init */
    slave_initialize();
    auth_initialise ();

    _server_proc();

    _Unchecked {ICECAST_LOG_INFO("Shutting down");}
#if !defined(_WIN32) || defined(_CONSOLE) || defined(__MINGW32__) || defined(__MINGW64__)
    shutdown_subsystems();
#endif
    if (pidfile)
    _Checked {
        remove (pidfile);
        free<char> (pidfile);
    }

    return 0;
}


