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

/** 
 * Client authentication functions
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "auth.h"
#include "source.h"
#include "client.h"
#include "cfgfile.h"
#include "httpp/httpp.h"
#include "md5.h"

#include "logging.h"
#define CATMODULE "auth_htpasswd"

#ifdef WIN32
#define snprintf _snprintf
#endif

#pragma CHECKED_SCOPE on

static auth_result htpasswd_adduser (_Ptr<auth_t> auth, const char *username : itype(_Nt_array_ptr<const char>), _Nt_array_ptr<const char> password);
static auth_result htpasswd_deleteuser(_Ptr<auth_t> auth, _Nt_array_ptr<const char> username);
static auth_result htpasswd_userlist(_Ptr<auth_t> auth, xmlNodePtr srcnode : itype(_Ptr<struct _xmlNode>));
static int _free_user (void *key : itype(_Ptr<void>));


typedef struct
{
    char *name : itype(_Nt_array_ptr<char>);
    char *pass : itype(_Nt_array_ptr<char>);
} htpasswd_user;

typedef struct {
    char *filename : itype(_Nt_array_ptr<char>);
    rwlock_t file_rwlock;
    avl_tree *users : itype(_Ptr<avl_tree>);
    time_t mtime;
} htpasswd_auth_state;

static void htpasswd_clear(_Ptr<auth_t> self) {
    _Ptr<htpasswd_auth_state> state = _Dynamic_bounds_cast<_Ptr<htpasswd_auth_state>>(self->state);
    free<char>(state->filename);
    if (state->users)
        _Unchecked {avl_tree_free(state->users, _free_user);}
    thread_rwlock_destroy(&state->file_rwlock);
    free<htpasswd_auth_state>(state);
}


/* md5 hash */
static _Nt_array_ptr<char> get_hash(const char *data : itype(_Nt_array_ptr<const char>), int len)
{
    struct MD5Context context = {};
    unsigned char digest _Checked[16];

    MD5Init(&context);

    MD5Update(&context, _Dynamic_bounds_cast<_Nt_array_ptr<const unsigned char>>(data, count(len)), len);

    MD5Final(digest, _Dynamic_bounds_cast<_Array_ptr<struct MD5Context>>(&context,  count(16)));

    _Nt_array_ptr<char> tmp = util_bin_to_hex(digest, 16);

    return tmp;
}


static int compare_users (void *arg : itype(_Ptr<void>), void *a : itype(_Ptr<void>), void *b : itype(_Ptr<void>))
{
    _Ptr<htpasswd_user> user1 = _Dynamic_bounds_cast<_Ptr<htpasswd_user>>(a);
    _Ptr<htpasswd_user> user2 = _Dynamic_bounds_cast<_Ptr<htpasswd_user>>(b);

    return strcmp (user1->name, user2->name);
}


static int _free_user (void *key)
{
    _Ptr<htpasswd_user> user = _Dynamic_bounds_cast<_Ptr<htpasswd_user>>(key);

    free<char> (user->name); /* ->pass is part of same buffer */
    free<htpasswd_user> (user);
    return 1;
}


static void htpasswd_recheckfile (_Ptr<htpasswd_auth_state> htpasswd)
{
    _Ptr<FILE> passwdfile = ((void *)0);
    _Ptr<avl_tree> new_users = ((void *)0);
    int num = 0;
    struct stat file_stat;
    _Ptr<char> sep = ((void *)0);
    char line _Nt_checked[MAX_LINE_LEN];

    if (htpasswd->filename == NULL)
        return;
    if (stat (htpasswd->filename, &file_stat) < 0)
    {
        _Unchecked {ICECAST_LOG_WARN("failed to check status of %s", htpasswd->filename);}

        /* Create a dummy users tree for things to use later */
        thread_rwlock_wlock (&htpasswd->file_rwlock);
        if(!htpasswd->users)
            _Unchecked {htpasswd->users = avl_tree_new(compare_users, NULL);}
        thread_rwlock_unlock (&htpasswd->file_rwlock);

        return;
    }

    if (file_stat.st_mtime == htpasswd->mtime)
    _Checked {
        /* common case, no update to file */
        return;
    }
    _Unchecked {ICECAST_LOG_INFO("re-reading htpasswd file \"%s\"", htpasswd->filename);}
    passwdfile = fopen (htpasswd->filename, "rb");
    if (passwdfile == NULL)
    {
        _Unchecked {ICECAST_LOG_WARN("Failed to open authentication database \"%s\": %s", 
                htpasswd->filename, strerror(errno));}
        return;
    }
    htpasswd->mtime = file_stat.st_mtime;

    _Unchecked {new_users = avl_tree_new (compare_users, NULL);}

    while (get_line(passwdfile, _Dynamic_bounds_cast<_Nt_array_ptr<char>>(line, count(MAX_LINE_LEN)), MAX_LINE_LEN))
    {
        int len;
        _Ptr<htpasswd_user> entry = NULL;

        num++;
        if(!line[0] || line[0] == '#')
            continue;

        sep = _Dynamic_bounds_cast<_Ptr<char>>(strrchr (line, ':'));
        if (sep == NULL)
        {
            _Unchecked {ICECAST_LOG_WARN("No separator on line %d (%s)", num, htpasswd->filename);}
            continue;
        }
        entry = calloc<htpasswd_user> (1, sizeof (htpasswd_user));
        len = strlen (line) + 1;
        entry->name = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(malloc<char> (len), count(MAX_LINE_LEN + 1));
        *sep = 0;
        memcpy<char> (_Dynamic_bounds_cast<_Array_ptr<char>>(entry->name, count(MAX_LINE_LEN + 1)), _Dynamic_bounds_cast<_Nt_array_ptr<char>>(line, count(MAX_LINE_LEN)), len);
        entry->pass = entry->name + (sep-line) + 1;
        avl_insert (new_users, _Dynamic_bounds_cast<_Ptr<void>>(entry));
    }
    fclose (passwdfile);

    thread_rwlock_wlock (&htpasswd->file_rwlock);
    if (htpasswd->users)
        _Unchecked {avl_tree_free (htpasswd->users, _free_user);}
    htpasswd->users = new_users;
    thread_rwlock_unlock (&htpasswd->file_rwlock);
}


static auth_result htpasswd_auth (_Ptr<auth_client> auth_user)
{
    _Ptr<auth_t> auth = auth_user->client->auth;
    _Ptr<htpasswd_auth_state> htpasswd = _Dynamic_bounds_cast<_Ptr<htpasswd_auth_state>>(auth->state);
    _Ptr<client_t> client = auth_user->client;
    htpasswd_user entry = {.name = NULL, .pass = NULL};
    _Ptr<void> result = NULL;

    if (client->username == NULL || client->password == NULL)
        return AUTH_FAILED;

    if (htpasswd->filename == NULL)
    _Checked {
        _Unchecked {ICECAST_LOG_ERROR("No filename given in options for authenticator.");}
        return AUTH_FAILED;
    }
    htpasswd_recheckfile (htpasswd);

    if (htpasswd->users == NULL) _Checked {
        _Unchecked {ICECAST_LOG_ERROR("No user list.");}
        return AUTH_FAILED;
    }

    thread_rwlock_rlock (&htpasswd->file_rwlock);
    entry.name = client->username;
    if (avl_get_by_key (htpasswd->users, _Dynamic_bounds_cast<_Ptr<void>>(&entry), &result) == 0)
    {
        _Ptr<htpasswd_user> found = _Dynamic_bounds_cast<_Ptr<htpasswd_user>>(result);
        _Nt_array_ptr<char> hashed_pw = ((void *)0);

        thread_rwlock_unlock (&htpasswd->file_rwlock);
        hashed_pw = get_hash (client->password, strlen (client->password));
        if (strcmp (found->pass, hashed_pw) == 0)
        _Checked {
            free<char> (hashed_pw);
            return AUTH_OK;
        }
        free<char> (hashed_pw);
        _Unchecked {ICECAST_LOG_DEBUG("incorrect password for client");}
        return AUTH_FAILED;
    }
    _Unchecked {ICECAST_LOG_DEBUG("no such username: %s", client->username);}
    thread_rwlock_unlock (&htpasswd->file_rwlock);
    return AUTH_FAILED;
}


int  auth_get_htpasswd_auth (auth_t *authenticator : itype(_Ptr<auth_t>), config_options_t *options : itype(_Ptr<config_options_t>))
{
    _Ptr<htpasswd_auth_state>state = NULL;

    authenticator->authenticate = htpasswd_auth;
    authenticator->free = htpasswd_clear;
    authenticator->adduser = htpasswd_adduser;
    authenticator->deleteuser = htpasswd_deleteuser;
    _Unchecked {authenticator->listuser = htpasswd_userlist;}

    state = _Dynamic_bounds_cast<_Ptr<htpasswd_auth_state>>(calloc<htpasswd_auth_state>(1, sizeof(htpasswd_auth_state)));

    while(options) _Checked {
        if(!strcmp(options->name, "filename"))
        _Unchecked {
            free<char> (state->filename);
            state->filename = ((_Nt_array_ptr<char> )strdup(options->value));
        }
        options = options->next;
    }

    if (state->filename)
        _Unchecked {ICECAST_LOG_INFO("Configured htpasswd authentication using password file \"%s\"", 
                state->filename);}
    else
        _Unchecked {ICECAST_LOG_ERROR("No filename given in options for authenticator.");}

    authenticator->state = _Dynamic_bounds_cast<_Ptr<void>>(state);

    thread_rwlock_create(&state->file_rwlock);
    htpasswd_recheckfile (state);

    return 0;
}


static auth_result htpasswd_adduser (_Ptr<auth_t> auth, const char *username : itype(_Nt_array_ptr<const char>), _Nt_array_ptr<const char> password)
{
    _Ptr<FILE> passwdfile = ((void *)0);
    _Nt_array_ptr<char> hashed_password = NULL;
    _Ptr<htpasswd_auth_state> state = _Dynamic_bounds_cast<_Ptr<htpasswd_auth_state>>(auth->state);
    htpasswd_user entry = {.name = NULL, .pass = NULL};
    _Ptr<void> result = NULL;

    if (state->filename == NULL) _Checked {
        _Unchecked {ICECAST_LOG_ERROR("No filename given in options for authenticator.");}
        return AUTH_FAILED;
    }

    htpasswd_recheckfile (state);

    if (state->filename == NULL) _Checked {
        _Unchecked {ICECAST_LOG_ERROR("No user list.");}
        return AUTH_FAILED;
    }

    thread_rwlock_wlock (&state->file_rwlock);

    entry.name = username;
    if (avl_get_by_key (state->users, _Dynamic_bounds_cast<_Ptr<void>>(&entry), &result) == 0)
    {
        thread_rwlock_unlock (&state->file_rwlock);
        return AUTH_USEREXISTS;
    }

    passwdfile = fopen(state->filename, "ab");

    if (passwdfile == NULL)
    {
        thread_rwlock_unlock (&state->file_rwlock);
        _Unchecked {ICECAST_LOG_WARN("Failed to open authentication database \"%s\": %s", 
                state->filename, strerror(errno));}
        return AUTH_FAILED;
    }

    hashed_password = get_hash(password, strlen(password));
    if (hashed_password) _Checked {
        _Unchecked {fprintf(passwdfile, "%s:%s\n", username, hashed_password);}
        free<char>(hashed_password);
    }

    fclose(passwdfile);
    thread_rwlock_unlock (&state->file_rwlock);

    return AUTH_USERADDED;
}


static auth_result htpasswd_deleteuser(_Ptr<auth_t> auth, _Nt_array_ptr<const char> username)
{
    _Ptr<FILE> passwdfile = ((void *)0);
    _Ptr<FILE> tmp_passwdfile = ((void *)0);
    _Ptr<htpasswd_auth_state> state = ((void *)0);
    char line _Nt_checked[MAX_LINE_LEN];
    _Ptr<char> sep = ((void *)0);
    _Nt_array_ptr<char> tmpfile = NULL;
    int tmpfile_len = 0;
    struct stat file_info;

    state = _Dynamic_bounds_cast<_Ptr<htpasswd_auth_state>>(auth->state);

    if (state->filename == NULL) _Checked {
        _Unchecked {ICECAST_LOG_ERROR("No filename given in options for authenticator.");}
        return AUTH_FAILED;
    }

    if (state->users == NULL) _Checked {
        _Unchecked {ICECAST_LOG_ERROR("No user list.");}
        return AUTH_FAILED;
    }

    thread_rwlock_wlock (&state->file_rwlock);
    passwdfile = fopen(state->filename, "rb");

    if(passwdfile == NULL) {
        _Unchecked {ICECAST_LOG_WARN("Failed to open authentication database \"%s\": %s", 
                state->filename, strerror(errno));}
        thread_rwlock_unlock (&state->file_rwlock);
        return AUTH_FAILED;
    }
    tmpfile_len = strlen(state->filename) + 6;
    tmpfile = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(calloc<char>(1, tmpfile_len), count(6));
    _Unchecked {snprintf ((char*)tmpfile, tmpfile_len, "%s.tmp", state->filename);}
    if (stat (tmpfile, &file_info) == 0)
    {
        _Unchecked {ICECAST_LOG_WARN("temp file \"%s\" exists, rejecting operation", tmpfile);}
        free<char> (tmpfile);
        fclose (passwdfile);
        thread_rwlock_unlock (&state->file_rwlock);
        return AUTH_FAILED;
    }

    tmp_passwdfile = fopen(tmpfile, "wb");

    if(tmp_passwdfile == NULL) {
        _Unchecked {ICECAST_LOG_WARN("Failed to open temporary authentication database \"%s\": %s", 
                tmpfile, strerror(errno));}
        fclose(passwdfile);
        free<char>(tmpfile);
        thread_rwlock_unlock (&state->file_rwlock);
        return AUTH_FAILED;
    }


    while(get_line(passwdfile, _Dynamic_bounds_cast<_Nt_array_ptr<char>>(line, count(MAX_LINE_LEN)), MAX_LINE_LEN)) {
        if(!line[0] || line[0] == '#')
            continue;

        sep = _Dynamic_bounds_cast<_Ptr<char>>(strchr(line, ':'));
        if(sep == NULL) _Checked {
            _Unchecked {ICECAST_LOG_DEBUG("No separator in line");}
            continue;
        }

        *sep = 0;
        if (strcmp(username, line)) _Checked {
            /* We did not match on the user, so copy it to the temp file */
            /* and put the : back in */
            *sep = ':';
            _Unchecked {fprintf(tmp_passwdfile, "%s\n", line);}
        }
    }

    fclose(tmp_passwdfile);
    fclose(passwdfile);

    /* Now move the contents of the tmp file to the original */
    /* Windows won't let us rename a file if the destination file
       exists...so, lets remove the original first */
    if (remove(state->filename) != 0) {
        _Unchecked {ICECAST_LOG_ERROR("Problem moving temp authentication file to original \"%s\" - \"%s\": %s", 
                tmpfile, state->filename, strerror(errno));}
    }
    else {
        if (rename(tmpfile, state->filename) != 0) {
            _Unchecked {ICECAST_LOG_ERROR("Problem moving temp authentication file to original \"%s\" - \"%s\": %s", 
                    tmpfile, state->filename, strerror(errno));}
        }
    }
    free<char>(tmpfile);
    thread_rwlock_unlock (&state->file_rwlock);
    htpasswd_recheckfile (state);

    return AUTH_USERDELETED;
}


static auth_result htpasswd_userlist(_Ptr<auth_t> auth, xmlNodePtr srcnode)
{
    _Ptr<htpasswd_auth_state> state = ((void *)0);
    _Ptr<struct _xmlNode> newnode = NULL;
    _Ptr<avl_node> node = ((void *)0);

    state = _Dynamic_bounds_cast<_Ptr<htpasswd_auth_state>>(auth->state);

    if (state->filename == NULL) _Checked {
        _Unchecked {ICECAST_LOG_ERROR("No filename given in options for authenticator.");}
        return AUTH_FAILED;
    }

    htpasswd_recheckfile (state);

    if (state->users == NULL) _Checked {
        _Unchecked {ICECAST_LOG_ERROR("No user list.");}
        return AUTH_FAILED;
    }

    thread_rwlock_rlock (&state->file_rwlock);
    node = avl_get_first (state->users);
    while (node)
    {
        _Ptr<htpasswd_user> user = _Dynamic_bounds_cast<_Ptr<htpasswd_user>>(node->key);
        _Unchecked {newnode = _Assume_bounds_cast<_Ptr<struct _xmlNode>>(xmlNewChild (srcnode, NULL, XMLSTR("User"), NULL));}
        _Unchecked {xmlNewTextChild((xmlNodePtr)newnode, NULL, XMLSTR("username"), XMLSTR(user->name));}
        node = avl_get_next (node);
    }
    thread_rwlock_unlock (&state->file_rwlock);

    return AUTH_OK;
}

