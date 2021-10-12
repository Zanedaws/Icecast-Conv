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

#ifndef __AUTH_H__
#define __AUTH_H__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

struct source_tag;
struct auth_tag;

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "cfgfile.h"
#include "client.h"
#include "thread/thread.h"

typedef enum
{
    AUTH_UNDEFINED,
    AUTH_OK,
    AUTH_FAILED,
    AUTH_FORBIDDEN,
    AUTH_USERADDED,
    AUTH_USEREXISTS,
    AUTH_USERDELETED
} auth_result;

typedef struct auth_client_tag
{
    char *mount : itype(_Nt_array_ptr<char>);
    client_t *client : itype(_Ptr<client_t>);
    void ((*process)(struct auth_tag * auth, struct auth_client_tag * auth_user)) : itype(_Ptr<void (_Ptr<struct auth_tag> auth, _Ptr<struct auth_client_tag> auth_user)>);
    struct auth_client_tag *next : itype(_Ptr<struct auth_client_tag>);
} auth_client;

typedef struct auth_tag
{
    char *mount : itype(_Nt_array_ptr<char>);

    /* Authenticate using the given username and password */
    auth_result ((*authenticate)(auth_client * aclient)) : itype(_Ptr<auth_result (_Ptr<auth_client> aclient)>);
    auth_result ((*release_listener)(auth_client * auth_user)) : itype(_Ptr<auth_result (_Ptr<auth_client> auth_user)>);

    /* auth handler for authenicating a connecting source client */
    void ((*stream_auth)(auth_client * auth_user)) : itype(_Ptr<void (_Ptr<auth_client> auth_user)>);

    /* auth handler for source startup, no client passed as it may disappear */
    void ((*stream_start)(auth_client * auth_user)) : itype(_Ptr<void (_Ptr<auth_client> auth_user)>);

    /* auth handler for source exit, no client passed as it may disappear */
    void ((*stream_end)(auth_client * auth_user)) : itype(_Ptr<void (_Ptr<auth_client> auth_user)>);

    /* auth state-specific free call */
    void ((*free)(struct auth_tag * self)) : itype(_Ptr<void (_Ptr<struct auth_tag> self)>);

    auth_result ((*adduser)(struct auth_tag * auth, const char * username, const char * password)) : itype(_Ptr<auth_result (_Ptr<struct auth_tag> auth, const char *username : itype(_Nt_array_ptr<const char>), _Nt_array_ptr<const char> password)>);
    auth_result ((*deleteuser)(struct auth_tag * auth, const char * username)) : itype(_Ptr<auth_result (_Ptr<struct auth_tag> auth, _Nt_array_ptr<const char> username)>);
    auth_result ((*listuser)(struct auth_tag * auth, xmlNode * srcnode)) : itype(_Ptr<auth_result (_Ptr<struct auth_tag> auth, xmlNodePtr srcnode)>);

    mutex_t lock;
    int running;
    int refcount;
    int allow_duplicate_users;

    thread_type *thread : itype(_Ptr<thread_type>);

    /* per-auth queue for clients */
    auth_client *head : itype(_Ptr<auth_client>);
auth_client **tailp : itype(_Ptr<_Ptr<auth_client>>);

    int pending_count;

    void *state : itype(_Ptr<void>);
    char *type : itype(_Nt_array_ptr<char>);
} auth_t;

void auth_add_listener (const char *mount : itype(_Nt_array_ptr<const char>), client_t *client : itype(_Ptr<client_t>));
int  auth_release_listener (client_t *client : itype(_Ptr<client_t>));

void auth_initialise (void);
void auth_shutdown (void);

auth_t  *auth_get_authenticator (xmlNodePtr node) : itype(_Ptr<auth_t>);
void    auth_release (auth_t *authenticator : itype(_Ptr<auth_t>));

/* call to trigger an event when a stream starts */
void auth_stream_start (struct _mount_proxy *mountinfo : itype(_Ptr<struct _mount_proxy>), const char *mount : itype(_Nt_array_ptr<const char>));

/* call to trigger an event when a stream ends */
void auth_stream_end (struct _mount_proxy *mountinfo : itype(_Ptr<struct _mount_proxy>), const char *mount : itype(_Nt_array_ptr<const char>));

/* call to trigger an event to authenticate a source client */
int auth_stream_authenticate (client_t *client : itype(_Ptr<client_t>), const char *mount : itype(_Nt_array_ptr<const char>), struct _mount_proxy *mountinfo : itype(_Ptr<struct _mount_proxy>));

/* called from auth thread, after the client has successfully authenticated
 * and requires adding to source or fserve. */
int auth_postprocess_listener (auth_client *auth_user : itype(_Ptr<auth_client>));

#endif


