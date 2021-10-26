/*
 * resolver.c - name resolver library
 *
 * Copyright (C) 1999 the icecast team <team@icecast.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Library General Public License for more details.
 *
 *  You should have received a copy of the GNU Library General Public
 *  License along with this library; if not, write to the Free
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifdef HAVE_CONFIG_H
 #include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#ifndef NO_THREAD
#include <thread/thread.h>
#else
#define thread_mutex_create(x) do{}while(0)
#define thread_mutex_destroy(x) do{}while(0)
#define thread_mutex_lock(x) do{}while(0)
#define thread_mutex_unlock(x) do{}while(0)
#endif

#include "resolver.h"
#include "sock.h"

#pragma CHECKED_SCOPE on

/* internal function */

static int _isip(_Nt_array_ptr<const char> what : count(len), int len);

/* internal data */

#ifndef NO_THREAD
static mutex_t _resolver_mutex;
#endif
static int _initialized = 0;

#ifdef HAVE_INET_PTON
static int _isip(_Nt_array_ptr<const char> what : count(len), int len)
{
    union {
        struct in_addr v4addr;
        struct in6_addr v6addr;
    } addr_u;

    int tmpRet;
    _Unchecked {tmpRet = inet_pton(AF_INET, (const char*)what, &addr_u.v4addr);}
    if (tmpRet <= 0){
        _Unchecked {tmpRet = inet_pton(AF_INET6, (const char*)what, &addr_u.v6addr);}
        return tmpRet > 0 ? 1 : 0;
    }

    return 1;
}

#else
static int _isip(const char *what : count(len), int len)
{
    struct in_addr inp;

    return inet_aton(what, &inp);
}
#endif


#if defined (HAVE_GETNAMEINFO) && defined (HAVE_GETADDRINFO)
char *resolver_getname(const char *ip : itype(_Nt_array_ptr<const char>) count(len), char *buff : itype(_Array_ptr<char>) count(len), int len) : itype(_Ptr<char>)
{
    _Ptr<struct addrinfo> head = NULL;
struct addrinfo hints;

    _Ptr<char> ret = NULL;

    if (!_isip(ip, len)) {
        strncpy(buff, ip, len);
        buff [len-1] = '\0';
        return buff;
    }

    memset (&hints, 0, sizeof (hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    if (getaddrinfo (_Dynamic_bounds_cast<_Nt_array_ptr<char>>(ip, count(MAX_ADDR_LEN)), NULL, &hints, &head))
        return NULL;

    int tmpRet;
    if (head) {
       _Unchecked {tmpRet = getnameinfo(head->ai_addr, head->ai_addrlen, buff, len, NULL,  
                    0, NI_NAMEREQD);}
       if (tmpRet == 0)
            ret = buff;

       freeaddrinfo (head);
    }

    return ret;
}


char *resolver_getip(const char *name : itype(_Nt_array_ptr<const char>) count(MAX_ADDR_LEN), char *buff : itype(_Array_ptr<char>) count(len), int len) : itype(_Ptr<char>)
{
    _Ptr<struct addrinfo> head = ((void *)0);
struct addrinfo hints;

    _Ptr<char> ret = NULL;

    if (_isip(name, MAX_ADDR_LEN)) _Checked {
        _Unchecked {strncpy(buff, name, len);}
        buff [len-1] = '\0';
        return buff;
    }

    memset (&hints, 0, sizeof (hints));
    hints . ai_family = AF_UNSPEC;
    hints . ai_socktype = SOCK_STREAM;
    if (getaddrinfo (name, NULL, &hints, &head))
        return NULL;

    int tmpRet;

    if (head) {
       _Unchecked {tmpRet = getnameinfo(head->ai_addr, head->ai_addrlen, buff, len, NULL,
                    0, NI_NUMERICHOST);}
       if (tmpRet == 0)
            ret = buff;
       freeaddrinfo (head);
    }

    return ret;
}

#else

char *resolver_getname(const char *ip, char *buff, int len)
{
    struct hostent *host;
    char *ret = NULL;
    struct in_addr addr;

    if (! _isip(ip))
    {
        strncpy(buff, ip, len);
        buff [len-1] = '\0';
        return buff;
    }

    thread_mutex_lock(&_resolver_mutex);
    if (inet_aton (ip, &addr)) {
        /* casting &addr to const char* as it is recommended on win* */
        if ((host=gethostbyaddr ((const char *)&addr, sizeof (struct in_addr), AF_INET)))
        {
            ret = strncpy (buff, host->h_name, len);
            buff [len-1] = '\0';
        }
    }

    thread_mutex_unlock(&_resolver_mutex);
    return ret;
}

char *resolver_getip(const char *name, char *buff, int len)
{
    struct hostent *host;
    char *ret = NULL;

    if (_isip(name))
    {
        strncpy(buff, name, len);
        buff [len-1] = '\0';
        return buff;
    }
    thread_mutex_lock(&_resolver_mutex);
    host = gethostbyname(name);
    if (host)
    {
        char * temp = inet_ntoa(*(struct in_addr *)host->h_addr);
        ret = strncpy(buff, temp, len);
        buff [len-1] = '\0';
    }
    thread_mutex_unlock(&_resolver_mutex);

    return ret;
}
#endif


void resolver_initialize()
_Checked {
    /* initialize the lib if we havne't done so already */

    if (!_initialized)
    _Unchecked {
        _initialized = 1;
        thread_mutex_create (&_resolver_mutex);

        /* keep dns connects (TCP) open */
#ifdef HAVE_SETHOSTENT
        sethostent(1);
#endif
    }
}

void resolver_shutdown(void)
_Checked {
    if (_initialized)
    _Unchecked {
        thread_mutex_destroy(&_resolver_mutex);
        _initialized = 0;
#ifdef HAVE_ENDHOSTENT
        endhostent();
#endif
    }
}

