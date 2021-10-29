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
 * Copyright 2012-2014, Philipp "ph3-der-loewe" Schafft <lion@lion.leolix.org>,
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifndef _WIN32
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h>
#ifdef HAVE_POLL
#include <sys/poll.h>
#endif
#else
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#define snprintf _snprintf
#define strcasecmp stricmp
#define strncasecmp strnicmp
#endif

#include "net/sock.h"
#include "thread/thread.h"

#include "cfgfile.h"
#include "util.h"
#include "compat.h"
#include "refbuf.h"
#include "connection.h"
#include "client.h"
#include "source.h"

#define CATMODULE "util"

#include "logging.h"

#define util_malloc(t, sz) (malloc<t>(sz))

#pragma CHECKED_SCOPE on

/* Abstract out an interface to use either poll or select depending on which
 * is available (poll is preferred) to watch a single fd.
 *
 * timeout is in milliseconds.
 *
 * returns > 0 if activity on the fd occurs before the timeout.
 *           0 if no activity occurs
 *         < 0 for error.
 */
int util_timed_wait_for_fd(sock_t fd, int timeout)
_Checked {
#ifdef HAVE_POLL
    struct pollfd ufds;

    ufds.fd = fd;
    ufds.events = POLLIN;
    ufds.revents = 0;

    //return poll(&ufds, 1, timeout);
    return 1;
#else
    fd_set rfds;
    struct timeval tv, *p=NULL;

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    if(timeout >= 0) {
        tv.tv_sec = timeout/1000;
        tv.tv_usec = (timeout % 1000)*1000;
        p = &tv;
    }
    return select(fd+1, &rfds, NULL, NULL, p);
#endif
}

int util_read_header(sock_t sock, char *buff : itype(_Array_ptr<char>) count(len), unsigned long len, int entire)
{
    int read_bytes, ret;
    unsigned long pos;
    char c;
    _Ptr<ice_config_t> config = ((void *)0);
    int header_timeout;

    config = config_get_config();
    header_timeout = config->header_timeout;
    config_release_config();

    read_bytes = 1;
    pos = 0;
    ret = 0;

    while ((read_bytes == 1) && (pos < (len - 1))) _Checked {
        read_bytes = 0;

        if (util_timed_wait_for_fd(sock, header_timeout*1000) > 0) {

            if ((read_bytes = recv(sock, &c, 1, 0))) {
                if (c != '\r') buff[pos++] = c;
                if (entire) {
                    if ((pos > 1) && (buff[pos - 1] == '\n' && 
                                      buff[pos - 2] == '\n')) {
                        ret = 1;
                        break;
                    }
                }
                else {
                    if ((pos > 1) && (buff[pos - 1] == '\n')) {
                        ret = 1;
                        break;
                    }
                }
            }
        } else {
            break;
        }
    }

    if (ret) buff[pos] = '\0';
    
    return ret;
}

char *util_get_extension(const char *path : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<char>) {
    _Nt_array_ptr<char> ext = ((_Nt_array_ptr<char> )strrchr(path, '.'));

    if(ext == NULL)
        return "";
    else
        return ext+1;
}

int util_check_valid_extension(const char *uri : itype(_Nt_array_ptr<const char>)) _Checked {
    int    ret = 0;
    _Nt_array_ptr<char> p2 = ((void *)0);

    if (uri) {
        p2 = ((_Nt_array_ptr<char> )strrchr(uri, '.'));
        if (p2) {
            p2++;
            if (strncmp(p2, "xsl", strlen("xsl")) == 0) {
                /* Build the full path for the request, concatenating the webroot from the config.
                ** Here would be also a good time to prevent accesses like '../../../../etc/passwd' or somesuch.
                */
                ret = XSLT_CONTENT;
            }
            if (strncmp(p2, "htm", strlen("htm")) == 0) {
                /* Build the full path for the request, concatenating the webroot from the config.
                ** Here would be also a good time to prevent accesses like '../../../../etc/passwd' or somesuch.
                */
                ret = HTML_CONTENT;
            }
            if (strncmp(p2, "html", strlen("html")) == 0) {
                /* Build the full path for the request, concatenating the webroot from the config.
                ** Here would be also a good time to prevent accesses like '../../../../etc/passwd' or somesuch.
                */
                ret = HTML_CONTENT;
            }

        }
    }
    return ret;
}

static int hex(char c)
_Checked {
    if(c >= '0' && c <= '9')
        return c - '0';
    else if(c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    else if(c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    else
        return -1;
}

static int verify_path(_Array_ptr<char> path : byte_count(3)) _Checked {
    int dir = 0, indotseq = 0;

    while(*path) {
        if(*path == '/' || *path == '\\') {
            if(indotseq)
                return 0;
            if(dir)
                return 0;
            dir = 1;
            path++;
            continue;
        }

        if(dir || indotseq) {
            if(*path == '.')
                indotseq = 1;
            else
                indotseq = 0;
        }
        
        dir = 0;
        path++;
    }

    return 1;
}

char *util_get_path_from_uri(char *uri : itype(_Nt_array_ptr<char>)) : itype(_Ptr<char>) {
    _Nt_array_ptr<char> path = util_normalise_uri(uri);
    _Array_ptr<char> fullpath = ((void *)0);

    if(!path)
        return NULL;
    else _Checked {
        fullpath = util_get_path_from_normalised_uri(path);
        free<char>(path);
        return fullpath;
    }
}

char *util_get_path_from_normalised_uri(const char *uri : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<char>) {
    _Nt_array_ptr<char> fullpath = NULL;
    _Nt_array_ptr<char> webroot = ((void *)0);
    _Ptr<ice_config_t> config = config_get_config();

    webroot = config->webroot_dir;

    size_t uriLen = strlen(uri);
    size_t webrootLen = strlen(webroot);

    fullpath = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(malloc<char>(uriLen + webrootLen + 1), byte_count(uriLen + webrootLen + 1));
    if (fullpath)
        //_Unchecked {sprintf (fullpath, "%s%s", webroot, uri);}
    config_release_config();

    return fullpath;
}

static char hexchars _Checked[16] = {
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
};

static char safechars _Checked[256] = {
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  0,  0,  0,  0,  0,  0,
      0,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
      1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  0,  0,  0,  0,  0,
      0,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
      1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
      0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
};

char *util_url_escape(const char *src : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<char>)
{
    if (!src)
        return NULL;
    size_t len = strlen(src);
    _Nt_array_ptr<char> dst = NULL; 
    _Nt_array_ptr<unsigned char> source = _Dynamic_bounds_cast<_Nt_array_ptr<unsigned char>>(src, byte_count(len));
    size_t i, j;

    
    /* Efficiency not a big concern here, keep the code simple/conservative */
    dst = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(calloc<char>(1, len*3 + 1), byte_count(len * 3 + 1));

    for(i = 0, j = 0; i < len; i++) _Checked {
        if(safechars[source[i]]) {
            dst[j++] = source[i];
        } else {
            dst[j++] = '%';
            dst[j++] = hexchars[(source[i] >> 4) & 0x0F];
            dst[j++] = hexchars[ source[i]       & 0x0F];
        }
    }

    dst[j] = 0;
    return dst;
}

char *util_url_unescape(const char *src : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<char>)
{
    int len = strlen(src);
    _Nt_array_ptr<char> decoded : byte_count(len + 1)= _Dynamic_bounds_cast<_Nt_array_ptr<char>>(calloc<char>(1, len+1), byte_count(len+1));
    int i;
    _Array_ptr<char> dst = NULL;
    int done = 0;
    _Ptr<char> dstTmp = NULL;

    //_Checked{decoded = calloc<char>(1, len + 1);}

    dst = _Dynamic_bounds_cast<_Array_ptr<char>>(decoded, byte_count(len + 1));

    for(i=0; i < len; i++) _Checked {
        switch(src[i]) _Unchecked {
            case '%':
                if(i+2 >= len) {
                    free<char>(_Dynamic_bounds_cast<_Array_ptr<char>>(decoded, byte_count(0)));
                    return NULL;
                }
                if(hex(src[i+1]) == -1 || hex(src[i+2]) == -1 ) {
                    free<char>(_Dynamic_bounds_cast<_Array_ptr<char>>(decoded, byte_count(0)));
                    return NULL;
                }
                dstTmp = _Assume_bounds_cast<_Ptr<char>>(dst++);
                *dstTmp = hex(src[i+1]) * 16  + hex(src[i+2]);
                i+= 2;
                break;
            case '#':
                done = 1;
                break;
            case 0:
                ICECAST_LOG_ERROR("Fatal internal logic error in util_url_unescape()");
                free<char>(_Dynamic_bounds_cast<_Array_ptr<char>>(decoded, byte_count(0)));
                return NULL;
                break;
            default:
                dstTmp = _Assume_bounds_cast<_Ptr<char>>(dst++);
                *dstTmp = src[i];
                break;
        }
        if(done)
            break;
    }
    _Unchecked {dstTmp = _Assume_bounds_cast<_Ptr<char>>(dst);}
    *dstTmp = 0; /* null terminator */

    return decoded;
}

/* Get an absolute path (from the webroot dir) from a URI. Return NULL if the
 * path contains 'disallowed' sequences like foo/../ (which could be used to
 * escape from the webroot) or if it cannot be URI-decoded.
 * Caller should free the path.
 */
char *util_normalise_uri(const char *uri : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<char>) {
    _Nt_array_ptr<char> path = ((void *)0);
#ifdef _WIN32
    size_t len;
#endif

    if(uri[0] != '/')
        return NULL;

    path = util_url_unescape(uri);

    if(path == NULL) {
        _Unchecked {ICECAST_LOG_WARN("Error decoding URI: %s\n", uri);}
        return NULL;
    }

#ifdef _WIN32
    /* If we are on Windows, strip trailing dots, as Win API strips it anyway */
    for (len = strlen(path); len > 0 && path[len-1] == '.'; len--)
        path[len-1] = '\0';
#endif

    /* We now have a full URI-decoded path. Check it for allowability */
    if(verify_path(_Dynamic_bounds_cast<_Nt_array_ptr<char>>(path, byte_count(3))))
        return path;
    else {
        _Unchecked {ICECAST_LOG_WARN("Rejecting invalid path \"%s\"", path);}
        free<char>(path);
        return NULL;
    }
}

static char base64table _Checked[64] = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
    'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
    'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'
};

static signed char base64decode _Checked[256] = {
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, 62, -2, -2, -2, 63,
     52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -2, -2, -2, -1, -2, -2,
     -2,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
     15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -2, -2, -2, -2, -2,
     -2, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
     41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
     -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2
};

char *util_bin_to_hex(unsigned char *data : itype(_Array_ptr<unsigned char>) count(len), int len) : itype(_Nt_array_ptr<char>)
{
    _Nt_array_ptr<char> hex : byte_count(len * 2 + 1) = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(malloc<char>(len*2 + 1), byte_count(len * 2 + 1));
    int i;

    for(i = 0; i < len; i++) _Checked {
        hex[i*2] = hexchars[(data[i]&0xf0) >> 4];
        hex[i*2+1] = hexchars[data[i]&0x0f];
    }

    hex[len*2] = 0;

    return hex;
}

/* This isn't efficient, but it doesn't need to be */
char *util_base64_encode(const char *data : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<char>)
{
    int len = strlen(data);
    int tmp = strlen(data);
    _Nt_array_ptr<char> out : byte_count(tmp * 4/3 + 4)= _Dynamic_bounds_cast<_Nt_array_ptr<char>>(malloc<char>(tmp*4/3 + 4), byte_count(tmp*4/3 + 4));
    _Nt_array_ptr<char> result : byte_count(tmp * 4/3 + 4)= out;
    int chunk;

    while(len > 0) _Checked {
        chunk = (len >3)?3:len;
        *out++ = base64table[(*data & 0xFC)>>2];
        _Unchecked {*out++ = base64table[((*data & 0x03)<<4) | ((*(data+1) & 0xF0) >> 4)];}
        switch(chunk) {
            case 3:
                _Unchecked {*out++ = base64table[((*(data+1) & 0x0F)<<2) | ((*(data+2) & 0xC0)>>6)];}
                _Unchecked {*out++ = base64table[(*(data+2)) & 0x3F];}
                break;
            case 2:
                _Unchecked {*out++ = base64table[((*(data+1) & 0x0F)<<2)];}
                *out++ = '=';
                break;
            case 1:
                *out++ = '=';
                *out++ = '=';
                break;
        }
        data += chunk;
        len -= chunk;
    }
    *out = 0;

    return result;
}

char *util_base64_decode(const char *data : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<char>)
{
    _Nt_array_ptr<const unsigned char> input = _Dynamic_bounds_cast<_Nt_array_ptr<const unsigned char>>(data, byte_count(1));
    int len = strlen (data);
    int tmp = strlen (data);
    _Nt_array_ptr<char> out : byte_count(tmp * 3/4 + 5) = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(malloc<char>(tmp*3/4 + 5), byte_count(tmp*3/4 + 5));
    _Nt_array_ptr<char> result : byte_count(tmp * 3/4 + 5)= out;
    signed char vals _Checked[4];

    while(len > 0) _Checked {
        if(len < 4)
        _Unchecked {
            free<void>(_Dynamic_bounds_cast<_Array_ptr<void>>(result, byte_count(0)));
            return NULL; /* Invalid Base64 data */
        }

        vals[0] = base64decode[*input++];
        vals[1] = base64decode[*input++];
        vals[2] = base64decode[*input++];
        vals[3] = base64decode[*input++];

        if(vals[0] < 0 || vals[1] < 0 || vals[2] < -1 || vals[3] < -1) {
            len -= 4;
            continue;
        }

        *out++ = vals[0]<<2 | vals[1]>>4;
        /* vals[3] and (if that is) vals[2] can be '=' as padding, which is
           looked up in the base64decode table as '-1'. Check for this case,
           and output zero-terminators instead of characters if we've got
           padding. */
        if(vals[2] >= 0)
            *out++ = ((vals[1]&0x0F)<<4) | (vals[2]>>2);
        else
            *out++ = 0;

        if(vals[3] >= 0)
            *out++ = ((vals[2]&0x03)<<6) | (vals[3]);
        else
            *out++ = 0;

        len -= 4;
    }
    *out = 0;

    return result;
}

/* TODO, FIXME: handle memory allocation errors better. */
static inline void   _build_headers_loop(char **ret : itype(_Ptr<_Nt_array_ptr<char>>), _Ptr<size_t> len, _Ptr<ice_config_http_header_t> header, int status) {
    size_t headerlen;
    _Nt_array_ptr<const char> name = ((void *)0);
    _Nt_array_ptr<const char> value = ((void *)0);
    _Nt_array_ptr<char> r = *ret;

    if (!header)
        return;

    do {
        /* filter out header's we don't use. */
        if (header->status != 0 && header->status != status) continue;

        /* get the name of the header */
        name = header->name;

        /* handle type of the header */
        value = NULL;
        switch (header->type) _Checked {
            case HTTP_HEADER_TYPE_STATIC:
                value = header->value;
                break;
        }

        /* check data */
        if (!name || !value)
            continue;

        /* append the header to the buffer */
        headerlen = strlen(name) + strlen(value) + 4;
        *len += headerlen;
        r = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(realloc<char>(r, *len), byte_count(*len));
        _Unchecked {strcat((char*)r, name);}
        _Unchecked {strcat((char*)r, ": ");}
        _Unchecked {strcat((char*)r, value);}
        _Unchecked {strcat((char*)r, "\r\n");}
    } while ((header = header->next));
    *ret = r;
}
static char *_build_headers(int status, _Ptr<ice_config_t> config, _Ptr<source_t> source) : itype(_Nt_array_ptr<char>){
    _Ptr<mount_proxy> mountproxy = NULL;
    _Nt_array_ptr<char> ret = NULL;
    size_t len = 1;

    if (source)
        mountproxy = config_find_mount(config, source->mount, MOUNT_TYPE_NORMAL);

    ret = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(calloc<char>(1, 1), byte_count(1));
    *ret = 0;

    
    _Unchecked {
      char* tmpRetPtr = (char*)ret;
      _build_headers_loop(&tmpRetPtr, &len, config->http_headers, status);
    }
    if (mountproxy && mountproxy->http_headers)
        _Unchecked {
          char* tmpRetPtr = (char*)ret;
          _build_headers_loop(&tmpRetPtr, &len, mountproxy->http_headers, status);
        }

    return ret;
}

ssize_t util_http_build_header(char *out : itype(_Nt_array_ptr<char>), size_t len, ssize_t offset, int cache, int status, const char *statusmsg : itype(_Nt_array_ptr<const char>), const char *contenttype : itype(_Nt_array_ptr<const char>), const char *charset : itype(_Nt_array_ptr<const char>) count(5), const char *datablock : itype(_Nt_array_ptr<const char>), struct source_tag *source : itype(_Ptr<struct source_tag>)) {
    _Nt_array_ptr<const char> http_version : byte_count(3) = "1.0";
    _Ptr<ice_config_t> config = ((void *)0);
    time_t now;
    struct tm result;
    _Ptr<struct tm> gmtime_result = NULL;
    char currenttime_buffer _Nt_checked[80];
    char status_buffer _Nt_checked[80];
    char contenttype_buffer _Nt_checked[80];
    ssize_t ret;
    _Nt_array_ptr<char> extra_headers = ((void *)0);

    if (!out)
        return -1;

    if (offset == -1)
        offset = strlen (out);

    out += offset;
    len -= offset;

    if (status == -1)
    _Checked {
        status_buffer[0] = '\0';
    }
    else
    _Checked {
        if (!statusmsg)
	{
	    switch (status)
	    {
	        case 200: statusmsg = "OK"; break;
		case 206: statusmsg = "Partial Content"; http_version = "1.1"; break;
		case 400: statusmsg = "Bad Request"; break;
		case 401: statusmsg = "Authentication Required"; break;
		case 403: statusmsg = "Forbidden"; break;
		case 404: statusmsg = "File Not Found"; break;
		case 416: statusmsg = "Request Range Not Satisfiable"; break;
		default:  statusmsg = "(unknown status code)"; break;
	    }
	}
	_Unchecked { snprintf (status_buffer, sizeof (status_buffer), "HTTP/%s %d %s\r\n", http_version, status, statusmsg); };
    }

    if (contenttype)
    {
    	if (charset)
            _Unchecked {snprintf (contenttype_buffer, sizeof (contenttype_buffer), "Content-Type: %s; charset=%s\r\n",
	                                                               contenttype, charset);}
	else
            _Unchecked {snprintf (contenttype_buffer, sizeof (contenttype_buffer), "Content-Type: %s\r\n",
                                                                       contenttype);}
    }
    else
    _Checked {
        contenttype_buffer[0] = '\0';
    }

    _Unchecked {time(&now);}
#ifndef _WIN32
    _Unchecked {gmtime_result = _Assume_bounds_cast<_Ptr<struct tm>>(gmtime_r(&now, &result));}
#else
    /* gmtime() on W32 breaks POSIX and IS thread-safe (uses TLS) */
    gmtime_result = gmtime (&now);
    if (gmtime_result)
        memcpy (&result, gmtime_result, sizeof (result));
#endif

    if (gmtime_result)
        strftime(currenttime_buffer, sizeof(currenttime_buffer), "Date: %a, %d %b %Y %X GMT\r\n", gmtime_result);
    else
        currenttime_buffer[0] = '\0';

    config = config_get_config();
    extra_headers = ((_Nt_array_ptr<char> )_build_headers(status, config, source));
    _Unchecked {ret = snprintf (out, len, "%sServer: %s\r\nConnection: Close\r\n%s%s%s%s%s%s%s",
                              status_buffer,
			      config->server_id,
			      currenttime_buffer,
			      contenttype_buffer,
			      (status == 401 ? "WWW-Authenticate: Basic realm=\"Icecast2 Server\"\r\n" : ""),
                              (cache     ? "" : "Cache-Control: no-cache, no-store\r\n"
                                                "Expires: Mon, 26 Jul 1997 05:00:00 GMT\r\n"
                                                "Pragma: no-cache\r\n"),
                              extra_headers,
                              (datablock ? "\r\n" : ""),
                              (datablock ? datablock : ""));}
    free<char>(extra_headers);
    config_release_config();

    return ret;
}


util_dict *util_dict_new(void) : itype(_Ptr<util_dict>)
{
    return (_Ptr<util_dict>)calloc<util_dict>(1, sizeof(util_dict));
}

void util_dict_free(util_dict *dict : itype(_Ptr<util_dict>))
_Checked {
    _Ptr<util_dict> next = ((void *)0);

    while (dict) {
        next = dict->next;

        if (dict->key)
            free<char> (dict->key);
        if (dict->val)
            free<char> (dict->val);
        free<util_dict> (dict);

        dict = next;
    }
}

const char *util_dict_get(util_dict *dict : itype(_Ptr<util_dict>), const char *key : itype(_Nt_array_ptr<const char>)) : itype(_Ptr<const char>)
{
    while (dict) _Checked {
        if (!strcmp(key, dict->key))
            return dict->val;
        dict = dict->next;
    }
    return NULL;
}

int util_dict_set(util_dict *dict : itype(_Ptr<util_dict>), const char *key : itype(_Nt_array_ptr<const char>) count(100), const char *val : itype(_Nt_array_ptr<const char>))
{
    _Ptr<util_dict> prev = ((void *)0);

    if (!dict || !key) _Checked {
        _Unchecked {ICECAST_LOG_ERROR("NULL values passed to util_dict_set()");}
        return 0;
    }

    prev = NULL;
    while (dict) _Checked {
        if (!dict->key || !strcmp(dict->key, key))
            break;
        prev = dict;
        dict = dict->next;
    }

    if (!dict) _Checked {
        dict = util_dict_new();
        if (!dict) {
            _Unchecked {ICECAST_LOG_ERROR("unable to allocate new dictionary");}
            return 0;
        }
        if (prev)
            prev->next = dict;
    }

    if (dict->key)
        free<char> (dict->val);
    else if (!(dict->key = ((_Nt_array_ptr<char> )strdup(key)))) {
        if (prev)
            prev->next = NULL;
        util_dict_free (dict);

        _Unchecked {ICECAST_LOG_ERROR("unable to allocate new dictionary key");}
        return 0;
    }

    dict->val = ((_Nt_array_ptr<char> )strdup(val));
    if (!dict->val) _Checked {
        _Unchecked {ICECAST_LOG_ERROR("unable to allocate new dictionary value");}
        return 0;
    }

    return 1;
}

/* given a dictionary, URL-encode each val and 
   stringify it in order as key=val&key=val... if val 
   is set, or just key&key if val is NULL.
  TODO: Memory management needs overhaul. */
char *util_dict_urlencode(util_dict *dict : itype(_Ptr<util_dict>), char delim) : itype(_Nt_array_ptr<char>)
{
    _Nt_array_ptr<char> res = NULL;
    _Nt_array_ptr<char> tmp = NULL;
    _Nt_array_ptr<char> enc = ((void *)0);
    int start = 1;

    for (res = NULL; dict; dict = dict->next) {
        /* encode key */
        if (!dict->key)
            continue;
        if (start) {
            size_t keyLen = strlen(dict -> key);
            _Nt_array_ptr<char> res_with_len : byte_count(keyLen) = NULL;
            _Unchecked {
              res_with_len = _Assume_bounds_cast<_Nt_array_ptr<char>>(malloc(keyLen + 1), byte_count(keyLen));
            }
            if (!(res_with_len)) {
                return NULL;
            }
            res = res_with_len;
            //_Unchecked {sprintf(res, "%s", dict->key);}
            start = 0;
        } else {
            size_t keyLen = strlen(dict -> key);
            size_t resLen = strlen(res);
            _Nt_array_ptr<char> tmp_with_len : byte_count(resLen + keyLen + 2) = NULL;
            _Unchecked {
              tmp_with_len = _Assume_bounds_cast<_Nt_array_ptr<char>>(realloc<char>(_Assume_bounds_cast<_Array_ptr<char>>(res, count(1)), resLen + keyLen + 2), byte_count(resLen + keyLen + 2));
            }
            if (!(tmp_with_len)) {
                free<char>(res);
                return NULL;
            } else
                res = tmp_with_len;
            //_Unchecked {sprintf(res + strlen(res), "%c%s", delim, dict->key);}
        }

        /* encode value */
        if (!dict->val)
            continue;
        if (!(enc = util_url_escape(dict->val))) {
            free<char>(res);
            return NULL;
        }
        size_t resLen2 = strlen(res);
        size_t encLen = strlen(enc);
        _Nt_array_ptr<char> tmp_with_len2 : byte_count(resLen2 + encLen + 2) = NULL;
        _Unchecked {
          tmp_with_len2 = _Assume_bounds_cast<_Nt_array_ptr<char>>(realloc<char>(_Assume_bounds_cast<_Array_ptr<char>>(res, count(1)), resLen2 + encLen + 2), byte_count(resLen2 + encLen + 2));
        }
        tmp = tmp_with_len2;
        if (!(tmp)) {
            free<char>(enc);
            free<char>(res);
            return NULL;
        } else
            res = tmp;
        //_Unchecked {sprintf(res + strlen(res), "=%s", enc);}
        free<char>(enc);
    }

    return res;
}

#ifndef HAVE_LOCALTIME_R
struct tm *localtime_r (const time_t *timep, struct tm *result)
{
     static mutex_t localtime_lock;
     static int initialised = 0;
     struct tm *tm;

     if (initialised == 0)
     {
         thread_mutex_create (&localtime_lock);
         initialised = 1;
     }
     thread_mutex_lock (&localtime_lock);
     tm = localtime (timep);
     memcpy (result, tm, sizeof (*result));
     thread_mutex_unlock (&localtime_lock);
     return result;
}
#endif


/* helper function for converting a passed string in one character set to another
 * we use libxml2 for this
 */
char *util_conv_string(const char *string : itype(_Nt_array_ptr<const char>), const char *in_charset : itype(_Nt_array_ptr<const char>), const char *out_charset : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<char>)
{
    _Ptr<struct _xmlCharEncodingHandler> in = NULL;
    _Ptr<struct _xmlCharEncodingHandler> out = NULL;
    _Nt_array_ptr<char> ret = NULL;

    if (string == NULL || in_charset == NULL || out_charset == NULL)
        return NULL;

    _Unchecked {in  = _Assume_bounds_cast<_Ptr<struct _xmlCharEncodingHandler>>(xmlFindCharEncodingHandler (in_charset));}
    _Unchecked {out = _Assume_bounds_cast<_Ptr<struct _xmlCharEncodingHandler>>(xmlFindCharEncodingHandler (out_charset));}

    if (in && out)
    {
        _Ptr<struct xmlBuffer> orig = NULL;
        _Unchecked {orig = _Assume_bounds_cast<_Ptr<struct xmlBuffer>>(xmlBufferCreate ());}
        _Ptr<struct xmlBuffer> utf8 = NULL;
        _Unchecked {utf8 = _Assume_bounds_cast<_Ptr<struct xmlBuffer>>(xmlBufferCreate ());}
        _Ptr<struct xmlBuffer> conv = NULL;
        _Unchecked {conv = _Assume_bounds_cast<_Ptr<struct xmlBuffer>>(xmlBufferCreate ());}

        _Unchecked {ICECAST_LOG_INFO("converting metadata from %s to %s", in_charset, out_charset);}
        _Unchecked {xmlBufferCCat ((xmlBufferPtr)orig, string);}
        int tmpRet;
        _Unchecked {tmpRet = xmlCharEncInFunc((xmlCharEncodingHandler*)in, (xmlBufferPtr)utf8, (xmlBufferPtr)orig);}
        if (tmpRet > 0)
        {
            _Unchecked {xmlCharEncOutFunc ((xmlCharEncodingHandler*)out, (xmlBufferPtr)conv, NULL);}
            _Unchecked {tmpRet = xmlCharEncOutFunc ((xmlCharEncodingHandler*)out, (xmlBufferPtr)conv, (xmlBufferPtr)utf8);}
            if (tmpRet >= 0)
                _Unchecked {ret = _Assume_bounds_cast<_Nt_array_ptr<char>>(strdup(xmlBufferContent ((const xmlBuffer*)conv)), byte_count(4096));}
        }
        _Unchecked {xmlBufferFree ((xmlBufferPtr)orig);}
        _Unchecked {xmlBufferFree ((xmlBufferPtr)utf8);}
        _Unchecked {xmlBufferFree ((xmlBufferPtr)conv);}
    }
    _Unchecked {xmlCharEncCloseFunc ((xmlCharEncodingHandler*)in);}
    _Unchecked {xmlCharEncCloseFunc ((xmlCharEncodingHandler*)out);}

    return ret;
}


int get_line(FILE *file : itype(_Ptr<FILE>), char *buf : itype(_Nt_array_ptr<char>) count(siz), size_t siz)
{
    if(fgets(buf, (int)siz, file)) _Checked {
        size_t len = strlen(buf);
        if(len > 0 && buf[len-1] == '\n') {
            buf[--len] = 0;
            if(len > 0 && buf[len-1] == '\r')
                buf[--len] = 0;
        }
        return 1;
    }
    return 0;
}

