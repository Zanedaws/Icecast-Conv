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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <libxml/xmlmemory.h>
#include <libxml/debugXML.h>
#include <libxml/HTMLtree.h>
#include <libxml/xmlIO.h>
#include <libxml/xinclude.h>
#include <libxml/catalog.h>
#include <libxslt/xslt.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/transform.h>
#include <libxslt/xsltutils.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef  HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef WIN32
#define snprintf _snprintf
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
#include "fserve.h"
#include "util.h"

#define CATMODULE "xslt"

#include "logging.h"

#pragma CHECKED_SCOPE on

typedef struct {
    char *filename : itype(_Nt_array_ptr<char>);
    time_t             last_modified;
    time_t             cache_age;
    xsltStylesheetPtr  stylesheet : itype(_Ptr<struct _xsltStylesheet>);
} stylesheet_cache_t;

#ifndef HAVE_XSLTSAVERESULTTOSTRING
int xsltSaveResultToString(xmlChar **doc_txt_ptr, int * doc_txt_len, xmlDocPtr result, xsltStylesheetPtr style) {
    xmlOutputBufferPtr buf;

    *doc_txt_ptr = NULL;
    *doc_txt_len = 0;
    if (result->children == NULL)
	return(0);

	buf = xmlAllocOutputBuffer(NULL);

    if (buf == NULL)
		return(-1);
    xsltSaveResultTo(buf, result, style);
    if (buf->conv != NULL) {
		*doc_txt_len = buf->conv->use;
		*doc_txt_ptr = xmlStrndup(buf->conv->content, *doc_txt_len);
    } else {
		*doc_txt_len = buf->buffer->use;
		*doc_txt_ptr = xmlStrndup(buf->buffer->content, *doc_txt_len);
    }
    (void)xmlOutputBufferClose(buf);
    return 0;
}
#endif

/* Keep it small... */
#define CACHESIZE 3

static stylesheet_cache_t cache _Checked[CACHESIZE];
static mutex_t xsltlock;

void xslt_initialize(void)
{
    memset(_Dynamic_bounds_cast<_Array_ptr<void>>(cache, byte_count(sizeof(stylesheet_cache_t)*CACHESIZE)), 0, sizeof(stylesheet_cache_t)*CACHESIZE);
    thread_mutex_create(&xsltlock);
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlSubstituteEntitiesDefault(1);
    _Unchecked {xmlLoadExtDtdDefaultValue = 1;}
}

void xslt_shutdown(void) {
    int i;

    for(i=0; i < CACHESIZE; i++) {
        if(cache[i].filename)
            free<char>(cache[i].filename);
        if(cache[i].stylesheet)
            _Unchecked {xsltFreeStylesheet((xsltStylesheetPtr)cache[i].stylesheet);}
    }

    thread_mutex_destroy (&xsltlock);
    xmlCleanupParser();
    xsltCleanupGlobals();
}

static int evict_cache_entry(void) {
    int i, age=0, oldest=0;

    for(i=0; i < CACHESIZE; i++) _Checked {
        if(cache[i].cache_age > age) {
            age = cache[i].cache_age;
            oldest = i;
        }
    }

    _Unchecked {xsltFreeStylesheet((xsltStylesheetPtr)cache[oldest].stylesheet);}
    free<char>(cache[oldest].filename);

    return oldest;
}

static xsltStylesheetPtr xslt_get_stylesheet(_Nt_array_ptr<const char> fn) : itype(_Ptr<struct _xsltStylesheet>) {
    int i;
    int empty = -1;
    struct stat file;

    if(stat(fn, &file)) {
        _Unchecked {ICECAST_LOG_WARN("Error checking for stylesheet file \"%s\": %s", fn, 
                strerror(errno));}
        return NULL;
    }

    for(i=0; i < CACHESIZE; i++) _Checked {
        if(cache[i].filename)
        {
#ifdef _WIN32
            if(!stricmp(fn, cache[i].filename))
#else
            if(!strcmp(fn, cache[i].filename))
#endif
            _Unchecked {
                if(file.st_mtime > cache[i].last_modified)
                _Checked {
                    _Unchecked {xsltFreeStylesheet((xsltStylesheetPtr)cache[i].stylesheet);}

                    cache[i].last_modified = file.st_mtime;
                    _Unchecked {cache[i].stylesheet = _Assume_bounds_cast<_Ptr<struct _xsltStylesheet>>(xsltParseStylesheetFile (XMLSTR(fn)));}
                    cache[i].cache_age = time(NULL);
                }
                ICECAST_LOG_DEBUG("Using cached sheet %i", i);
                return cache[i].stylesheet;
                return NULL;
            }
        }
        else
            empty = i;
    }

    if(empty>=0)
        i = empty;
    else
        i = evict_cache_entry();

    cache[i].last_modified = file.st_mtime;
    cache[i].filename = strdup(fn);
    _Unchecked {cache[i].stylesheet = _Assume_bounds_cast<_Ptr<struct _xsltStylesheet>>(xsltParseStylesheetFile (XMLSTR(fn)));}
    cache[i].cache_age = time(NULL);
    return cache[i].stylesheet;
    return NULL;
}

void xslt_transform(xmlDocPtr doc : itype(_Ptr<struct _xmlDoc>), const char *xslfilename : itype(_Nt_array_ptr<const char>), client_t *client : itype(_Ptr<client_t>))
{
    _Ptr<struct _xmlDoc>    res = NULL;
    _Ptr<struct _xsltStylesheet> cur = NULL;
    _Nt_array_ptr<xmlChar> string = NULL;
    int len, problem = 0;
    _Nt_array_ptr<const char> mediatype = NULL;
    _Nt_array_ptr<const char> charset : count(5) = NULL;
    int tmpRet;

    _Unchecked {xmlSetGenericErrorFunc ("", log_parse_failure);}
    _Unchecked {xsltSetGenericErrorFunc ("", log_parse_failure);}

    thread_mutex_lock(&xsltlock);
    cur = xslt_get_stylesheet(xslfilename);

    if (cur == NULL)
    {
        thread_mutex_unlock(&xsltlock);
        _Unchecked {ICECAST_LOG_ERROR("problem reading stylesheet \"%s\"", xslfilename);}
        client_send_404 (client, "Could not parse XSLT file");
        return;
    }

    _Unchecked {res = _Assume_bounds_cast<_Ptr<struct _xmlDoc>>(xsltApplyStylesheet((xsltStylesheetPtr)cur, doc, NULL));}
    if (res != NULL) {
        _Unchecked {
        xmlChar* tmpStr = (xmlChar*)string;
        tmpRet = xsltSaveResultToString((xmlChar**)&tmpStr, &len, (xmlDocPtr)res, (xsltStylesheetPtr)cur);}
        if (tmpRet < 0)
            problem = 1;
    } else _Checked {
        problem = 1;
    }

    /* lets find out the content type and character encoding to use */
    _Unchecked {if (cur->encoding)
       charset = _Assume_bounds_cast<_Nt_array_ptr<const char>>(cur->encoding, byte_count(5));}

    _Unchecked { if (cur->mediaType)
        mediatype = _Assume_bounds_cast<_Nt_array_ptr<const char>>(cur->mediaType, byte_count(9999));
    else
    {
        /* check method for the default, a missing method assumes xml */
        if (cur->method && xmlStrcmp (cur->method, XMLSTR("html")) == 0)
            mediatype = "text/html";
        else
            if (cur->method && xmlStrcmp (cur->method, XMLSTR("text")) == 0)
                mediatype = "text/plain";
            else
                mediatype = "text/xml";
    }
    }
    if (problem == 0)
    {
        ssize_t ret;
        int failed = 0;
        _Ptr<refbuf_t> refbuf = NULL;
        size_t full_len = strlen (mediatype) + len + 1024;
        if (full_len < 4096)
            full_len = 4096;
        refbuf = refbuf_new (full_len);

        if (string == NULL)
            _Unchecked {string = _Assume_bounds_cast<_Nt_array_ptr<xmlChar>>(xmlCharStrdup (""), byte_count(4096));}
        ret = util_http_build_header(refbuf->data, full_len, 0, 0, 200, NULL, mediatype, charset, NULL, NULL);
        if (ret == -1) {
            _Unchecked {ICECAST_LOG_ERROR("Dropping client as we can not build response headers.");}
            client_send_500(client, "Header generation failed.");
        } else _Checked {
            if ( full_len < (ret + len + 64) ) _Unchecked {
                _Nt_array_ptr<char> new_data : byte_count(PER_CLIENT_REFBUF_SIZE)= NULL;
                full_len = ret + len + 64;
                new_data = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(realloc<char>(refbuf->data, full_len), byte_count(PER_CLIENT_REFBUF_SIZE));
                if (new_data) {
                    ICECAST_LOG_DEBUG("Client buffer reallocation succeeded.");
                    refbuf->data = new_data;
                    refbuf->len = full_len;
                    ret = util_http_build_header(refbuf->data, full_len, 0, 0, 200, NULL, _Assume_bounds_cast<_Nt_array_ptr<const char>>(mediatype, byte_count(0)), _Assume_bounds_cast<_Nt_array_ptr<const char>>(charset, count(5)), NULL, NULL);
                    if (ret == -1) {
                        ICECAST_LOG_ERROR("Dropping client as we can not build response headers.");
                        client_send_500(client, "Header generation failed.");
                        failed = 1;
                    }
                } else {
                    ICECAST_LOG_ERROR("Client buffer reallocation failed. Dropping client.");
                    client_send_500(client, "Buffer reallocation failed.");
                    failed = 1;
                }
            }

            if (!failed) _Unchecked {
                  snprintf(refbuf->data + ret, full_len - ret, "Content-Length: %d\r\n\r\n%s", len, string);

                client->respcode = 200;
                client_set_queue (client, NULL);
                client->refbuf = refbuf;
                refbuf->len = strlen (refbuf->data);
                fserve_add_client (client, NULL);
            }
        }
        //xmlFree (string);
    }
    else
    {
        _Unchecked {ICECAST_LOG_WARN("problem applying stylesheet \"%s\"", xslfilename);}
        client_send_404 (client, "XSLT problem");
    }
    thread_mutex_unlock (&xsltlock);
    //xmlFreeDoc(res);
}

