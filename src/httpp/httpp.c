/* Httpp.c
**
** http parsing engine
** 
** This program is distributed under the GNU General Public License, version 2.
** A copy of this license is included with this source.
*/

#ifdef HAVE_CONFIG_H
 #include <config.h>
#endif

#include <stdio.h>

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include <avl/avl.h>
#include "httpp.h"

#if defined(_WIN32) && !defined(HAVE_STRCASECMP)
#define strcasecmp stricmp
#endif

#define MAX_HEADERS 32

#pragma CHECKED_SCOPE on

/* internal functions */

/* misc */
static _Nt_array_ptr<char> _lowercase(_Nt_array_ptr<char> str);

/* for avl trees */
static int _compare_vars(void *compare_arg : itype(_Ptr<void>), void *a : itype(_Ptr<void>), void *b : itype(_Ptr<void>));
static int _free_vars(void *key : itype(_Ptr<void>));

http_parser_t *httpp_create_parser(void) : itype(_Ptr<http_parser_t>)
{
    return (_Ptr<http_parser_t>)malloc<http_parser_t>(sizeof(http_parser_t));
}

void httpp_initialize(http_parser_t *parser : itype(_Ptr<http_parser_t>), http_varlist_t *defaults : itype(_Ptr<http_varlist_t>))
{
    _Ptr<http_varlist_t> list = ((void *)0);

    parser->req_type = httpp_req_none;
    parser->uri = NULL;
    parser->vars = avl_tree_new(_compare_vars, NULL);
    parser->queryvars = avl_tree_new(_compare_vars, NULL);

    /* now insert the default variables */
    list = defaults;
    while (list != NULL) {
        httpp_setvar(parser, list->var.name, list->var.value);
        list = list->next;
    }
}

static int split_headers(_Nt_array_ptr<char> data : count(len), unsigned long len, _Array_ptr<_Nt_array_ptr<char>> line : count(32))
_Checked {
    /* first we count how many lines there are 
    ** and set up the line[] array     
    */
    int lines = 0;
    unsigned long i;
    line[lines] = data;
    for (i = 0; i < len && lines < MAX_HEADERS; i++) {
        if (data[i] == '\r')
            data[i] = '\0';
        if (data[i] == '\n') {
            lines++;
            data[i] = '\0';
            if (lines >= MAX_HEADERS)
                return MAX_HEADERS;
            if (i + 1 < len) {
                if (data[i + 1] == '\n' || data[i + 1] == '\r')
                    break;
                line[lines] = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(&data[i + 1], byte_count(512));
            }
        }
    }

    i++;
    while (i < len && data[i] == '\n') i++;

    return lines;
}

static void parse_headers(_Ptr<http_parser_t> parser, _Array_ptr<_Nt_array_ptr<char>> line : count(32), int lines)
{
    int i, l;
    int whitespace, slen;
    _Nt_array_ptr<char> name = NULL;
    _Nt_array_ptr<char> value = NULL;

    /* parse the name: value lines. */
    for (l = 1; l < lines; l++) {
        whitespace = 0;
        name = line[l];
        value = NULL;
        slen = strlen(line[l]);
        for (i = 0; i < slen; i++) _Checked {
            if (line[l][i] == ':') {
                whitespace = 1;
                line[l][i] = '\0';
            } else {
                if (whitespace) {
                    whitespace = 0;
                    while (i < slen && line[l][i] == ' ')
                        i++;

                    if (i < slen)
                        value = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(&line[l][i], count(512));
                    
                    break;
                }
            }
        }
        
        if (name != NULL && value != NULL) {
            httpp_setvar(parser, _lowercase(name), value);
            name = NULL; 
            value = NULL;
        }
    }
}

int httpp_parse_response(http_parser_t *parser : itype(_Ptr<http_parser_t>), const char *http_data : itype(_Array_ptr<const char>) count(4096), unsigned long len, const char *uri : itype(_Nt_array_ptr<const char>))
{
    _Nt_array_ptr<char> data : byte_count(len) = NULL;
    _Nt_array_ptr<char> line _Checked[MAX_HEADERS] = {((void *)0)};
    int lines, slen,i, whitespace=0, where=0,code;
    _Nt_array_ptr<char> version =NULL;
_Nt_array_ptr<char> resp_code =NULL;
_Nt_array_ptr<char> message =NULL;

    
    if(http_data == NULL)
        return 0;

    /* make a local copy of the data, including 0 terminator */
    data = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(malloc<char>(len+1), byte_count(len+1));
    if (data == NULL) return 0;
    _Unchecked {memcpy<char>((char*)data, http_data, len);}
    data[len] = 0;

    lines = split_headers(data, len, line);

    /* In this case, the first line contains:
     * VERSION RESPONSE_CODE MESSAGE, such as HTTP/1.0 200 OK
     */
    slen = strlen(line[0]);
    version = line[0];
    for(i=0; i < slen; i++) _Checked {
        if(line[0][i] == ' ') {
            line[0][i] = 0;
            whitespace = 1;
        } else if(whitespace) {
            whitespace = 0;
            where++;
            if(where == 1)
                resp_code = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(&line[0][i], byte_count(512));
            else {
                message = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(&line[0][i], byte_count(512));
                break;
            }
        }
    }

    if(version == NULL || resp_code == NULL || message == NULL) {
        free<char>(data);
        return 0;
    }

    httpp_setvar(parser, HTTPP_VAR_ERROR_CODE, resp_code);
    code = atoi(resp_code);
    if(code < 200 || code >= 300) {
        httpp_setvar(parser, HTTPP_VAR_ERROR_MESSAGE, message);
    }

    httpp_setvar(parser, HTTPP_VAR_URI, uri);
    httpp_setvar(parser, HTTPP_VAR_REQ_TYPE, "NONE");

    parse_headers(parser, line, lines);

    free<char>(data);

    return 1;
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

static char *url_escape(_Nt_array_ptr<const char> src) : itype(_Nt_array_ptr<char>)
{
    int len = strlen(src);
    _Nt_array_ptr<unsigned char>decoded = NULL;
    int i;
    _Nt_array_ptr<char> dst = NULL;
    int done = 0;

    decoded = _Dynamic_bounds_cast<_Nt_array_ptr<unsigned char>>(calloc<unsigned char>(1, len + 1), byte_count(512));

    dst = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(decoded, byte_count(512));

    for(i=0; i < len; i++) _Checked {
        switch(src[i]) _Unchecked {
        case '%':
            if(i+2 >= len) {
                free<unsigned char>(decoded);
                return NULL;
            }
            if(hex(src[i+1]) == -1 || hex(src[i+2]) == -1 ) {
                free<unsigned char>(decoded);
                return NULL;
            }

            *dst++ = hex(src[i+1]) * 16  + hex(src[i+2]);
            i+= 2;
            break;
        case '+':
            *dst++ = ' ';
            break;
        case '#':
            done = 1;
            break;
        case 0:
            free<unsigned char>(decoded);
            return NULL;
            break;
        default:
            *dst++ = src[i];
            break;
        }
        if(done)
            break;
    }

    *dst = 0; /* null terminator */

    return _Dynamic_bounds_cast<_Nt_array_ptr<char>>(decoded, byte_count(512));
}

/** TODO: This is almost certainly buggy in some cases */
static void parse_query(_Ptr<http_parser_t> parser, _Nt_array_ptr<char> query)
{
    int len;
    int i=0;
    _Nt_array_ptr<char> key = query;
    _Nt_array_ptr<char> val =NULL;

    if(!query || !*query)
        return;

    len = strlen(query);

    while(i<len) _Checked {
        switch(query[i]) _Unchecked {
        case '&':
            query[i] = 0;
            if(val && key)
                httpp_set_query_param(parser, key, val);
            key = query+i+1;
            break;
        case '=':
            query[i] = 0;
            val = query+i+1;
            break;
        }
        i++;
    }

    if(val && key) {
        httpp_set_query_param(parser, key, val);
    }
}

int httpp_parse(http_parser_t *parser : itype(_Ptr<http_parser_t>), const char *http_data : itype(_Array_ptr<const char>) count(len), unsigned long len)
{
    _Nt_array_ptr<char> data : byte_count(len) = NULL;
    _Nt_array_ptr<char> tmp = ((void *)0);

    _Nt_array_ptr<char> line _Checked[MAX_HEADERS] = {((void *)0)}; /* limited to 32 lines, should be more than enough */
    int i;
    int lines;
    _Nt_array_ptr<char> req_type = NULL;
    _Nt_array_ptr<char> uri = NULL;
    _Nt_array_ptr<char> version = NULL;
    int whitespace, where, slen;

    if (http_data == NULL)
        return 0;

    /* make a local copy of the data, including 0 terminator */
    data = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(malloc<char>(len+1), byte_count(len+1));
    if (data == NULL) return 0;
    memcpy<char>(data, http_data, len);
    data[len] = 0;

    lines = split_headers(data, len, line);

    /* parse the first line special
    ** the format is:
    ** REQ_TYPE URI VERSION
    ** eg:
    ** GET /index.html HTTP/1.0
    */
    where = 0;
    whitespace = 0;
    slen = strlen(line[0]);
    req_type = line[0];
    for (i = 0; i < slen; i++) _Checked {
        if (line[0][i] == ' ') {
            whitespace = 1;
            line[0][i] = '\0';
        } else {
            /* we're just past the whitespace boundry */
            if (whitespace) {
                whitespace = 0;
                where++;
                switch (where) {
                case 1:
                    uri = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(&line[0][i], byte_count(512));
                    break;
                case 2:
                    version = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(&line[0][i], byte_count(512));
                    break;
                }
            }
        }
    }

     if (strcasecmp("GET", req_type) == 0) {
        parser->req_type = httpp_req_get;
     } else if (strcasecmp("POST", req_type) == 0) {
        parser->req_type = httpp_req_post;
     } else if (strcasecmp("PUT", req_type) == 0) {
        parser->req_type = httpp_req_put;
     } else if (strcasecmp("HEAD", req_type) == 0) {
        parser->req_type = httpp_req_head;
     } else if (strcasecmp("SOURCE", req_type) == 0) {
        parser->req_type = httpp_req_source;
     } else if (strcasecmp("PLAY", req_type) == 0) {
        parser->req_type = httpp_req_play;
     } else if (strcasecmp("STATS", req_type) == 0) {
        parser->req_type = httpp_req_stats;
    } else {
        parser->req_type = httpp_req_unknown;
    }

    if (uri != NULL && strlen(uri) > 0) {
        _Nt_array_ptr<char> query = ((void *)0);
        if((query = ((_Nt_array_ptr<char> )strchr(uri, '?'))) != NULL) {
            httpp_setvar(parser, HTTPP_VAR_RAWURI, uri);
            httpp_setvar(parser, HTTPP_VAR_QUERYARGS, query);
            *query = 0;
            query++;
            parse_query(parser, query);
        }

        parser->uri = ((_Nt_array_ptr<char> )strdup(uri));
    } else {
        free<char>(data);
        return 0;
    }

    if ((version != NULL) && ((tmp = ((_Nt_array_ptr<char> )strchr(version, '/'))) != NULL)) _Checked {
        tmp[0] = '\0';
        _Nt_array_ptr<char> holder : byte_count(2) = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(&tmp[1], byte_count(2));
        if ((strlen(version) > 0) && (strlen(holder) > 0)) _Unchecked {
            httpp_setvar(parser, HTTPP_VAR_PROTOCOL, version);
            httpp_setvar(parser, HTTPP_VAR_VERSION, &tmp[1]);
        } else _Unchecked {
            free<char>(data);
            return 0;
        }
    } else {
        free<char>(data);
        return 0;
    }

    if (parser->req_type != httpp_req_none && parser->req_type != httpp_req_unknown) {
        switch (parser->req_type) {
        case httpp_req_get:
            httpp_setvar(parser, HTTPP_VAR_REQ_TYPE, "GET");
            break;
        case httpp_req_post:
            httpp_setvar(parser, HTTPP_VAR_REQ_TYPE, "POST");
            break;
        case httpp_req_put:
            httpp_setvar(parser, HTTPP_VAR_REQ_TYPE, "PUT");
            break;
        case httpp_req_head:
            httpp_setvar(parser, HTTPP_VAR_REQ_TYPE, "HEAD");
            break;
        case httpp_req_source:
            httpp_setvar(parser, HTTPP_VAR_REQ_TYPE, "SOURCE");
            break;
        case httpp_req_play:
            httpp_setvar(parser, HTTPP_VAR_REQ_TYPE, "PLAY");
            break;
        case httpp_req_stats:
            httpp_setvar(parser, HTTPP_VAR_REQ_TYPE, "STATS");
            break;
        default:
            break;
        }
    } else {
        free<char>(data);
        return 0;
    }

    if (parser->uri != NULL) {
        httpp_setvar(parser, HTTPP_VAR_URI, parser->uri);
    } else {
        free<char>(data);
        return 0;
    }

    parse_headers(parser, line, lines);

    free<char>(data);

    return 1;
}

void httpp_deletevar(http_parser_t *parser : itype(_Ptr<http_parser_t>), const char *name : itype(_Nt_array_ptr<const char>))
{
    http_var_t var = {};

    if (parser == NULL || name == NULL)
        return;
    var.name = (_Nt_array_ptr<char>)name;
    var.value = NULL;
    avl_delete<void>(parser->vars, _Dynamic_bounds_cast<_Ptr<void>>(&var), _free_vars);
}

void httpp_setvar(http_parser_t *parser : itype(_Ptr<http_parser_t>), const char *name : itype(_Nt_array_ptr<const char>), const char *value : itype(_Nt_array_ptr<const char>))
{
    _Ptr<http_var_t> var = NULL;

    if (name == NULL || value == NULL)
        return;

    var = _Dynamic_bounds_cast<_Ptr<http_var_t>>(malloc<http_var_t>(sizeof(http_var_t)));
    if (var == NULL) return;

    var->name = ((_Nt_array_ptr<char> )strdup(name));
    var->value = ((_Nt_array_ptr<char> )strdup(value));

    if (httpp_getvar(parser, name) == NULL) {
        avl_insert(parser->vars, _Dynamic_bounds_cast<_Ptr<void>>(var));
    } else {
        avl_delete<void>(parser->vars, _Dynamic_bounds_cast<_Ptr<void>>(var), _free_vars);
        avl_insert(parser->vars, _Dynamic_bounds_cast<_Ptr<void>>(var));
    }
}

const char *httpp_getvar(http_parser_t *parser : itype(_Ptr<http_parser_t>), const char *name : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<const char>)
{
    http_var_t var = {};
    _Ptr<http_var_t> found = NULL;
    _Ptr<_Ptr<void>>fp = NULL;

    if (parser == NULL || name == NULL)
        return NULL;

    fp = _Dynamic_bounds_cast<_Ptr<_Ptr<void>>>(&found);
    var.name = (_Nt_array_ptr<char>)name;
    var.value = NULL;

    if (avl_get_by_key(parser->vars, _Dynamic_bounds_cast<_Ptr<void>>(&var), fp) == 0)
        return found->value;
    else
        return NULL;
}

void httpp_set_query_param(http_parser_t *parser : itype(_Ptr<http_parser_t>), const char *name : itype(_Nt_array_ptr<const char>), const char *value : itype(_Nt_array_ptr<const char>))
{
    _Ptr<http_var_t> var = NULL;

    if (name == NULL || value == NULL)
        return;

    var = _Dynamic_bounds_cast<_Ptr<http_var_t>>(malloc<http_var_t>(sizeof(http_var_t)));
    if (var == NULL) return;

    var->name = ((_Nt_array_ptr<char> )strdup(name));
    var->value = ((_Nt_array_ptr<char> )url_escape(value));

    if (httpp_get_query_param(parser, name) == NULL) {
        avl_insert(parser->queryvars, _Dynamic_bounds_cast<_Ptr<void>>(var));
    } else {
        avl_delete<void>(parser->queryvars, _Dynamic_bounds_cast<_Ptr<void>>(var), _free_vars);
        avl_insert(parser->queryvars, _Dynamic_bounds_cast<_Ptr<void>>(var));
    }
}

const char *httpp_get_query_param(http_parser_t *parser : itype(_Ptr<http_parser_t>), const char *name : itype(_Nt_array_ptr<const char>)) : itype(_Nt_array_ptr<const char>)
{
    http_var_t var = {};
    _Ptr<http_var_t> found = NULL;
    _Ptr<_Ptr<void>> fp = NULL;

    fp = _Dynamic_bounds_cast<_Ptr<_Ptr<void>>>(&found);
    var.name = (_Nt_array_ptr<char>)name;
    var.value = NULL;

    if (avl_get_by_key(parser->queryvars, _Dynamic_bounds_cast<_Ptr<void>>(&var), fp) == 0)
        return found->value;
    else
        return NULL;
}

void httpp_clear(http_parser_t *parser : itype(_Ptr<http_parser_t>))
{
    parser->req_type = httpp_req_none;
    if (parser->uri)
        free<char>(parser->uri);
    parser->uri = NULL;
    avl_tree_free<void>(parser->vars, _free_vars);
    avl_tree_free<void>(parser->queryvars, _free_vars);
    parser->vars = NULL;
}

void httpp_destroy(http_parser_t *parser : itype(_Ptr<http_parser_t>))
{
    httpp_clear(parser);
    free<http_parser_t>(parser);
}

static _Nt_array_ptr<char> _lowercase(_Nt_array_ptr<char> str)
_Checked {
    _Array_ptr<char> p = str;
    _Unchecked {for (; *(char*)p != '\0'; p++)
        *(char*)p = tolower(*(char*)p);}

    return str;
}

static int _compare_vars(void *compare_arg : itype(_Ptr<void>), void *a : itype(_Ptr<void>), void *b : itype(_Ptr<void>))
{
    _Ptr<http_var_t> vara = NULL;
    _Ptr<http_var_t> varb = NULL;

    vara = _Dynamic_bounds_cast<_Ptr<http_var_t>>(a);
    varb = _Dynamic_bounds_cast<_Ptr<http_var_t>>(b);

    return strcmp(vara->name, varb->name);
}

static int _free_vars(void *key : itype(_Ptr<void>))
{
    _Ptr<http_var_t> var = NULL;

    var = _Dynamic_bounds_cast<_Ptr<http_var_t>>(key);

    if (var->name)
        free<char>(var->name);
    if (var->value)
        free<void>(_Dynamic_bounds_cast<_Array_ptr<void>>(var->value, byte_count(0)));
    free<http_var_t>(var);

    return 1;
}

