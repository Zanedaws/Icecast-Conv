/* Icecast
 *
 * This program is distributed under the GNU General Public License,
 * version 2. A copy of this license is included with this source.
 * At your option, this specific source file can also be distributed
 * under the GNU GPL version 3.
 *
 * Copyright 2012,      David Richards, Mozilla Foundation,
 *                      and others (see AUTHORS for details).
 */

/* format_ebml.c
 *
 * format plugin for WebM/EBML
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "refbuf.h"
#include "source.h"
#include "client.h"

#include "stats.h"
#include "format.h"
#include "format_ebml.h"

#define CATMODULE "format-ebml"

#include "logging.h"

#define EBML_DEBUG 0
#define EBML_HEADER_MAX_SIZE 131072
#define EBML_SLICE_SIZE 4096

#pragma CHECKED_SCOPE on

typedef struct ebml_client_data_st ebml_client_data_t;

struct ebml_client_data_st {

    refbuf_t *header : itype(_Ptr<refbuf_t>);
    int header_pos;

};

struct ebml_st {

    char *cluster_id : itype(_Nt_array_ptr<char>);
    int cluster_start;
    
    int position;
    unsigned char *input_buffer : itype(_Nt_array_ptr<unsigned char>);
    unsigned char *buffer : itype(_Nt_array_ptr<unsigned char>);

    int header_read;
    int header_size;
    int header_position;
    int header_read_position;
    unsigned char *header : itype(_Nt_array_ptr<unsigned char>);

};

static void ebml_free_plugin (_Ptr<format_plugin_t> plugin);
static _Ptr<refbuf_t> ebml_get_buffer(_Ptr<source_t> source);
static int  ebml_write_buf_to_client (_Ptr<client_t> client);
static void  ebml_write_buf_to_file (_Ptr<source_t> source, _Ptr<refbuf_t> refbuf);
static int  ebml_create_client_data (_Ptr<source_t> source, _Ptr<client_t> client);
static void ebml_free_client_data (_Ptr<client_t> client);

static _Ptr<ebml_t> ebml_create(void);
static void ebml_destroy(_Ptr<ebml_t> ebml);
static int ebml_read_space(_Ptr<ebml_t> ebml);
static int ebml_read(_Ptr<ebml_t> ebml, char *buffer : itype(_Nt_array_ptr<char>) byte_count(len), int len);
static int ebml_last_was_sync(_Ptr<ebml_t> ebml);
static char *ebml_write_buffer(_Ptr<ebml_t> ebml, int len) : itype(_Nt_array_ptr<char>);
static int ebml_wrote(_Ptr<ebml_t> ebml, int len);

int format_ebml_get_plugin (source_t *source : itype(_Ptr<source_t>))
{

    _Ptr<ebml_source_state_t> ebml_source_state = calloc<ebml_source_state_t>(1, sizeof(ebml_source_state_t));
    _Ptr<format_plugin_t> plugin = calloc<format_plugin_t>(1, sizeof(format_plugin_t));

    plugin->get_buffer = ebml_get_buffer;
    plugin->write_buf_to_client = ebml_write_buf_to_client;
    plugin->create_client_data = ebml_create_client_data;
    plugin->free_plugin = ebml_free_plugin;
    plugin->write_buf_to_file = ebml_write_buf_to_file;
    plugin->set_tag = NULL;
    plugin->apply_settings = NULL;

    plugin->contenttype = httpp_getvar (source->parser, "content-type");

    plugin->_state = _Dynamic_bounds_cast<_Ptr<void>>(ebml_source_state);
    source->format = plugin;

    ebml_source_state->ebml = _Dynamic_bounds_cast<_Ptr<ebml_t>>(ebml_create());
    return 0;
}

static void ebml_free_plugin (_Ptr<format_plugin_t> plugin)
{

    _Ptr<ebml_source_state_t> ebml_source_state = _Dynamic_bounds_cast<_Ptr<ebml_source_state_t>>(plugin->_state);

    refbuf_release (ebml_source_state->header);
    ebml_destroy(ebml_source_state->ebml);
    free<ebml_source_state_t> (ebml_source_state);
    free<format_plugin_t> (plugin);

}

static int send_ebml_header (_Ptr<client_t> client)
{

    _Ptr<ebml_client_data_t> ebml_client_data = _Dynamic_bounds_cast<_Ptr<ebml_client_data_t>>(client->format_data);
    int len = EBML_SLICE_SIZE;
    int ret;

    if (ebml_client_data->header->len - ebml_client_data->header_pos < len) 
    _Checked {
        len = ebml_client_data->header->len - ebml_client_data->header_pos;
    }
    ret = client_send_bytes<char> (client, 
                             ebml_client_data->header->data + ebml_client_data->header_pos,
                             len);

    if (ret > 0)
    _Checked {
        ebml_client_data->header_pos += ret;
    }

    return ret;

}

static int ebml_write_buf_to_client (_Ptr<client_t> client)
{

    _Ptr<ebml_client_data_t> ebml_client_data = _Dynamic_bounds_cast<_Ptr<ebml_client_data_t>>(client->format_data);

    if (ebml_client_data->header_pos != ebml_client_data->header->len)
    {
        return send_ebml_header (client);
    }
    else
    {
        client->write_to_client = format_generic_write_to_client;
        return client->write_to_client(client);
    }

}

static _Ptr<refbuf_t> ebml_get_buffer(_Ptr<source_t> source)
{

    _Ptr<ebml_source_state_t> ebml_source_state = _Dynamic_bounds_cast<_Ptr<ebml_source_state_t>>(source->format->_state);
    _Ptr<format_plugin_t> format = source->format;
    _Nt_array_ptr<char> data = NULL;
    int bytes = 0;
    _Ptr<refbuf_t> refbuf = NULL;
    int ret;

    while (1)
    _Checked {

        if ((bytes = ebml_read_space(ebml_source_state->ebml)) > 0)
        _Unchecked {
            refbuf = refbuf_new(bytes);
            ebml_read(ebml_source_state->ebml, refbuf->data, bytes);

            if (ebml_source_state->header == NULL)
            _Checked {
                ebml_source_state->header = refbuf;
                continue;
            }

            if (ebml_last_was_sync(ebml_source_state->ebml))
            _Checked {
                refbuf->sync_point = 1;
            }
            return refbuf;

        }
        else{

            data = ebml_write_buffer(ebml_source_state->ebml, EBML_SLICE_SIZE);
            bytes = client_read_bytes (source->client, data, EBML_SLICE_SIZE);
            if (bytes <= 0)
            {
                ebml_wrote (ebml_source_state->ebml, 0);
                return NULL;
            }
            format->read_bytes += bytes;
            ret = ebml_wrote (ebml_source_state->ebml, bytes);
            if (ret != bytes) {
                _Unchecked {ICECAST_LOG_ERROR("Problem processing stream");}
                source->running = 0;
                return NULL;
            }
        }
    }
}

static int ebml_create_client_data (_Ptr<source_t> source, _Ptr<client_t> client)
{

    _Ptr<ebml_client_data_t> ebml_client_data = calloc<ebml_client_data_t>(1, sizeof(ebml_client_data_t));
    _Ptr<ebml_source_state_t> ebml_source_state = _Dynamic_bounds_cast<_Ptr<ebml_source_state_t>>(source->format->_state);

    int ret = -1;

    if ((ebml_client_data) && (ebml_source_state->header))
    {
        ebml_client_data->header = ebml_source_state->header;
        refbuf_addref (ebml_client_data->header);
        client->format_data = ebml_client_data;
        client->free_client_data = ebml_free_client_data;
        ret = 0;
    }

    return ret;

}


static void ebml_free_client_data (_Ptr<client_t> client)
{

    _Ptr<ebml_client_data_t> ebml_client_data = _Dynamic_bounds_cast<_Ptr<ebml_client_data_t>>(client->format_data);

    refbuf_release (ebml_client_data->header);
    free<void> (client->format_data);
    client->format_data = NULL;
}


static void ebml_write_buf_to_file_fail (_Ptr<source_t> source)
{
    _Unchecked {ICECAST_LOG_WARN("Write to dump file failed, disabling");}
    fclose (source->dumpfile);
    source->dumpfile = NULL;
}


static void ebml_write_buf_to_file (_Ptr<source_t> source, _Ptr<refbuf_t> refbuf)
{

    _Ptr<ebml_source_state_t> ebml_source_state = _Dynamic_bounds_cast<_Ptr<ebml_source_state_t>>(source->format->_state);

    if (ebml_source_state->file_headers_written == 0)
    {
        if (fwrite (ebml_source_state->header->data, 1,
                    ebml_source_state->header->len, 
                    source->dumpfile) != ebml_source_state->header->len)
            ebml_write_buf_to_file_fail(source);
        else
            ebml_source_state->file_headers_written = 1;
    }

    if (fwrite (refbuf->data, 1, refbuf->len, source->dumpfile) != refbuf->len)
    {
        ebml_write_buf_to_file_fail(source);
    }

}


/* internal ebml parsing */

static void ebml_destroy(_Ptr<ebml_t> ebml)
_Checked {

    free<unsigned char>(ebml->header);
    free<unsigned char>(ebml->input_buffer);
    free<unsigned char>(ebml->buffer);
    free<ebml_t>(ebml);

}

static _Ptr<ebml_t> ebml_create(void)
{

    _Ptr<ebml_t> ebml = calloc<ebml_t>(1, sizeof(ebml_t));

    ebml->header = _Dynamic_bounds_cast<_Nt_array_ptr<unsigned char>>(calloc<unsigned char>(1, EBML_HEADER_MAX_SIZE), byte_count(EBML_HEADER_MAX_SIZE));
    ebml->buffer = _Dynamic_bounds_cast<_Nt_array_ptr<unsigned char>>(calloc<unsigned char>(1, EBML_SLICE_SIZE * 4), byte_count(EBML_HEADER_MAX_SIZE * 4));
    ebml->input_buffer = _Dynamic_bounds_cast<_Nt_array_ptr<unsigned char>>(calloc<unsigned char>(1, EBML_SLICE_SIZE), byte_count(EBML_HEADER_MAX_SIZE));

    ebml->cluster_id = "\x1F\x43\xB6\x75";

    ebml->cluster_start = -2;

    return ebml;

}

static int ebml_read_space(_Ptr<ebml_t> ebml)
_Checked {

    int read_space;

    if (ebml->header_read == 1)
    {
        if (ebml->cluster_start > 0)
            read_space = ebml->cluster_start;
        else
            read_space = ebml->position - 4;
            
        return read_space;
    }
    else
    {
        if (ebml->header_size != 0)
            return ebml->header_size;
        else
            return 0;
    }

}

static int ebml_read(_Ptr<ebml_t> ebml, char *buffer : itype(_Nt_array_ptr<char>) byte_count(len), int len)
{

    int read_space;
    int to_read;

    if (len < 1)
        return 0;

    if (ebml->header_read == 1) 
    {
        if (ebml->cluster_start > 0)
            read_space = ebml->cluster_start;
        else
            read_space = ebml->position - 4;

        if (read_space < 1)
            return 0;

        if (read_space >= len )
            to_read = len;
        else
            to_read = read_space;

        _Unchecked {memcpy(buffer, ebml->buffer, to_read);}
        memmove(ebml->buffer, ebml->buffer + to_read, ebml->position - to_read);
        ebml->position -= to_read;
        
        if (ebml->cluster_start > 0)
            ebml->cluster_start -= to_read;
    }
    else
    _Checked {
        if (ebml->header_size != 0)
        _Unchecked {
            read_space = ebml->header_size - ebml->header_read_position;

            if (read_space >= len)
                to_read = len;
            else
                to_read = read_space;

            memcpy(buffer, ebml->header, to_read);
            ebml->header_read_position += to_read;

            if (ebml->header_read_position == ebml->header_size)
                ebml->header_read = 1;
        }
        else
        {
            return 0;
        }
    }

    return to_read;

}

static int ebml_last_was_sync(_Ptr<ebml_t> ebml)
_Checked {

    if (ebml->cluster_start == 0)
    {
        ebml->cluster_start -= 1;
        return 0;
    }
  
    if (ebml->cluster_start == -1)
    {
        ebml->cluster_start -= 1;
        return 1;
    }
    
    return 0;

}

static char *ebml_write_buffer(_Ptr<ebml_t> ebml, int len) : itype(_Nt_array_ptr<char>)
{

    return _Dynamic_bounds_cast<_Nt_array_ptr<char>>(ebml->input_buffer, byte_count(len));

}


static int ebml_wrote(_Ptr<ebml_t> ebml, int len)
_Checked {

    int b;

    if (ebml->header_size == 0) {
        if ((ebml->header_position + len) > EBML_HEADER_MAX_SIZE) {
            _Unchecked {ICECAST_LOG_ERROR("EBML Header too large, failing");}
            return -1;
        }
        
        if (EBML_DEBUG)
        {
            _Unchecked {printf("EBML: Adding to header, ofset is %d size is %d adding %d\n", 
                   ebml->header_size, ebml->header_position, len);}
        }
        
        _Unchecked {memcpy<unsigned char>(ebml->header + ebml->header_position, ebml->input_buffer, len);}
        ebml->header_position += len;
    }
    else
    _Unchecked {
        memcpy<unsigned char>(ebml->buffer + ebml->position, ebml->input_buffer, len);
    }
    
    for (b = 0; b < len - 4; b++)
    {
        int tmpResVar;
        _Unchecked {tmpResVar = memcmp(ebml->input_buffer + b, ebml->cluster_id, 4);}
        if (!tmpResVar)
        {
            if (EBML_DEBUG)
            _Unchecked {
                printf("EBML: found cluster\n");
            }
        
            if (ebml->header_size == 0)
            _Unchecked {
                ebml->header_size = ebml->header_position - len + b;
                memcpy<unsigned char>(ebml->buffer, ebml->input_buffer + b, len - b);
                ebml->position = len - b;
                ebml->cluster_start = -1;
                return len;
            }
            else
            {
                ebml->cluster_start = ebml->position + b;
            }
        }
    }
    
    ebml->position += len;

    return len;

}
