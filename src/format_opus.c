/* Icecast
 *
 *  This program is distributed under the GNU General Public License,
 *  version 2. A copy of this license is included with this source.
 *  At your option, this specific source file can also be distributed
 *  under the GNU GPL version 3.
 *
 * Copyright 2012,      David Richards, Mozilla Foundation,
 *                      and others (see AUTHORS for details).
 */


/* Ogg codec handler for opus streams */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <ogg/ogg.h>

typedef struct source_tag source_t;

#include "format_opus.h"
#include "refbuf.h"
#include "client.h"

#define CATMODULE "format-opus"
#include "logging.h"

#pragma CHECKED_SCOPE on

static void opus_codec_free (_Ptr<ogg_state_t> ogg_info, _Ptr<ogg_codec_t> codec)
{
    _Unchecked {ogg_stream_clear (&codec->os);}
    free<ogg_codec_t> (codec);
}


static _Ptr<refbuf_t> process_opus_page(_Ptr<ogg_state_t> ogg_info, _Ptr<ogg_codec_t> codec, _Ptr<ogg_page> page)
{
    _Ptr<refbuf_t> refbuf = ((void *)0);

    if (codec->headers < 2)
    {
        ogg_packet packet;

        _Unchecked {ogg_stream_pagein (&codec->os, (ogg_page *)page);}
         
        int tmpRetVal;
        _Unchecked {tmpRetVal = ogg_stream_packetout(&codec->os, &packet);}
        while (tmpRetVal > 0)
        {
           /* first time around (normal case) yields comments */
           codec->headers++;
           _Unchecked {tmpRetVal = ogg_stream_packetout(&codec->os, &packet);}
        }
        /* add header page to associated list */
        format_ogg_attach_header (ogg_info, page);
        return NULL;
    }
    refbuf = make_refbuf_with_page (page);
    return refbuf;
}


ogg_codec_t *initial_opus_page(format_plugin_t *plugin : itype(_Ptr<format_plugin_t>), ogg_page *page : itype(_Ptr<ogg_page>)) : itype(_Ptr<ogg_codec_t>)
{
    _Ptr<ogg_state_t> ogg_info = _Dynamic_bounds_cast<_Ptr<ogg_state_t>>(plugin->_state);
    _Ptr<ogg_codec_t> codec = calloc<ogg_codec_t> (1, sizeof (ogg_codec_t));
    ogg_packet packet;

    _Unchecked {ogg_stream_init (&codec->os, ogg_page_serialno (page));}
    _Unchecked {ogg_stream_pagein (&codec->os, page);}

    _Unchecked {ogg_stream_packetout (&codec->os, &packet);}

    _Unchecked {ICECAST_LOG_DEBUG("checking for opus codec");}
    int tmpRetVal;
    _Unchecked {tmpRetVal = strncmp((char *)packet.packet, "OpusHead", 8);}
    if (packet.bytes < 8 || tmpRetVal != 0)
    {
        _Unchecked {ogg_stream_clear (&codec->os);}
        free<ogg_codec_t> (codec);
        return NULL;
    }
    _Unchecked {ICECAST_LOG_INFO("seen initial opus header");}
    codec->process_page = process_opus_page;
    codec->codec_free = opus_codec_free;
    codec->headers = 1;
    codec->name = "Opus";
    ogg_info->log_metadata = 1;
    format_ogg_attach_header (ogg_info, page);
    return codec;
}

