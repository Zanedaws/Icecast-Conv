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


/* Ogg codec handler for skeleton logical streams */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <ogg/ogg.h>

typedef struct source_tag source_t;

#include "refbuf.h"
#include "format_ogg.h"
#include "format_skeleton.h"
#include "client.h"
#include "stats.h"

#define CATMODULE "format-skeleton"
#include "logging.h"

#pragma CHECKED_SCOPE on

static void skeleton_codec_free (_Ptr<ogg_state_t> ogg_info, _Ptr<ogg_codec_t> codec)
{
    _Unchecked {ICECAST_LOG_DEBUG("freeing skeleton codec");}
    _Unchecked {ogg_stream_clear (&codec->os);}
    free<ogg_codec_t> (codec);
}


/* skeleton pages are not rebuilt, so here we just for headers and then
 * pass them straight through to the the queue
 */
static _Ptr<refbuf_t> process_skeleton_page(_Ptr<ogg_state_t> ogg_info, _Ptr<ogg_codec_t> codec, _Ptr<ogg_page> page)
{
    ogg_packet packet;
    
    int tmpRet;
    _Unchecked{tmpRet = ogg_stream_pagein (&codec->os, (ogg_page*)page);}
    if (tmpRet < 0)
    {
        ogg_info->error = 1;
        return NULL;
    }
    
    _Unchecked {tmpRet = ogg_stream_packetout (&codec->os, &packet);}
    while (tmpRet > 0)
    {
        codec->headers++;
    }

    /* all skeleon packets are headers */
    format_ogg_attach_header (ogg_info, page);
    return NULL;
}


/* Check if specified BOS page is the start of a skeleton stream and
 * if so, create a codec structure for handling it
 */
ogg_codec_t *initial_skeleton_page(format_plugin_t *plugin : itype(_Ptr<format_plugin_t>), ogg_page *page : itype(_Ptr<ogg_page>)) : itype(_Ptr<ogg_codec_t>)
{
    _Ptr<ogg_state_t> ogg_info = _Dynamic_bounds_cast<_Ptr<ogg_state_t>>(plugin->_state);
    _Ptr<ogg_codec_t> codec = calloc<ogg_codec_t> (1, sizeof (ogg_codec_t));
    ogg_packet packet;

    _Unchecked {ogg_stream_init (&codec->os, ogg_page_serialno ((const ogg_page*)page));}
    _Unchecked {ogg_stream_pagein (&codec->os, page);}

    _Unchecked {ogg_stream_packetout (&codec->os, &packet);}

    _Unchecked {ICECAST_LOG_DEBUG("checking for skeleton codec");}

    int tmpRet;
    _Unchecked {tmpRet = memcmp(packet.packet, "fishead\0", 8);}
    if ((packet.bytes<8) || tmpRet)
    {
        _Unchecked {ogg_stream_clear (&codec->os);}
        free<ogg_codec_t> (codec);
        return NULL;
    }

    _Unchecked {ICECAST_LOG_INFO("seen initial skeleton header");}
    codec->process_page = process_skeleton_page;
    codec->codec_free = skeleton_codec_free;
    codec->headers = 1;
    codec->name = "Skeleton";

    format_ogg_attach_header (ogg_info, page);
    return codec;
}

