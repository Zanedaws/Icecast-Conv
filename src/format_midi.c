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


/* Ogg codec handler for MIDI logical streams */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <ogg/ogg.h>
#include <string.h>

typedef struct source_tag source_t;

#include "refbuf.h"
#include "format_ogg.h"
#include "client.h"
#include "stats.h"

#define CATMODULE "format-midi"
#include "logging.h"

#pragma CHECKED_SCOPE on

static void midi_codec_free (_Ptr<ogg_state_t> ogg_info, _Ptr<ogg_codec_t> codec)
{
    _Unchecked {ICECAST_LOG_DEBUG("freeing MIDI codec");}
    _Unchecked {ogg_stream_clear (&codec->os);}
    free<ogg_codec_t> (codec);
}


/* Here, we just verify the page is ok and then add it to the queue */
static _Ptr<refbuf_t> process_midi_page(_Ptr<ogg_state_t> ogg_info, _Ptr<ogg_codec_t> codec, _Ptr<ogg_page> page)
{
    _Ptr<refbuf_t> refbuf = ((void *)0);

//   if (ogg_stream_pagein (&codec->os, page) < 0)
    {
        ogg_info->error = 1;
        return NULL;
    }
    refbuf = make_refbuf_with_page (page);
    return refbuf;
}


/* Check for midi header in logical stream */

ogg_codec_t *initial_midi_page(format_plugin_t *plugin : itype(_Ptr<format_plugin_t>), ogg_page *page : itype(_Ptr<ogg_page>)) : itype(_Ptr<ogg_codec_t>)
{
    _Ptr<ogg_state_t> ogg_info = _Dynamic_bounds_cast<_Ptr<ogg_state_t>>(plugin->_state);
    _Ptr<ogg_codec_t> codec = calloc<ogg_codec_t> (1, sizeof (ogg_codec_t));
    ogg_packet packet;

//   ogg_stream_init (&codec->os, ogg_page_serialno (page));
//   ogg_stream_pagein (&codec->os, page);

    _Unchecked {ogg_stream_packetout (&codec->os, &packet);}

    _Unchecked {ICECAST_LOG_DEBUG("checking for MIDI codec");}
    int tmpMemcmpVar;
    do
    {
        if (packet.bytes < 9)
            break;
        _Unchecked {tmpMemcmpVar = memcmp(packet.packet, "OggMIDI\000", 8);}
        if (tmpMemcmpVar != 0)
            break;
        if (packet.bytes != 12)
            break;

        _Unchecked {ICECAST_LOG_INFO("seen initial MIDI header");}
        codec->process_page = process_midi_page;
        codec->codec_free = midi_codec_free;
        codec->headers = 1;
        codec->name = "MIDI";

        format_ogg_attach_header (ogg_info, page);
        return codec;
    } while (0);

    _Unchecked {ogg_stream_clear (&codec->os);}
    free<ogg_codec_t> (codec);
    return NULL;
}

