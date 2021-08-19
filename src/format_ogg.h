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

/* format_ogg.h
**
** vorbis format plugin header
**
*/
#ifndef __FORMAT_OGG_H__
#define __FORMAT_OGG_H__

#include <ogg/ogg.h>
#include "refbuf.h"
#include "format.h"

typedef struct ogg_state_tag
{
    char *mount : itype(_Nt_array_ptr<char>);
    ogg_sync_state oy;
    int error;

    int codec_count;
    struct ogg_codec_tag *codecs : itype(_Ptr<struct ogg_codec_tag>);
    char *artist : itype(_Nt_array_ptr<char>);
    char *title : itype(_Nt_array_ptr<char>);
    int log_metadata;
    refbuf_t *file_headers : itype(_Ptr<refbuf_t>);
    refbuf_t *header_pages : itype(_Ptr<refbuf_t>);
    refbuf_t *header_pages_tail : itype(_Ptr<refbuf_t>);
    refbuf_t **bos_end : itype(_Ptr<_Ptr<refbuf_t>>);
    int bos_completed;
    long bitrate;
    struct ogg_codec_tag *current : itype(_Ptr<struct ogg_codec_tag>);
    struct ogg_codec_tag *codec_sync : itype(_Ptr<struct ogg_codec_tag>);
} ogg_state_t;


/* per codec/logical structure */
typedef struct ogg_codec_tag
{
    struct ogg_codec_tag *next : itype(_Ptr<struct ogg_codec_tag>);
    ogg_stream_state os;
    unsigned headers;
    const char *name : itype(_Nt_array_ptr<const char>);
    void *specific : itype(_Ptr<void>);
    refbuf_t *possible_start : itype(_Ptr<refbuf_t>);
    refbuf_t *page : itype(_Ptr<refbuf_t>);

    refbuf_t * ((*process)(ogg_state_t * ogg_info, struct ogg_codec_tag * codec)) : itype(_Ptr<_Ptr<refbuf_t> (_Ptr<ogg_state_t> ogg_info, _Ptr<struct ogg_codec_tag> codec)>);
    refbuf_t * ((*process_page)(ogg_state_t * ogg_info : itype(_Ptr<ogg_state_t>), struct ogg_codec_tag * codec : itype(_Ptr<struct ogg_codec_tag>), ogg_page * page : itype(_Ptr<ogg_page>))) : itype(_Ptr<_Ptr<refbuf_t> (_Ptr<ogg_state_t> ogg_info, _Ptr<struct ogg_codec_tag> codec, _Ptr<ogg_page> page)>);
    void ((*codec_free)(ogg_state_t * ogg_info, struct ogg_codec_tag * codec)) : itype(_Ptr<void (_Ptr<ogg_state_t> ogg_info, _Ptr<struct ogg_codec_tag> codec)>);
} ogg_codec_t;


refbuf_t *make_refbuf_with_page(ogg_page *page : itype(_Ptr<ogg_page>)) : itype(_Ptr<refbuf_t>);
void format_ogg_attach_header (ogg_state_t *ogg_info : itype(_Ptr<ogg_state_t>), ogg_page *page : itype(_Ptr<ogg_page>));
void format_ogg_free_headers (ogg_state_t *ogg_info : itype(_Ptr<ogg_state_t>));
int format_ogg_get_plugin (source_t *source : itype(_Ptr<source_t>));

#endif  /* __FORMAT_OGG_H__ */
