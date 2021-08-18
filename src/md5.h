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

#ifndef __MD5_H__
#define __MD5_H__

#include "compat.h"

#define HASH_LEN     16

struct MD5Context
{       
    uint32_t     buf[4];
    uint32_t [2] bits : itype(uint32_t _Checked[2]);
    unsigned char in[64];
};

void MD5Init(struct MD5Context *context : itype(_Ptr<struct MD5Context>));
void MD5Update(struct MD5Context *context : itype(_Ptr<struct MD5Context>), const unsigned char *buf : itype(_Array_ptr<const unsigned char>), unsigned len);
void MD5Final(unsigned char *digest : itype(unsigned char _Checked[HASH_LEN]), struct MD5Context *context : itype(_Array_ptr<struct MD5Context>));


#endif


