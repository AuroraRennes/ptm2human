/*
 * vim:ts=4:sw=4:expandtab
 *
 * stream.c: synchronize trace stream and decode it
 * Copyright (C) 2013  Chih-Chyuan Hwang (hwangcc@csie.nctu.edu.tw)
 * Copyright (C) 2024  Tai Yue, Yibo Jin, Fengwei Zhang, Zhenyu Ning,
 *                     Pengfei Wang, Xu Zhou, Kai Lu (the Stalker project)
 * Copyright (C) 2026  Quentin Ducasse (quentin.ducasse8@gmail.com)
 *
 * Modified 2026 by Quentin Ducasse: decode_stream()'s packet dispatch is
 * table-driven rather than a linear tracepkts[] scan.
 *
 * Follows the ETMv4 stream in Stalker, which forked ptm2human for
 * hardware-assisted greybox fuzzing:
 *   Tai Yue, Yibo Jin, Fengwei Zhang, Zhenyu Ning, Pengfei Wang, Xu Zhou,
 *   and Kai Lu. "Efficiently Rebuilding Coverage in Hardware-Assisted
 *   Greybox Fuzzing." RAID '24, pp. 450-464.
 *   https://doi.org/10.1145/3678890.3678933
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include <stdio.h>
#include "log.h"
#include "tracer.h"
#include "stream.h"
#include "pktproto.h"

struct tracepkt **tracepkts;
sync_func synchronization;

/* packet_index[c] mirrors etmv4pkts[]'s DEF_TRACEPKT registration
 * order in etmv4.c (index -1 means "no match"); values 35-54 are the
 * ATOM-format entries (atom_format_1 .. atom_format_6_11) */
static int packet_index[256] = {0, 1, 3, 3, 2, -1, 4, 4, -1, -1, -1, -1, 6, 6, 5, 5, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 13, 13, 13, 13, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 15, 15, 15, 15, 21, 21, 21, 21, 19, 19, 19, 19, 19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, -1, -1, -1, -1, -1, -1, -1, -1, 18, 18, 18, 18, 14, 16, 18, 18, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 30, 30, 31, 32, -1, 33, 34, -1, -1, -1, -1, -1, -1, -1, -1, -1, 29, 29, 29, 29, -1, 23, 24, -1, -1, -1, 25, 26, -1, 27, 28, -1, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 43, 44, 45, 46, 47, 40, 41, 42, 36, 36, 36, 36, 38, 38, 38, 38, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 48, 49, 50, 51, 52, 39, 35, 35, 37, 37, 37, 37, 37, 37, 37, 37};

int decode_stream(struct stream *stream)
{
    int cur, i, ret;

    if (!stream) {
        LOGE("Invalid struct stream pointer\n");
        return -1;
    }
    if (stream->state == READING) {
        /* READING -> SYNCING */
        stream->state++;
    } else {
        LOGE("Stream state is not correct\n");
        return -1;
    }

    LOGV("Syncing the trace stream...\n");
    cur = synchronization(stream);
    if (cur < 0) {
        LOGE("Cannot find any synchronization packet\n");
        return -1;
    } else {
        LOGD("Trace starts from offset %d\n", cur);
    }

    LOGV("Decoding the trace stream...\n");
    /* INSYNC -> DECODING */
    stream->state++;
    for (; cur < stream->buff_len; ) {
        unsigned char c = stream->buff[cur];

        LOGD("Got a packet header 0x%02x at offset %d\n", c, cur);

        i = packet_index[c];
        if (i == -1) {
            LOGE("Cannot recognize a packet header 0x%02x\n", c);
            LOGE("Proceed on guesswork\n");
            cur++;
            continue;
        }

        ret = tracepkts[i]->decode((const unsigned char *)&(stream->buff[cur]), stream);
        if (ret <= 0) {
            LOGE("Cannot decode a packet of type %s at offset %d\n", tracepkts[i]->name, cur);
            LOGE("Proceed on guesswork\n");
            cur++;
        } else {
            cur += ret;
        }
    }

    LOGV("Complete decode of the trace stream\n");

    return 0;
}
