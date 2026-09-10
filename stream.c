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
 * table-driven rather than a linear tracepkts[] scan, with ATOM-format
 * packets special-cased and an early return once overflow_nums > 0, to keep
 * up with hardware-trace decode rates during fuzzing.
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
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "tracer.h"
#include "stream.h"
#include "pktproto.h"

struct tracepkt **tracepkts;
sync_func synchronization;

/* Adapter state, defined in stalker_adapter.c. */
extern unsigned int from_exception;
extern unsigned long long IRQ_addr;
extern unsigned long long atom_in_slide;
extern unsigned int branch_flag;
extern unsigned int bb_mode;
extern unsigned long long hash;
extern unsigned long long overflow_nums;
extern unsigned long long atom_nums;
extern void stalker_exception_resume(void);

/* packet_index[c]: tracepkts[] index (etmv4.c DEF_TRACEPKT order) of header byte
 * c, -1 if none; ATOM_IDX_FIRST..LAST are the atom_format entries. Hand-made, so
 * verify_dispatch_tables() checks it and that range against tracepkts[] once. */
static int packet_index[256] = {0, 1, 3, 3, 2, -1, 4, 4, -1, -1, -1, -1, 6, 6, 5, 5, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 13, 13, 13, 13, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 15, 15, 15, 15, 21, 21, 21, 21, 19, 19, 19, 19, 19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, -1, -1, -1, -1, -1, -1, -1, -1, 18, 18, 18, 18, 14, 16, 18, 18, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 30, 30, 31, 32, -1, 33, 34, -1, -1, -1, -1, -1, -1, -1, -1, -1, 29, 29, 29, 29, -1, 23, 24, -1, -1, -1, 25, 26, -1, 27, 28, -1, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 53, 43, 44, 45, 46, 47, 40, 41, 42, 36, 36, 36, 36, 38, 38, 38, 38, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 48, 49, 50, 51, 52, 39, 35, 35, 37, 37, 37, 37, 37, 37, 37, 37};

#ifdef AFLCS_STALKER_DECODER
/* atom_length/atom_map/atom_flag give, for a given ATOM packet byte,
 * how many atoms it encodes, their E/N bit pattern, and whether the batch
 * ends on a taken (address-committing) branch. */
static int atom_length[256] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 5, 5, 5, 2, 2, 2, 2, 4, 4, 4, 4, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 5, 1, 1, 3, 3, 3, 3, 3, 3, 3, 3};
static unsigned int atom_map[256] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15, 31, 63, 127, 255, 511, 1023, 2047, 4095, 8191, 16383, 32767, 65535, 131071, 262143, 524287, 1048575, 2097151, 4194303, 8388607, 16777215, 0, 10, 21, 0, 2, 1, 3, 7, 0, 5, 10, 14, 30, 62, 126, 254, 510, 1022, 2046, 4094, 8190, 16382, 32766, 65534, 131070, 262142, 524286, 1048574, 2097150, 4194302, 8388606, 16777214, 15, 0, 1, 0, 4, 2, 6, 1, 5, 3, 7};
static unsigned int atom_flag[256] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1};

static void sdbm(unsigned long atom_serial, int len)
{
    while (len--) {
        hash = (atom_serial >> (len) & 0b1) + (hash << 1) + (hash << 3) - hash;
    }
}
#endif

/* Registration indices the fast paths below key off, checked at first decode. */
#define ATOM_IDX_FIRST 35
#define ATOM_IDX_LAST  54

/* One-shot audit of packet_index[] against tracepkts[] */
static void verify_dispatch_tables(void)
{
    int n, c;

    for (n = 0; tracepkts[n]; n++) ;

    for (c = 0; c < 256; c++) {
        int i = packet_index[c];
        int match = -1, j;

        for (j = 0; j < n; j++) {
            if (((unsigned char)c & tracepkts[j]->mask) == tracepkts[j]->val) {
                match = j;
                break;
            }
        }

        if (i != match) {
            fprintf(stderr,
                    "stream.c: packet_index[0x%02x] = %d, but tracepkts[] says %d"
                    " (%s) -- the hand-generated dispatch tables are out of sync"
                    " with etmv4.c's DEF_TRACEPKT order\n",
                    c, i, match, (match >= 0) ? tracepkts[match]->name : "none");
            abort();
        }
    }

#ifdef AFLCS_STALKER_DECODER
    /* The ATOM fast path is a range test, so the range must be exactly the
     * ATOM entries: no non-ATOM packet inside it, no ATOM packet outside it. */
    for (c = 0; c < n; c++) {
        int is_atom = !strncmp(tracepkts[c]->name, "atom_format", 11);
        int in_range = (c >= ATOM_IDX_FIRST && c <= ATOM_IDX_LAST);

        if (is_atom != in_range) {
            fprintf(stderr,
                    "stream.c: tracepkts[%d] (%s) %s the ATOM fast-path range"
                    " %d..%d\n", c, tracepkts[c]->name,
                    is_atom ? "falls outside" : "falls inside",
                    ATOM_IDX_FIRST, ATOM_IDX_LAST);
            abort();
        }
    }
#endif
}

int decode_stream(struct stream *stream)
{
    int cur, i, ret;
    static int tables_verified = 0;

#ifdef AFLCS_STALKER_DECODER
    int len;
    unsigned long atom_serial;
    hash = 0;
#endif

    if (!stream) {
        LOGE("Invalid struct stream pointer\n");
        return -1;
    }

    if (!tables_verified) {
        tables_verified = 1;
        verify_dispatch_tables();
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

#ifdef AFLCS_STALKER_DECODER
        if (overflow_nums > 0) {
            return 0;
        }

        /* ATOM fast path: fuzzing build only. Without it the packets fall
         * through to the normal tracepkts[]->decode()/tracer_atom() route,
         * which is what the standalone ptm2human CLI needs. */
        if (i >= ATOM_IDX_FIRST && i <= ATOM_IDX_LAST) {
            /* ATOM-format packet: accumulate branch_flag/atom_in_slide/hash
             * directly from the packet byte instead of going through the
             * normal tracepkts[]->decode()/tracer_atom() chain. */
            stalker_exception_resume();
            len = atom_length[c];
            atom_serial = atom_map[c];
            branch_flag = atom_flag[c];
            atom_in_slide += len;
            /* tracer_atom() counts these in the CLI build; the fast path is
             * the only thing that sees them here, so count them here too or
             * the diagnostic reads a flat zero. */
            atom_nums += (unsigned long long)len;
            if (bb_mode == 0) {
                sdbm(atom_serial, len);
            }
            cur++;
            continue;
        }
#endif

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
