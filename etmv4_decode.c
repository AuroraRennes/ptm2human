/*
 * vim:ts=4:sw=4:expandtab
 *
 * etmv4_decode.c: Buffer-based ETMv4 decode entry point for the adapter
 * Copyright (C) 2013  Chih-Chyuan Hwang (hwangcc@csie.nctu.edu.tw)
 * Copyright (C) 2024  Tai Yue, Yibo Jin, Fengwei Zhang, Zhenyu Ning,
 *                     Pengfei Wang, Xu Zhou, Kai Lu (the Stalker project)
 * Copyright (C) 2026  Quentin Ducasse (quentin.ducasse8@gmail.com)
 *
 * Written 2026 by Quentin Ducasse, derived from ptm2human's ETMv4 decoder
 * and from Stalker's AFL-ETM/etmv4_decode.c.
 *
 * Follows the ETMv4 decoder in Stalker, which forked ptm2human for
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
#include <errno.h>
#include "log.h"
#include "tracer.h"
#include "stream.h"
#include "pktproto.h"
#include "etmv4_decode.h"

int debuglog_on = 0;

/* Global trace contents */
unsigned char *g_trace_bits;

/* Decodes without formatting */
int etmv4_decode(unsigned char *trace_bits, char *buf, int size)
{
    int ret;
    unsigned int trcidr12 = 0, trcidr13 = 0;
    struct stream stream;

    if (!buf || size <= 0) {
        return EXIT_FAILURE;
    }

    /* Clamp to the actual DMA buffer size */
    if (size > 0x4000000) {
        size = 0x4000000;
    }

    g_trace_bits = trace_bits;

    memset(&stream, 0, sizeof(struct stream));

    decode_etmv4();

    /* validate context ID size */
    switch (CONTEXTID_SIZE(&(stream.tracer))) {
    case 0:
    case 1:
    case 2:
    case 4:
        break;
    default:
        LOGE("Invalid context ID size %d\n", CONTEXTID_SIZE(&(stream.tracer)));
        return EXIT_FAILURE;
        break;
    }

    /* validate CONDTYPE in trcidr0 */
    if (CONDTYPE(&(stream.tracer)) > 2) {
        LOGE("Invalid CONDTYPE in TRCIDR0: %d (should be either 0 or 1)\n", CONDTYPE(&(stream.tracer)));
        return EXIT_FAILURE;
    }

    /* validate trcidr12 and trcidr13 */
    if (trcidr12 < trcidr13) {
        LOGE("Invalid TRCIDR12/TRCIDR13: TRCIDR12 (%d) < TRCIDR13 (%d)\n", trcidr12, trcidr13);
        return EXIT_FAILURE;
    } else {
        COND_KEY_MAX_INCR(&(stream.tracer)) = trcidr12 - trcidr13;
    }

    stream.buff_len = size;
    stream.buff = malloc(stream.buff_len);
    if (!(stream.buff)) {
        LOGE("Fail to allocate memory (%s)\n", strerror(errno));
        return EXIT_FAILURE;
    }
    memcpy(stream.buff, buf, size);

    ret = decode_stream(&stream);

    free((void *)stream.buff);

    if (ret) {
        return EXIT_FAILURE;
    } else {
        return EXIT_SUCCESS;
    }
}
