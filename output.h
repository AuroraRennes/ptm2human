/*
 * vim:ts=4:sw=4:expandtab
 *
 * output.h: Marcos for outputing decode results
 * Copyright (C) 2013  Chih-Chyuan Hwang (hwangcc@csie.nctu.edu.tw)
 * Copyright (C) 2026  Quentin Ducasse (quentin.ducasse8@gmail.com)
 *
 * Modified 2026 by Quentin Ducasse: under AFLCS_STALKER_DECODER, OUTPUT() is
 * compiled out unless AFLCS_DECODER_VERBOSE is also defined. The standalone
 * ptm2human CLI build is unaffected.
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
#ifndef _OUTPUT_H
#define _OUTPUT_H

/* Adding the flag STALKER_DECODER removes packet printing. Combining
 * it with DECODER_VERBOSE re-enables them. The default ptm2human CLI
 * is unaffected and always prints
 */
#if defined(AFLCS_STALKER_DECODER) && !defined(AFLCS_DECODER_VERBOSE)

/* The if(0) is there simply to remove the "unused" warnings */
#define OUTPUT(f, args...) \
    do { \
        if (0) { \
            fprintf(stdout, f, ## args); \
        } \
    } while (0)

#else

#define OUTPUT(f, args...) fprintf(stdout, f, ## args)

#endif

#endif
