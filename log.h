/*
 * vim:ts=4:sw=4:expandtab
 *
 * log.h: Macros for logging functions
 * Copyright (C) 2013  Chih-Chyuan Hwang (hwangcc@csie.nctu.edu.tw)
 * Copyright (C) 2026  Quentin Ducasse (quentin.ducasse8@gmail.com)
 *
 * Modified 2026 by Quentin Ducasse: LOGV, LOGD and LOGE are compiled out
 * under AFLCS_STALKER_DECODER unless AFLCS_DECODER_VERBOSE is also defined.
 * The standalone ptm2human CLI build is unaffected.
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
#ifndef _LOG_H
#define _LOG_H

extern int debuglog_on;

#if defined(AFLCS_STALKER_DECODER) && !defined(AFLCS_DECODER_VERBOSE)

#define LOGV(f, args...) do { if (0) { fprintf(stdout, f, ## args); } } while (0)
#define LOGD(f, args...) do { if (0) { fprintf(stderr, "%s:%s:%d - " f, __FILE__, __FUNCTION__, __LINE__, ## args); } } while (0)
#define LOGE(f, args...) do { if (0) { fprintf(stderr, "ERROR: " f, ## args); } } while (0)

#else

#define LOGV(f, args...) fprintf(stdout, f, ## args)
#define LOGD(f, args...) do { if (debuglog_on) fprintf(stderr, "%s:%s:%d - " f, __FILE__, __FUNCTION__, __LINE__, ## args); } while (0)
#define LOGE(f, args...) fprintf(stderr, "ERROR: " f, ## args)

#endif

#endif
