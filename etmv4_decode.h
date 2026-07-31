/*
 * vim:ts=4:sw=4:expandtab
 *
 * etmv4_decode.h: Header of etmv4 decode loop
 * Copyright (C) 2013  Chih-Chyuan Hwang (hwangcc@csie.nctu.edu.tw)
 * Copyright (C) 2024  Tai Yue, Yibo Jin, Fengwei Zhang, Zhenyu Ning,
 *                     Pengfei Wang, Xu Zhou, Kai Lu (the Stalker project)
 * Copyright (C) 2026  Quentin Ducasse (quentin.ducasse8@gmail.com)
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
#ifndef _ETMV4_DECODE_H
#define _ETMV4_DECODE_H

extern int etmv4_decode(unsigned char *trace_bits, char *buf, int size);

#endif