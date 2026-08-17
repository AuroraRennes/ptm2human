/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026  Quentin Ducasse (quentin.ducasse8@gmail.com) */
/* New adapter code gluing the vendored ptm2human/Stalker ETMv4 decoder into
 * coresight_mode, in place of Stalker's own afl-fuzz.c. Stalker:
 *   Tai Yue, Yibo Jin, Fengwei Zhang, Zhenyu Ning, Pengfei Wang, Xu Zhou,
 *   and Kai Lu. "Efficiently Rebuilding Coverage in Hardware-Assisted
 *   Greybox Fuzzing." RAID '24, pp. 450-464.
 *   https://doi.org/10.1145/3678890.3678933 */
#ifndef STALKER_ADAPTER_H
#define STALKER_ADAPTER_H

#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

#include "utils.h" /* struct map_info */

/* Locate the traced binary's own entry in map_info (by matching /proc/<pid>/exe)
 * and take text_start_addr/text_end_addr from its mapped range. */
int stalker_decoder_init(pid_t pid, struct map_info *map_info,
                         int map_info_num);

/* bb_mode=1 -> branch broadcast/precise addressing, bb_mode=0 -> atom/path.
 * Mirrors set_etm_bb_mode()'s hardware-side toggle. Caller must keep this
 * in sync. */
void stalker_decoder_set_bb_mode(int bb_mode);

/* Clears trace_bits, resets per-exec decode state, and decodes buf/buf_size
 * into trace_bits. Returns 0 on success, -1 on a hard failure (invalid args). */
int stalker_decode_trace(unsigned char *trace_bits, size_t trace_bits_size,
                         void *buf, size_t buf_size);

/* Did the decode that just ran observed an ETM overflow packet? */
bool stalker_decode_did_overflow(void);

/* Per-exec decode counters */
struct stalker_decode_stats {
  unsigned long long addr_pkt_nums;
  unsigned long long addr_pkt_committed;
  unsigned long long addr_pkt_branchflag0;
  unsigned long long addr_pkt_out_of_range;
  unsigned long long addr_pkt_irq_swallowed;
  unsigned long long atom_nums;
  unsigned long long branch_nums;
  unsigned long long overflow_nums;
  unsigned long long exception_nums;
  unsigned long long text_start_addr;
  unsigned long long text_end_addr;
};

void stalker_decoder_get_stats(struct stalker_decode_stats *out);

#endif /* STALKER_ADAPTER_H */
