/*
 * vim:ts=4:sw=4:expandtab
 *
 * tracer-etmv4.c: Core of ETMv4 tracer
 * Copyright (C) 2013  Chih-Chyuan Hwang (hwangcc@csie.nctu.edu.tw)
 * Copyright (C) 2024  Tai Yue, Yibo Jin, Fengwei Zhang, Zhenyu Ning,
 *                     Pengfei Wang, Xu Zhou, Kai Lu (the Stalker project)
 * Copyright (C) 2026  Quentin Ducasse (quentin.ducasse8@gmail.com)
 *
 * Modified 2026 by Quentin Ducasse: New adapter code. Glues the decoder
 * into AFL++ coresight_mode's common.c.
 *
 * Follows the Stalker implementation, which forked ptm2human for
 * hardware-assisted greybox fuzzing:
 *   Tai Yue, Yibo Jin, Fengwei Zhang, Zhenyu Ning, Pengfei Wang, Xu Zhou,
 *   and Kai Lu. "Efficiently Rebuilding Coverage in Hardware-Assisted
 *   Greybox Fuzzing." RAID '24, pp. 450-464.
 *   https://doi.org/10.1145/3678890.3678933
 */

/* readlink() is POSIX, which -std=c11 alone does not expose. */
#define _DEFAULT_SOURCE

#include "stalker_adapter.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "etmv4_decode.h"
#include "log.h"

/* Decoder state the decoder uses as externs */
unsigned long long text_start_addr;
unsigned long long text_end_addr;
unsigned long long IRQ_addr;
unsigned long long overflow_nums;
unsigned long long exception_nums;
unsigned long long branch_nums;
unsigned long long basic_block;
unsigned long long hash;
unsigned long long pre_basic_block;

unsigned int branch_flag;
unsigned int count_atom;
unsigned int bb_mode;
unsigned int from_exception;
unsigned long long atom_nums;
unsigned long long atom_in_slide;

/* Diagnostic only */
unsigned long long addr_pkt_nums;
unsigned long long addr_pkt_irq_swallowed;
unsigned long long addr_pkt_branchflag0;
unsigned long long addr_pkt_out_of_range;
unsigned long long addr_pkt_committed;

/* AFLCS_STALKER_ADDRTRACE=N: dump the first N reconstructed address packets
 * of each exec, to see what the decoder actually reconstructs. */
unsigned int stalker_addr_trace;
unsigned int stalker_addr_seen;

int stalker_decoder_init(pid_t pid, struct map_info *map_info,
                         int map_info_num)
{
  char exe_link[PATH_MAX];
  char real_exe[PATH_MAX];
  ssize_t len;
  int idx, i;

  if (!map_info || map_info_num <= 0) {
    LOGE("stalker_decoder_init: no map_info\n");
    return -1;
  }

  snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
  len = readlink(exe_link, real_exe, sizeof(real_exe) - 1);
  idx = 0;
  if (len < 0) {
    LOGE("stalker_decoder_init: readlink(/proc/%d/exe) failed (%s), "
         "falling back to map_info[0] (%s)\n",
         pid, strerror(errno), map_info[0].path);
  } else {
    real_exe[len] = '\0';
    idx = -1;
    for (i = 0; i < map_info_num; i++) {
      if (strcmp(map_info[i].path, real_exe) == 0) {
        idx = i;
        break;
      }
    }
    if (idx < 0) {
      LOGE("stalker_decoder_init: no map_info entry matches exe '%s', "
           "falling back to map_info[0] (%s)\n",
           real_exe, map_info[0].path);
      idx = 0;
    }
  }

  if (idx != 0) {
    LOGE("stalker_decoder_init: matched target at map_info[%d] ('%s'), "
         "not [0]\n",
         idx, map_info[idx].path);
    return -1;
  }

  /* setup_map_info() only records regions carrying the x bit, so this entry
   * is the binary's executable mapping. Note only this one range is used: a
   * binary with several executable mappings would have the others silently excluded.
   *
   * Note: Stalker additionally parsed the ELF entry point into main_entry_addr,
   * to re-arm its entry_flag gate once execution re-reached _start. Since our
   * forkserver sits at libc main, this flag is not needed anymore. */
  text_start_addr = map_info[idx].start;
  text_end_addr = map_info[idx].end;

  {
    const char *at = getenv("AFLCS_STALKER_ADDRTRACE");
    stalker_addr_trace = at ? (unsigned int)atoi(at) : 0;
  }

  LOGV("[STALKER-DECODER] text_range=0x%llx-0x%llx (matched %s)\n",
       text_start_addr, text_end_addr, map_info[idx].path);

  return 0;
}

void stalker_decoder_set_bb_mode(int mode)
{
  bb_mode = mode ? 1 : 0;
}

int stalker_decode_trace(unsigned char *trace_bits, size_t trace_bits_size,
                         void *buf, size_t buf_size)
{
  if (!trace_bits || !buf) {
    return -1;
  }

  /* Cleanup bitmap. */
  memset(trace_bits, 0, trace_bits_size);

  /* Reset counters, hash is reset in decode_stream() itself. */
  overflow_nums = 0;
  exception_nums = 0;
  branch_nums = 0;
  atom_nums = 0;
  atom_in_slide = 1;
  count_atom = 0;
  addr_pkt_nums = 0;
  addr_pkt_irq_swallowed = 0;
  addr_pkt_branchflag0 = 0;
  addr_pkt_out_of_range = 0;
  addr_pkt_committed = 0;
  stalker_addr_seen = 0;
  branch_flag = 0;
  from_exception = 0;
  IRQ_addr = 0;
  basic_block = 0;
  pre_basic_block = 0;

  etmv4_decode(trace_bits, (char *)buf, (int)buf_size);

  LOGV("[STALKER-DECODER] buf_size=%zu branch_flag=%u "
       "atom_nums=%llu branch_nums=%llu count_atom=%u overflow_nums=%llu "
       "exception_nums=%llu addr_pkt_nums=%llu atom_in_slide=%llu "
       "addr_pkt_committed=%llu addr_pkt_branchflag0=%llu "
       "addr_pkt_out_of_range=%llu addr_pkt_irq_swallowed=%llu\n",
       buf_size, branch_flag, atom_nums, branch_nums,
       count_atom, overflow_nums, exception_nums, addr_pkt_nums,
       atom_in_slide, addr_pkt_committed, addr_pkt_branchflag0,
       addr_pkt_out_of_range, addr_pkt_irq_swallowed);

  return 0;
}

bool stalker_decode_did_overflow(void)
{
  return overflow_nums > 0;
}

void stalker_decoder_get_stats(struct stalker_decode_stats *out)
{
  if (!out) {
    return;
  }

  out->addr_pkt_nums = addr_pkt_nums;
  out->addr_pkt_committed = addr_pkt_committed;
  out->addr_pkt_branchflag0 = addr_pkt_branchflag0;
  out->addr_pkt_out_of_range = addr_pkt_out_of_range;
  out->addr_pkt_irq_swallowed = addr_pkt_irq_swallowed;
  out->atom_nums = atom_nums;
  out->branch_nums = branch_nums;
  out->overflow_nums = overflow_nums;
  out->exception_nums = exception_nums;
  out->text_start_addr = text_start_addr;
  out->text_end_addr = text_end_addr;
}
