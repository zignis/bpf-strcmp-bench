// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (c) 2026 zignis

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// method to bench
#define BENCH_NAIVE

// "POST" in little-endian
#define TAG_POST 0x54534f50
#define HAYSTACK 8192
#define NEEDLE_SIZE 4

const volatile unsigned long long iterations = 0;

SEC("sk_skb/stream_verdict")
int handle_verdict(struct __sk_buff *skb) {
  if (bpf_skb_pull_data(skb, HAYSTACK) < 0)
    return SK_DROP;

  const void *data = (void *)(long)skb->data;
  const void *data_end = (void *)(long)skb->data_end;

  for (__u64 i = 0; i < iterations; i++) {
    const __u64 j = i & HAYSTACK - NEEDLE_SIZE;
    const char *p = data + j;

    if (p + NEEDLE_SIZE > (char *)data_end)
      break;

#ifdef BENCH_NAIVE

    if (p[0] == 'P' && p[1] == 'O' && p[2] == 'S' && p[3] == 'T')
      return SK_PASS;

#elif defined(BENCH_MEMCMP)

    if (__builtin_memcmp(p, "POST", NEEDLE_SIZE) == 0)
      return SK_PASS;

#elif defined(BENCH_STRNCMP)

    // this will simply fail since the helper is not allowed to read pkt
    // pointers
    if (bpf_strncmp(p, NEEDLE_SIZE, "POST") == 0)
      return SK_PASS;

#elif defined(BENCH_INT_TAG)

    if (*(__u32 *)p == TAG_POST)
      return SK_PASS;

#endif
  }

  return SK_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
