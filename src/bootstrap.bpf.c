// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

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

    if (p[0] == 'P' && p[1] == 'O' && p[2] == 'S' && p[3] == 'T')
      return SK_PASS;
  }

  return SK_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
