// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include "bootstrap.skel.h"
#include <stdio.h>

typedef unsigned long long ull;

static int try_bpf_load(const ull iterations) {
  struct bootstrap_bpf *skel = bootstrap_bpf__open();
  if (!skel)
    return 0;

  skel->rodata->iterations = iterations;
  const int err = bootstrap_bpf__load(skel);
  bootstrap_bpf__destroy(skel);
  return err == 0;
}

int main(void) {
  libbpf_set_print(NULL); // suppress verifier logs

  ull l = 0, r = 1, max_iters = 0;

  // find upper bound
  while (try_bpf_load(r)) {
    l = r;
    r *= 2;
  }

  // binary search
  while (l <= r) {
    const ull mid = l + (r - l) / 2;

    if (try_bpf_load(mid)) {
      max_iters = mid;
      l = mid + 1;
    } else {
      r = mid - 1;
    }
  }

  printf("max iterations: %llu\n", max_iters);
  return 0;
}