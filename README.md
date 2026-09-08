# eBPF string comparison

## Results

| Method             | Max iterations | Processed instructions | `max_states_per_insn` | `total_states` | `peak_states` | Failure reason                             |
|--------------------|----------------|------------------------|-----------------------|----------------|---------------|--------------------------------------------|
| Naive              | 1,638          | 34,420                 | 4                     | 499            | 499           | The sequence of 8193 jumps is too complex. |
| `__builtin_memcmp` | 8190           | 2,04,783               | 4                     | 2053           | 2053          | The sequence of 8193 jumps is too complex. |
| `bpf_strncmp`      | 0              | 24                     | 0                     | 2              | 2             | helper access to the packet is not allowed |
| Integer tags       | 8190           | 1,31,064               | 4                     | 1299           | 1299          | The sequence of 8193 jumps is too complex. |

### Environment

- Kernel: 6.8.0-139-generic
- Architecture: aarch64
- Clang: 18.1.3
- LLVM: 18.1.3
- libbpf: v1.7.0-38-gdcaac95

## Reproducing locally

### Fetch submodules

After cloning the repo, you can update the git submodule with following commands (or you can clone with `--recursive`):

```sh
git submodule update --init --recursive
```

### Install deps

For dependencies, it varies from distribution to distribution. You can refer to shell.nix and dockerfile for installation.

On Ubuntu, you may run `make install` or

```sh
sudo apt-get install -y --no-install-recommends \
        libelf1 libelf-dev zlib1g-dev libssl-dev\
        make clang llvm
```

to install dependencies.

### Build the project

Define the method to bench (one of `BENCH_NAIVE`, `BENCH_MEMCMP`, `BENCH_INT_TAG`) in `src/bootstrap.bpf.c`.

To build the project, run the following command:

```sh
make build
```

This will compile the code and create the necessary binaries.

### Run the benchmark

You can run the binary with:

```console
sudo src/bootstrap
```

## License

This project is built on top of the [eunomia-bpf bootstrap template](https://github.com/eunomia-bpf/bpf-developer-tutorial).

This project is licensed under the MIT License. See the **[LICENSE](LICENSE)** file for more information.
