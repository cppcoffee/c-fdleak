# c-fdleak

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build

```shell
$ AYA_BUILD_EBPF=true cargo build --release
```

or

```shell
$ make
```

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package c-fdleak --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/c-fdleak` can be
copied to a Linux server or VM and run there.

## Usage

```shell
Usage: c-fdleak [OPTIONS] --pid <PID>

Options:
  -p, --pid <PID>          pid of the process
  -t, --timeout <TIMEOUT>  timeout in seconds [default: 30]
  -o, --output <OUTPUT>    output file [default: /tmp/fdleak.out]
  -v, --verbose            verbose mode
  -h, --help               Print help
  -V, --version            Print version
```

### Example:

```shell
# ./target/release/c-fdleak --pid 5382
```

Generating flame graphs:

```shell
# ./FlameGraph/flamegraph.pl /tmp/fdleak.out > /tmp/1.svg
```
