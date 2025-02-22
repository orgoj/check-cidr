# check-cidr - IP/CIDR in file checker

A simple Rust program that checks whether a given IP or CIDR is contained within a rule loaded from a file. The rule file contains one IP/CIDR per line. Empty lines and lines starting with `#`, as well as any text following the first IP/CIDR on a line, are ignored.

## Usage

```
check-cidr [OPTIONS] <INPUT_STR> <FILE_PATH>
```

### Arguments

- `<INPUT_STR>`: IP or CIDR to check
- `<FILE_PATH>`: Path to the file with rules

### Options

- `-p, --print`: Print all matching lines instead of just indicating containment
- `-q, --quiet`: Suppress output on success
- `-h, --help`: Print help
- `-V, --version`: Print version

## Examples

- Check if IP `192.168.1.1` is contained in rules from file `rules.txt`:

```bash
check-cidr 192.168.1.1 rules.txt
```

- Check if CIDR `10.0.0.0/24` is contained in rules from file `rules.txt` and print all matching lines:

```bash
check-cidr -p 10.0.0.0/24 rules.txt
```

- Check if IP `8.8.8.8` is contained in rules from file `rules.txt` and suppress output on success:

```bash
check-cidr -q 8.8.8.8 rules.txt
```

## Build

Requires [Rust](https://www.rust-lang.org/) and [Cargo](https://doc.rust-lang.org/cargo/).

You can use [mise-en-place](https://mise.jdx.dev/) to install Rust.

```bash
mise use rust
```

Build:

```bash
cargo build --release
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
