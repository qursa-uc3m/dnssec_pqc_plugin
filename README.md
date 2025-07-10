# DNSSEC PQC Plugin for CoreDNS

This is a **plugin of CoreDNS** that integrates support for **Post-Quantum Cryptography (PQC)** signature algorithms. It is intended for research and testing purposes within the context of DNSSEC and PQC algorithm evaluation.

## PQC DNSSEC Plugin

The `dnssec_pqc` plugin extends CoreDNS to allow DNSSEC zone signing and validation using a set of post-quantum signature algorithms. It builds upon the original `dnssec` plugin by replacing or augmenting cryptographic operations with post-quantum alternatives.

## Supported Algorithms and Identifiers

The plugin currently supports the following post-quantum signature schemes, identified by custom algorithm IDs:

| Algorithm        | ID | liboqs Name |
|------------------|----|-------------|
| FALCON512        | 17 | Falcon-512 |
| ML-DSA-44        | 18 | ML-DSA-44 |
| SPHINCS_SHA2     | 19 | SPHINCS+-SHA2-128f-simple |
| MAYO1            | 20 | MAYO-1 |
| SNOVA            | 21 | SNOVA_24_5_4 |
| FALCON1024       | 27 | Falcon-1024 |
| ML-DSA-65        | 28 | ML-DSA-65 |
| SPHINCS_SHAKE    | 29 | SPHINCS+-SHAKE-128f-simple |
| MAYO3            | 30 | MAYO-3 |
| SNOVASHAKE       | 31 | SNOVA_24_5_4_SHAKE |
| FALCONPADDED512  | 37 | Falcon-padded-512 |
| ML-DSA-87        | 38 | ML-DSA-87 |
| FALCONPADDED1024 | 47 | Falcon-padded-1024 |

## Dependencies

TThis plugin depends on a custom version of the `miekg/dns` library, that can be found at [qursa-uc3m/dns](https://github.com/qursa-uc3m/dns), which has been modified to support PQC extensions.

To use this version, the following replacement must be added to the `go.mod` file of CoreDNS:

```bash
replace github.com/miekg/dns => github.com/qursa-uc3m/dns
```

## Installation

You can install the plugin using the provided scripts, which will handle the installation of the required dependencies and CoreDNS with the PQC plugin enabled.

First ensure you have `liboqs` installed:

```bash
./scripts/install_liboqs.sh
```

This installs the `liboqs` version `0.14.0-rc1` by default.

and then install CoreDNS with PQC plugin:

```bash
./scripts/build.sh
```

This modifies the CoreDNS source code on the fly to include the PQC plugin and the necessary dependencies. For reference, you can examine the manual approach used in [Juligent/coredns](https://github.com/Juligent/coredns).

## Key Generation

The plugin includes a key generator tool for creating PQC DNSSEC keys. It's also built with `./scripts/build.sh` and you can use with the following command:

```bash
./keygen/keygen -algorithm <algorithm_name> -number <algorithm_number> [-domain <domain>]
```

**Usage:** Requires `-algorithm <name>` (use liboqs Name from table above) and `-number <id>` (algorithm ID from table). Optionally specify `-domain <domain>` (defaults to `mydomain.org`). Use `-help` to see available algorithms.

For example

```bash
./keygen/keygen -algorithm ML-DSA-44 -number 18
```

To see exact algorithm names available in your installation, run: `./keygen/keygen -help`

## Example Configuration

To configure CoreDNS to use the PQC plugin, you can create a `Corefile` with the following content. This example assumes you have a DNSSEC key file for your domain and that you want to forward queries to Google's public DNS server:

```bash
example.org:1053 {
    dnssec_pqc {
        key file <your_path>/dnssec_test/Kexample.org.+XXX+XXXXX
    }
    forward . 8.8.8.8
    log
}
.:1053 {
    forward . 8.8.8.8
    log
}
```

## Testing

This repository includes a testing script to evaluate PQC algorithms.

### Testing script dependencies

You may need to install the following dependencies first:

```bash
sudo apt-get install linux-tools-common linux-tools-generic dnsutils bind9-utils
```

### Testing script usage

```bash
./scripts/dns_test.sh <algorithm|all> [iterations]
```

The default number of iterations is 1. Results are saved in `resultados_*` directories with performance metrics and logs.

For example, you can test a single algorithm with:

```bash
sudo ./scripts/dns_test.sh ML-DSA-44
```

Or test all the available algorithms for a given number of iterations:

```bash
sudo ./scripts/dns_test.sh all 10
```
