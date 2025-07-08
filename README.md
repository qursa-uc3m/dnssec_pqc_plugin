# DNSSEC PQC Plugin for CoreDNS

This is a **plugin of CoreDNS** that integrates support for **Post-Quantum Cryptography (PQC)** signature algorithms. It is intended for research and testing purposes within the context of DNSSEC and PQC algorithm evaluation.

## PQC DNSSEC Plugin

The `dnssec_pqc` plugin extends CoreDNS to allow DNSSEC zone signing and validation using a set of post-quantum signature algorithms. It builds upon the original `dnssec` plugin by replacing or augmenting cryptographic operations with post-quantum alternatives.

## Supported Algorithms and Identifiers

The plugin currently supports the following post-quantum signature schemes, identified by custom algorithm IDs:

| Algorithm        | ID |
|------------------|----|
| FALCON512        | 17 |
| DILITHIUM2       | 18 |
| SPHINCS_SHA2     | 19 |
| MAYO1            | 20 |
| SNOVA            | 21 |
| FALCON1024       | 27 |
| DILITHIUM3       | 28 |
| SPHINCS_SHAKE    | 29 |
| MAYO3            | 30 |
| SNOVASHAKE       | 31 |
| FALCONPADDED512  | 37 |
| DILITHIUM5       | 38 |
| FALCONPADDED1024 | 47 |

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

This installs the `liboqs` version `0.12.0` by default.

and then install CoreDNS with PQC plugin:

```bash
./scripts/install_coredns.sh
```

This modifies the CoreDNS source code on the fly to include the PQC plugin and the necessary dependencies. For reference, you can examine the manual approach used in [Juligent/coredns](https://github.com/Juligent/coredns).

## Example Configuration

To configure CoreDNS to use the PQC plugin, you can create a `Corefile` with the following content. This example assumes you have a DNSSEC key file for your domain and that you want to forward queries to Google's public DNS server:

```bash
example.org:1053 {
    dnssec {
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
