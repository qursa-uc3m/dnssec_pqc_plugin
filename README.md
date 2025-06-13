# dnssec_pqc
This is a **plugin of CoreDNS** that integrates support for **Post-Quantum Cryptography (PQC)** signature algorithms. It is intended for research and testing purposes within the context of DNSSEC and PQC algorithm evaluation.


## PQC DNSSEC Plugin

The `dnssec_pqc` plugin extends CoreDNS to allow DNSSEC zone signing and validation using a set of post-quantum signature algorithms. It builds upon the original `dnssec` plugin by replacing or augmenting cryptographic operations with post-quantum alternatives. 

### Supported Algorithms and Identifiers

The plugin currently supports the following post-quantum signature schemes, identified by custom algorithm IDs:

## Supported Algorithms
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

TThis plugin depends on a custom version of the miekg/dns library, which has been modified to support PQC extensions.
  
> https://github.com/qursa-uc3m/dns  
> Branch: `pqcintegrated`

To use this version, the following replacement must be added to the go.mod file of CoreDNS:

```bash
replace github.com/miekg/dns => github.com/qursa-uc3m/dns pqcintegrated
```
This enables PQC support.



## Installation

To install, you need the fork that includes this plugin because it uses the custom library and enables the plugin within CoreDNS. Although you could apply these changes manually, the recommended process to use this plugin is: 

```bash
git clone https://github.com/Juligent/coredns
cd coredns
go mod tidy
go clean
go build
```

## Configuration example of the Corefile


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

