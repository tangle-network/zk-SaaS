# zk-SaaS
Rust implementation of the zkSaaS protocol based on [zkSaaS: Zero-Knowledge SNARKs as a Service](https://eprint.iacr.org/2023/905.pdf). Originally derived from https://github.com/guruvamsi-policharla/zksaas.

zkSaaS is a protocol (and more generally a service) that leverages secure multi-party computation to generate zkSNARKs. It does so by distributing the core computations used in the zero-knowledge prover of the target protocols. The protocol itself is a $(t,N)$-threshold protocol, meaning it tolerates up to $t$ corruptions out of $N$ nodes. In this protocol $t$ is usually assigned to be $N/4$ where $N$ is the number of participating nodes in the computation. Currently, this repo supports the Groth16 prover and we plan to support other protocols as we further benchmark this protocol.

**WARNING:** This implementation has not been audited. The risk posed by vulnerabilities is a loss of privacy in the witness used for proof generation.

## Dependencies
This project relies on the [arkworks](http://arkworks.rs) project for finite field and elliptic curve arithmetic. For communication we use an adapted mpc-net crate from [collaborative-zksnark](https://github.com/alex-ozdemir/collaborative-zksnark).

## Overview
* [`secret-sharing/`](secret-sharing): A packed secret sharing and reed solomon error correcting decoder library built on top of the finite field generics in arkworks.
* [`dist-primitives/`](dist-primitives): Contains implementations of the distributed fast-fourier transform, multiscalar multiplication and partial products, complete with correctness tests.
* [`groth16/`](groth16): Contains a distributed and local version of groth16 used for benchmarking timings.
* [`scripts/`](scripts): Contains shell scripts to run various tests and benchmarks.
* [`fixtures/`](fixtures): Circom circuit and proving key fixtures for local proving tests.

## Network Topology
The network topology of the MPC computation is modelled as a star topology. There are two types of nodes in the MPC, denoted _king_ and _client_. The king is the center node and is expected to have the highest computational throughput. It is tasked with evaluating the $O(N)$ computations such as the FFTs. The clients are the nodes that connect to the king and are expected to have lower computational throughput. The workload of the prover is distributed across clients who run in time $O(N/(l\cdot\log{N}))$

## Testing
The testnet requires mutual TLS for ensuring security as well as enforcing the network topology. The network topology is a star
graph, and as such, the center node (i.e., the "king") must be started first with a list of valid certificates that each individually represent
the client nodes that will connect to the king.

Thus, we must first generate identities for each of the nodes, including the king. This can be done with the following command:

```bash
cargo run --example gen_cert -- ./certs/public_n.cert.der ./certs/private_n.key.der 127.0.0.1
```

* Note: change `public_n` and `private_n` to the desired name for each node.
* Note: we do not need certificates backed by a CA like LetsEncrypt, since we are the only ones who will be using these certificates and trust ourselves to create them.
* Note: the final argument, 127.0.0.1, will need to be changed to the IP address of the node you plan to pin the identity to. For localhost testing, `127.0.0.1` is acceptable since each node is running with a bind address on 127.0.0.1.

With these public key documents (in the form of certificates), we start the king by passing in the king's private key and public key, as well as a list of all the client's public keys.
For the clients, we pass the public and private key of the client, followed by the public key of the king.
Since we are using mutual TLS, we enforce that the king can receive packets from the list of identities passed in, and that the clients can only receive packets from the king.

An example of this network being set up, including the generation of all certificates and private keys,
can be found in `./scripts/prod_net_example.sh`. This example network sets up the nodes, then performs a
protocol where each node sends its ID to the king, then, the king sums the IDs and returns the result to
each client.

## Integration
An example integration occurring against a blockchain can be found in our [gadget](https://github.com/webb-tools/gadget). Here we hook up the mpc-net to an existing gossip network for a Substrate blockchain.

## License
This library is released under the MIT License.
