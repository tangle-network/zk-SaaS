# zk-SaaS
zkSaaS implementation in Rust based on the paper [zkSaaS: Zero-Knowledge SNARKs as a Service](https://eprint.iacr.org/2023/905.pdf). Originally derived from https://github.com/guruvamsi-policharla/zksaas.

zkSaaS is a protocol (and more generally a service) that leverages secure multi-party computation to generate zkSNARKs. It does so by distributing the core computations used in the zero-knowledge prover of the target protocols. Currently, this repo supports the Groth16 prover. The protocol itself is a threshold protocol, meaning it tolerates up to $t$ corruptions. In this protocol $t$ is usually assigned to be $N/4$ where $N$ is the number of participating nodes in the computation.

This work can very likely be extended to other proving systems, and we welcome such contributions or discussions.

## Current implementations
The current implementations supported must be compatible with Arkworks and R1CS. The two currently supported compilers are Circom and Arkworks, which we can map similarly into Arkworks R1CS primitives.

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
