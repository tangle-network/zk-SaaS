# zk-SaaS
Zero Knowledge SaaS implementation in rust

## Network Topology
Star topology. The "king" is the center node, and is expected to have the highest computational throughput. The "clients" are the nodes that connect to the king, and are expected to have lower computational throughput.

## Running a testnet
The testnet requires mutual TLS for ensuring security as well as enforcing the network topology. The network topology is a star
graph, and as such, the center node (i.e., the "king") must be started first with a list of valid certificates that each individually represent
the client nodes that will connect to the king.

Thus, we must first generate identities for each of the nodes, including the king. This can be done with the following command:

```bash
cargo run --example gen_cert -- ./certs/public_n.cert.der ./certs/private_n.key.der localhost
```

* Note: change `public_n` and `private_n` to the desired name for each node.
* Note: we do not need certificates backed by a CA like LetsEncrypt, since we are the only ones who will be using these certificates and trust ourselves to create them.
* Note: the final argument, localhost, will need to be changed to the IP address of the node if you are running the king and clients on different machines. For localhost testing, `localhost` is acceptable

With these public key documents (in the form of certificates), we start the king by passing in the king's private key and public key, as well as a list of all the client's public keys.
For the clients, we pass the public and private key of the client, followed by the public key of the king.
Since we are using mutual TLS, we enforce that the king can receive packets from the list of identities passed in, and that the clients can only receive packets from the king.
