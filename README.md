# sssmemvault #

This is Shamir's Secret Sharing based in-memory secret vault, which is
planned to be used in networks with more than one static node that act
as gatekeepers to the secrets.

The idea is that they synchronize state from each other, but presence
of more than one node is needed for secret to be available. Finally,
secret fragments may be encrypted so that only specific third party
can actually combine them to usable secret.

Master private key is not owned by any of the nodes, but it is used to
provision secrets.

The state of the system consists of entries, signed by master public key. with:

- timestamp
- key (string)
- readers (list of IP addresses that are allowed to ask for this data)
- a list of owner (IP address) and SSS fragment data (encrypted bytes)

Each key in the system is unique; if there is conflict, highest
timestamp wins.

## Communication ##

- Each participating node listens to insecure GRPC HTTP requests on
  (default) port 59240.

- Each node has private key that is associated with their IP.

- Each node has all other nodes' public keys and the IPs in their
  configuration file.

- GRPC requests are allowed only if they contain header, which has
  request timestamp which is recent enough, and is signed using
  private key of the IP address request originates from.


## Configuration file (for each node) ##

- path to their private key file

- master public key

- list of other nodes, with each having:

  - GRPC endpoint

  - public key

  - optional poll duration flag (Go duration style, e.g. 60m), which
    indicates that node should be polled with that frequency

## Requests ##

- List request: results in list of timestamp+key pairs the remote node has

- Get (timestamp,key) request: Returns the whole signed entry

- Get decoded (timestamp, key) request: Returns the decrypted
  owner-specific SSS fragment, if the requesting node IP is in the
  readers list.

## Implementation

Modern Go, using Google's Tink library to get algorithm agility.
