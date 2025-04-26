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

## Implementation ##

Modern Go, using Google's Tink library to get algorithm agility.

## Example Setup ##

This example demonstrates setting up two nodes:
*   Node 1: `192.168.42.2`
*   Node 2: `192.168.42.34`

We will use Tink's command-line tool `tinkey` to generate the necessary keys. You might need to install `tinkey` first (e.g., via Go install or pre-built binaries).

**1. Generate Master Key Pair (ED25519 for signing)**

Only the master public key is needed by the nodes. Keep the private key secure and offline.

```bash
# Generate master private key
tinkey create-keyset --key-template ED25519 --out master_private.json
# Extract master public key
tinkey create-public-keyset --in master_private.json --out master_public.json
```

**2. Generate Node 1 Key Pair (ECDSA_P256 for signing, DHKEM_X25519 for hybrid encryption)**

Nodes need both signing and hybrid encryption capabilities from the same keyset. We'll use a combined template if available, or generate separate keys and potentially combine them manually if `tinkey` doesn't directly support a combined template suitable for both `tink.Signer/Verifier` and `tink.HybridEncrypt/Decrypt`. *Assuming separate generation for clarity, though a combined key might be possible depending on Tink features.*

*Note: Tinkey might require specific templates. We'll use standard ones.*

```bash
# Generate Node 1 private key (suitable for signing and hybrid decryption)
# Using ECDSA_P256 for signing and DHKEM_X25519... for hybrid
# Tinkey might require creating these separately and combining, or using a specific template.
# Let's assume we generate a keyset suitable for both:
# (Adjust template based on actual tinkey capabilities/needs)
# Example using ECDSA for signing:
tinkey create-keyset --key-template ECDSA_P256 --out node1_private_sig.json
# Example using DHKEM for hybrid:
tinkey create-keyset --key-template DHKEM_X25519_HKDF_SHA256_AES_256_GCM --out node1_private_hybrid.json

# *** Ideally, combine these into a single keyset file `node1_private.json` ***
# (Manual JSON editing might be needed if tinkey doesn't have a direct command)
# For this example, let's assume node1_private.json contains keys for both.
# If using separate files, the config/code would need adjustment.
# Assuming a combined node1_private.json exists:
echo "Manually create node1_private.json containing keys from node1_private_sig.json and node1_private_hybrid.json"
# Create Node 1 public key
tinkey create-public-keyset --in node1_private.json --out node1_public.json
```

**3. Generate Node 2 Key Pair**

Repeat the process for Node 2.

```bash
# Generate Node 2 private key (suitable for signing and hybrid decryption)
echo "Manually create node2_private.json containing appropriate ECDSA and DHKEM keys"
# Create Node 2 public key
tinkey create-public-keyset --in node2_private.json --out node2_public.json
```

**4. Create Configuration Files**

Place the generated public keys (`master_public.json`, `node1_public.json`, `node2_public.json`) and the respective private keys (`node1_private.json`, `node2_private.json`) where the nodes can access them.

**`config_node1.yaml` (for 192.168.42.2):**

```yaml
# config_node1.yaml
private_key_path: "node1_private.json" # Path to Node 1's private key
master_public_key: "master_public.json" # Path to Master public key
listen_address: ":59240"
my_ip: "192.168.42.2" # This node's IP
max_timestamp_skew: 30s

peers:
  "192.168.42.34": # Peer is Node 2
    endpoint: "192.168.42.34:59240"
    public_key: "node2_public.json" # Path to Node 2's public key
    poll_interval: "60s" # Poll Node 2 every 60 seconds
```

**`config_node2.yaml` (for 192.168.42.34):**

```yaml
# config_node2.yaml
private_key_path: "node2_private.json" # Path to Node 2's private key
master_public_key: "master_public.json" # Path to Master public key
listen_address: ":59240"
my_ip: "192.168.42.34" # This node's IP
max_timestamp_skew: 30s

peers:
  "192.168.42.2": # Peer is Node 1
    endpoint: "192.168.42.2:59240"
    public_key: "node1_public.json" # Path to Node 1's public key
    poll_interval: "60s" # Poll Node 1 every 60 seconds
```

**5. Run the Daemons**

Ensure the `sssmemvaultd` binary is built (`go build ./cmd/sssmemvaultd`).

**On Node 1 (192.168.42.2):**

```bash
./sssmemvaultd --config config_node1.yaml --loglevel debug
```

**On Node 2 (192.168.42.34):**

```bash
./sssmemvaultd --config config_node2.yaml --loglevel debug
```

The nodes will now start, connect to each other based on the configuration, listen for incoming requests, and periodically poll peers specified with `poll_interval`.

**6. Provisioning a Secret with `sssmemvault-push`**

Use the `sssmemvault-push` tool (build it with `go build ./cmd/sssmemvault-push` or `make sssmemvault-push`) to create and push a new secret entry. This requires the *master private key* and the *public keys* of the owner nodes.

```bash
# Example: Push a secret named "api-key" with value "supersecret123"
# Owned by Node 1 and Node 2 (2 parts, threshold 2)
# Readable by Node 1, Node 2, and an external client 10.0.0.5
# Push the entry to both Node 1 and Node 2

./sssmemvault-push \
  --master-key master_private.json \
  --owner 192.168.42.2=node1_public.json \
  --owner 192.168.42.34=node2_public.json \
  --reader 192.168.42.2 \
  --reader 192.168.42.34 \
  --reader 10.0.0.5 \
  --key "api-key" \
  --secret "supersecret123" \
  --parts 2 \
  --threshold 2 \
  --target 192.168.42.2:59240 \
  --target 192.168.42.34:59240 \
  --loglevel info
```

This command will:
1. Load the master private key (`master_private.json`).
2. Load the public keys for the owners (`node1_public.json`, `node2_public.json`).
3. Split the secret `"supersecret123"` into 2 fragments with a threshold of 2.
4. Encrypt fragment 0 for Node 1 (`192.168.42.2`) using its public key.
5. Encrypt fragment 1 for Node 2 (`192.168.42.34`) using its public key.
6. Create a protobuf `Entry` containing the key, timestamp, reader list, and the map of owner IPs to their encrypted fragments.
7. Sign the `Entry` using the master private key.
8. Connect to the target nodes (`192.168.42.2:59240`, `192.168.42.34:59240`).
9. Call the `Push` RPC on each target node to send the signed entry.

The nodes receiving the `Push` request will verify the master signature and add the entry to their in-memory store if the signature is valid and the timestamp is newer than any existing entry for that key.
