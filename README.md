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

## Building ##

```bash
make sssmemvault
```

This creates the `sssmemvault` binary.

## Commands ##

The `sssmemvault` tool has three subcommands:

*   `daemon`: Runs the sssmemvault node.
*   `push`: Creates and pushes a new secret entry to nodes.
*   `get`: Retrieves and reconstructs a secret from nodes.

Use `sssmemvault <command> --help` for details on each subcommand's flags.

## Example Setup ##

This example demonstrates setting up two nodes and using the commands:
*   Node 1: `192.168.42.2`
*   Node 2: `192.168.42.34`
*   Client: `10.0.0.5` (needs its own key pair for `get`)

We will use Tink's command-line tool `tinkey` to generate the necessary keys. You might need to install `tinkey` first (e.g., via Go install or pre-built binaries).

**1. Generate Master Key Pair (ED25519 for signing)**

Only the master public key is needed by the nodes. Keep the private key secure and offline (used only by `sssmemvault push`).

```bash
# Generate master private key
tinkey create-keyset --key-template ED25519 --out master_private.json
# Extract master public key
tinkey create-public-keyset --in master_private.json --out master_public.json
```

**2. Generate Node 1 Key Pair (ECDSA_P256 + DHKEM_X25519)**

Nodes need a private keyset containing *both* a signing key (e.g., ECDSA_P256) for authenticating requests *and* a hybrid decryption key (e.g., DHKEM_X25519_HKDF_SHA256_AES_256_GCM) for decrypting their SSS fragment. The corresponding public keyset is needed by peers and the `push` command.

*Creating a combined keyset might require manual JSON editing or specific Tink library usage, as `tinkey` might not directly create a single keyset with both types.*

```bash
# Generate Node 1 signing key
tinkey create-keyset --key-template ECDSA_P256 --out node1_private_sig.json
# Generate Node 1 hybrid key
tinkey create-keyset --key-template DHKEM_X25519_HKDF_SHA256_AES_256_GCM --out node1_private_hybrid.json

# *** Manually combine the key material from both files into node1_private.json ***
# The JSON structure should look something like:
# {
#   "primaryKeyId": <ID of one key>,
#   "key": [
#     { /* Key material from node1_private_sig.json */ },
#     { /* Key material from node1_private_hybrid.json */ }
#   ]
# }
echo "Manually create node1_private.json containing keys from node1_private_sig.json and node1_private_hybrid.json"

# Create Node 1 public keyset from the combined private keyset
tinkey create-public-keyset --in node1_private.json --out node1_public.json
```

**3. Generate Node 2 Key Pair**

Repeat the process for Node 2, creating `node2_private.json` and `node2_public.json`.

```bash
# Generate Node 2 signing key
tinkey create-keyset --key-template ECDSA_P256 --out node2_private_sig.json
# Generate Node 2 hybrid key
tinkey create-keyset --key-template DHKEM_X25519_HKDF_SHA256_AES_256_GCM --out node2_private_hybrid.json
# *** Manually combine into node2_private.json ***
echo "Manually create node2_private.json containing appropriate ECDSA and DHKEM keys"
# Create Node 2 public keyset
tinkey create-public-keyset --in node2_private.json --out node2_public.json
```

**4. Generate Client Key Pair (for `get` command)**

The client machine (`10.0.0.5` in this example) needs its own private key (signing only is sufficient) to authenticate `get` requests. The corresponding public key needs to be known by the nodes (via the config file) to verify the client's requests.

```bash
# Generate Client private key (signing only)
tinkey create-keyset --key-template ECDSA_P256 --out client_private.json
# Extract Client public key
tinkey create-public-keyset --in client_private.json --out client_public.json
```

**5. Create Configuration File (`config.yaml`)**

This file is used by the `daemon` command and optionally by `push` and `get` to find peers/targets. Place the generated public keys (`master_public.json`, `node1_public.json`, `node2_public.json`, `client_public.json`) and the respective private keys (`node1_private.json`, `node2_private.json`) where the nodes can access them. The client only needs `client_private.json`.

```yaml
# config.yaml

# --- Daemon Settings ---
# Path to the private key file for the node running the daemon.
# This keyset MUST contain both signing and hybrid decryption keys.
private_key_path: "node_private.json" # Node 1 uses node1_private.json, Node 2 uses node2_private.json
# Path to the master public key file (used to verify pushed entries).
master_public_key: "master_public.json"
# Address and port the daemon listens on.
listen_address: ":59240"
# Maximum allowed time difference for authenticated requests.
max_timestamp_skew: 30s

# --- Peer Information ---
# Map of peer IP addresses to their configuration.
# The daemon uses this to know about other nodes for synchronization and auth verification.
# Client commands ('push', 'get') can use this to find targets/owners if not specified via flags.
peers:
  # Configuration for Node 1 (used by Node 2 daemon)
  "192.168.42.2":
    endpoint: "192.168.42.2:59240"
    public_key: "node1_public.json" # Node 1's public keyset (verify + encrypt)
    # poll_interval: "60s" # Optional: Poll Node 1 every 60 seconds

  # Configuration for Node 2 (used by Node 1 daemon)
  "192.168.42.34":
    endpoint: "192.168.42.34:59240"
    public_key: "node2_public.json" # Node 2's public keyset (verify + encrypt)
    poll_interval: "60s" # Poll Node 2 every 60 seconds

  # Configuration for the Client (used by Node 1 & 2 daemons for auth verification)
  # The client itself doesn't run a daemon, but nodes need its public key.
  "10.0.0.5":
    endpoint: "" # Endpoint not needed as client doesn't listen
    public_key: "client_public.json" # Client's public key (verification only)
    # poll_interval not applicable
```

**6. Run the Daemons**

Ensure the `sssmemvault` binary is built (`make sssmemvault`).

**On Node 1 (192.168.42.2):**
*   Copy `config.yaml` (or a version tailored for Node 1).
*   Ensure `node1_private.json`, `master_public.json`, `node2_public.json`, `client_public.json` are accessible.
*   Crucially, rename/copy `node1_private.json` to match the `private_key_path` in `config.yaml` (e.g., `node_private.json`).

```bash
# Assuming config.yaml has private_key_path: "node_private.json"
cp node1_private.json node_private.json

./sssmemvault daemon --config config.yaml --my-ip 192.168.42.2 --loglevel debug
```

**On Node 2 (192.168.42.34):**
*   Copy `config.yaml` (or a version tailored for Node 2).
*   Ensure `node2_private.json`, `master_public.json`, `node1_public.json`, `client_public.json` are accessible.
*   Rename/copy `node2_private.json` to match `private_key_path` (e.g., `node_private.json`).

```bash
# Assuming config.yaml has private_key_path: "node_private.json"
cp node2_private.json node_private.json

./sssmemvault daemon --config config.yaml --my-ip 192.168.42.34 --loglevel debug
```

The nodes will now start, load their respective private keys, connect to peers defined in the config, listen for requests, and poll peers with `poll_interval`.

**7. Provisioning a Secret (`sssmemvault push`)**

Use the `sssmemvault push` subcommand. This requires the *master private key* and the *public keys* of the owner nodes. Run this from any machine that has access to these keys.

```bash
# Example: Push a secret named "api-key" with value "supersecret123"
# Owned by Node 1 and Node 2 (2 parts, threshold 2)
# Readable by Node 1, Node 2, and the client 10.0.0.5
# Push the entry to both Node 1 and Node 2 using explicit flags:

./sssmemvault push \
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

# Alternatively, push using a config file to source owners and targets:
# (Ensure config.yaml contains the necessary peer info)

./sssmemvault push \
  --master-key master_private.json \
  --config config.yaml \
  --reader 192.168.42.2 \
  --reader 192.168.42.34 \
  --reader 10.0.0.5 \
  --key "api-key" \
  --secret "supersecret123" \
  --parts 2 \
  --threshold 2 \
  --loglevel info
```

This command will:
1. Load the master private key.
2. Load the public keys for the specified owners.
3. Split the secret into 2 fragments (threshold 2).
4. Encrypt fragment 0 for Node 1, fragment 1 for Node 2.
5. Create the signed protobuf `Entry`.
6. Connect to the target nodes and call the `Push` RPC.

Nodes receiving the `Push` will verify the master signature and store the entry. The synchronizer will eventually propagate the entry between nodes if it wasn't pushed to all initially.

**8. Retrieving a Secret (`sssmemvault get`)**

Use the `sssmemvault get` subcommand from an authorized reader machine (e.g., `10.0.0.5`). This requires the *client's private key* for authentication and a `config.yaml` file to find the owner node endpoints.

**On the Client machine (10.0.0.5):**
*   Ensure `sssmemvault` binary, `client_private.json`, and `config.yaml` are present.
*   The `config.yaml` needs `peers` entries for at least the *owner* nodes (`192.168.42.2`, `192.168.42.34`) so the `get` command knows their endpoints. It doesn't need the full daemon config sections.

```bash
# Example: Retrieve the "api-key" secret

# Using config file to find owner endpoints and specifying targets to query initially
./sssmemvault get \
  --private-key client_private.json \
  --config config.yaml \
  --key "api-key" \
  --target 192.168.42.2:59240 \
  --target 192.168.42.34:59240 \
  --output api-key.txt \
  --loglevel info

# If successful, api-key.txt will contain "supersecret123"
cat api-key.txt
```

This command will:
1. Load the client private key (`client_private.json`).
2. Load the config file (`config.yaml`) to find peer endpoints.
3. Connect to the specified target nodes (`--target`) and call `List` to find the latest timestamp for `"api-key"`.
4. Call `Get` on the node with the latest timestamp to retrieve the full entry.
5. Identify the owner IPs from the entry (`192.168.42.2`, `192.168.42.34`).
6. Look up the endpoints for these owners in the loaded `config.yaml`.
7. Connect to *each* owner node endpoint.
8. Call `GetDecoded` on each owner node (authenticating with `client_private.json`).
9. Combine the received decrypted fragments using Shamir's algorithm.
10. Write the reconstructed secret to `api-key.txt`.
