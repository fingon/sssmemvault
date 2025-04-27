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
  owner-specific SSS fragment, re-encrypted using the requesting
  node's hybrid public key, if the requesting node IP is in the
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
*   Client: `10.0.0.5` (needs its own *signing* key pair for `get`)

We will use Tink's command-line tool `tinkey` to generate the necessary keys. You might need to install `tinkey` first (e.g., via Go install or pre-built binaries).

**1. Generate Master Key Pair (Signing Only)**

Only the master *signing* public key is needed by the nodes. Keep the master *signing* private key secure and offline (used only by `sssmemvault push`). We'll use ED25519.

```bash
# Generate master signing private key
tinkey create-keyset --key-template ED25519 --out master_signing_private.json
# Extract master signing public key
tinkey create-public-keyset --in master_signing_private.json --out master_signing_public.json
```

**2. Generate Node 1 Key Pairs (Signing + Hybrid)**

Nodes need *separate* keysets: one for signing requests (e.g., ECDSA_P256) and one for hybrid encryption/decryption (e.g., DHKEM_X25519_HKDF_SHA256_AES_256_GCM).

```bash
# --- Node 1 Signing Key ---
# Generate Node 1 signing private key
tinkey create-keyset --key-template ECDSA_P256 --out node1_signing_private.json
# Extract Node 1 signing public key
tinkey create-public-keyset --in node1_signing_private.json --out node1_signing_public.json

# --- Node 1 Hybrid Key ---
# Generate Node 1 hybrid private key
tinkey create-keyset --key-template DHKEM_X25519_HKDF_SHA256_AES_256_GCM --out node1_hybrid_private.json
# Extract Node 1 hybrid public key
tinkey create-public-keyset --in node1_hybrid_private.json --out node1_hybrid_public.json
```

**3. Generate Node 2 Key Pairs**

Repeat the process for Node 2, creating:
*   `node2_signing_private.json` / `node2_signing_public.json`
*   `node2_hybrid_private.json` / `node2_hybrid_public.json`

```bash
# --- Node 2 Signing Key ---
tinkey create-keyset --key-template ECDSA_P256 --out node2_signing_private.json
tinkey create-public-keyset --in node2_signing_private.json --out node2_signing_public.json

# --- Node 2 Hybrid Key ---
tinkey create-keyset --key-template DHKEM_X25519_HKDF_SHA256_AES_256_GCM --out node2_hybrid_private.json
tinkey create-public-keyset --in node2_hybrid_private.json --out node2_hybrid_public.json
```

**4. Generate Client Key Pair (Signing Only)**

The client machine (`10.0.0.5` in this example) needs its own *signing* private key to authenticate `get` requests. The corresponding *signing* public key needs to be known by the nodes (via the config file) to verify the client's requests.

```bash
# Generate Client signing private key
tinkey create-keyset --key-template ECDSA_P256 --out client_signing_private.json
# Extract Client signing public key
tinkey create-public-keyset --in client_signing_private.json --out client_signing_public.json

# --- Client Hybrid Key (Needed by nodes to encrypt GetDecoded responses for the client) ---
tinkey create-keyset --key-template DHKEM_X25519_HKDF_SHA256_AES_256_GCM --out client_hybrid_private.json
tinkey create-public-keyset --in client_hybrid_private.json --out client_hybrid_public.json
```

**5. Create Configuration File (`config.yaml`)**

This file is used by the `daemon` command and optionally by `push` and `get` to find peers/targets. Place the generated public keys (`master_signing_public.json`, `node1_signing_public.json`, `node1_hybrid_public.json`, etc.) and the respective private keys (`node1_signing_private.json`, `node1_hybrid_private.json`, etc.) where the nodes can access them. The client only needs `client_signing_private.json`.

```yaml
# config.yaml

# --- Daemon Settings ---
# Path to the private key file for signing outgoing requests.
signing_private_key_path: "node_signing_private.json" # Node 1 uses node1_signing_private.json, Node 2 uses node2_signing_private.json
# Path to the private key file for decrypting owned SSS fragments.
hybrid_private_key_path: "node_hybrid_private.json" # Node 1 uses node1_hybrid_private.json, Node 2 uses node2_hybrid_private.json
# Path to the master public key file (used to verify pushed entry signatures).
master_signing_public_key: "master_signing_public.json"
# Address and port the daemon listens on.
listen_address: ":59240"
# Maximum allowed time difference for authenticated requests.
max_timestamp_skew: 30s

# --- Peer Information ---
# Map of peer IP addresses to their configuration.
# The daemon uses this to know about other nodes for synchronization and auth verification.
# Client commands ('push', 'get') can use this to find targets/owners if not specified via flags.
peers:
  # Configuration for Node 1 (used by Node 2 daemon, and by clients)
  "192.168.42.2":
    endpoint: "192.168.42.2:59240"
    signing_public_key: "node1_signing_public.json" # For verifying requests FROM Node 1
    hybrid_public_key: "node1_hybrid_public.json"   # For encrypting fragments FOR Node 1 (used by 'push')
    # Optional: Restrict requests signed by Node 1's key to only come from its specific IP
    # allowed_source_cidrs: ["192.168.42.2/32"]
    # poll_interval: "60s" # Optional: Poll Node 1 every 60 seconds

  # Configuration for Node 2 (used by Node 1 daemon, and by clients)
  "192.168.42.34":
    endpoint: "192.168.42.34:59240"
    signing_public_key: "node2_signing_public.json" # For verifying requests FROM Node 2
    hybrid_public_key: "node2_hybrid_public.json"   # For encrypting fragments FOR Node 2 (used by 'push')
    # Optional: Allow requests signed by Node 2's key from its IP or a specific management subnet
    allowed_source_cidrs: ["192.168.42.34/32", "10.1.2.0/24"]
    poll_interval: "60s" # Poll Node 2 every 60 seconds

  # Configuration for the Client (used by Node 1 & 2 daemons for auth verification)
  # The client itself doesn't run a daemon, but nodes need its public signing key.
  "10.0.0.5":
    endpoint: "" # Endpoint not needed as client doesn't listen
    signing_public_key: "client_signing_public.json" # For verifying requests FROM the client
    hybrid_public_key: "client_hybrid_public.json"   # For encrypting GetDecoded responses FOR the client
    # Optional: Ensure requests signed by the client key ONLY come from the client's IP
    allowed_source_cidrs: ["10.0.0.5/32"]
    # poll_interval not applicable
```

**6. Run the Daemons**

Ensure the `sssmemvault` binary is built (`make sssmemvault`).

**On Node 1 (192.168.42.2):**
*   Copy `config.yaml` (or a version tailored for Node 1).
*   Ensure `node1_signing_private.json`, `node1_hybrid_private.json`, `master_signing_public.json`, `node2_signing_public.json`, `node2_hybrid_public.json`, `client_signing_public.json` are accessible.
*   Crucially, rename/copy `node1_signing_private.json` and `node1_hybrid_private.json` to match the paths in `config.yaml` (e.g., `node_signing_private.json`, `node_hybrid_private.json`).

```bash
# Assuming config.yaml uses "node_signing_private.json" and "node_hybrid_private.json"
cp node1_signing_private.json node_signing_private.json
cp node1_hybrid_private.json node_hybrid_private.json

./sssmemvault daemon --config config.yaml --my-ip 192.168.42.2 --loglevel debug
```

**On Node 2 (192.168.42.34):**
*   Copy `config.yaml` (or a version tailored for Node 2).
*   Ensure `node2_signing_private.json`, `node2_hybrid_private.json`, `master_signing_public.json`, `node1_signing_public.json`, `node1_hybrid_public.json`, `client_signing_public.json` are accessible.
*   Rename/copy `node2_signing_private.json` and `node2_hybrid_private.json` to match the paths in `config.yaml`.

```bash
# Assuming config.yaml uses "node_signing_private.json" and "node_hybrid_private.json"
cp node2_signing_private.json node_signing_private.json
cp node2_hybrid_private.json node_hybrid_private.json

./sssmemvault daemon --config config.yaml --my-ip 192.168.42.34 --loglevel debug
```

The nodes will now start, load their respective signing and hybrid private keys, connect to peers defined in the config, listen for requests, and poll peers with `poll_interval`.

**7. Provisioning a Secret (`sssmemvault push`)**

Use the `sssmemvault push` subcommand. This requires the *master signing private key* and the *hybrid public keys* of the owner nodes. Run this from any machine that has access to these keys.

```bash
# Example: Push a secret named "api-key" with value "supersecret123"
# Owned by Node 1 and Node 2.
# Split into 4 fragments, requiring 3 to reconstruct (threshold 3).
# Assign 2 fragments to Node 1 and 2 fragments to Node 2.
# Readable by Node 1, Node 2, and the client 10.0.0.5
# Push the entry to both Node 1 and Node 2 using explicit flags:

./sssmemvault push \
  --master-signing-key master_signing_private.json \
  --owner 192.168.42.2=node1_hybrid_public.json:2 \
  --owner 192.168.42.34=node2_hybrid_public.json:2 \
  --reader 192.168.42.2 \
  --reader 192.168.42.34 \
  --reader 10.0.0.5 \
  --key "api-key" \
  --secret "supersecret123" \
  --parts 4 \
  --threshold 3 \
  --target 192.168.42.2:59240 \
  --target 192.168.42.34:59240 \
  --loglevel info

# Alternatively, push using a config file to source owners and targets:
# (Ensure config.yaml contains the necessary peer info, specifically the hybrid_public_key for owners)

./sssmemvault push \
  --master-signing-key master_signing_private.json \
  --config config.yaml \
  # Note: When using --config, owners are derived, and count defaults to 1 per owner.
  # To specify counts with --config, you must also provide explicit --owner flags.
  # Example below assumes owners are NOT derived from config:
  --owner 192.168.42.2=node1_hybrid_public.json:2 \
  --owner 192.168.42.34=node2_hybrid_public.json:2 \
  --reader 192.168.42.2 \
  --reader 192.168.42.34 \
  --reader 10.0.0.5 \
  --key "api-key" \
  --secret "supersecret123" \
  --parts 4 \
  --threshold 3 \
  --loglevel info
```

This command will:
1. Load the master signing private key.
2. Parse owner info (`IP=Path:Count`) and load hybrid public keys.
3. Validate that the sum of counts from `--owner` flags equals `--parts`.
4. Split the secret into 4 fragments (threshold 3).
5. Encrypt fragments and assign them according to specified counts:
    - Fragment 0 -> Encrypt with Node 1 key
    - Fragment 1 -> Encrypt with Node 1 key
    - Fragment 2 -> Encrypt with Node 2 key
    - Fragment 3 -> Encrypt with Node 2 key
6. Create the protobuf `Entry`, storing the encrypted fragments in lists associated with each owner IP (`OwnerFragments` map).
7. Sign the entry using the master signing private key.
8. Connect to the target nodes and call the `Push` RPC.

Nodes receiving the `Push` will verify the master signature (using `master_signing_public.json` from their config) and store the entry. The synchronizer will eventually propagate the entry between nodes if it wasn't pushed to all initially.

**8. Retrieving a Secret (`sssmemvault get`)**

Use the `sssmemvault get` subcommand from an authorized reader machine (e.g., `10.0.0.5`). This requires the *client's signing private key* for authentication and a `config.yaml` file to find the owner node endpoints.

**On the Client machine (10.0.0.5):**
*   Ensure `sssmemvault` binary, `client_signing_private.json`, and `config.yaml` are present.
*   The `config.yaml` needs `peers` entries for at least the *owner* nodes (`192.168.42.2`, `192.168.42.34`) so the `get` command knows their endpoints. It doesn't need the full daemon config sections, just the `endpoint` and potentially `signing_public_key` for the peers it contacts.

```bash
# Example: Retrieve the "api-key" secret

# Using config file to find owner endpoints and specifying targets to query initially
./sssmemvault get \
  --signing-private-key client_signing_private.json \
  --hybrid-private-key client_hybrid_private.json \
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
1. Load the client signing private key (`client_signing_private.json`).
2. Load the config file (`config.yaml`) to find peer endpoints.
3. Connect to the specified target nodes (`--target`) and call `List` (authenticating with the client signing key) to find the latest timestamp for `"api-key"`.
4. Call `Get` on the node with the latest timestamp (authenticating again) to retrieve the full entry.
5. Identify the owner IPs from the entry (`192.168.42.2`, `192.168.42.34`).
6. Look up the endpoints for these owners in the loaded `config.yaml`.
7. Connect to *each* owner node endpoint.
8. Call `GetDecoded` on each owner node (authenticating with `client_signing_private.json`). Each owner node will:
    a. Decrypt its fragment using its *hybrid private key*.
    b. Re-encrypt the fragment using the client's *hybrid public key* (found in the node's `config.yaml`).
    c. Return the re-encrypted fragment.
9. Decrypt each received fragment using the client's *hybrid private key* (`--hybrid-private-key`).
10. Combine the decrypted fragments using Shamir's algorithm.
11. Write the reconstructed secret to `api-key.txt`.
