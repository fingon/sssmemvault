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

- Each node/client has a unique **name** (string) and a corresponding *signing* private key.
- Each node also has a *hybrid* key pair for fragment encryption/decryption.
- Each node has all other nodes' (and relevant clients') public keys (signing and hybrid) and their names mapped in its configuration file (`peers` section).
- Authenticated GRPC requests (List, Get, GetDecoded) must contain headers with:
    - The requesting node/client's **name** (`x-request-node-name`).
    - A recent timestamp (`x-request-timestamp`).
    - A signature over the timestamp, created using the requestor's *signing* private key (`x-request-signature`).
- The receiving node verifies the signature using the public key associated with the provided name in its configuration.


## Configuration file (for each node) ##

- path to their *signing* private key file (`signing_private_key_path`)
- path to their *hybrid* private key file (`hybrid_private_key_path`)
- path to the *master signing* public key file (`master_signing_public_key`)
- listen address (`listen_address`)
- max timestamp skew (`max_timestamp_skew`)
- map of peer nodes (`peers`), where the key is the peer's unique **name** (string) and the value contains:
  - `endpoint`: GRPC endpoint (host:port)
  - `signing_public_key`: Path to the peer's public key for verifying their requests.
  - `hybrid_public_key`: Path to the peer's public key for encrypting data *for* them (used by `push` and `GetDecoded`).
  - `poll_interval` (optional): Go duration string (e.g., `60s`), indicating this peer should be polled for updates.

## Requests ##

- List request: results in list of timestamp+key pairs the remote node has

- Get (timestamp,key) request: Returns the whole signed entry

- Get decoded (timestamp, key) request: Returns the decrypted
  owner-specific SSS fragment(s), re-encrypted using the requesting
  node's hybrid public key, if the requesting node **name** is in the
  entry's `readers` list.

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

This example demonstrates setting up two nodes (`node-A`, `node-B`) and a client (`client-X`) and using the commands.

We will use Tink's command-line tool `tinkey` to generate the necessary keys. You might need to install `tinkey` first (e.g., via Go install or pre-built binaries). Node endpoints are assumed to be `node-a.example.com:59240` and `node-b.example.com:59240`.

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
# --- Node A Signing Key ---
# Generate Node A signing private key
tinkey create-keyset --key-template ECDSA_P256 --out nodeA_signing_private.json
# Extract Node A signing public key
tinkey create-public-keyset --in nodeA_signing_private.json --out nodeA_signing_public.json

# --- Node A Hybrid Key ---
# Generate Node A hybrid private key
tinkey create-keyset --key-template DHKEM_X25519_HKDF_SHA256_AES_256_GCM --out nodeA_hybrid_private.json
# Extract Node A hybrid public key
tinkey create-public-keyset --in nodeA_hybrid_private.json --out nodeA_hybrid_public.json
```

**3. Generate Node B Key Pairs**

Repeat the process for Node B, creating:
*   `nodeB_signing_private.json` / `nodeB_signing_public.json`
*   `nodeB_hybrid_private.json` / `nodeB_hybrid_public.json`

```bash
# --- Node B Signing Key ---
tinkey create-keyset --key-template ECDSA_P256 --out nodeB_signing_private.json
tinkey create-public-keyset --in nodeB_signing_private.json --out nodeB_signing_public.json

# --- Node B Hybrid Key ---
tinkey create-keyset --key-template DHKEM_X25519_HKDF_SHA256_AES_256_GCM --out nodeB_hybrid_private.json
tinkey create-public-keyset --in nodeB_hybrid_private.json --out nodeB_hybrid_public.json
```

**4. Generate Client Key Pairs (Signing + Hybrid)**

The client (`client-X` in this example) needs its own *signing* private key to authenticate `get` requests and its *hybrid* private key to decrypt the fragments returned by `GetDecoded`. The corresponding public keys need to be known by the nodes (via the config file).

```bash
# --- Client X Signing Key ---
# Generate Client signing private key
tinkey create-keyset --key-template ECDSA_P256 --out clientX_signing_private.json
# Extract Client signing public key
tinkey create-public-keyset --in clientX_signing_private.json --out clientX_signing_public.json

# --- Client X Hybrid Key ---
tinkey create-keyset --key-template DHKEM_X25519_HKDF_SHA256_AES_256_GCM --out clientX_hybrid_private.json
tinkey create-public-keyset --in clientX_hybrid_private.json --out clientX_hybrid_public.json
```

**5. Create Configuration File (`config.yaml`)**

This file is used by the `daemon` command and optionally by `push` and `get` to find peers/targets. Place the generated public keys (`master_signing_public.json`, `nodeA_signing_public.json`, `nodeA_hybrid_public.json`, etc.) and the respective private keys (`nodeA_signing_private.json`, `nodeA_hybrid_private.json`, etc.) where the nodes can access them. The client needs its own private keys (`clientX_signing_private.json`, `clientX_hybrid_private.json`).

```yaml
# config.yaml

# --- Daemon Settings ---
# Path to the private key file for signing outgoing requests.
signing_private_key_path: "node_signing_private.json" # Node A uses nodeA_signing_private.json, Node B uses nodeB_signing_private.json
# Path to the private key file for decrypting owned SSS fragments.
hybrid_private_key_path: "node_hybrid_private.json" # Node A uses nodeA_hybrid_private.json, Node B uses nodeB_hybrid_private.json
# Path to the master public key file (used to verify pushed entry signatures).
master_signing_public_key: "master_signing_public.json"
# Address and port the daemon listens on.
listen_address: ":59240"
# Maximum allowed time difference for authenticated requests.
max_timestamp_skew: 30s

# --- Peer Information ---
# Map of peer **names** (arbitrary strings) to their configuration.
# The daemon uses this to know about other nodes for synchronization and auth verification.
# Client commands ('push', 'get') can use this to find targets/owners if not specified via flags.
peers:
  # Configuration for Node A (used by Node B daemon, and by clients)
  "node-A":
    endpoint: "node-a.example.com:59240" # Or IP:port "192.168.42.2:59240"
    signing_public_key: "nodeA_signing_public.json" # For verifying requests FROM Node A
    hybrid_public_key: "nodeA_hybrid_public.json"   # For encrypting fragments FOR Node A (used by 'push' and GetDecoded)
    # poll_interval: "60s" # Optional: Poll Node A every 60 seconds

  # Configuration for Node B (used by Node A daemon, and by clients)
  "node-B":
    endpoint: "node-b.example.com:59240" # Or IP:port "192.168.42.34:59240"
    signing_public_key: "nodeB_signing_public.json" # For verifying requests FROM Node B
    hybrid_public_key: "nodeB_hybrid_public.json"   # For encrypting fragments FOR Node B (used by 'push' and GetDecoded)
    poll_interval: "60s" # Poll Node B every 60 seconds

  # Configuration for the Client (used by Node A & B daemons for auth verification and GetDecoded encryption)
  # The client itself doesn't run a daemon, but nodes need its public keys.
  "client-X":
    endpoint: "" # Endpoint not needed as client doesn't listen
    signing_public_key: "clientX_signing_public.json" # For verifying requests FROM the client
    hybrid_public_key: "clientX_hybrid_public.json"   # For encrypting GetDecoded responses FOR the client
    # poll_interval not applicable
```

**6. Run the Daemons**

Ensure the `sssmemvault` binary is built (`make sssmemvault`).

**On Node A:**
*   Copy `config.yaml`.
*   Ensure `nodeA_signing_private.json`, `nodeA_hybrid_private.json`, `master_signing_public.json`, `nodeB_signing_public.json`, `nodeB_hybrid_public.json`, `clientX_signing_public.json`, `clientX_hybrid_public.json` are accessible.
*   Crucially, rename/copy `nodeA_signing_private.json` and `nodeA_hybrid_private.json` to match the paths in `config.yaml` (e.g., `node_signing_private.json`, `node_hybrid_private.json`).

```bash
# Assuming config.yaml uses "node_signing_private.json" and "node_hybrid_private.json"
cp nodeA_signing_private.json node_signing_private.json
cp nodeA_hybrid_private.json node_hybrid_private.json

./sssmemvault daemon --config config.yaml --my-name node-A --loglevel debug
```

**On Node B:**
*   Copy `config.yaml`.
*   Ensure `nodeB_signing_private.json`, `nodeB_hybrid_private.json`, `master_signing_public.json`, `nodeA_signing_public.json`, `nodeA_hybrid_public.json`, `clientX_signing_public.json`, `clientX_hybrid_public.json` are accessible.
*   Rename/copy `nodeB_signing_private.json` and `nodeB_hybrid_private.json` to match the paths in `config.yaml`.

```bash
# Assuming config.yaml uses "node_signing_private.json" and "node_hybrid_private.json"
cp nodeB_signing_private.json node_signing_private.json
cp nodeB_hybrid_private.json node_hybrid_private.json

./sssmemvault daemon --config config.yaml --my-name node-B --loglevel debug
```

The nodes will now start, load their respective signing and hybrid private keys, connect to peers defined in the config (using peer names), listen for requests, and poll peers with `poll_interval`.

**7. Provisioning a Secret (`sssmemvault push`)**

Use the `sssmemvault push` subcommand. This requires the *master signing private key* and the *hybrid public keys* of the owner nodes. Run this from any machine that has access to these keys.

```bash
# Example: Push a secret named "api-key" with value "supersecret123"
# Owned by Node A and Node B.
# Split into 4 fragments, requiring 3 to reconstruct (threshold 3).
# Assign 2 fragments to Node A and 2 fragments to Node B.
# Readable by Node A, Node B, and the client client-X.
# Push the entry to both Node A and Node B using explicit flags:

./sssmemvault push \
  --master-signing-key master_signing_private.json \
  --owner node-A=nodeA_hybrid_public.json:2 \
  --owner node-B=nodeB_hybrid_public.json:2 \
  --reader node-A \
  --reader node-B \
  --reader client-X \
  --key "api-key" \
  --secret "supersecret123" \
  --parts 4 \
  --threshold 3 \
  --target node-a.example.com:59240 \
  --target node-b.example.com:59240 \
  --loglevel info

# Alternatively, push using a config file to source owners and targets:
# (Ensure config.yaml contains the necessary peer info for node-A and node-B,
# specifically their hybrid_public_key)

./sssmemvault push \
  --master-signing-key master_signing_private.json \
  --config config.yaml \
  # Note: When using --config, owners are derived from the 'peers' section.
  # The count defaults to 1 per owner unless explicit --owner flags are also provided
  # to override specific counts or if the derived owners are not sufficient.
  # Example below assumes owners ARE derived from config, but we still need readers:
  --reader node-A \
  --reader node-B \
  --reader client-X \
  --key "another-api-key" \
  --secret "differentSecret987" \
  --parts 2 \ # Must match number of owners derived from config (node-A, node-B)
  --threshold 2 \
  --loglevel info
```

This command will:
1. Load the master signing private key.
2. Parse owner info (`Name=Path:Count`) or derive owners from `--config`. Load hybrid public keys.
3. Validate that the total fragment count (from `--owner` flags or derived count) equals `--parts`.
4. Split the secret into fragments based on `--parts` and `--threshold`.
5. Encrypt fragments and assign them according to specified counts (or round-robin if derived).
6. Create the protobuf `Entry`, storing the encrypted fragments in lists associated with each owner **name** (`OwnerFragments` map). Include reader **names**.
7. Sign the entry using the master signing private key.
8. Connect to the target nodes and call the `Push` RPC.

Nodes receiving the `Push` will verify the master signature (using `master_signing_public.json` from their config) and store the entry. The synchronizer will eventually propagate the entry between nodes if it wasn't pushed to all initially.

**8. Retrieving a Secret (`sssmemvault get`)**

Use the `sssmemvault get` subcommand from an authorized reader machine (e.g., `client-X`). This requires the *client's name* (`--client-name`), its *signing private key* (`--signing-private-key`) for authentication, its *hybrid private key* (`--hybrid-private-key`) for decryption, and optionally a `config.yaml` file to find owner node endpoints.

**On the Client machine (client-X):**
*   Ensure `sssmemvault` binary, `clientX_signing_private.json`, `clientX_hybrid_private.json`, and `config.yaml` are present.
*   The `config.yaml` needs `peers` entries for at least the *owner* nodes (`node-A`, `node-B`) so the `get` command knows their endpoints.

```bash
# Example: Retrieve the "api-key" secret

# Using config file to find owner endpoints and specifying targets to query initially
./sssmemvault get \
  --client-name client-X \
  --signing-private-key clientX_signing_private.json \
  --hybrid-private-key clientX_hybrid_private.json \
  --config config.yaml \
  --key "api-key" \
  --target node-a.example.com:59240 \
  --target node-b.example.com:59240 \
  --output api-key.txt \
  --loglevel info

# If successful, api-key.txt will contain "supersecret123"
cat api-key.txt
```

This command will:
1. Load the client signing private key (`clientX_signing_private.json`).
2. Load the client hybrid private key (`clientX_hybrid_private.json`).
3. Load the config file (`config.yaml`) to find peer endpoints.
4. Connect to the specified target nodes (`--target`) and call `List` (authenticating with `--client-name` and `--signing-private-key`) to find the latest timestamp for `"api-key"`.
5. Call `Get` on the node with the latest timestamp (authenticating again) to retrieve the full entry.
6. Identify the owner **names** from the entry (`node-A`, `node-B`).
7. Look up the endpoints for these owners by **name** in the loaded `config.yaml`.
8. Connect to *each* owner node endpoint.
9. Call `GetDecoded` on each owner node (authenticating with `--client-name` and `--signing-private-key`). Each owner node will:
    a. Verify the client (`client-X`) is in the entry's `readers` list.
    b. Decrypt its fragment(s) using its own *hybrid private key*.
    c. Find the client's *hybrid public key* (`clientX_hybrid_public.json`) using the client's name (`client-X`) in its `peers` config.
    d. Re-encrypt the fragment(s) using the client's *hybrid public key*.
    e. Return the re-encrypted fragment(s).
10. Decrypt each received fragment using the client's *hybrid private key* (`--hybrid-private-key`).
11. Combine the decrypted fragments using Shamir's algorithm (needs enough fragments to meet the threshold).
12. Write the reconstructed secret to `api-key.txt`.
