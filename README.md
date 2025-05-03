# sssmemvault #

Disclaimer: This is pre-alpha code. This disclaimer will probably go
away once all TODOs in the end of the README are done, and first
release happens. This is mostly exercise in AI assisted coding as this
isn't high priority enough for me to spend significant time on, but it
is good testbench for 'let AI code, let me verify' model of work. (And
yes, I need the tool, once it is done.)

## Motivation ##

I have some compute, and I also have lots of storage connected to
it. In general I am not a fan of unencrypted storage, and the typical
problem is - what to do when machine starts? I do not like the idea of
e.g. USB keys as source of encryption credentials, as if machine is
stolen with its key, the data is available to whoever stole
it. Storing the keys on device itself feels weird too, TPM or not
(there is too much stuff there for me to feel it is 'trusted'). So..

### The goals ###

- (sufficient number of) other weakly trusted nodes on same network
  enable use of local encrypted storage on each node

- if node can fetch keys using help of its peers, it is 'fine'

- the encryption storage keys are only stored in memory

=> If whole cluster suffers power outage, manual intervention is
needed. (but this is probably rare, as opposed to maintenance or
single node replacement)

### Non-goals ###

Prevent sophisticated attacker with physical access from getting to
the data. There are plenty of attacks that are relatively hard to
protect against, but I feel them to be unlikely for me
personally. Those can happen any time, by e.g.

1. starting headless machine as root from external storage (if
   allowed) or mounting their local storage in different device (hard
   to protect against),

2. doing bad things to root filesystem, and

3. enjoying once the machine is started by me after perceived outage.

Prevent sophisticated attacker with root access to the node from
getting data. If this happens, you can anyway get encryption keys from
memory so this is not something worth protecting against.

## So, what is sssmemvault? ##

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

- Each node/client has a unique **name** (string) and a corresponding combined keyset (private and public).
- The private keyset contains both a *signing* private key and a *hybrid* private key.
- The public keyset contains both a *signing* public key and a *hybrid* public key.
- Each node has all other nodes' (and relevant clients') public keysets (`public_key_path`) and their names mapped in its configuration file (`peers` section).
- Authenticated GRPC requests (List, Get, GetDecoded) must contain headers with:
    - The requesting node/client's **name** (`x-request-node-name`).
    - A recent timestamp (`x-request-timestamp`).
    - A signature over the timestamp, created using the requestor's *signing* private key (extracted from their combined private keyset) (`x-request-signature`).
- The receiving node verifies the signature using the *signing* public key (extracted from the public keyset associated with the provided name in its configuration).


## Configuration file (for each node) ##

- path to their combined *private* keyset file (`private_key_path`) containing both signing and hybrid private keys.
- path to the *master signing* public key file (`master_public_key_path`) - this remains a signing-only key.
- listen address (`listen_address`)
- max timestamp skew (`max_timestamp_skew`)
- map of peer nodes (`peers`), where the key is the peer's unique **name** (string) and the value contains:
  - `endpoint`: GRPC endpoint (host:port)
  - `public_key_path`: Path to the peer's combined *public* keyset file (containing signing and hybrid public keys). Used for verifying their requests and encrypting data *for* them.
  - `poll_interval` (optional): Go duration string (e.g., `60s`), indicating this peer should be polled for updates.
  - `fragments_per_owner` (optional, integer): Number of SSS fragments this peer should own for secrets it's an owner of. Defaults to `1` if omitted or <= 0.

## Requests ##

- List request: results in list of timestamp+key pairs the remote node has

- Get (timestamp,key) request: Returns the whole signed entry

- Get decoded (timestamp, key) request: Returns the decrypted
  owner-specific SSS fragment(s), re-encrypted using the requesting
  node's *hybrid public key* (extracted from their public keyset), if the requesting node **name** is in the
  entry's `readers` list.

## Implementation ##

Modern Go, using Google's Tink library to get algorithm agility.

## Building ##

```bash
make sssmemvault
```

This creates the `sssmemvault` binary.

## Commands ##

The `sssmemvault` tool has four subcommands:

*   `genkeys`: Generates combined private and public keyset files for a node or client.
*   `daemon`: Runs the sssmemvault daemon node.
    *   `--detach` / `-d`: Runs the daemon in the background. Requires `--pidfile` and `--logfile`.
    *   `--pidfile`: Path to the PID file (used with `--detach`). Default: `/var/run/sssmemvaultd.pid`. Can be set via `SSSMEMVAULT_PIDFILE` env var.
    *   `--logfile`: Path to the log file (used with `--detach`). Default: `/var/log/sssmemvaultd.log`. Can be set via `SSSMEMVAULT_LOGFILE` env var.
    *   `--config-check-interval`: How often to check the config file for changes (e.g., `60s`, `5m`). If changes are detected (based on modification time and content hash), the daemon gracefully restarts its services with the new configuration. Set to `0s` to disable automatic checking. Default: `1m`. Reload can also be triggered manually by sending `SIGHUP` to the daemon process.
*   `push`: Creates and pushes a new secret entry to nodes (owners and fragment distribution derived from config).
*   `get`: Retrieves and reconstructs a secret from nodes.

Use `sssmemvault <command> --help` for details on each subcommand's flags.

## Example Setup ##

This example demonstrates setting up two nodes (`node-A`, `node-B`) and a client (`client-X`) and using the commands.

We will use the `sssmemvault genkeys` command to generate the necessary combined keysets. Node endpoints are assumed to be `node-a.example.com:59240` and `node-b.example.com:59240`.

**1. Generate Master Key Pair (Signing Only)**

Only the master *signing* public key is needed by the nodes. Keep the master *signing* private key secure and offline (used only by `sssmemvault push`). We'll use Tink's `tinkey` tool for this specific key as `sssmemvault genkeys` creates combined keys. We'll use ED25519.

```bash
# Generate master signing private key
tinkey create-keyset --key-template ED25519 --out master_private.json
# Extract master signing public key
tinkey create-public-keyset --in master_private.json --out master_public.json
```

**2. Generate Node A Combined Keyset**

Use the new `sssmemvault genkeys` command.

```bash
./sssmemvault genkeys \
  --private-out nodeA_private.json \
  --public-out nodeA_public.json
```

**3. Generate Node B Combined Keyset**

```bash
./sssmemvault genkeys \
  --private-out nodeB_private.json \
  --public-out nodeB_public.json
```

**4. Generate Client Combined Keyset**

```bash
./sssmemvault genkeys \
  --private-out clientX_private.json \
  --public-out clientX_public.json
```

**5. Create Configuration File (`config.yaml`)**

This file is used by the `daemon` command and is **required** by `push` and `get`. Place the generated keysets where the nodes/clients can access them.

```yaml
# config.yaml

# --- Daemon Settings ---
# Path to the node's combined private keyset file (signing + hybrid).
private_key_path: "node_private.json" # Node A uses nodeA_private.json, Node B uses nodeB_private.json
# Path to the master public key file (signing only, used to verify pushed entry signatures).
master_public_key_path: "master_public.json"
# Address and port the daemon listens on.
listen_address: ":59240"
# Maximum allowed time difference for authenticated requests.
max_timestamp_skew: 30s

# --- Peer Information ---
# Map of peer **names** (arbitrary strings) to their configuration.
# The daemon uses this to know about other nodes for synchronization and auth verification.
# Client commands ('push', 'get') use this to find targets/owners and their public keys.
peers:
  # Configuration for Node A (used by Node B daemon, and by clients)
  "node-A":
    endpoint: "node-a.example.com:59240" # Or IP:port "192.168.42.2:59240"
    public_key_path: "nodeA_public.json" # Path to Node A's combined public keyset
    # poll_interval: "60s" # Optional: Poll Node A every 60 seconds

  # Configuration for Node B (used by Node A daemon, and by clients)
  "node-B":
    endpoint: "node-b.example.com:59240" # Or IP:port "192.168.42.34:59240"
    public_key_path: "nodeB_public.json" # Path to Node B's combined public keyset
    poll_interval: "60s" # Poll Node B every 60 seconds
    # fragments_per_owner: 1 # Explicitly setting the default

  # Configuration for the Client (used by Node A & B daemons for auth verification and GetDecoded encryption)
  # The client itself doesn't run a daemon, but nodes need its public keyset info.
  # fragments_per_owner is not relevant here as clients don't own fragments.
  "client-X":
    endpoint: "" # Endpoint not needed as client doesn't listen
    public_key_path: "clientX_public.json" # Path to Client X's combined public keyset
    # poll_interval not applicable
```

**6. Run the Daemons**

Ensure the `sssmemvault` binary is built (`make sssmemvault`).

**On Node A:**
*   Copy `config.yaml`.
*   Ensure `nodeA_private.json`, `master_public.json`, `nodeB_public.json`, `clientX_public.json` are accessible.
*   Crucially, rename/copy `nodeA_private.json` to match the `private_key_path` in `config.yaml` (e.g., `node_private.json`).

```bash
# Assuming config.yaml uses "node_private.json"
cp nodeA_private.json node_private.json

./sssmemvault daemon --config config.yaml --my-name node-A --loglevel debug
```

**On Node B:**
*   Copy `config.yaml`.
*   Ensure `nodeB_private.json`, `master_public.json`, `nodeA_public.json`, `clientX_public.json` are accessible.
*   Rename/copy `nodeB_private.json` to match the `private_key_path` in `config.yaml`.

```bash
# Assuming config.yaml uses "node_private.json"
cp nodeB_private.json node_private.json

./sssmemvault daemon --config config.yaml --my-name node-B --loglevel debug
```

The nodes will now start, load their respective combined private keysets, connect to peers defined in the config, listen for requests, poll peers with `poll_interval`, and automatically reload their configuration if the `config.yaml` file is modified (unless `--config-check-interval=0s` is used). You can also trigger a reload manually by sending a `SIGHUP` signal (e.g., `kill -HUP <pid>`).

To run in the background (detached mode):

```bash
# Example for Node A
./sssmemvault daemon \
  --config config.yaml \
  --my-name node-A \
  --detach \
  --pidfile /var/run/sssmemvaultd-nodeA.pid \
  --logfile /var/log/sssmemvaultd-nodeA.log \
  --loglevel info
```

**7. Provisioning a Secret (`sssmemvault push`)**

Use the `sssmemvault push` subcommand. This requires the *master signing private key* and a `--config` file. Owners are derived from the peers listed in the config file. Run this from any machine that has access to the master private key and the config file.

```bash
# Example: Push a secret named "api-key" with value "supersecret123"
# Owned by Node A and Node B (derived from config).
# Total fragments = fragments_per_owner[node-A] + fragments_per_owner[node-B] (default 1+1=2).
# Threshold = 2 (requires both fragments).
# Readable by Node A, Node B, and the client client-X.
# Targets are derived from config unless specified with --target.

./sssmemvault push \
  --master-private-key master_private.json \
  --config config.yaml \
  --reader node-A \
  --reader node-B \
  --reader client-X \
  --key "api-key" \
  --secret "supersecret123" \
  --threshold 2 \
  --loglevel info
```

This command will:
1. Load the master signing private key.
2. Load the config file.
3. Identify owner peers (nodes with public keys and endpoints listed in `peers`).
4. Calculate the total number of fragments needed by summing `fragments_per_owner` for each owner peer (defaulting to 1 if not specified).
5. Validate that `--threshold` is not greater than the total number of fragments.
6. Split the secret into the calculated total number of fragments using the specified `--threshold`.
7. Distribute and encrypt the fragments: assign `fragments_per_owner` fragments to each owner, encrypting them using the owner's *hybrid public key* (from their `public_key_path` in the config).
8. Create the protobuf `Entry`, storing the encrypted fragments associated with each owner **name**. Include reader **names**.
8. Sign the entry using the master signing private key.
9. Connect to the target nodes (derived from config or specified via `--target`) and call the `Push` RPC.

Nodes receiving the `Push` will verify the master signature (using `master_public_key_path` from their config) and store the entry.

**8. Retrieving a Secret (`sssmemvault get`)**

Use the `sssmemvault get` subcommand from an authorized reader machine (e.g., `client-X`). This requires the *client's name* (`--client-name`), its combined *private keyset* (`--private-key`), and a `--config` file.

**On the Client machine (client-X):**
*   Ensure `sssmemvault` binary, `clientX_private.json`, and `config.yaml` are present.
*   The `config.yaml` needs `peers` entries for at least the *owner* nodes (`node-A`, `node-B`) so the `get` command knows their endpoints and the nodes know the client's public key.

```bash
# Example: Retrieve the "api-key" secret and print it to standard output

./sssmemvault get \
  --client-name client-X \
  --private-key clientX_private.json \
  --config config.yaml \
  --key "api-key"

# To save the output to a file:
# ./sssmemvault get ... > api-key.txt
```

This command will:
1. Load the client's combined private keyset (`--private-key`) for authentication and decryption.
2. Load the configuration (`--config`) to find the endpoints of the owner nodes.
3. Contact the necessary owner nodes (derived from the config) to retrieve the latest version of the secret entry for the given key (`--key`).
4. Request the encrypted fragments from the owner nodes, authenticating as the client (`--client-name`).
5. Decrypt the received fragments using the client's private key.
6. Combine the decrypted fragments to reconstruct the original secret.
7. Print the reconstructed secret to standard output.

# TODO #

- Make first release once all known TODOs are done

- Make sure this actually works for real (in my homelab)
