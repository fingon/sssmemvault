package main_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/fingon/sssmemvault/internal/config"
	// Register Tink primitives
	_ "github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/hybrid"
	_ "github.com/tink-crypto/tink-go/v2/hybrid"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto" // Updated proto path
	"github.com/tink-crypto/tink-go/v2/signature"
	_ "github.com/tink-crypto/tink-go/v2/signature"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/icmd"
)

const (
	testSecretKey = "integration-test-key"
	testSecretVal = "super-secret-value-shhh"
	node1Name     = "test-node-1"
	node2Name     = "test-node-2"
	clientName    = "test-client-1"
	nodeIP        = "127.0.0.1"
	node1Port     = "59251" // Use distinct ports
	node2Port     = "59252"
	pollInterval  = "5s" // Faster polling for test
)

var (
	node1Endpoint = net.JoinHostPort(nodeIP, node1Port)
	node2Endpoint = net.JoinHostPort(nodeIP, node2Port)
)

// peerKeyPaths holds the public key paths needed for peer configuration.
type peerKeyPaths struct {
	SigningPublic string
	HybridPublic  string
}

// generateTinkKeyset generates a Tink keyset for a *single* key template.
func generateSingleTinkKeyset(t *testing.T, dir, name string, keyTemplate *tinkpb.KeyTemplate) (privPath, pubPath string) {
	t.Helper()

	privPath = filepath.Join(dir, name+"_private.json")
	pubPath = filepath.Join(dir, name+"_public.json")

	// Create a new keyset handle with the specified template
	handle, err := keyset.NewHandle(keyTemplate)
	assert.NilError(t, err, "Failed to create new keyset handle for %s", name)

	// Write private keyset
	privBuf := new(bytes.Buffer)
	writer := keyset.NewJSONWriter(privBuf)
	err = insecurecleartextkeyset.Write(handle, writer)
	assert.NilError(t, err, "Failed to write private keyset for %s", name)
	err = os.WriteFile(privPath, privBuf.Bytes(), 0o600)
	assert.NilError(t, err, "Failed to save private keyset file for %s", name)

	// Get and write public keyset
	pubHandle, err := handle.Public()
	assert.NilError(t, err, "Failed to get public keyset handle for %s", name)
	pubBuf := new(bytes.Buffer)
	pubWriter := keyset.NewJSONWriter(pubBuf)
	err = insecurecleartextkeyset.Write(pubHandle, pubWriter)
	assert.NilError(t, err, "Failed to write public keyset for %s", name)
	err = os.WriteFile(pubPath, pubBuf.Bytes(), 0o600)
	assert.NilError(t, err, "Failed to save public keyset file for %s", name)

	return privPath, pubPath
}

// createNodeConfig creates a YAML config file for a daemon node.
func createNodeConfig(t *testing.T, dir, name, myPort, mySigningPrivKeyPath, myHybridPrivKeyPath, masterSigningPubKeyPath string, peers map[string]peerKeyPaths) string {
	t.Helper()
	cfgPath := filepath.Join(dir, name+"_config.yaml")
	listenAddr := net.JoinHostPort("", myPort) // Listen on all interfaces for the given port

	peerConfigs := make(map[string]config.PeerConfig) // Map key is now peer name
	pollDuration := time.Second * 5                   // Convert string to duration for config struct
	for peerName, keys := range peers {
		// Determine endpoint based on Name - assumes test setup uses specific ports/endpoints
		var endpoint string
		switch peerName {
		case node1Name:
			endpoint = node1Endpoint
		case node2Name:
			endpoint = node2Endpoint
		case clientName:
			endpoint = "" // Client doesn't listen
		default:
			t.Fatalf("Unknown peer name in test setup: %s", peerName)
		}

		// Add all peers (nodes and client) to the config
		peerCfg := config.PeerConfig{
			SigningPublicKey: keys.SigningPublic, // Use absolute path
			HybridPublicKey:  keys.HybridPublic,  // Use absolute path
		}

		// Set endpoint and poll interval only for actual peer nodes, not the client
		if endpoint != "" && peerName != clientName { // Check it's not the client
			peerCfg.Endpoint = endpoint
			peerCfg.PollInterval = &pollDuration
		} else {
			// Client entry or self-entry might not have endpoint/poll interval
			peerCfg.Endpoint = endpoint // Can be empty for client
			peerCfg.PollInterval = nil
		}
		peerConfigs[peerName] = peerCfg
	}

	nodeCfg := config.Config{
		SigningPrivateKeyPath:  mySigningPrivKeyPath,    // Use absolute path
		HybridPrivateKeyPath:   myHybridPrivKeyPath,     // Use absolute path
		MasterSigningPublicKey: masterSigningPubKeyPath, // Use absolute path
		ListenAddress:          listenAddr,
		MaxTimestampSkew:       30 * time.Second,
		Peers:                  peerConfigs,
	}

	yamlData, err := yaml.Marshal(nodeCfg)
	assert.NilError(t, err, "Failed to marshal config for %s", name)

	err = os.WriteFile(cfgPath, yamlData, 0o600)
	assert.NilError(t, err, "Failed to write config file for %s", name)

	return cfgPath
}

// waitForDaemon checks if a gRPC server is listening on the given endpoint.
func waitForDaemon(t *testing.T, endpoint string, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.Fatalf("Timeout waiting for daemon at %s: %v", endpoint, ctx.Err())
		case <-ticker.C:
			// Use a short timeout for each dial attempt directly with grpc.NewClient
			dialCtx, dialCancel := context.WithTimeout(ctx, 500*time.Millisecond)
			conn, err := grpc.NewClient(endpoint,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithBlock(), // Try to connect synchronously
				grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
					// Ensure the dialer respects the context deadline
					var d net.Dialer
					if deadline, ok := dialCtx.Deadline(); ok {
						d.Timeout = time.Until(deadline)
					} else {
						// Should not happen in this test as dialCtx has a timeout, but handle defensively
						d.Timeout = 500 * time.Millisecond
					}
					return d.DialContext(ctx, "tcp", addr)
				}),
			)
			dialCancel() // Release context resources for this attempt

			if err == nil {
				_ = conn.Close() // Close the connection immediately if successful
				t.Logf("Daemon detected at %s", endpoint)
				return // Success
			}
			t.Logf("Waiting for daemon at %s (dial error: %v)", endpoint, err)
		}
	}
}

func TestPushAndGetIntegration(t *testing.T) {
	// Use long test flag if needed: if testing.Short() { t.Skip("Skipping integration test in short mode") }
	tmpDir := t.TempDir()
	absTmpDir, err := filepath.Abs(tmpDir) // Get absolute path
	assert.NilError(t, err)

	// --- Generate Keys (Separate Signing and Hybrid) ---
	// Master key (signing only)
	masterSigningPriv, masterSigningPub := generateSingleTinkKeyset(t, absTmpDir, "master_signing", signature.ED25519KeyTemplate())

	// Node 1 keys
	node1SigningPriv, node1SigningPub := generateSingleTinkKeyset(t, absTmpDir, "node1_signing", signature.ECDSAP256KeyTemplate())
	node1HybridPriv, node1HybridPub := generateSingleTinkKeyset(t, absTmpDir, node1Name+"_hybrid", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Key_Template())

	// Node 2 keys
	node2SigningPriv, node2SigningPub := generateSingleTinkKeyset(t, absTmpDir, node2Name+"_signing", signature.ECDSAP256KeyTemplate())
	node2HybridPriv, node2HybridPub := generateSingleTinkKeyset(t, absTmpDir, node2Name+"_hybrid", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Key_Template())

	// Client keys
	clientSigningPriv, clientSigningPub := generateSingleTinkKeyset(t, absTmpDir, clientName+"_signing", signature.ECDSAP256KeyTemplate())
	clientHybridPriv, clientHybridPub := generateSingleTinkKeyset(t, absTmpDir, clientName+"_hybrid", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Key_Template())

	// --- Create Config Files ---
	// Define peer public key info needed by each node/client config
	node1PeerKeys := peerKeyPaths{SigningPublic: node1SigningPub, HybridPublic: node1HybridPub}
	node2PeerKeys := peerKeyPaths{SigningPublic: node2SigningPub, HybridPublic: node2HybridPub}
	clientPeerKeys := peerKeyPaths{SigningPublic: clientSigningPub, HybridPublic: clientHybridPub}

	// Define all known peers for config generation (using names as keys)
	allPeers := map[string]peerKeyPaths{
		node1Name:  node1PeerKeys,
		node2Name:  node2PeerKeys,
		clientName: clientPeerKeys,
	}

	// Peers needed for Node 1's config (all peers)
	peersForNode1Config := allPeers
	// Peers needed for Node 2's config (all peers)
	peersForNode2Config := allPeers
	// Peers needed for Client's config (only needs actual nodes for endpoint lookup)
	peersForClientConfig := map[string]peerKeyPaths{
		node1Name: node1PeerKeys,
		node2Name: node2PeerKeys,
		// Client doesn't need its own entry in its config for lookups
	}

	// Create config files using the new function signature
	node1CfgPath := createNodeConfig(t, absTmpDir, node1Name, node1Port, node1SigningPriv, node1HybridPriv, masterSigningPub, peersForNode1Config)
	node2CfgPath := createNodeConfig(t, absTmpDir, node2Name, node2Port, node2SigningPriv, node2HybridPriv, masterSigningPub, peersForNode2Config)
	// Client config doesn't need its own private keys specified, only master public and peer info
	clientCfgPath := createNodeConfig(t, absTmpDir, clientName, "", "", "", masterSigningPub, peersForClientConfig)

	// --- Start Daemons ---

	// Start Node 1
	cmdNode1 := icmd.Command("go", "run", ".", "daemon",
		"--config", node1CfgPath,
		"--my-name", node1Name, // Use --my-name
		"--loglevel", "debug", // Use debug for more test output
	)
	resNode1 := icmd.StartCmd(cmdNode1)
	t.Logf("Started Node 1 (PID %d)", resNode1.Cmd.Process.Pid)
	t.Cleanup(func() {
		t.Log("Cleaning up Node 1...")
		err := resNode1.Cmd.Process.Signal(syscall.SIGTERM) // Send SIGTERM for graceful shutdown
		assert.NilError(t, err, "Failed to send SIGTERM to Node 1")
		// Wait for process to exit, check status
		state, waitErr := resNode1.Cmd.Process.Wait()
		assert.NilError(t, waitErr, "Error waiting for Node 1 to exit")
		t.Logf("Node 1 exited: %s", state)
		if !state.Success() {
			t.Logf("Node 1 stderr:\n%s", resNode1.Stderr())
			t.Logf("Node 1 stdout:\n%s", resNode1.Stdout())
		}
		// assert.Assert(t, state.Success(), "Node 1 did not exit successfully") // Allow non-zero exit on SIGTERM
	})

	// Start Node 2
	cmdNode2 := icmd.Command("go", "run", ".", "daemon",
		"--config", node2CfgPath,
		"--my-name", node2Name, // Use --my-name
		"--loglevel", "debug",
	)
	resNode2 := icmd.StartCmd(cmdNode2)
	t.Logf("Started Node 2 (PID %d)", resNode2.Cmd.Process.Pid)
	t.Cleanup(func() {
		t.Log("Cleaning up Node 2...")
		err := resNode2.Cmd.Process.Signal(syscall.SIGTERM)
		assert.NilError(t, err, "Failed to send SIGTERM to Node 2")
		state, waitErr := resNode2.Cmd.Process.Wait()
		assert.NilError(t, waitErr, "Error waiting for Node 2 to exit")
		t.Logf("Node 2 exited: %s", state)
		if !state.Success() {
			t.Logf("Node 2 stderr:\n%s", resNode2.Stderr())
			t.Logf("Node 2 stdout:\n%s", resNode2.Stdout())
		}
		// assert.Assert(t, state.Success(), "Node 2 did not exit successfully")
	})

	// --- Wait for Daemons to be Ready ---
	t.Log("Waiting for daemons to start...")
	waitForDaemon(t, node1Endpoint, 30*time.Second)
	waitForDaemon(t, node2Endpoint, 30*time.Second)
	// Add a small delay for synchronizers to potentially connect/start polling
	time.Sleep(2 * time.Second)
	t.Log("Daemons appear ready.")

	// --- Push Secret ---
	t.Log("Pushing secret...")
	// The push command needs the master *signing* private key and the owners' *hybrid* public keys.
	pushCmd := icmd.Command("go", "run", ".", "push",
		"--master-signing-key", masterSigningPriv,
		"--owner", fmt.Sprintf("%s=%s:%d", node1Name, node1HybridPub, 2), // Assign 2 fragments to Node 1
		"--owner", fmt.Sprintf("%s=%s:%d", node2Name, node2HybridPub, 2), // Assign 2 fragments to Node 2
		"--reader", node1Name, // Allow nodes themselves to read for testing simplicity
		"--reader", node2Name,
		"--reader", clientName, // Allow client to read
		"--key", testSecretKey,
		"--secret", testSecretVal,
		"--parts", "4", // Use 4 parts
		"--threshold", "3", // Require 3 parts to reconstruct
		"--target", node1Endpoint, // Push to both nodes
		"--target", node2Endpoint,
		"--loglevel", "info",
	)
	pushResult := icmd.RunCmd(pushCmd)
	pushResult.Assert(t, icmd.Success)
	t.Log("Push command successful.")

	// Allow time for potential synchronization if push only went to one node initially
	time.Sleep(time.Duration(6) * time.Second) // Wait longer than poll interval

	// --- Get Secret ---
	// The get command needs the client's name, signing private key, and hybrid private key.
	t.Log("Getting secret...")
	outputFilePath := filepath.Join(absTmpDir, "retrieved_secret.txt")
	getCmd := icmd.Command("go", "run", ".", "get",
		"--client-name", clientName, // Provide client name
		"--signing-private-key", clientSigningPriv,
		"--hybrid-private-key", clientHybridPriv,
		"--config", clientCfgPath, // Use client config to find owner endpoints by name
		"--key", testSecretKey,
		"--target", node1Endpoint, // Can target either node to start the process
		"--output", outputFilePath,
		"--loglevel", "info",
	)
	getResult := icmd.RunCmd(getCmd)
	getResult.Assert(t, icmd.Success)
	t.Log("Get command successful.")

	// --- Verify Secret ---
	retrievedBytes, err := os.ReadFile(outputFilePath)
	assert.NilError(t, err, "Failed to read output file")
	assert.Equal(t, string(retrievedBytes), testSecretVal, "Retrieved secret does not match original")
	t.Log("Secret verification successful.")

	// Cleanup is handled by t.Cleanup calls registered earlier
	t.Log("Integration test finished.")
}
