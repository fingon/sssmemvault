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

// --- Test Helper Functions ---

// testKeyPaths holds paths to generated keys for a single entity (node/client/master).
type testKeyPaths struct {
	SigningPrivate string
	SigningPublic  string
	HybridPrivate  string
	HybridPublic   string
}

// generateTestKeys generates all necessary keys for the integration test.
func generateTestKeys(t *testing.T, dir string) (masterKeys, node1Keys, node2Keys, clientKeys testKeyPaths) {
	t.Helper()
	// Master key (signing only)
	masterKeys.SigningPrivate, masterKeys.SigningPublic = generateSingleTinkKeyset(t, dir, "master_signing", signature.ED25519KeyTemplate())

	// Node 1 keys
	node1Keys.SigningPrivate, node1Keys.SigningPublic = generateSingleTinkKeyset(t, dir, node1Name+"_signing", signature.ECDSAP256KeyTemplate())
	node1Keys.HybridPrivate, node1Keys.HybridPublic = generateSingleTinkKeyset(t, dir, node1Name+"_hybrid", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Key_Template())

	// Node 2 keys
	node2Keys.SigningPrivate, node2Keys.SigningPublic = generateSingleTinkKeyset(t, dir, node2Name+"_signing", signature.ECDSAP256KeyTemplate())
	node2Keys.HybridPrivate, node2Keys.HybridPublic = generateSingleTinkKeyset(t, dir, node2Name+"_hybrid", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Key_Template())

	// Client keys
	clientKeys.SigningPrivate, clientKeys.SigningPublic = generateSingleTinkKeyset(t, dir, clientName+"_signing", signature.ECDSAP256KeyTemplate())
	clientKeys.HybridPrivate, clientKeys.HybridPublic = generateSingleTinkKeyset(t, dir, clientName+"_hybrid", hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Key_Template())

	return masterKeys, node1Keys, node2Keys, clientKeys
}

// createTestConfigs creates the necessary config files for nodes and the client.
func createTestConfigs(t *testing.T, dir string, masterKeys, node1Keys, node2Keys, clientKeys testKeyPaths) (node1CfgPath, node2CfgPath, clientCfgPath string) {
	t.Helper()
	// Define peer public key info needed by each node/client config
	node1PeerKeys := peerKeyPaths{SigningPublic: node1Keys.SigningPublic, HybridPublic: node1Keys.HybridPublic}
	node2PeerKeys := peerKeyPaths{SigningPublic: node2Keys.SigningPublic, HybridPublic: node2Keys.HybridPublic}
	clientPeerKeys := peerKeyPaths{SigningPublic: clientKeys.SigningPublic, HybridPublic: clientKeys.HybridPublic}

	// Define all known peers for config generation (using names as keys)
	allPeers := map[string]peerKeyPaths{
		node1Name:  node1PeerKeys,
		node2Name:  node2PeerKeys,
		clientName: clientPeerKeys,
	}

	// Peers needed for Client's config (only needs actual nodes for endpoint lookup)
	peersForClientConfig := map[string]peerKeyPaths{
		node1Name: node1PeerKeys,
		node2Name: node2PeerKeys,
	}

	// Create config files
	node1CfgPath = createNodeConfig(t, dir, node1Name, node1Port, node1Keys.SigningPrivate, node1Keys.HybridPrivate, masterKeys.SigningPublic, allPeers)
	node2CfgPath = createNodeConfig(t, dir, node2Name, node2Port, node2Keys.SigningPrivate, node2Keys.HybridPrivate, masterKeys.SigningPublic, allPeers)
	clientCfgPath = createNodeConfig(t, dir, clientName, "", "", "", masterKeys.SigningPublic, peersForClientConfig) // Client config doesn't need its own private keys

	return node1CfgPath, node2CfgPath, clientCfgPath
}

// startTestDaemon starts a daemon process in the background.
func startTestDaemon(t *testing.T, cfgPath, nodeName string) *icmd.Result {
	t.Helper()
	cmd := icmd.Command("go", "run", ".", "daemon",
		"--config", cfgPath,
		"--my-name", nodeName,
		"--loglevel", "debug",
	)
	res := icmd.StartCmd(cmd)
	t.Logf("Started %s (PID %d)", nodeName, res.Cmd.Process.Pid)
	return res
}

// stopTestDaemon stops a daemon process gracefully.
func stopTestDaemon(t *testing.T, nodeName string, res *icmd.Result) {
	t.Helper()
	t.Logf("Cleaning up %s...", nodeName)
	err := res.Cmd.Process.Signal(syscall.SIGTERM) // Send SIGTERM for graceful shutdown
	assert.NilError(t, err, "Failed to send SIGTERM to %s", nodeName)
	// Wait for process to exit, check status
	state, waitErr := res.Cmd.Process.Wait()
	assert.NilError(t, waitErr, "Error waiting for %s to exit", nodeName)
	t.Logf("%s exited: %s", nodeName, state)
	if !state.Success() {
		t.Logf("%s stderr:\n%s", nodeName, res.Stderr())
		t.Logf("%s stdout:\n%s", nodeName, res.Stdout())
	}
	// assert.Assert(t, state.Success(), "%s did not exit successfully", nodeName) // Allow non-zero exit on SIGTERM
}

// runPushCommand executes the push command.
func runPushCommand(t *testing.T, masterSigningPriv, node1HybridPub, node2HybridPub string) {
	t.Helper()
	t.Log("Pushing secret...")
	pushCmd := icmd.Command("go", "run", ".", "push",
		"--master-signing-key", masterSigningPriv,
		"--owner", fmt.Sprintf("%s=%s:%d", node1Name, node1HybridPub, 2),
		"--owner", fmt.Sprintf("%s=%s:%d", node2Name, node2HybridPub, 2),
		"--reader", node1Name,
		"--reader", node2Name,
		"--reader", clientName,
		"--key", testSecretKey,
		"--secret", testSecretVal,
		"--parts", "4",
		"--threshold", "3",
		"--target", node1Endpoint,
		"--target", node2Endpoint,
		"--loglevel", "info",
	)
	pushResult := icmd.RunCmd(pushCmd)
	pushResult.Assert(t, icmd.Success)
	t.Log("Push command successful.")
}

// runGetCommand executes the get command.
func runGetCommand(t *testing.T, clientSigningPriv, clientHybridPriv, clientCfgPath, outputFilePath string) {
	t.Helper()
	t.Log("Getting secret...")
	getCmd := icmd.Command("go", "run", ".", "get",
		"--client-name", clientName,
		"--signing-private-key", clientSigningPriv,
		"--hybrid-private-key", clientHybridPriv,
		"--config", clientCfgPath,
		"--key", testSecretKey,
		"--target", node1Endpoint, // Target one node to start
		"--output", outputFilePath,
		"--loglevel", "info",
	)
	getResult := icmd.RunCmd(getCmd)
	getResult.Assert(t, icmd.Success)
	t.Log("Get command successful.")
}

// --- Main Test Function ---

func TestPushAndGetIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	absTmpDir, err := filepath.Abs(tmpDir)
	assert.NilError(t, err)

	// --- Setup: Generate Keys and Configs ---
	masterKeys, node1Keys, node2Keys, clientKeys := generateTestKeys(t, absTmpDir)
	node1CfgPath, node2CfgPath, clientCfgPath := createTestConfigs(t, absTmpDir, masterKeys, node1Keys, node2Keys, clientKeys)

	// --- Start Daemons ---
	resNode1 := startTestDaemon(t, node1CfgPath, node1Name)
	t.Cleanup(func() { stopTestDaemon(t, node1Name, resNode1) })

	resNode2 := startTestDaemon(t, node2CfgPath, node2Name)
	t.Cleanup(func() { stopTestDaemon(t, node2Name, resNode2) })

	// --- Wait for Daemons ---
	t.Log("Waiting for daemons to start...")
	waitForDaemon(t, node1Endpoint, 30*time.Second)
	waitForDaemon(t, node2Endpoint, 30*time.Second)
	time.Sleep(2 * time.Second) // Allow time for initial sync/connection attempts
	t.Log("Daemons appear ready.")

	// --- Execute Push ---
	runPushCommand(t, masterKeys.SigningPrivate, node1Keys.HybridPublic, node2Keys.HybridPublic)

	// Allow time for potential synchronization
	time.Sleep(time.Duration(6) * time.Second) // Wait longer than poll interval

	// --- Execute Get ---
	outputFilePath := filepath.Join(absTmpDir, "retrieved_secret.txt")
	runGetCommand(t, clientKeys.SigningPrivate, clientKeys.HybridPrivate, clientCfgPath, outputFilePath)

	// --- Verify Secret ---
	retrievedBytes, err := os.ReadFile(outputFilePath)
	assert.NilError(t, err, "Failed to read output file")
	assert.Equal(t, string(retrievedBytes), testSecretVal, "Retrieved secret does not match original")
	t.Log("Secret verification successful.")

	// Cleanup is handled by t.Cleanup calls
	t.Log("Integration test finished.")
}
