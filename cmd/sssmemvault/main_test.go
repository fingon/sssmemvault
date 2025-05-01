package main_test

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
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
	pollInterval  = 2 * time.Second // Faster polling for test
)

var (
	node1Endpoint = net.JoinHostPort(nodeIP, node1Port)
	node2Endpoint = net.JoinHostPort(nodeIP, node2Port)
)

// peerInfo holds paths needed for peer configuration.
type peerInfo struct {
	PublicKeyPath string // Combined public keyset (signing + hybrid)
}

// generateCombinedKeyset generates combined private and public keyset files.
// This simulates the `genkeys` command for testing purposes.
func generateCombinedKeyset(t *testing.T, dir, name string) (privPath, pubPath string) {
	t.Helper()

	privPath = filepath.Join(dir, name+"_private.json")
	pubPath = filepath.Join(dir, name+"_public.json")

	// Use KeysetManager to build the combined keyset
	manager := keyset.NewManager()

	// Add signing key
	signingTemplate := signature.ECDSAP256KeyTemplate()
	signingKeyID, err := manager.Add(signingTemplate) // Add returns keyID, err
	assert.NilError(t, err, "Failed to add signing key template to manager for %s", name)
	err = manager.SetPrimary(signingKeyID) // Set signing key as primary
	assert.NilError(t, err, "Failed to set signing key as primary for %s", name)

	// Add hybrid key
	hybridTemplate := hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Key_Template()
	_, err = manager.Add(hybridTemplate) // Add returns keyID, err - we don't need the ID here
	assert.NilError(t, err, "Failed to add hybrid key template to manager for %s", name)

	// Get the final combined handle (signing key remains primary)
	privateHandle, err := manager.Handle()
	assert.NilError(t, err, "Failed to get final combined handle for %s", name)

	// Write private keyset
	privBuf := new(bytes.Buffer)
	privWriter := keyset.NewJSONWriter(privBuf)
	err = insecurecleartextkeyset.Write(privateHandle, privWriter)
	assert.NilError(t, err, "Failed to write private keyset for %s", name)
	err = os.WriteFile(privPath, privBuf.Bytes(), 0o600)
	assert.NilError(t, err, "Failed to save private keyset file for %s", name)

	// Get and write public keyset
	publicHandle, err := privateHandle.Public()
	assert.NilError(t, err, "Failed to get public keyset handle for %s", name)
	pubBuf := new(bytes.Buffer)
	pubWriter := keyset.NewJSONWriter(pubBuf)
	err = insecurecleartextkeyset.Write(publicHandle, pubWriter)
	assert.NilError(t, err, "Failed to write public keyset for %s", name)
	err = os.WriteFile(pubPath, pubBuf.Bytes(), 0o600)
	assert.NilError(t, err, "Failed to save public keyset file for %s", name)

	return privPath, pubPath
}

// generateMasterKeys generates the master signing key pair (signing only).
func generateMasterKeys(t *testing.T, dir string) (privPath, pubPath string) {
	t.Helper()
	privPath = filepath.Join(dir, "master_private.json")
	pubPath = filepath.Join(dir, "master_public.json")

	handle, err := keyset.NewHandle(signature.ED25519KeyTemplate())
	assert.NilError(t, err, "Failed to create master keyset handle")

	// Write private
	privBuf := new(bytes.Buffer)
	writer := keyset.NewJSONWriter(privBuf)
	err = insecurecleartextkeyset.Write(handle, writer)
	assert.NilError(t, err, "Failed to write master private keyset")
	err = os.WriteFile(privPath, privBuf.Bytes(), 0o600)
	assert.NilError(t, err, "Failed to save master private keyset file")

	// Write public
	pubHandle, err := handle.Public()
	assert.NilError(t, err, "Failed to get master public keyset handle")
	pubBuf := new(bytes.Buffer)
	pubWriter := keyset.NewJSONWriter(pubBuf)
	err = insecurecleartextkeyset.Write(pubHandle, pubWriter)
	assert.NilError(t, err, "Failed to write master public keyset")
	err = os.WriteFile(pubPath, pubBuf.Bytes(), 0o600)
	assert.NilError(t, err, "Failed to save master public keyset file")

	return privPath, pubPath
}

// createNodeConfig creates a YAML config file for a daemon node.
func createNodeConfig(t *testing.T, dir, name, myPort, myPrivateKeyPath, masterPubKeyPath string, peers map[string]peerInfo) string {
	t.Helper()
	cfgPath := filepath.Join(dir, name+"_config.yaml")
	listenAddr := net.JoinHostPort("", myPort) // Listen on all interfaces for the given port

	peerConfigs := make(map[string]config.PeerConfig) // Map key is now peer name
	pollDuration := pollInterval                      // Use defined duration
	for peerName, peerData := range peers {
		// Determine endpoint based on Name - assumes test setup uses specific ports/endpoints
		var endpoint string
		switch peerName {
		case node1Name:
			endpoint = node1Endpoint
		case node2Name:
			endpoint = node2Endpoint
		case clientName:
			endpoint = "" // Client doesn't listen, no endpoint needed in peer config for it
		default:
			t.Fatalf("Unknown peer name in test setup: %s", peerName)
		}

		// Add all peers (nodes and client) to the config
		peerCfg := config.PeerConfig{
			PublicKeyPath: peerData.PublicKeyPath, // Use absolute path
			Endpoint:      endpoint,               // Set endpoint (can be empty for client)
		}

		// Set poll interval only for actual peer nodes, not the client or self
		// Note: The current node's own entry in `peers` is usually ignored by the synchronizer,
		// but setting PollInterval doesn't hurt. Client entry should not have it.
		if endpoint != "" && peerName != clientName {
			// Make a copy of the duration for the pointer
			interval := pollDuration
			peerCfg.PollInterval = &interval
		} else {
			peerCfg.PollInterval = nil
		}
		peerConfigs[peerName] = peerCfg
	}

	nodeCfg := config.Config{
		PrivateKeyPath:      myPrivateKeyPath, // Use absolute path
		MasterPublicKeyPath: masterPubKeyPath, // Use absolute path
		ListenAddress:       listenAddr,
		MaxTimestampSkew:    30 * time.Second,
		Peers:               peerConfigs,
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

// --- Test Setup Helpers ---

// testKeys holds paths to generated keys for a single entity (node/client/master).
type testKeys struct {
	PrivatePath string
	PublicPath  string
}

// generateAllTestKeys generates all necessary keys for the integration test.
func generateAllTestKeys(t *testing.T, dir string) (masterKeys, node1Keys, node2Keys, clientKeys testKeys) {
	t.Helper()
	// Master key (signing only) - still generate separate for clarity, though config uses combined format
	masterKeys.PrivatePath, masterKeys.PublicPath = generateMasterKeys(t, dir) // Use specific master key gen

	// Node 1 keys (combined)
	node1Keys.PrivatePath, node1Keys.PublicPath = generateCombinedKeyset(t, dir, node1Name)

	// Node 2 keys (combined)
	node2Keys.PrivatePath, node2Keys.PublicPath = generateCombinedKeyset(t, dir, node2Name)

	// Client keys (combined)
	clientKeys.PrivatePath, clientKeys.PublicPath = generateCombinedKeyset(t, dir, clientName)

	return masterKeys, node1Keys, node2Keys, clientKeys
}

// createTestConfigs creates the necessary config files for nodes.
// Client config is no longer strictly needed by the client itself if targets are specified,
// but nodes still need the client's public key info in their peer list.
func createTestConfigs(t *testing.T, dir string, masterKeys, node1Keys, node2Keys, clientKeys testKeys) (node1CfgPath, node2CfgPath string) {
	t.Helper()
	// Define peer public key info needed by each node config
	node1PeerInfo := peerInfo{PublicKeyPath: node1Keys.PublicPath}
	node2PeerInfo := peerInfo{PublicKeyPath: node2Keys.PublicPath}
	clientPeerInfo := peerInfo{PublicKeyPath: clientKeys.PublicPath}

	// Define all known peers for config generation (using names as keys)
	allPeers := map[string]peerInfo{
		node1Name:  node1PeerInfo,
		node2Name:  node2PeerInfo,
		clientName: clientPeerInfo, // Nodes need client info for auth/encryption
	}

	// Create config files for nodes
	node1CfgPath = createNodeConfig(t, dir, node1Name, node1Port, node1Keys.PrivatePath, masterKeys.PublicPath, allPeers)
	node2CfgPath = createNodeConfig(t, dir, node2Name, node2Port, node2Keys.PrivatePath, masterKeys.PublicPath, allPeers)

	// We don't strictly need a separate client config file anymore if we provide targets to 'get',
	// but the nodes' configs contain the necessary peer info (including client pubkey).
	// If 'get' were to rely solely on --config, we would create one similar to node configs
	// but without listen address and potentially without its own private keys listed.

	return node1CfgPath, node2CfgPath
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

// runPushCommand executes the push command using the new config structure.
func runPushCommand(t *testing.T, masterPrivKeyPath, nodeConfigPath string) {
	t.Helper()
	t.Log("Pushing secret...")
	// Owners are derived from config, parts must match number of owners (peers) in config.
	// Threshold must be <= parts.
	// Readers are specified.
	// Targets can be specified or derived from config.
	numParts := 2 // Since we have node1 and node2 in the config
	threshold := 2
	pushCmd := icmd.Command("go", "run", ".", "push",
		"--master-private-key", masterPrivKeyPath,
		"--config", nodeConfigPath, // Use one of the node configs to find peers/targets
		"--reader", node1Name,
		"--reader", node2Name,
		"--reader", clientName,
		"--key", testSecretKey,
		"--secret", testSecretVal,
		"--parts", strconv.Itoa(numParts),
		"--threshold", strconv.Itoa(threshold),
		// "--target", node1Endpoint, // Optionally specify targets
		// "--target", node2Endpoint,
		"--loglevel", "info",
	)
	pushResult := icmd.RunCmd(pushCmd)
	pushResult.Assert(t, icmd.Success)
	t.Log("Push command successful.")
}

// runGetCommand executes the get command using the new config structure.
func runGetCommand(t *testing.T, clientPrivKeyPath, nodeConfigPath, outputFilePath string) {
	t.Helper()
	t.Log("Getting secret...")
	// Need client name, client private key, config (for peer endpoints), key, and target(s).
	getCmd := icmd.Command("go", "run", ".", "get",
		"--client-name", clientName,
		"--private-key", clientPrivKeyPath,
		"--config", nodeConfigPath, // Use node config to find peer endpoints
		"--key", testSecretKey,
		// "--target", node1Endpoint, // Optionally specify targets
		// "--target", node2Endpoint,
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
	masterKeys, node1Keys, node2Keys, clientKeys := generateAllTestKeys(t, absTmpDir)
	node1CfgPath, node2CfgPath := createTestConfigs(t, absTmpDir, masterKeys, node1Keys, node2Keys, clientKeys)

	// --- Start Daemons ---
	resNode1 := startTestDaemon(t, node1CfgPath, node1Name)
	t.Cleanup(func() { stopTestDaemon(t, node1Name, resNode1) })

	resNode2 := startTestDaemon(t, node2CfgPath, node2Name)
	t.Cleanup(func() { stopTestDaemon(t, node2Name, resNode2) })

	// --- Wait for Daemons ---
	t.Log("Waiting for daemons to start...")
	waitForDaemon(t, node1Endpoint, 30*time.Second)
	waitForDaemon(t, node2Endpoint, 30*time.Second)
	// Increase sleep slightly to ensure peers likely connect and initial sync attempt happens
	time.Sleep(pollInterval + 1*time.Second)
	t.Log("Daemons appear ready.")

	// --- Execute Push ---
	// Use node1's config for push, it contains peer info for node2.
	runPushCommand(t, masterKeys.PrivatePath, node1CfgPath)

	// Allow time for synchronization
	t.Logf("Waiting for sync (%s)...", pollInterval+1*time.Second)
	time.Sleep(pollInterval + 1*time.Second) // Wait longer than poll interval

	// --- Execute Get ---
	outputFilePath := filepath.Join(absTmpDir, "retrieved_secret.txt")
	// Use node1's config for get, it contains peer info needed to find owner endpoints.
	runGetCommand(t, clientKeys.PrivatePath, node1CfgPath, outputFilePath)

	// --- Verify Secret ---
	retrievedBytes, err := os.ReadFile(outputFilePath)
	assert.NilError(t, err, "Failed to read output file")
	assert.Equal(t, string(retrievedBytes), testSecretVal, "Retrieved secret does not match original")
	t.Log("Secret verification successful.")

	// Cleanup is handled by t.Cleanup calls
	t.Log("Integration test finished.")
}
