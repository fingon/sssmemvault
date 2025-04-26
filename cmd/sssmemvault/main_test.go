package main_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	node1IP       = "127.0.0.1"
	node2IP       = "127.0.0.2" // Use different loopback IP for node 2
	clientIP      = "127.0.0.3" // Use different loopback IP for client to avoid config key collision
	node1Port     = "59251"     // Use distinct ports
	node2Port     = "59252"
	pollInterval  = "5s" // Faster polling for test
)

var (
	node1Endpoint = net.JoinHostPort(node1IP, node1Port)
	node2Endpoint = net.JoinHostPort(node2IP, node2Port)
)

// keyPaths holds the file paths for generated keys.
type keyPaths struct {
	Private string
	Public  string
}

// generateTinkKeyset generates a Tink keyset containing keys derived from all
// specified templates and saves the private and public keysets to files.
// It returns paths to the private and public keyset files.
// Uses keyset.Manager for modern Tink API usage.
func generateTinkKeyset(t *testing.T, dir, name string, keyTemplates ...*tinkpb.KeyTemplate) keyPaths {
	t.Helper()

	privPath := filepath.Join(dir, name+"_private.json") // Combined private keyset
	pubPath := filepath.Join(dir, name+"_public.json")

	// Use Keyset Manager to combine multiple key types
	manager := keyset.NewManager()
	var primaryKeyID uint32 // Store the ID of the key intended to be primary

	// Add all specified key templates to the manager
	for i, kt := range keyTemplates {
		keyID, err := manager.Add(kt)
		assert.NilError(t, err, "Failed to add key template %d (%s) to manager for %s", i, kt.TypeUrl, name)
		// Convention: Assume the *first* key added should be the primary key.
		// Adjust if a different primary key logic is needed.
		if i == 0 {
			primaryKeyID = keyID
		}
	}

	// Ensure at least one key was added
	assert.Assert(t, primaryKeyID != 0, "No keys were added to the manager for %s", name)

	// Set the designated primary key
	err := manager.SetPrimary(primaryKeyID)
	assert.NilError(t, err, "Failed to set primary key (ID: %d) for %s", primaryKeyID, name)

	// Get the handle containing all keys from the manager
	handle, err := manager.Handle()
	assert.NilError(t, err, "Failed to get combined keyset handle from manager for %s", name)

	// Write private keyset using insecurecleartextkeyset
	privBuf := new(bytes.Buffer)
	writer := keyset.NewJSONWriter(privBuf)
	err = insecurecleartextkeyset.Write(handle, writer)
	assert.NilError(t, err, "Failed to write private keyset for %s", name)
	err = os.WriteFile(privPath, privBuf.Bytes(), 0o600)
	assert.NilError(t, err, "Failed to save private keyset file for %s", name)

	// Get public keyset handle
	pubHandle, err := handle.Public()
	assert.NilError(t, err, "Failed to get public keyset handle for %s", name)

	// Write public keyset
	pubBuf := new(bytes.Buffer)
	pubWriter := keyset.NewJSONWriter(pubBuf)
	err = insecurecleartextkeyset.Write(pubHandle, pubWriter) // Write public keyset
	assert.NilError(t, err, "Failed to write public keyset for %s", name)
	err = os.WriteFile(pubPath, pubBuf.Bytes(), 0o600)
	assert.NilError(t, err, "Failed to save public keyset file for %s", name)

	return keyPaths{Private: privPath, Public: pubPath}
}

// createNodeConfig creates a YAML config file for a daemon node.
func createNodeConfig(t *testing.T, dir, name, myPort, myPrivKeyPath, masterPubKeyPath string, peers map[string]keyPaths) string {
	t.Helper()
	cfgPath := filepath.Join(dir, name+"_config.yaml")
	listenAddr := net.JoinHostPort("", myPort) // Listen on all interfaces for the given port

	peerConfigs := make(map[string]config.PeerConfig)
	pollDuration := time.Second * 5 // Convert string to duration for config struct
	for ip, keys := range peers {
		// Determine endpoint based on IP - assumes test setup uses specific ports
		var endpoint string
		switch ip {
		case node1IP:
			endpoint = node1Endpoint
		case node2IP:
			endpoint = node2Endpoint
		}

		// Only add peers with endpoints (i.e., other nodes, not the client)
		if endpoint != "" {
			peerConfigs[ip] = config.PeerConfig{
				Endpoint:     endpoint,
				PublicKey:    keys.Public, // Use absolute path
				PollInterval: &pollDuration,
				// AllowedSourceCIDRs: []string{fmt.Sprintf("%s/32", ip)}, // Restrict source IP
			}
			continue
		}
		if strings.Contains(keys.Public, "client") {
			// Add client config without endpoint or polling
			peerConfigs[ip] = config.PeerConfig{
				Endpoint:  "", // No endpoint for client
				PublicKey: keys.Public,
				// AllowedSourceCIDRs: []string{fmt.Sprintf("%s/32", ip)}, // Restrict source IP
			}
		}
	}

	nodeCfg := config.Config{
		PrivateKeyPath:   myPrivKeyPath,    // Use absolute path
		MasterPublicKey:  masterPubKeyPath, // Use absolute path
		ListenAddress:    listenAddr,
		MaxTimestampSkew: 30 * time.Second,
		Peers:            peerConfigs,
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

	// --- Generate Keys ---
	// Master key (signing only)
	masterKeys := generateTinkKeyset(t, absTmpDir, "master",
		signature.ED25519KeyTemplate(), // Only signing needed
	)

	// Node 1 keys (signing + hybrid decryption in one keyset)
	node1Keys := generateTinkKeyset(t, absTmpDir, "node1",
		signature.ECDSAP256KeyTemplate(),                                       // For request signing/verification
		hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Key_Template(), // For fragment encryption/decryption
	)

	// Node 2 keys (signing + hybrid decryption in one keyset)
	node2Keys := generateTinkKeyset(t, absTmpDir, "node2",
		signature.ECDSAP256KeyTemplate(),                                       // For request signing/verification
		hybrid.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_Key_Template(), // For fragment encryption/decryption
	)

	// Client key (signing only)
	clientKeys := generateTinkKeyset(t, absTmpDir, "client",
		signature.ECDSAP256KeyTemplate(), // Only signing needed for client 'get' requests
	)

	// --- Create Config Files ---
	// Use distinct IPs (node1IP, node2IP, clientIP) as keys
	allPeersForNode1 := map[string]keyPaths{
		node2IP:  node2Keys,  // Node 1 needs Node 2's public key
		clientIP: clientKeys, // Node 1 needs Client's public key
	}
	allPeersForNode2 := map[string]keyPaths{
		node1IP:  node1Keys,  // Node 2 needs Node 1's public key
		clientIP: clientKeys, // Node 2 needs Client's public key
	}
	// Client config needs peer info to find endpoints, but doesn't need itself.
	allPeersForClient := map[string]keyPaths{
		node1IP: node1Keys, // Client needs Node 1's public key (for endpoint lookup)
		node2IP: node2Keys, // Client needs Node 2's public key (for endpoint lookup)
		// No entry for clientIP needed here
	}

	// Pass the appropriate peer map to each config creation function
	node1CfgPath := createNodeConfig(t, absTmpDir, "node1", node1Port, node1Keys.Private, masterKeys.Public, allPeersForNode1)
	node2CfgPath := createNodeConfig(t, absTmpDir, "node2", node2Port, node2Keys.Private, masterKeys.Public, allPeersForNode2)
	// Client config needs peer endpoints and master public key, but not its own private key path here.
	// It uses the allPeersForClient map to find owner endpoints.
	clientCfgPath := createNodeConfig(t, absTmpDir, "client", "", "", masterKeys.Public, allPeersForClient)

	// --- Start Daemons ---

	// Start Node 1
	cmdNode1 := icmd.Command("go", "run", ".", "daemon",
		"--config", node1CfgPath,
		"--my-ip", node1IP,
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
		"--my-ip", node2IP,
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
	// The push command needs the public keyset containing the hybrid encryption key for each owner.
	// The owner public keyset file generated by generateTinkKeyset now contains both verification and encryption keys.
	pushCmd := icmd.Command("go", "run", ".", "push",
		"--master-key", masterKeys.Private,
		"--owner", fmt.Sprintf("%s=%s", node1IP, node1Keys.Public), // Use combined public keyset path
		"--owner", fmt.Sprintf("%s=%s", node2IP, node2Keys.Public), // Use combined public keyset path
		"--reader", node1IP, // Allow nodes themselves to read for testing simplicity
		"--reader", node2IP,
		"--reader", clientIP, // Allow client (now 127.0.0.3) to read
		"--key", testSecretKey,
		"--secret", testSecretVal,
		"--parts", "2",
		"--threshold", "2",
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
	t.Log("Getting secret...")
	outputFilePath := filepath.Join(absTmpDir, "retrieved_secret.txt")
	getCmd := icmd.Command("go", "run", ".", "get",
		"--private-key", clientKeys.Private,
		"--config", clientCfgPath, // Use client config to find owner endpoints
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
