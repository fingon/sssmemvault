package main_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync" // Add missing import
	"syscall"
	"testing"
	"time"

	"github.com/fingon/sssmemvault/internal/config"
	// Register Tink primitives
	_ "github.com/tink-crypto/tink-go/v2/aead"
	_ "github.com/tink-crypto/tink-go/v2/hybrid"
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
	node3Name     = "test-node-3" // Added for the 3-node test
	clientName    = "test-client-1"
	nodeIP        = "127.0.0.1"
	pollInterval  = 2 * time.Second // Faster polling for test
)

// peerInfo holds paths and endpoint needed for peer configuration.
type peerInfo struct {
	Name          string
	PublicKeyPath string // Combined public keyset (signing + hybrid)
	Endpoint      string // e.g., "127.0.0.1:59251" (empty for client)
	Port          string // e.g., "59251" (empty for client)
}

// testKeys holds paths to generated keys for a single entity (node/client/master).
type testKeys struct {
	PrivatePath string
	PublicPath  string
}

// testNode represents a running daemon instance.
type testNode struct {
	Name    string
	CfgPath string
	Result  *icmd.Result
}

func generateKeyset(t *testing.T, command, name string) testKeys {
	t.Helper()
	tmpDir := t.TempDir()
	dir, err := filepath.Abs(tmpDir)
	assert.NilError(t, err)
	privPath := filepath.Join(dir, name+"_private.json")
	pubPath := filepath.Join(dir, name+"_public.json")
	getCmd := icmd.Command("go", "run", ".", "gen", command,
		"--private-out", privPath,
		"--public-out", pubPath,
	)
	getResult := icmd.RunCmd(getCmd)
	getResult.Assert(t, icmd.Success)

	return testKeys{PrivatePath: privPath, PublicPath: pubPath}
}

// createNodeConfig creates a YAML config file for a daemon node.
// It includes all provided peers in the 'peers' section.
func createNodeConfig(t *testing.T, dir string, node peerInfo, nodePrivKeyPath, masterPubKeyPath string, allPeers []peerInfo) string {
	t.Helper()
	cfgPath := filepath.Join(dir, node.Name+"_config.yaml")
	listenAddr := net.JoinHostPort("", node.Port) // Listen on all interfaces for the given port

	peerConfigs := make(map[string]config.PeerConfig) // Map key is peer name
	pollDuration := pollInterval                      // Use defined duration

	for _, p := range allPeers {
		peerCfg := config.PeerConfig{
			PublicKeyPath: p.PublicKeyPath, // Use absolute path
			Endpoint:      p.Endpoint,      // Use endpoint from peerInfo (can be empty for client)
		}

		// Set poll interval only for actual peer nodes (those with an endpoint), not the client or self.
		if p.Endpoint != "" && p.Name != node.Name {
			interval := pollDuration
			peerCfg.PollInterval = &interval
		} else {
			peerCfg.PollInterval = nil
		}
		// Set default fragments per owner for test config
		if peerCfg.FragmentsPerOwner <= 0 {
			peerCfg.FragmentsPerOwner = 1
		}
		peerConfigs[p.Name] = peerCfg
	}

	nodeCfg := config.Config{
		PrivateKeyPath:      nodePrivKeyPath,  // Use absolute path
		MasterPublicKeyPath: masterPubKeyPath, // Use absolute path
		ListenAddress:       listenAddr,
		MaxTimestampSkew:    30 * time.Second,
		Peers:               peerConfigs,
	}

	yamlData, err := yaml.Marshal(nodeCfg)
	assert.NilError(t, err, "Failed to marshal config for %s", node.Name)

	// Log the generated config content for debugging
	t.Logf("Generated config for %s (%s):\n%s", node.Name, cfgPath, string(yamlData))

	err = os.WriteFile(cfgPath, yamlData, 0o600)
	assert.NilError(t, err, "Failed to write config file for %s", node.Name)

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

// setupTestEnvironment generates keys and configs for a given set of node names.
func setupTestEnvironment(t *testing.T, nodeNames []string, ofs int) (
	masterKeys testKeys,
	clientKeys testKeys,
	nodeInfos map[string]peerInfo, // Map: Node Name -> Peer Info
	nodeKeyPaths map[string]string, // Map: Node Name -> Private Key Path
	nodeCfgPaths map[string]string, // Map: Node Name -> Config Path
) {
	t.Helper()
	tmpDir := t.TempDir()
	absTmpDir, err := filepath.Abs(tmpDir)
	assert.NilError(t, err)

	// Generate Master Key
	masterKeys = generateKeyset(t, "sign", "master")

	// Generate Client Key
	clientKeys = generateKeyset(t, "keys", clientName)
	clientInfo := peerInfo{Name: clientName, PublicKeyPath: clientKeys.PublicPath, Endpoint: "", Port: ""} // Client has no endpoint/port

	// Generate Node Keys and Collect Peer Info
	nodeInfos = make(map[string]peerInfo)
	nodeKeyPaths = make(map[string]string)
	allPeers := []peerInfo{clientInfo} // Start with client info

	nodePorts := map[string]string{}
	for i, nodeName := range nodeNames {
		nodePorts[nodeName] = strconv.Itoa(59123 + ofs + i)
	}
	nodeEndpoints := map[string]string{}
	for k, v := range nodePorts {
		nodeEndpoints[k] = net.JoinHostPort(nodeIP, v)
	}

	for _, name := range nodeNames {
		keys := generateKeyset(t, "keys", name)
		nodeKeyPaths[name] = keys.PrivatePath
		info := peerInfo{
			Name:          name,
			PublicKeyPath: keys.PublicPath,
			Endpoint:      nodeEndpoints[name],
			Port:          nodePorts[name],
		}
		nodeInfos[name] = info
		allPeers = append(allPeers, info)
	}

	// Create Node Config Files
	nodeCfgPaths = make(map[string]string)
	for _, name := range nodeNames {
		nodeInfo := nodeInfos[name]
		t.Logf("Generating config for node %s using PeerInfo: %+v", name, nodeInfo) // Log PeerInfo
		nodeCfgPaths[name] = createNodeConfig(t, absTmpDir, nodeInfo, nodeKeyPaths[name], masterKeys.PublicPath, allPeers)
	}

	return masterKeys, clientKeys, nodeInfos, nodeKeyPaths, nodeCfgPaths
}

// startDaemons starts daemon processes for the given nodes and returns a map of running nodes.
func startDaemons(t *testing.T, nodeInfos map[string]peerInfo, nodeCfgPaths map[string]string) map[string]*testNode {
	t.Helper()
	runningNodes := make(map[string]*testNode)
	for name, info := range nodeInfos {
		cfgPath := nodeCfgPaths[name]
		cmd := icmd.Command("go", "run", ".", "daemon",
			"--config", cfgPath,
			"--my-name", name,
			"--log-level", "debug",
		)
		res := icmd.StartCmd(cmd)
		t.Logf("Started %s (PID %d) listening on %s", name, res.Cmd.Process.Pid, info.Endpoint)
		runningNode := &testNode{Name: name, CfgPath: cfgPath, Result: res}
		runningNodes[name] = runningNode
		// Add cleanup for each started daemon
		t.Cleanup(func() { stopDaemon(t, runningNode) })
	}
	return runningNodes
}

// stopDaemon stops a single daemon process gracefully.
func stopDaemon(t *testing.T, node *testNode) {
	t.Helper()
	// Check if process is already finished
	if node.Result.Cmd == nil || node.Result.Cmd.ProcessState != nil {
		t.Logf("Daemon %s already stopped.", node.Name)
		return
	}
	t.Logf("Stopping daemon %s (PID %d)...", node.Name, node.Result.Cmd.Process.Pid)
	err := node.Result.Cmd.Process.Signal(syscall.SIGTERM) // Send SIGTERM for graceful shutdown
	assert.NilError(t, err, "Failed to send SIGTERM to %s", node.Name)

	// Wait for process to exit, check status
	state, waitErr := node.Result.Cmd.Process.Wait()
	assert.NilError(t, waitErr, "Error waiting for %s to exit", node.Name)
	t.Logf("%s exited: %s", node.Name, state)
	if !state.Success() {
		// Log output only if exit was not successful (SIGTERM often results in non-zero exit)
		t.Logf("%s stderr:\n%s", node.Name, node.Result.Stderr())
		t.Logf("%s stdout:\n%s", node.Name, node.Result.Stdout())
	}

	// Second stop will abort early
	node.Result.Cmd = nil
}

// waitForDaemons waits for all specified daemons to become available.
func waitForDaemons(t *testing.T, nodes map[string]*testNode, nodeInfos map[string]peerInfo, timeout time.Duration) { // Add nodeInfos parameter
	t.Helper()
	var wg sync.WaitGroup
	for _, node := range nodes {
		// Get endpoint from nodeInfos map using the node's name
		info, ok := nodeInfos[node.Name]
		if !ok || info.Endpoint == "" {
			t.Fatalf("Could not find endpoint information for node %s in nodeInfos map", node.Name)
		}
		endpoint := info.Endpoint

		wg.Add(1)
		go func(ep string) { // Pass endpoint directly to goroutine
			defer wg.Done()
			waitForDaemon(t, ep, timeout)
		}(endpoint)
	}
	wg.Wait()
	// Increase sleep slightly to ensure peers likely connect and initial sync attempt happens
	time.Sleep(pollInterval + 1*time.Second)
	t.Log("All specified daemons appear ready.")
}

// runPushCommand executes the push command. Parts are now derived from config.
func runPushCommand(t *testing.T, masterPrivKeyPath, configPath string, threshold int, readers []string, secretKey, secretValue string) {
	t.Helper()
	t.Logf("Pushing secret '%s' (threshold=%d)...", secretKey, threshold)

	args := []string{
		"run", ".", "push",
		"--master-private-key", masterPrivKeyPath,
		"--config", configPath, // Config provides owner/target info and fragment counts
		"--key", secretKey,
		"--secret", secretValue,
		"--threshold", strconv.Itoa(threshold),
		"--log-level", "info",
	}
	for _, r := range readers {
		args = append(args, "--reader", r)
	}
	// Targets are derived from config by default now

	pushCmd := icmd.Command("go", args...)
	pushResult := icmd.RunCmd(pushCmd)
	pushResult.Assert(t, icmd.Success)
	t.Logf("Push command for key '%s' successful.", secretKey)
}

// runGetCommand executes the get command.
func runGetCommand(t *testing.T, clientName, clientPrivKeyPath, configPath, secretKey, outputFilePath string) {
	t.Helper()
	t.Logf("Getting secret '%s'...", secretKey)
	// Need client name, client private key, config (for peer endpoints), key.
	// Targets are derived from config by default now.
	getCmd := icmd.Command("go", "run", ".", "get",
		"--client-name", clientName,
		"--private-key", clientPrivKeyPath,
		"--config", configPath, // Use config to find peer endpoints
		"--key", secretKey,
		"--output", outputFilePath,
		"--log-level", "info",
	)
	getResult := icmd.RunCmd(getCmd)
	getResult.Assert(t, icmd.Success)
	t.Logf("Get command for key '%s' successful.", secretKey)
}

// verifySecret checks if the content of the output file matches the expected secret.
func verifySecret(t *testing.T, outputFilePath, expectedSecret string) {
	t.Helper()
	retrievedBytes, err := os.ReadFile(outputFilePath)
	assert.NilError(t, err, "Failed to read output file: %s", outputFilePath)
	assert.Equal(t, string(retrievedBytes), expectedSecret, "Retrieved secret does not match original")
	t.Logf("Secret verification successful for file: %s", outputFilePath)
}

// --- Test Functions ---

// TestPushAndGetIntegration_TwoNodes tests the basic 2-node push/get scenario.
func TestPushAndGetIntegration_TwoNodes(t *testing.T) {
	t.Parallel()

	nodeNames := []string{node1Name, node2Name}
	masterKeys, clientKeys, nodeInfos, _, nodeCfgPaths := setupTestEnvironment(t, nodeNames, 0)

	// Start Daemons
	runningNodes := startDaemons(t, nodeInfos, nodeCfgPaths)
	// Cleanup handled by t.Cleanup in startDaemons

	// Wait for Daemons
	waitForDaemons(t, runningNodes, nodeInfos, 30*time.Second) // Pass nodeInfos

	// Execute Push (2 parts, threshold 2)
	readers := []string{node1Name, node2Name, clientName}
	// Use node1's config for push, it contains peer info for node2.
	// Parts (2) is derived from config (1 fragment per owner node). Threshold is 2.
	runPushCommand(t, masterKeys.PrivatePath, nodeCfgPaths[node1Name], 2, readers, testSecretKey, testSecretVal)

	// Allow time for synchronization
	t.Logf("Waiting for sync (%s)...", pollInterval+1*time.Second)
	time.Sleep(pollInterval + 1*time.Second) // Wait longer than poll interval

	// Execute Get
	outputFilePath := filepath.Join(filepath.Dir(nodeCfgPaths[node1Name]), "retrieved_secret_2nodes.txt")
	// Use node1's config for get, it contains peer info needed to find owner endpoints.
	runGetCommand(t, clientName, clientKeys.PrivatePath, nodeCfgPaths[node1Name], testSecretKey, outputFilePath)

	// Verify Secret
	verifySecret(t, outputFilePath, testSecretVal)

	t.Log("Two-node integration test finished.")
}

// TestPushAndGetIntegration_TwoOutOfThreeNodes tests retrieving a secret when one of three nodes is down.
func TestPushAndGetIntegration_TwoOutOfThreeNodes(t *testing.T) {
	t.Parallel()

	nodeNames := []string{node1Name, node2Name, node3Name}
	masterKeys, clientKeys, nodeInfos, _, nodeCfgPaths := setupTestEnvironment(t, nodeNames, 100)

	// Start Daemons
	runningNodes := startDaemons(t, nodeInfos, nodeCfgPaths)
	// Cleanup handled by t.Cleanup in startDaemons

	// Wait for Daemons
	waitForDaemons(t, runningNodes, nodeInfos, 30*time.Second) // Pass nodeInfos

	// Execute Push (3 parts, threshold 2)
	readers := []string{node1Name, node2Name, node3Name, clientName}
	// Use node1's config for push, it contains info for all peers.
	// Parts (3) is derived from config (1 fragment per owner node). Threshold is 2.
	runPushCommand(t, masterKeys.PrivatePath, nodeCfgPaths[node1Name], 2, readers, testSecretKey, testSecretVal)

	// Allow time for synchronization between the 3 nodes
	t.Logf("Waiting for sync (%s)...", pollInterval+1*time.Second)
	time.Sleep(pollInterval + 1*time.Second)

	// --- Simulate Node Failure ---
	t.Logf("Stopping node %s to simulate failure...", node3Name)
	stopDaemon(t, runningNodes[node3Name])
	// Remove node3 from runningNodes map to avoid waiting for it later if needed
	delete(runningNodes, node3Name)
	// Wait a moment to ensure the port is released/daemon is down
	time.Sleep(1 * time.Second)
	t.Logf("Node %s stopped.", node3Name)

	// --- Execute Get (expecting success with 2 out of 3) ---
	outputFilePath := filepath.Join(filepath.Dir(nodeCfgPaths[node1Name]), "retrieved_secret_2of3.txt")
	// Use node1's config for get. It knows about all 3 original owners,
	// but the 'get' command should only need to contact the available ones (node1, node2)
	// to satisfy the threshold of 2.
	runGetCommand(t, clientName, clientKeys.PrivatePath, nodeCfgPaths[node1Name], testSecretKey, outputFilePath)

	// --- Verify Secret ---
	verifySecret(t, outputFilePath, testSecretVal)

	t.Log("Two-out-of-three nodes integration test finished.")
}
