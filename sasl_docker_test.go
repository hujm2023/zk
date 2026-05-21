package zk

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIntegrationSASLDigestDocker(t *testing.T) {
	if os.Getenv("ZK_SASL_DOCKER_TEST") != "1" {
		t.Skip("set ZK_SASL_DOCKER_TEST=1 to run Docker-backed SASL verification")
	}

	port := freeTCPPort(t)
	name := fmt.Sprintf("zk-sasl-digest-%d", time.Now().UnixNano())
	tmpDir := t.TempDir()
	writeSASLDockerConfig(t, tmpDir)

	args := []string{
		"run", "-d",
		"--name", name,
		"-p", fmt.Sprintf("127.0.0.1:%d:2181", port),
		"-e", "SERVER_JVMFLAGS=-Djava.security.auth.login.config=/conf/jaas.conf",
		"-v", filepath.Join(tmpDir, "zoo.cfg") + ":/conf/zoo.cfg:ro",
		"-v", filepath.Join(tmpDir, "jaas.conf") + ":/conf/jaas.conf:ro",
		"zookeeper:3.9",
		"zkServer.sh", "start-foreground", "/conf/zoo.cfg",
	}
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("failed to start ZooKeeper docker container: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	waitForTCPPort(t, addr, 30*time.Second)

	authConn, authEvents, err := Connect([]string{addr}, 5*time.Second, WithSASLDigest("admin", "secret"))
	if err != nil {
		t.Fatalf("Connect with SASL returned error: %v", err)
	}
	defer authConn.Close()
	waitForSessionState(t, authEvents, 10*time.Second)

	path := "/sasl-digest-test"
	_, err = authConn.Create(path, []byte("secret"), 0, SASLACL(PermAll, "admin"))
	if err != nil && err != ErrNodeExists {
		t.Fatalf("authenticated Create returned error: %v", err)
	}

	plainConn, plainEvents, err := Connect([]string{addr}, 5*time.Second)
	if err != nil {
		t.Fatalf("plain Connect returned error: %v", err)
	}
	defer plainConn.Close()
	waitForSessionState(t, plainEvents, 10*time.Second)

	if _, _, err = plainConn.Get(path); err != ErrNoAuth {
		t.Fatalf("plain Get returned %v, want ErrNoAuth", err)
	}

	data, _, err := authConn.Get(path)
	if err != nil {
		t.Fatalf("authenticated Get returned error: %v", err)
	}
	if string(data) != "secret" {
		t.Fatalf("authenticated Get returned %q, want secret", data)
	}

	authConn.Close()
	reconnectConn, reconnectEvents, err := Connect([]string{addr}, 5*time.Second, WithSASLDigest("admin", "secret"))
	if err != nil {
		t.Fatalf("reconnect Connect with SASL returned error: %v", err)
	}
	defer reconnectConn.Close()
	waitForSessionState(t, reconnectEvents, 10*time.Second)
	if _, _, err = reconnectConn.Get(path); err != nil {
		t.Fatalf("reconnected authenticated Get returned error: %v", err)
	}
}

func writeSASLDockerConfig(t *testing.T, dir string) {
	t.Helper()

	zooCfg := strings.Join([]string{
		"tickTime=2000",
		"dataDir=/data",
		"clientPort=2181",
		"admin.enableServer=false",
		"4lw.commands.whitelist=*",
		"authProvider.1=org.apache.zookeeper.server.auth.SASLAuthenticationProvider",
		"",
	}, "\n")
	if err := ioutil.WriteFile(filepath.Join(dir, "zoo.cfg"), []byte(zooCfg), 0644); err != nil {
		t.Fatalf("failed to write zoo.cfg: %v", err)
	}

	jaas := strings.Join([]string{
		"Server {",
		"  org.apache.zookeeper.server.auth.DigestLoginModule required",
		"  user_admin=\"secret\";",
		"};",
		"",
	}, "\n")
	if err := ioutil.WriteFile(filepath.Join(dir, "jaas.conf"), []byte(jaas), 0644); err != nil {
		t.Fatalf("failed to write jaas.conf: %v", err)
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate local TCP port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func waitForTCPPort(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", addr)
}

func waitForSessionState(t *testing.T, events <-chan Event, timeout time.Duration) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for {
		select {
		case event, ok := <-events:
			if !ok {
				t.Fatal("connection closed before session was established")
			}
			if event.State == StateHasSession {
				return
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}
