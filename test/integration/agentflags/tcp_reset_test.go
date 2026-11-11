package agentflags

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	pkgutils "github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

/*
TCP Reset on Deny

With --enable-tcp-reset-on-deny the server pod's ingress program answers a TCP
SYN that policy denies with a RST, which the client sees as "connection
refused". Without the flag the SYN is dropped and the client's connect times
out. The kernel test (pkg/ebpf) checks the RST's bytes; these specs check what
it can't: that the RST reaches a client on the same node, on another node and
through a ClusterIP Service, that the flag reaches programs pods already run,
and that the server's own egress policy neither blocks the RST nor lets the
client's retries in.

The flag is set on the aws-node DaemonSet, so each change is a rollout. The
specs run in order and share one deny policy: flag off, on, then off again.
*/
var _ = Describe("TCP Reset on Deny", Ordered, func() {

	var (
		checkPod        *v1.Pod
		serverPod       *v1.Pod
		sameNodeClient  *v1.Pod
		otherNodeClient *v1.Pod
		allowedClient   *v1.Pod
		serverIP        string
		serverVIP       string
		originalArgs    []string
	)

	BeforeAll(func() {
		originalArgs = agentArgs()
		// Registered first, so it runs after the pods and policies are gone,
		// and the flag never leaks into the specs that run after these.
		DeferCleanup(func() {
			By("Restoring the agent's original args")
			setAgentArgs(originalArgs)
		})

		nodes, err := utils.SchedulableNodes(ctx, fw.K8sClient)
		Expect(err).ToNot(HaveOccurred())
		Expect(len(nodes)).To(BeNumerically(">=", 2), "a client on another node than the server needs two nodes")
		serverNode, otherNode := nodes[0], nodes[1]

		By("Creating the pods: the server and a client on node " + serverNode + ", two clients on node " + otherNode)
		check := utils.BuildBPFCheckPod(namespace, serverNode)
		// The specs span two agent rollouts, longer than the default sleep.
		check.Spec.Containers[0].Command = []string{"sleep", "1800"}
		checkPod = createPod(check)
		// No "-" in the names: GetPodIdentifier drops a name's last "-" segment,
		// and pods that share an identifier share their BPF programs and maps.
		serverPod = createPod(rstPod("rstserver", "rst-server", serverNode))
		serverIP = serverPod.Status.PodIP
		sameNodeClient = createPod(rstPod("rstsame", "rst-client", serverNode))
		otherNodeClient = createPod(rstPod("rstother", "rst-client", otherNode))
		allowedClient = createPod(rstPod("rstallowed", "rst-allowed", otherNode))

		By("Creating a ClusterIP Service for the server")
		svc, err := fw.ServiceManager.CreateService(ctx, &v1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "rstserver", Namespace: namespace},
			Spec: v1.ServiceSpec{
				Selector: map[string]string{"app": "rst-server"},
				Ports: []v1.ServicePort{{Protocol: v1.ProtocolTCP, Port: rstServicePort,
					TargetPort: intstr.FromInt(rstServerPort)}},
			},
		})
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() { Expect(fw.ServiceManager.DeleteService(ctx, svc)).To(Succeed()) })
		serverVIP = svc.Spec.ClusterIP
		Expect(serverVIP).ToNot(BeEmpty())

		By("Applying the server's ingress policy: from the allowed client only")
		createPolicy(&network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "rst-server-ingress", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "rst-server"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeIngress},
				Ingress: []network.NetworkPolicyIngressRule{{
					From: []network.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "rst-allowed"}},
					}},
				}},
			},
		})
	})

	It("times a denied connection out with the flag off", func() {
		// Also waits for the policy to take effect: the client connects until then.
		Eventually(func() ([]string, error) {
			return connectResults(otherNodeClient.Name, serverIP, rstServerPort, 0, 1)
		}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal([]string{timedOut}))
	})

	It("applies the flag to the programs pods already run", func() {
		identifier := pkgutils.GetPodIdentifier(serverPod.Name, namespace)
		before := podProgIDs(checkPod.Name, identifier)
		GinkgoWriter.Printf("server's programs before the flag change: %v\n", before)
		Expect(before).ToNot(BeEmpty(), "no programs found for %s", identifier)

		By("Turning the flag on")
		setAgentArgs(withTCPResetOnDeny(originalArgs))

		// The agent writes the flag into a map the programs share, and only
		// recovering that map at startup, instead of creating a new one,
		// reaches programs it doesn't reload. Unchanged program IDs show it
		// didn't reload them; the refused connects in the next spec show the
		// flag reached them.
		Expect(podProgIDs(checkPod.Name, identifier)).To(Equal(before), "the agent reloaded the server's programs")
		Expect(agentLogSinceStart(checkPod.Name, sharedMapsRecovered)).To(ContainSubstring(sharedMapsRecovered))
	})

	It("refuses a denied connection from the same node, another node and a ClusterIP", func() {
		// Several connects from one source port: had the RST recorded a flow,
		// the client's next SYN would match it as a reply and be let in.
		for _, client := range []*v1.Pod{sameNodeClient, otherNodeClient} {
			Expect(connectResults(client.Name, serverIP, rstServerPort, rstSrcPort, sameTupleTries)).
				To(Equal(repeated(refused, sameTupleTries)), "from %s on %s", client.Name, client.Spec.NodeName)
		}
		// The RST leaves the pod with the pod's address, and the host's
		// conntrack must rewrite it to the Service's for the client to match it.
		Expect(connectResults(otherNodeClient.Name, serverVIP, rstServicePort, 0, 1)).To(Equal([]string{refused}))
	})

	It("still connects allowed traffic", func() {
		Expect(connectResults(allowedClient.Name, serverIP, rstServerPort, 0, 1)).To(Equal([]string{connected}))
	})

	It("gets the RST out of a pod whose egress denies everything", func() {
		createPolicy(&network.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "rst-server-egress", Namespace: namespace},
			Spec: network.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "rst-server"}},
				PolicyTypes: []network.PolicyType{network.PolicyTypeEgress},
			},
		})
		// The allowed client serves too, and no policy selects it, so only the
		// server's egress policy can stop this connect.
		Eventually(func() ([]string, error) {
			return connectResults(serverPod.Name, allowedClient.Status.PodIP, rstServerPort, 0, 1)
		}, utils.EnforcementTimeout, utils.ProbeInterval).Should(Equal([]string{timedOut}),
			"the server's egress policy never took effect")

		Expect(connectResults(otherNodeClient.Name, serverIP, rstServerPort, rstSrcPort, sameTupleTries)).
			To(Equal(repeated(refused, sameTupleTries)))
		// Each RST passes egress on a record its SYN left; the server's own
		// connects have none and stay denied.
		Expect(connectResults(serverPod.Name, allowedClient.Status.PodIP, rstServerPort, 0, 1)).
			To(Equal([]string{timedOut}))
	})

	It("times a denied connection out again with the flag off", func() {
		By("Restoring the agent's original args")
		setAgentArgs(originalArgs)
		Expect(connectResults(otherNodeClient.Name, serverIP, rstServerPort, 0, 1)).To(Equal([]string{timedOut}))
	})
})

const (
	tcpResetOnDenyArg = "--enable-tcp-reset-on-deny"

	// The agent logs this at startup when it kept the shared TC maps it
	// found pinned.
	sharedMapsRecovered = "Recovered the shared TC maps"

	rstServerPort  = 8080
	rstServicePort = 80

	// A fixed source port, so retries reuse the 5-tuple.
	rstSrcPort     = 34569
	sameTupleTries = 3

	// Long enough for a SYN to be answered across nodes, short enough that a
	// dropped SYN costs little.
	connectTimeoutSeconds = 3

	connected = "CONNECTED"
	refused   = "REFUSED"
	timedOut  = "TIMEOUT"

	execAttempts = 3

	// Logged by every agent version at startup. The log outlives the agent,
	// so lines before the last one belong to an earlier agent.
	agentStarted = "Network Policy is enabled, registering controllers"
	npaLog       = "/host/var/log/aws-routed-eni/network-policy-agent.log"
)

// rstPod serves HTTP on rstServerPort, on both families: http.server's
// dual-stack server accepts IPv4 on an IPv6 socket. Every pod serves, so the
// server's egress spec has an allowed destination.
func rstPod(name, app, node string) *v1.Pod {
	grace := int64(0) // python as PID 1 ignores SIGTERM
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{"app": app}},
		Spec: v1.PodSpec{
			NodeName:                      node,
			TerminationGracePeriodSeconds: &grace,
			Containers: []v1.Container{{
				Name: "server", Image: "public.ecr.aws/docker/library/python:3.11-slim",
				Command: []string{"python3", "-m", "http.server", strconv.Itoa(rstServerPort), "--bind", "::"},
			}},
		},
	}
}

// withTCPResetOnDeny returns args with the flag on.
func withTCPResetOnDeny(args []string) []string {
	var out []string
	for _, a := range args {
		if !strings.HasPrefix(a, tcpResetOnDenyArg) {
			out = append(out, a)
		}
	}
	return append(out, tcpResetOnDenyArg+"=true")
}

// connectResults connects from pod to ip:port tries times, optionally from a
// fixed source port, and returns how each attempt ended: connected, refused
// (a RST) or timedOut (no answer). The ebpf suite's tryConnect can't be
// used: it reports refused and timed out alike.
func connectResults(pod, ip string, port, srcPort, tries int) ([]string, error) {
	family, anyAddr := "AF_INET", "0.0.0.0"
	if isV6(ip) {
		family, anyAddr = "AF_INET6", "::"
	}
	bind := ""
	if srcPort > 0 {
		// SO_REUSEADDR: a connect that succeeded leaves the port in TIME_WAIT.
		bind = fmt.Sprintf("s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('%s',%d))", anyAddr, srcPort)
	}
	script := fmt.Sprintf(`import socket
for _ in range(%d):
 s=socket.socket(socket.%s,socket.SOCK_STREAM);s.settimeout(%d)
 %s
 try:
  s.connect(('%s',%d));print('%s')
 except ConnectionRefusedError:
  print('%s')
 except TimeoutError:
  print('%s')
 finally:
  s.close()`, tries, family, connectTimeoutSeconds, bind, ip, port, connected, refused, timedOut)
	out, err := execInPod(namespace, pod, "connectResults", script)
	if err != nil {
		return nil, err
	}
	return strings.Fields(out), nil
}

func repeated(result string, n int) []string {
	results := make([]string, n)
	for i := range results {
		results[i] = result
	}
	return results
}

// podProgIDs returns the IDs of the programs the agent loaded for the pod
// identifier, by their pin names, on the check pod's node. The agent installs
// its CLI under the same host path on both families.
func podProgIDs(checkPodName, identifier string) map[string]int {
	out, err := fw.PodManager.ExecInPod(namespace, checkPodName,
		[]string{"chroot", "/host", "/opt/cni/bin/aws-eks-na-cli", "ebpf", "loaded-ebpfdata"})
	Expect(err).ToNot(HaveOccurred(), "failed to read the node's BPF programs")
	state, err := utils.ParseLoadedEBPFData(out)
	Expect(err).ToNot(HaveOccurred(), "failed to parse loaded-ebpfdata output")
	ids := map[string]int{}
	for pin, id := range state.ProgIDs {
		if strings.HasPrefix(pin, identifier+"_") {
			ids[pin] = id
		}
	}
	return ids
}

// Each suite is its own package, so the helpers below are copies of the ebpf
// suite's, cut to what these specs use, as soak/port-reuse keeps its own
// shellQuote.

// execInPod retries the exec itself: it reaches the kubelet through the
// apiserver and fails transiently, and a spec would read that as a result.
func execInPod(ns, pod, what, script string) (string, error) {
	var out string
	var err error
	for attempt := 1; attempt <= execAttempts; attempt++ {
		out, err = fw.PodManager.ExecInPod(ns, pod, []string{"python3", "-c", script})
		if err == nil {
			return out, nil
		}
		GinkgoWriter.Printf("%s exec attempt %d/%d failed: %v\n", what, attempt, execAttempts, err)
		time.Sleep(utils.PollIntervalShort)
	}
	return "", err
}

func isV6(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.To4() == nil
}

// agentLogSinceStart returns the agent's log lines from its last startup on
// that contain pattern. Unlike the ebpf suite's copy it doesn't read the
// rotated backups: the specs call it right after a rollout restarted the
// agent, and the log rotates at 200 MB by default (pkg/logger), so the
// startup line is still in the current log.
func agentLogSinceStart(checkPodName, pattern string) string {
	out, err := fw.PodManager.ExecInPod(namespace, checkPodName,
		[]string{"grep", "-h", "-e", agentStarted, "-e", pattern, npaLog})
	Expect(err).ToNot(HaveOccurred(), "failed to read the agent log")
	if i := strings.LastIndex(out, agentStarted); i >= 0 {
		out = out[i:]
	}
	return out
}
