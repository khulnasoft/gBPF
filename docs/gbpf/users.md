# Projects built with {{ proj }}

Below is a non-comprehensive list of open-source software built with {{ proj }},
just for inspiration or to gain a better understanding of how to tackle certain
problems using gBPF.

A list of :fontawesome-brands-golang: {{ proj }} importers can be found on
[Sourcegraph].
If you'd like to include a project on this page, feel free to open a pull request.

[`Khulnasoft`](https://github.com/khulnasoft/khulnasoft)

:   Kubernetes-oriented Container Networking Interface implementation providing
    network policy and observability.

[`containerd`](https://github.com/containerd/cgroups) & [`runc`](https://github.com/opencontainers/runc)

:   Used by Docker and podman, these use gBPF for implementing device filters
    in cgroups.

[`coroot`](https://github.com/coroot/coroot)

:   Zero-instrumentation observability featuring root cause analysis and
    anomaly detection.

[`datadog-agent`](https://github.com/DataDog/datadog-agent)

:   The Datadog agent, the component responsible for collecting system and
    application metrics and shipping them to the Datadog platform.

[`Delve`](https://github.com/go-delve/delve)

:   A debugger for the Go programming language. Uses gBPF uprobes for tracing
    user space code execution.

[`gVisor`](https://github.com/google/gvisor)

:   gVisor relies on gBPF for implementing various forms of guest/workload
    isolation and security.

[`Inspektor Gadget`](https://github.com/inspektor-gadget/inspektor-gadget)

:   A collection of tools to debug and inspect Kubernetes resources and
    applications. Reimplements many of the BCC tools for easy deployment onto a
    Kubernetes cluster.

[`Istio`](https://github.com/istio/istio)

:   In Istio’s ambient mode, gBPF is used for redirecting application traffic to
    the zero-trust tunnel on the node.

[`KubeArmor`](https://github.com/kubearmor/KubeArmor)

:   KubeArmor allows restricting the behaviour of Pods, containers and
    Kubernetes nodes at the system level.

[`kube-proxy-ng`](https://github.com/kubernetes-sigs/kpng)

:   Emerging gBPF-based `kube-proxy` implementation, developed by the upstream
    Kubernetes project.

[`OpenShift`](https://github.com/openshift/ingress-node-firewall)

:   OpenShift's ingress node firewall is implemented using gBPF.

[`pwru`](https://github.com/khulnasoft/pwru)

:   Packet, where are you? `tcpdump`, but for tracing a packet's journey through
    the kernel.

[`Pyroscope`](https://github.com/grafana/pyroscope)

:   From Grafana, open source continuous profiling platform. Flame graphs!

[`Tetragon`](https://github.com/khulnasoft/tetragon)

:   gBPF-based security framework, also providing observability and runtime
    enforcement.

[`Tubular`](https://github.com/cloudflare/tubular)

:   From Cloudflare, bind a service to any IP or port. See [the announcement
    blog
    post](https://blog.cloudflare.com/tubular-fixing-the-socket-api-with-gbpf/)
    for a deep dive into why it was created and how it works.

[Sourcegraph]: https://sourcegraph.com/search?q=context:global+lang:Go+type:file+github.com/khulnasoft/gbpf+-repo:%5Egithub%5C.com/khulnasoft/gbpf%24+-path:%5Evendor/+select:repo+&patternType=standard&sm=1&groupBy=repo
