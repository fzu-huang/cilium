// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/cilium/hive/job"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"

	"github.com/cilium/cilium/pkg/client"
)

// ExternalIPAMAllocatorParams 是创建 externalIPAMAllocator 所需的参数。
type ExternalIPAMAllocatorParams struct {
	Logger *slog.Logger

	IPv4Enabled bool
	IPv6Enabled bool

	// SocketPath 是外部 IPAM 服务的 Unix socket 路径。
	// 若为空，则使用 cilium agent 默认的 socket 路径。
	SocketPath string

	// LocalNode 是本地 CiliumNode 资源，用于监听 Spec.IPAM.PodCIDRs 变化。
	LocalNode agentK8s.LocalCiliumNodeResource

	// LocalNodeStore 用于将 PodCIDRs 同步到本地节点状态。
	LocalNodeStore *node.LocalNodeStore

	// JobGroup 用于启动后台 job。
	JobGroup job.Group
}

// externalIPAMAllocator 通过 Unix socket 调用 cilium IPAM REST API 来分配/释放 IP，
// 同时监听 CiliumNode 的 Spec.IPAM.PodCIDRs 变化并同步到 LocalNodeStore。
type externalIPAMAllocator struct {
	logger  *slog.Logger
	family  Family
	sockURL string // 形如 "unix:///var/run/cilium/cilium.sock"

	// mu 保护 client 的懒加载
	mu     sync.Mutex
	cached *client.Client
}

// newExternalIPAMAllocators 创建 IPv4 和 IPv6 两个 externalIPAMAllocator，
// 并启动 PodCIDRs 同步 job。
func newExternalIPAMAllocators(p ExternalIPAMAllocatorParams) (Allocator, Allocator) {
	sockURL := p.SocketPath
	if sockURL == "" {
		// 使用与 cilium agent 相同的默认 unix socket 地址
		sockURL = client.DefaultSockPathProtocol()
	} else {
		sockURL = "unix://" + sockURL
	}

	v4 := &externalIPAMAllocator{
		logger:  p.Logger,
		family:  IPv4,
		sockURL: sockURL,
	}
	v6 := &externalIPAMAllocator{
		logger:  p.Logger,
		family:  IPv6,
		sockURL: sockURL,
	}

	// 启动 PodCIDRs 同步 job，参考 multipool 的 startLocalNodeAllocCIDRsSync
	startExternalIPAMLocalNodeSync(p.IPv4Enabled, p.IPv6Enabled, p.JobGroup, p.LocalNode, p.LocalNodeStore)

	return v4, v6
}

// getClient 懒加载并缓存 cilium client。
func (e *externalIPAMAllocator) getClient() (*client.Client, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.cached != nil {
		return e.cached, nil
	}

	c, err := client.NewClient(e.sockURL)
	if err != nil {
		return nil, fmt.Errorf("external IPAM: failed to connect to %s: %w", e.sockURL, err)
	}
	e.cached = c
	return c, nil
}

// familyStr 返回地址族字符串，用于 IPAM API 调用。
func (e *externalIPAMAllocator) familyStr() string {
	if e.family == IPv4 {
		return "ipv4"
	}
	return "ipv6"
}

// Allocate 分配指定 IP（通过 PostIpamIP API）。
func (e *externalIPAMAllocator) Allocate(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	return e.AllocateWithoutSyncUpstream(ip, owner, pool)
}

// AllocateWithoutSyncUpstream 分配指定 IP，不触发上游同步。
func (e *externalIPAMAllocator) AllocateWithoutSyncUpstream(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	c, err := e.getClient()
	if err != nil {
		return nil, err
	}

	poolStr := pool.String()
	if err := c.IPAMAllocateIP(ip.String(), owner, poolStr); err != nil {
		return nil, fmt.Errorf("external IPAM: allocate IP %s failed: %w", ip, err)
	}

	return &AllocationResult{
		IP:         ip,
		IPPoolName: pool,
	}, nil
}

// Release 释放已分配的 IP。
func (e *externalIPAMAllocator) Release(ip net.IP, pool Pool) error {
	c, err := e.getClient()
	if err != nil {
		return err
	}

	if err := c.IPAMReleaseIP(ip.String(), pool.String()); err != nil {
		return fmt.Errorf("external IPAM: release IP %s failed: %w", ip, err)
	}
	return nil
}

// AllocateNext 通过 PostIpam API 分配下一个可用 IP。
func (e *externalIPAMAllocator) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	return e.AllocateNextWithoutSyncUpstream(owner, pool)
}

// AllocateNextWithoutSyncUpstream 分配下一个可用 IP，不触发上游同步。
func (e *externalIPAMAllocator) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	c, err := e.getClient()
	if err != nil {
		return nil, err
	}

	family := e.familyStr()
	poolStr := pool.String()
	resp, err := c.IPAMAllocate(family, owner, poolStr, false)
	if err != nil {
		return nil, fmt.Errorf("external IPAM: allocate next IP failed: %w", err)
	}

	if resp == nil || resp.Address == nil {
		return nil, fmt.Errorf("external IPAM: invalid response from IPAM service")
	}

	var ipStr string
	if e.family == IPv4 {
		ipStr = resp.Address.IPV4
	} else {
		ipStr = resp.Address.IPV6
	}

	if ipStr == "" {
		return nil, fmt.Errorf("external IPAM: no %s address returned", family)
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("external IPAM: invalid IP address %q returned", ipStr)
	}

	return &AllocationResult{
		IP:         ip,
		IPPoolName: pool,
	}, nil
}

// Dump 返回当前分配状态（external IPAM 不维护本地状态，返回空）。
func (e *externalIPAMAllocator) Dump() (map[Pool]map[string]string, string) {
	return nil, fmt.Sprintf("external IPAM via %s", e.sockURL)
}

// Capacity 返回容量（external IPAM 不维护本地容量信息，返回 0）。
func (e *externalIPAMAllocator) Capacity() uint64 {
	return 0
}

// RestoreFinished 标记恢复完成（external IPAM 无需特殊处理）。
func (e *externalIPAMAllocator) RestoreFinished() {}

// startExternalIPAMLocalNodeSync 启动一个后台 job，监听本地 CiliumNode 资源的变化，
// 将 Spec.IPAM.PodCIDRs 同步到 LocalNodeStore，与 multipool 的机制保持一致。
func startExternalIPAMLocalNodeSync(
	enableIPv4, enableIPv6 bool,
	jobGroup job.Group,
	localNode agentK8s.LocalCiliumNodeResource,
	localNodeStore *node.LocalNodeStore,
) {
	jobGroup.Add(
		job.Observer(
			"external-ipam-local-node-syncer",
			func(ctx context.Context, ev resource.Event[*ciliumv2.CiliumNode]) error {
				defer ev.Done(nil)

				if ev.Kind != resource.Upsert {
					return nil
				}

				no := nodeTypes.ParseCiliumNode(ev.Object)
				localNodeStore.Update(func(n *node.LocalNode) {
					if enableIPv4 && no.IPv4AllocCIDR != nil {
						n.IPv4AllocCIDR = no.IPv4AllocCIDR
						n.IPv4SecondaryAllocCIDRs = no.IPv4SecondaryAllocCIDRs
					}
					if enableIPv6 && no.IPv6AllocCIDR != nil {
						n.IPv6AllocCIDR = no.IPv6AllocCIDR
						n.IPv6SecondaryAllocCIDRs = no.IPv6SecondaryAllocCIDRs
					}
				})

				return nil
			},
			localNode,
		),
	)
}

var _ Allocator = (*externalIPAMAllocator)(nil)

// logExternalIPAMEvent 记录 external IPAM 事件日志（供调试使用）。
func logExternalIPAMEvent(logger *slog.Logger, msg string, ip net.IP, pool Pool) {
	logger.Debug(
		msg,
		logfields.IPAddr, ip,
		logfields.PoolName, pool,
	)
}
