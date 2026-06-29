package iroh

import (
	"encoding/json"
	"io"
	"sync/atomic"

	"github.com/tmc/go-iroh/internal/socket"
	"github.com/tmc/go-iroh/metrics"
)

// Metrics is a snapshot of endpoint counters.
type Metrics struct {
	ConnectsStarted  uint64
	ConnectsAccepted uint64
	ConnectsFailed   uint64
	AcceptsStarted   uint64
	AcceptsAccepted  uint64
	AcceptsFailed    uint64
	Socket           SocketMetrics
	NetReport        NetReportMetrics
}

// SocketMetrics is a snapshot of endpoint magic-socket datagram counters.
type SocketMetrics struct {
	UpdateDirectAddrs           uint64
	SendIPv4                    uint64
	SendIPv6                    uint64
	SendRelay                   uint64
	SendCustom                  uint64
	SendEndpointID              uint64
	SendBlackholed              uint64
	RecvDataIPv4                uint64
	RecvDataIPv6                uint64
	RecvDataRelay               uint64
	RecvDataCustom              uint64
	RecvDatagrams               uint64
	RelayHomeChange             uint64
	HolepunchAttempts           uint64
	PathsDirect                 uint64
	PathsRelay                  uint64
	PathsCustom                 uint64
	NumConnsDirect              uint64
	NumConnsOpened              uint64
	NumConnsClosed              uint64
	TransportIPPathsAdded       uint64
	TransportIPPathsRemoved     uint64
	TransportRelayPathsAdded    uint64
	TransportRelayPathsRemoved  uint64
	TransportCustomPathsAdded   uint64
	TransportCustomPathsRemoved uint64
	ActorLinkChange             uint64
}

// NetReportMetrics is a snapshot of endpoint net_report counters.
type NetReportMetrics struct {
	Reports                       uint64
	ReportsFull                   uint64
	PortmapAttempts               uint64
	PortmapExternalAddressUpdated uint64
	ReportsFailed                 uint64
}

// String implements expvar.Var, returning the metrics snapshot as JSON.
func (m Metrics) String() string {
	b, _ := json.Marshal(m)
	return string(b)
}

// Snapshot returns m as named counter values for [metrics.Registry].
func (m Metrics) Snapshot() metrics.Snapshot {
	return metrics.Snapshot{
		"connects_started":                            m.ConnectsStarted,
		"connects_accepted":                           m.ConnectsAccepted,
		"connects_failed":                             m.ConnectsFailed,
		"accepts_started":                             m.AcceptsStarted,
		"accepts_accepted":                            m.AcceptsAccepted,
		"accepts_failed":                              m.AcceptsFailed,
		"socket_update_direct_addrs":                  m.Socket.UpdateDirectAddrs,
		"socket_send_ipv4":                            m.Socket.SendIPv4,
		"socket_send_ipv6":                            m.Socket.SendIPv6,
		"socket_send_relay":                           m.Socket.SendRelay,
		"socket_send_custom":                          m.Socket.SendCustom,
		"socket_send_endpoint_id":                     m.Socket.SendEndpointID,
		"socket_send_blackholed":                      m.Socket.SendBlackholed,
		"socket_recv_data_ipv4":                       m.Socket.RecvDataIPv4,
		"socket_recv_data_ipv6":                       m.Socket.RecvDataIPv6,
		"socket_recv_data_relay":                      m.Socket.RecvDataRelay,
		"socket_recv_data_custom":                     m.Socket.RecvDataCustom,
		"socket_recv_datagrams":                       m.Socket.RecvDatagrams,
		"socket_relay_home_change":                    m.Socket.RelayHomeChange,
		"socket_holepunch_attempts":                   m.Socket.HolepunchAttempts,
		"socket_paths_direct":                         m.Socket.PathsDirect,
		"socket_paths_relay":                          m.Socket.PathsRelay,
		"socket_paths_custom":                         m.Socket.PathsCustom,
		"socket_num_conns_direct":                     m.Socket.NumConnsDirect,
		"socket_num_conns_opened":                     m.Socket.NumConnsOpened,
		"socket_num_conns_closed":                     m.Socket.NumConnsClosed,
		"socket_transport_ip_paths_added":             m.Socket.TransportIPPathsAdded,
		"socket_transport_ip_paths_removed":           m.Socket.TransportIPPathsRemoved,
		"socket_transport_relay_paths_added":          m.Socket.TransportRelayPathsAdded,
		"socket_transport_relay_paths_removed":        m.Socket.TransportRelayPathsRemoved,
		"socket_transport_custom_paths_added":         m.Socket.TransportCustomPathsAdded,
		"socket_transport_custom_paths_removed":       m.Socket.TransportCustomPathsRemoved,
		"socket_actor_link_change":                    m.Socket.ActorLinkChange,
		"net_report_reports":                          m.NetReport.Reports,
		"net_report_reports_full":                     m.NetReport.ReportsFull,
		"net_report_portmap_attempts":                 m.NetReport.PortmapAttempts,
		"net_report_portmap_external_address_updated": m.NetReport.PortmapExternalAddressUpdated,
		"net_report_reports_failed":                   m.NetReport.ReportsFailed,
	}
}

// WriteOpenMetrics writes m in OpenMetrics text format under the "endpoint"
// prefix.
func (m Metrics) WriteOpenMetrics(w io.Writer) error {
	r := metrics.NewRegistry()
	if err := r.Register("endpoint", m); err != nil {
		return err
	}
	return r.WriteOpenMetrics(w)
}

type endpointMetrics struct {
	connectsStarted                        atomic.Uint64
	connectsAccepted                       atomic.Uint64
	connectsFailed                         atomic.Uint64
	acceptsStarted                         atomic.Uint64
	acceptsAccepted                        atomic.Uint64
	acceptsFailed                          atomic.Uint64
	netReportReports                       atomic.Uint64
	netReportReportsFull                   atomic.Uint64
	netReportPortmapAttempts               atomic.Uint64
	netReportPortmapExternalAddressUpdated atomic.Uint64
	netReportFailed                        atomic.Uint64
}

func (m *endpointMetrics) snapshot(socketMetrics SocketMetrics) Metrics {
	return Metrics{
		ConnectsStarted:  m.connectsStarted.Load(),
		ConnectsAccepted: m.connectsAccepted.Load(),
		ConnectsFailed:   m.connectsFailed.Load(),
		AcceptsStarted:   m.acceptsStarted.Load(),
		AcceptsAccepted:  m.acceptsAccepted.Load(),
		AcceptsFailed:    m.acceptsFailed.Load(),
		Socket:           socketMetrics,
		NetReport: NetReportMetrics{
			Reports:                       m.netReportReports.Load(),
			ReportsFull:                   m.netReportReportsFull.Load(),
			PortmapAttempts:               m.netReportPortmapAttempts.Load(),
			PortmapExternalAddressUpdated: m.netReportPortmapExternalAddressUpdated.Load(),
			ReportsFailed:                 m.netReportFailed.Load(),
		},
	}
}

// Metrics returns a point-in-time snapshot of endpoint counters.
func (e *Endpoint) Metrics() Metrics {
	var socketMetrics SocketMetrics
	if e != nil && e.magic != nil {
		socketMetrics = socketMetricsFromInternal(e.magic.Metrics())
	}
	return e.metrics.snapshot(socketMetrics)
}

func socketMetricsFromInternal(s socket.MetricsSnapshot) SocketMetrics {
	return SocketMetrics{
		UpdateDirectAddrs:           s.UpdateDirectAddrs,
		SendIPv4:                    s.IPv4Sent,
		SendIPv6:                    s.IPv6Sent,
		SendRelay:                   s.RelaySent,
		SendCustom:                  s.CustomSent,
		SendEndpointID:              s.EndpointIDSent,
		SendBlackholed:              s.Blackholed,
		RecvDataIPv4:                s.IPv4Recv,
		RecvDataIPv6:                s.IPv6Recv,
		RecvDataRelay:               s.RelayRecv,
		RecvDataCustom:              s.CustomRecv,
		RecvDatagrams:               s.RecvDatagrams,
		RelayHomeChange:             s.RelayHomeChange,
		HolepunchAttempts:           s.HolepunchAttempts,
		PathsDirect:                 s.PathsDirect,
		PathsRelay:                  s.PathsRelay,
		PathsCustom:                 s.PathsCustom,
		NumConnsDirect:              s.NumConnsDirect,
		NumConnsOpened:              s.NumConnsOpened,
		NumConnsClosed:              s.NumConnsClosed,
		TransportIPPathsAdded:       s.TransportIPPathsAdded,
		TransportIPPathsRemoved:     s.TransportIPPathsRemoved,
		TransportRelayPathsAdded:    s.TransportRelayPathsAdded,
		TransportRelayPathsRemoved:  s.TransportRelayPathsRemoved,
		TransportCustomPathsAdded:   s.TransportCustomPathsAdded,
		TransportCustomPathsRemoved: s.TransportCustomPathsRemoved,
		ActorLinkChange:             s.ActorLinkChange,
	}
}
