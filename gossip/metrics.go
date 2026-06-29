package gossip

import (
	"encoding/json"
	"sync/atomic"

	"github.com/tmc/go-iroh/internal/gossipproto"
	"github.com/tmc/go-iroh/internal/postcard"
	"github.com/tmc/go-iroh/metrics"
)

// Metrics is a snapshot of gossip counters.
type Metrics struct {
	MsgsCtrlSent           uint64
	MsgsCtrlRecv           uint64
	MsgsDataSent           uint64
	MsgsDataRecv           uint64
	MsgsDataSentSize       uint64
	MsgsDataRecvSize       uint64
	MsgsCtrlSentSize       uint64
	MsgsCtrlRecvSize       uint64
	NeighborUp             uint64
	NeighborDown           uint64
	ActorTickMain          uint64
	ActorTickRx            uint64
	ActorTickEndpoint      uint64
	ActorTickDialer        uint64
	ActorTickDialerSuccess uint64
	ActorTickDialerFailure uint64
	ActorTickInEventRx     uint64
	ActorTickTimers        uint64
}

// String implements expvar.Var, returning the metrics snapshot as JSON.
func (m Metrics) String() string {
	b, _ := json.Marshal(m)
	return string(b)
}

// Snapshot returns m as named counter values for [metrics.Registry].
func (m Metrics) Snapshot() metrics.Snapshot {
	return metrics.Snapshot{
		"msgs_ctrl_sent":            m.MsgsCtrlSent,
		"msgs_ctrl_recv":            m.MsgsCtrlRecv,
		"msgs_data_sent":            m.MsgsDataSent,
		"msgs_data_recv":            m.MsgsDataRecv,
		"msgs_data_sent_size":       m.MsgsDataSentSize,
		"msgs_data_recv_size":       m.MsgsDataRecvSize,
		"msgs_ctrl_sent_size":       m.MsgsCtrlSentSize,
		"msgs_ctrl_recv_size":       m.MsgsCtrlRecvSize,
		"neighbor_up":               m.NeighborUp,
		"neighbor_down":             m.NeighborDown,
		"actor_tick_main":           m.ActorTickMain,
		"actor_tick_rx":             m.ActorTickRx,
		"actor_tick_endpoint":       m.ActorTickEndpoint,
		"actor_tick_dialer":         m.ActorTickDialer,
		"actor_tick_dialer_success": m.ActorTickDialerSuccess,
		"actor_tick_dialer_failure": m.ActorTickDialerFailure,
		"actor_tick_in_event_rx":    m.ActorTickInEventRx,
		"actor_tick_timers":         m.ActorTickTimers,
	}
}

type gossipMetrics struct {
	msgsCtrlSent           atomic.Uint64
	msgsCtrlRecv           atomic.Uint64
	msgsDataSent           atomic.Uint64
	msgsDataRecv           atomic.Uint64
	msgsDataSentSize       atomic.Uint64
	msgsDataRecvSize       atomic.Uint64
	msgsCtrlSentSize       atomic.Uint64
	msgsCtrlRecvSize       atomic.Uint64
	neighborUp             atomic.Uint64
	neighborDown           atomic.Uint64
	actorTickMain          atomic.Uint64
	actorTickRx            atomic.Uint64
	actorTickEndpoint      atomic.Uint64
	actorTickDialer        atomic.Uint64
	actorTickDialerSuccess atomic.Uint64
	actorTickDialerFailure atomic.Uint64
	actorTickInEventRx     atomic.Uint64
	actorTickTimers        atomic.Uint64
}

func (m *gossipMetrics) snapshot() Metrics {
	if m == nil {
		return Metrics{}
	}
	return Metrics{
		MsgsCtrlSent:           m.msgsCtrlSent.Load(),
		MsgsCtrlRecv:           m.msgsCtrlRecv.Load(),
		MsgsDataSent:           m.msgsDataSent.Load(),
		MsgsDataRecv:           m.msgsDataRecv.Load(),
		MsgsDataSentSize:       m.msgsDataSentSize.Load(),
		MsgsDataRecvSize:       m.msgsDataRecvSize.Load(),
		MsgsCtrlSentSize:       m.msgsCtrlSentSize.Load(),
		MsgsCtrlRecvSize:       m.msgsCtrlRecvSize.Load(),
		NeighborUp:             m.neighborUp.Load(),
		NeighborDown:           m.neighborDown.Load(),
		ActorTickMain:          m.actorTickMain.Load(),
		ActorTickRx:            m.actorTickRx.Load(),
		ActorTickEndpoint:      m.actorTickEndpoint.Load(),
		ActorTickDialer:        m.actorTickDialer.Load(),
		ActorTickDialerSuccess: m.actorTickDialerSuccess.Load(),
		ActorTickDialerFailure: m.actorTickDialerFailure.Load(),
		ActorTickInEventRx:     m.actorTickInEventRx.Load(),
		ActorTickTimers:        m.actorTickTimers.Load(),
	}
}

func (m *gossipMetrics) recordSend(msg gossipproto.TopicMessage) {
	if isDataMessage(msg) {
		m.msgsDataSent.Add(1)
		m.msgsDataSentSize.Add(messageSize(msg))
		return
	}
	m.msgsCtrlSent.Add(1)
	m.msgsCtrlSentSize.Add(messageSize(msg))
}

func (m *gossipMetrics) recordRecv(msg gossipproto.TopicMessage) {
	if isDataMessage(msg) {
		m.msgsDataRecv.Add(1)
		m.msgsDataRecvSize.Add(messageSize(msg))
		return
	}
	m.msgsCtrlRecv.Add(1)
	m.msgsCtrlRecvSize.Add(messageSize(msg))
}

func isDataMessage(msg gossipproto.TopicMessage) bool {
	return msg.Kind == gossipproto.TopicMessageGossip && msg.Gossip.Kind == gossipproto.PlumtreeGossip
}

func messageSize(msg gossipproto.TopicMessage) uint64 {
	b, err := postcard.Marshal(msg)
	if err != nil {
		return 0
	}
	return uint64(len(b))
}
