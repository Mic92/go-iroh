package quic

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/ackhandler"
	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

// A hard-blocked connection cannot send, but it must still run its timers: the
// loss detection alarm is what declares the in-flight packets lost and gets the
// frames requeued, so skipping it leaves the connection waiting on the idle
// timeout instead.

// newBlockedTimerConn builds a post-handshake Conn with just enough state for
// maybeResetTimer: a one-hour idle timeout, so any deadline the test observes
// came from a loss detection alarm rather than from the idle timer.
func newBlockedTimerConn(t *testing.T) *Conn {
	t.Helper()
	c := &Conn{}
	c.config = populateConfig(&Config{MaxIdleTimeout: time.Hour})
	c.idleTimeout = time.Hour
	c.handshakeComplete = true
	now := monotime.Now()
	c.creationTime = now
	c.lastPacketReceivedTime = now
	c.rttStats = utils.NewRTTStats()
	c.rttStats.UpdateRTT(100*time.Millisecond, 0)
	c.sentPacketHandler = ackhandler.NewSentPacketHandler(
		0,
		protocol.InitialPacketSize,
		c.rttStats,
		&c.connStats,
		true,
		false,
		func(protocol.PacketNumber) {},
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	)
	c.receivedPacketHandler = *ackhandler.NewReceivedPacketHandler(utils.DefaultLogger)
	c.timer = time.NewTimer(time.Hour)
	t.Cleanup(func() { c.timer.Stop() })
	return c
}

func TestMaybeResetTimerHardBlockedKeepsLossAlarm(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newBlockedTimerConn(t)
		now := monotime.Now()
		c.sentPacketHandler.SentPacket(now, 0, protocol.InvalidPacketNumber, nil,
			[]ackhandler.Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT,
			protocol.ECNNon, 1000, false, false)

		deadline := c.sentPacketHandler.GetLossDetectionTimeout()
		if deadline.IsZero() {
			t.Fatal("no loss detection alarm after sending an ack-eliciting packet")
		}
		if idle := c.nextIdleTimeoutTime(); !deadline.Before(idle) {
			t.Fatalf("loss alarm %v is not before the idle timeout %v; the test cannot tell them apart", deadline, idle)
		}

		c.blocked = blockModeHardBlocked
		c.maybeResetTimer()

		time.Sleep(monotime.Until(deadline) - time.Nanosecond)
		select {
		case <-c.timer.C:
			t.Fatal("timer fired before the loss detection alarm")
		default:
		}
		time.Sleep(time.Nanosecond)
		select {
		case <-c.timer.C:
		default:
			t.Fatal("hard-blocked connection did not arm its loss detection alarm")
		}
	})
}
