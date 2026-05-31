package quic

import "time"

const qntMaxRetryInterval = 2 * time.Second

func qntRetryDelay(attempt uint8, initialRTT time.Duration) time.Duration {
	base := initialRTT / 10
	if base <= 0 {
		return 0
	}
	if attempt > 8 {
		attempt = 8
	}
	interval := base << attempt
	if attempt > 0 {
		interval -= base << (attempt - 1)
	}
	if interval > qntMaxRetryInterval {
		return qntMaxRetryInterval
	}
	return interval
}
