package run

import (
	"time"

	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

func captureStats(d <-chan bool, handle *pcap.Handle, interval time.Duration, l *zap.SugaredLogger) {
	/*
		Log the capture statistics
	*/
	defer wgCaptureStatsRunning.Done()
	ticker := time.NewTicker(interval)
	l.Debug("Capture statistics: running")
	wgCaptureStatsPending.Done()
	for {
		select {
		case _ = <-d:
			l.Debug("Capture statistics: Stopping...")
			return
		case _ = <-ticker.C:
			stats, _ := handle.Stats()
			received := uint64(stats.PacketsReceived)
			dropped := uint64(stats.PacketsDropped)
			droppedPercent := (float64(dropped) / float64(received)) * 100
			ifDropped := uint64(stats.PacketsIfDropped)
			if dropped == 0 && ifDropped == 0 {
				l.Infof("Statistics: Received %v, dropped %v (%.3f %%) and ifdropped %v packets", received, dropped,
					droppedPercent, ifDropped)
			} else {
				l.Warnf("Statistics: Received %v, dropped %v (%.3f %%) and ifdropped %v packets", received, dropped,
					droppedPercent, ifDropped)
			}
		}
	}
}
