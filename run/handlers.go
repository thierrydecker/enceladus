package run

import (
	"github.com/google/gopacket"
	"go.uber.org/zap"
)

func handlePacket(p <-chan gopacket.Packet, ptc chan<- gopacket.Packet, d <-chan bool, l *zap.SugaredLogger, n int) {
	defer wgPacketHandlerRunning.Done()
	l.Debugf("Packet handling %v: running", n)
	wgPacketHandlerPending.Done()
	for {
		select {
		case _ = <-d:
			l.Debugf("Packet handling %v: Stopping...", n)
			return
		case pkt := <-p:
			ptc <- pkt
		}
	}
}
