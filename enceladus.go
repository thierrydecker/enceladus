package main

import (
	"os"
	"os/signal"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

func main() {
	/*
		Setup application logger
	*/
	l, err := applicationLogger()
	if err != nil {
		panic(err)
	}
	/*
		Flushing Zap buffers
	*/
	defer l.Debugf("Main application: logger buffers flushed")
	defer func(logger *zap.SugaredLogger) {
		err := logger.Sync()
		if err != nil {
			panic(err)
		}
	}(l)
	defer l.Debugf("Main application: flushing logger buffers...")
	hwAddress, err := getHWAddress(conf.deviceAlias)
	if err != nil {
		panic(err)
	}
	if hwAddress == "" {
		l.Warnf("Main application: hardware address not found for device %v", conf.deviceAlias)
		return
	}
	conf.deviceHWAddress = hwAddress
	l.Infof("Main application: hardware address device %v", conf.deviceHWAddress)
	/*
		Setup capture
	*/
	inactive, err := pcap.NewInactiveHandle(conf.deviceName)
	if err != nil {
		panic(err)
	}
	err = inactive.SetBufferSize(320000000)
	if err != nil {
		panic(err)
	}
	err = inactive.SetPromisc(false)
	if err != nil {
		panic(err)
	}
	err = inactive.SetImmediateMode(false)
	if err != nil {
		panic(err)
	}
	err = inactive.SetSnapLen(int(conf.snapLength))
	if err != nil {
		panic(err)
	}
	handle, err := inactive.Activate()
	if err != nil {
		panic(err)
	}
	defer l.Info("Main application: pcap handle cleaned")
	defer inactive.CleanUp()
	defer l.Info("Main application: cleaning up pcap handle...")

	defer l.Info("Main application: pcap handle closed")
	defer handle.Close()
	defer l.Info("Main application: closing up pcap handle...")
	/*
		Relay incoming signals to application
	*/
	signal.Notify(signals, os.Interrupt)
	/*
		Starting signal handler
	*/
	l.Debug("Main application: starting signal handlers")
	wgSignalsHandlersPending.Add(1)
	wgSignalsHandlersRunning.Add(1)
	go handleSignals(signals, doneSignal, l)
	wgSignalsHandlersPending.Wait()
	l.Info("Main application: Signal handler started")
	/*
		Starting capture statistics
	*/
	l.Debug("Main application: starting capture statistics")
	wgCaptureStatsPending.Add(1)
	wgCaptureStatsRunning.Add(1)
	go captureStats(doneCaptureStats, handle, conf.statsInterval, l)
	wgCaptureStatsPending.Wait()
	l.Debug("Main application: Capture statistics started")
	/*
		Starting packet decoder
	*/
	l.Debug("Main application: starting packet decoders")
	for i := 0; i < packetDecodersCount; i++ {
		wgPacketDecoderPending.Add(1)
		wgPacketDecoderRunning.Add(1)
		go decodePacket(packetsToDecode, donePacketDecoding, l, i+1)
	}
	wgPacketDecoderPending.Wait()
	/*
		Starting packet handler
	*/
	l.Debug("Main application: starting packet handlers")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChannel := packetSource.Packets()
	for i := 0; i < packetHandlersCount; i++ {
		wgPacketHandlerPending.Add(1)
		wgPacketHandlerRunning.Add(1)
		go handlePacket(packetChannel, packetsToDecode, donePacketHandling, l, i+1)
	}
	wgPacketHandlerPending.Wait()
	/*
		Application is now running
	*/
	l.Info("Main application: running")
	/*
		Main loop of the application waiting for a signal to stop
	*/
	for {
		select {
		case <-doneSignal:
			l.Info("Main application: exiting...")
			/*
				Stop signal handler
			*/
			l.Info("Main application: Stopping signal handler...")
			wgSignalsHandlersRunning.Wait()
			l.Info("Main application: Signal handler stopped")
			/*
				Stopping packet handler
			*/
			l.Info("Main application: Stopping packets handler...")
			for i := 0; i < packetHandlersCount; i++ {
				donePacketHandling <- true
			}
			wgPacketHandlerRunning.Wait()
			l.Info("Main application: Packet handlers stopped")

			/*
				Stopping packet decoder
			*/
			l.Info("Main application: Stopping packets decoder...")
			for i := 0; i < packetDecodersCount; i++ {
				donePacketDecoding <- true
			}
			wgPacketDecoderRunning.Wait()
			l.Info("Main application: Packet decoders stopped")

			/*
				Stop capture statistics
			*/
			l.Info("Main application: Stopping capture statistics...")
			doneCaptureStats <- true
			wgCaptureStatsRunning.Wait()
			l.Info("Main application: Capture statistics stopped")
			/*
				Log final statistics
			*/
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
			return
		default:
			time.Sleep(conf.ttlInterval)
		}
	}
}
