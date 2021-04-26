package main

import (
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type snifferConfig struct {
	deviceName    string
	snapLength    int32
	timeout       time.Duration
	statsInterval time.Duration
	ttlInterval   time.Duration
}

var (
	/*
		Wait groups used to synchronize starting processes
	*/
	wgSignalsHandlersPending = sync.WaitGroup{}
	wgCaptureStatsPending    = sync.WaitGroup{}
	wgPacketHandlerPending   = sync.WaitGroup{}
	/*
		Wait groups used to synchronize stopping processes
	*/
	wgSignalsHandlersRunning = sync.WaitGroup{}
	wgCaptureStatsRunning    = sync.WaitGroup{}
	wgPacketHandlerRunning   = sync.WaitGroup{}
	/*
		Channels used to synchronize processes activity
	*/
	signals            = make(chan os.Signal, 1)
	doneSignal         = make(chan bool, 1)
	doneCaptureStats   = make(chan bool, 1)
	donePacketHandling = make(chan bool, 1)
	/*
		Capture configuration
	*/
	conf = snifferConfig{
		deviceName:    "\\Device\\NPF_{E9D609AF-F749-4AFD-83CF-FADD7F780699}",
		snapLength:    1600,
		timeout:       pcap.BlockForever,
		statsInterval: 60 * time.Second,
		ttlInterval:   100 * time.Nanosecond,
	}
)

func main() {
	/*
		Setup capture
	*/
	handle, err := pcap.OpenLive(conf.deviceName, conf.snapLength, false, conf.timeout)
	if err != nil {
		panic(err)
	}
	defer handle.Close()
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
	defer func(logger *zap.SugaredLogger) {
		err := logger.Sync()
		if err != nil {
			panic(err)
		}
	}(l)
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
	l.Info("Application: Signal handler started")
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
		Starting packet handler
	*/
	l.Debug("Main application: starting packet handling")
	wgPacketHandlerPending.Add(1)
	wgPacketHandlerRunning.Add(1)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChannel := packetSource.Packets()
	go handlePacket(packetChannel, donePacketHandling, l)
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
				Stop capture statistics
			*/
			l.Info("Main application: Stopping capture statistics...")
			doneCaptureStats <- true
			wgCaptureStatsRunning.Wait()
			l.Info("Main application: Capture statistics stopped")
			/*
				Stopping packet handler
			*/
			l.Info("Main application: Stopping packet handler...")
			donePacketHandling <- true
			wgPacketHandlerRunning.Wait()
			l.Info("Main application: Packet handler stopped")
			/*
				Log final statistics
			*/
			stats, _ := handle.Stats()
			received := uint64(stats.PacketsReceived)
			dropped := uint64(stats.PacketsDropped)
			ifDropped := uint64(stats.PacketsIfDropped)
			if dropped == 0 && ifDropped == 0 {
				l.Infof("Main application: Received %v, dropped %v and ifdropped %v packets", received, dropped, ifDropped)
			} else {
				l.Warnf("Main application: Received %v, dropped %v and ifdropped %v packets", received, dropped, ifDropped)
			}
			/*
				Application is now stopped
			*/
			l.Info("Main application: Stopped")
			return
		default:
			time.Sleep(conf.ttlInterval)
		}
	}

}

func applicationLogger() (*zap.SugaredLogger, error) {
	/*
		applicationLogger returns an *zap.SugaredLogger used for logging across the application
	*/
	config := zap.Config{
		Encoding:         "console",
		Level:            zap.NewAtomicLevelAt(zapcore.InfoLevel),
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stdout"},
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey:   "message",
			LevelKey:     "level",
			EncodeLevel:  zapcore.CapitalColorLevelEncoder,
			TimeKey:      "time",
			EncodeTime:   zapcore.ISO8601TimeEncoder,
			CallerKey:    "caller",
			EncodeCaller: zapcore.ShortCallerEncoder,
		},
	}
	logger, err := config.Build()
	if err != nil {
		return nil, err
	}
	return logger.Sugar(), nil
}

func handleSignals(s <-chan os.Signal, d chan<- bool, l *zap.SugaredLogger) {
	/*
		Signal handling
	*/
	defer wgSignalsHandlersRunning.Done()
	l.Debug("Signal handler: running")
	wgSignalsHandlersPending.Done()
	for {
		select {
		case s := <-s:
			l.Debugf("Signal handler: received %v signal", s)
			d <- true
			return
		default:
			time.Sleep(conf.ttlInterval)
		}
	}
}

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
			ifDropped := uint64(stats.PacketsIfDropped)
			if dropped == 0 && ifDropped == 0 {
				l.Infof("Statistics: Received %v, dropped %v and ifdropped %v packets", received, dropped, ifDropped)
			} else {
				l.Warnf("Statistics: Received %v, dropped %v and ifdropped %v packets", received, dropped, ifDropped)
			}
		default:
			time.Sleep(conf.ttlInterval)
		}
	}
}

func handlePacket(p <-chan gopacket.Packet, d <-chan bool, l *zap.SugaredLogger) {
	defer wgPacketHandlerRunning.Done()
	l.Debug("Packet handling: running")
	wgPacketHandlerPending.Done()
	for {
		select {
		case _ = <-d:
			l.Debug("Packet handling: Stopping...")
			return
		case packet := <-p:
			ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethernetLayer != nil {
				ethernet, _ := ethernetLayer.(*layers.Ethernet)
				src := ethernet.SrcMAC
				dst := ethernet.SrcMAC
				typ := ethernet.EthernetType
				l.Debugf("Packet handling: Received Ethernet frame, src: %v, dst: %v, type: %v", src, dst, typ)
			} else {
				l.Warn("Packet handling: Received unknown frame")
			}
		default:
			time.Sleep(conf.ttlInterval)
		}
	}
}
