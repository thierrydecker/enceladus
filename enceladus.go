package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/log"
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

type influxConfig struct {
	bucket string
	org    string
	token  string
	url    string
	agent  string
}

var (
	/*
		Workers counts
	*/
	packetHandlersCount = 1
	packetDecodersCount = 5
	/*
		Wait groups used to synchronize starting processes
	*/
	wgSignalsHandlersPending = sync.WaitGroup{}
	wgCaptureStatsPending    = sync.WaitGroup{}
	wgPacketDecoderPending   = sync.WaitGroup{}
	wgPacketHandlerPending   = sync.WaitGroup{}
	/*
		Wait groups used to synchronize stopping processes
	*/
	wgSignalsHandlersRunning = sync.WaitGroup{}
	wgCaptureStatsRunning    = sync.WaitGroup{}
	wgPacketDecoderRunning   = sync.WaitGroup{}
	wgPacketHandlerRunning   = sync.WaitGroup{}
	/*
		Channels used to synchronize processes activity
	*/
	signals            = make(chan os.Signal, 1)
	doneSignal         = make(chan bool, 1)
	doneCaptureStats   = make(chan bool, 1)
	donePacketDecoding = make(chan bool, packetDecodersCount)
	donePacketHandling = make(chan bool, packetHandlersCount)
	/*
		Channel for buffering packets coming from pcap
	*/
	packetsToDecode = make(chan gopacket.Packet, 2000*packetDecodersCount)
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
	/*
		InfluxDb configuration
	*/
	confDb = influxConfig{
		bucket: "enceladus",
		org:    "Enceladus",
		token:  "ngqTyxbvTtfTKiL7UjjPXNRo33ubL8oP0RLdHsIi7T9st6XEoppL_BUZjjsEzvC6ukNnZXoIGwvutIdwXsRENQ==",
		url:    "http://192.168.56.102:8086",
		agent:  "tdecker",
	}
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
				l.Infof("Statistics: Received %v, dropped %v (%.3f %%) and ifdropped %v packets", received, dropped, droppedPercent, ifDropped)
			} else {
				l.Warnf("Statistics: Received %v, dropped %v (%.3f %%) and ifdropped %v packets", received, dropped, droppedPercent, ifDropped)
			}
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
			droppedPercent := (float64(dropped) / float64(received)) * 100
			ifDropped := uint64(stats.PacketsIfDropped)
			if dropped == 0 && ifDropped == 0 {
				l.Infof("Statistics: Received %v, dropped %v (%.3f %%) and ifdropped %v packets", received, dropped, droppedPercent, ifDropped)
			} else {
				l.Warnf("Statistics: Received %v, dropped %v (%.3f %%) and ifdropped %v packets", received, dropped, droppedPercent, ifDropped)
			}
		default:
			time.Sleep(conf.ttlInterval)
		}
	}
}

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
		default:
			time.Sleep(conf.ttlInterval)
		}
	}
}

func decodePacket(p <-chan gopacket.Packet, d <-chan bool, l *zap.SugaredLogger, n int) {
	defer wgPacketDecoderRunning.Done()
	l.Debugf("Packet decoding %v: running", n)
	/*
		Create InfluxDb client
	*/
	client := influxdb2.NewClientWithOptions(
		confDb.url,
		confDb.token,
		influxdb2.DefaultOptions().
			SetPrecision(time.Nanosecond),
	)
	/*
		Disable InfluxDb logging
	*/
	log.Log = nil
	writeAPI := client.WriteAPI(confDb.org, confDb.bucket)
	errorsCh := writeAPI.Errors()
	go func(l *zap.SugaredLogger) {
		for err := range errorsCh {
			l.Errorf("Packet decoding %v: Write to InfluxDb Error %v", n, err)
		}
	}(l)
	defer client.Close()
	defer writeAPI.Flush()
	wgPacketDecoderPending.Done()
	for {
		select {
		case _ = <-d:
			l.Debugf("Packet decoding %v: Stopping...", n)
			return
		case packet := <-p:
			/*
				Common fields
			*/
			packetTimestamp := time.Now()
			packetLength := len(packet.Data())
			/*
				Decode ethernet layer if present
			*/
			ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethernetLayer != nil {
				/*
					Ethernet fields
				*/
				ethernet, _ := ethernetLayer.(*layers.Ethernet)
				srcMac := ethernet.SrcMAC
				dstMac := ethernet.SrcMAC
				ethernetType := ethernet.EthernetType
				msg := fmt.Sprintf("Packet decoding %v: Received Ethernet frame, ", n)
				msg += fmt.Sprintf("timestamp: %v, ", packetTimestamp)
				msg += fmt.Sprintf("packetLength: %v, ", packetLength)
				msg += fmt.Sprintf("srcMac: %v, ", srcMac)
				msg += fmt.Sprintf("dstMac: %v, ", dstMac)
				msg += fmt.Sprintf("ethernetType: %v", ethernetType)
				l.Debug(msg)
				/*
					Send data to InfluxDb
				*/
				point := influxdb2.NewPoint(
					"Ethernet",
					map[string]string{
						"agent":        confDb.agent,
						"ethernetType": ethernetType.String(),
					},
					map[string]interface{}{
						"srcMac":       srcMac,
						"srcDst":       dstMac,
						"packetLength": packetLength,
					},
					packetTimestamp,
				)
				writeAPI.WritePoint(point)
			} else {
				msg := fmt.Sprintf("Packet decoding %v: Received unknown message, ", n)
				msg += fmt.Sprintf("timestamp: %v, ", packetTimestamp)
				msg += fmt.Sprintf("packetLength: %v, ", packetLength)
				l.Warn(msg)
			}
		default:
			time.Sleep(conf.ttlInterval)
		}
	}
}
