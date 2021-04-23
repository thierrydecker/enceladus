package main

import (
	"os"
	"os/signal"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type snifferConfig struct {
	deviceName    string
	snapLength    int32
	timeout       time.Duration
	statsInterval time.Duration
}

var (
	/*
		Wait groups used to synchronize starting processes
	*/
	wgSignalsHandlersPending = sync.WaitGroup{}
	/*
		Wait groups used to synchronize stopping processes
	*/
	wgSignalsHandlersRunning = sync.WaitGroup{}
	/*
		Channels used to synchronize processes activity
	*/
	signals    = make(chan os.Signal, 1)
	doneSignal = make(chan bool, 1)
	/*
		Capture configuration
	*/
	conf = snifferConfig{
		deviceName:    "\\Device\\NPF_{E9D609AF-F749-4AFD-83CF-FADD7F780699}",
		snapLength:    1600,
		timeout:       pcap.BlockForever,
		statsInterval: 2 * time.Second,
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
	l.Debug("Application: starting signal handlers")
	wgSignalsHandlersPending.Add(1)
	wgSignalsHandlersRunning.Add(1)
	go handleSignals(signals, doneSignal, l)
	wgSignalsHandlersPending.Wait()
	l.Info("Application: Signal handler started")

	go captureStats(handle, conf.statsInterval, l)

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
				Application is now stopped
			*/
			l.Info("Main application: Stopped")
			return
		default:
			runtime.Gosched()
		}
	}

}

func applicationLogger() (*zap.SugaredLogger, error) {
	/*
		applicationLogger returns an *zap.SugaredLogger used for logging across the application
	*/
	config := zap.Config{
		Encoding:         "console",
		Level:            zap.NewAtomicLevelAt(zapcore.DebugLevel),
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
			runtime.Gosched()
		}
	}
}

func captureStats(handle *pcap.Handle, interval time.Duration, l *zap.SugaredLogger) {
	/*
		Log the capture statistics
	*/
	ticker := time.NewTicker(interval)
	for {
		select {
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
			runtime.Gosched()
		}
	}
}
