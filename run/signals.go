package run

import (
	"os"

	"go.uber.org/zap"
)

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
		}
	}
}
