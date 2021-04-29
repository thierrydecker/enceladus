package main

import (
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

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
		deviceAlias:   "Wifi",
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
		token:  "22uA599OEWY8glANSowAvBmC92BXwbaJLyEIR23XFU23DSci8F7mUWRyVz3nmsgjW2KeemDz6WsDaPLE_37ubA==",
		url:    "http://192.168.56.102:8086",
		agent:  "tdecker",
	}
)
