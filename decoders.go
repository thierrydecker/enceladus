package main

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/log"
	"go.uber.org/zap"
)

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
				dstMac := ethernet.DstMAC
				direction := "Promiscious"
				switch {
				case conf.deviceHWAddress == srcMac.String():
					direction = "out"
				case conf.deviceHWAddress == dstMac.String():
					direction = "in"
				}
				ethernetType := ethernet.EthernetType
				msg := fmt.Sprintf("Packet decoding %v: Received Ethernet frame, ", n)
				msg += fmt.Sprintf("timestamp: %v, ", packetTimestamp)
				msg += fmt.Sprintf("packetLength: %v, ", packetLength)
				msg += fmt.Sprintf("srcMac: %v, ", srcMac)
				msg += fmt.Sprintf("dstMac: %v, ", dstMac)
				msg += fmt.Sprintf("direction: %v, ", direction)
				msg += fmt.Sprintf("ethernetType: %v", ethernetType)
				l.Debug(msg)
				/*
					Send data to InfluxDb
				*/
				point := influxdb2.NewPoint(
					"Ethernet",
					map[string]string{
						"agent":        confDb.agent,
						"device":       conf.deviceAlias,
						"ethernetType": ethernetType.String(),
						"direction":    direction,
					},
					map[string]interface{}{
						"srcMac":       srcMac,
						"dstMac":       dstMac,
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
		}
	}
}
