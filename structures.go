package main

import (
	"time"
)

type snifferConfig struct {
	deviceName      string // Used for opening live capture
	deviceAlias     string // Used for retrieving hardware address of the device
	deviceHWAddress string
	snapLength      int32
	timeout         time.Duration
	statsInterval   time.Duration
	ttlInterval     time.Duration
}

type influxConfig struct {
	bucket string
	org    string
	token  string
	url    string
	agent  string
}
