package main

import (
	"time"
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
