package main

import (
	"net"
)

func getHWAddress(deviceName string) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, device := range interfaces {
		if device.Name == deviceName {
			return device.HardwareAddr.String(), nil
		}
	}
	return "", err
}
