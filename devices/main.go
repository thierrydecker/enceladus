package devices

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

func Devices() {
	fmt.Println()
	fmt.Println("Devices found on this host:")
	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Devices : %v\n\n", devices)
	for idx, device := range devices {
		fmt.Printf("Device %v name: %v\n", idx, device.Name)
		fmt.Printf("Device %v description: %v\n", idx, device.Description)
		fmt.Printf("Device %v flags: %v\n", idx, device.Flags)
		for id, address := range device.Addresses {
			fmt.Printf("Device %v IP %v       : %v\n", idx, id, address.IP)
		}
		fmt.Println()
	}
}
