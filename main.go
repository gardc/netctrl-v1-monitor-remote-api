package main

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"log"
	"net"
	"net/http"
	"netctrl.io/monitor/remote-api/networking"
)

type ARPLayerRequest struct {
	SrcMAC    net.HardwareAddr `json:"sm"`
	SrcIP     net.IP           `json:"si"`
	DstMAC    net.HardwareAddr `json:"dm"`
	DstIP     net.IP           `json:"di"`
	ArpOpcode uint16           `json:"o"`
}

func main() {
	testMAC, _ := net.ParseMAC("00:00:5e:00:53:01")
	testIP := net.ParseIP("192.0.2.1")
	testdata := ARPLayerRequest{
		SrcMAC:    testMAC,
		SrcIP:     testIP,
		DstMAC:    testMAC,
		DstIP:     testIP,
		ArpOpcode: 2,
	}
	testdataJson, _ := json.Marshal(testdata)
	fmt.Printf("\nTestdata: %+v\n", string(testdataJson))

	// Init Gin
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	v1 := r.Group("/v1")
	{
		// Get IPs for scan functionality
		v1.GET("/ips", func(c *gin.Context) {
			ipString := c.Query("ip")
			ip := net.ParseIP(ipString).To4()
			if ip == nil {
				c.JSON(400, gin.H{
					"message": "no IP",
				})
				return
			}
			ipNet := net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(24, 32),
			}
			ips := networking.IPs(&ipNet)
			c.JSON(200, gin.H{
				"ips": ips,
			})
		})

		// Get ARP Layer for ARP spoof function in NS
		v1.POST("/packet", func(c *gin.Context) {
			var req ARPLayerRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				log.Println(err)
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}
			log.Printf("Received json: %v", c.Request.Body)

			packet := networking.CreatePacket(req.SrcMAC, req.SrcIP, req.DstMAC, req.DstIP, req.ArpOpcode)
			// fmt.Printf("packet: %v \n", packet)

			c.JSON(http.StatusOK, gin.H{
				"packet": packet,
			})
		})
	}

	r.Run() // listen and serve on 0.0.0.0:8080
}
