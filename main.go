package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"netctrl.io/monitor/remote-api/networking"
)

var jwtSecret []byte

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authToken := c.GetHeader("Authorization")
		authToken = strings.Replace(authToken, "Bearer ", "", -1)
		token, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})
		if err != nil {
			log.Printf("Error parsing token: %v", err)
			c.AbortWithStatus(400)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Set("proUser", claims["proUser"])
			c.Next()
		} else {
			c.AbortWithStatus(401)
			return
		}
	}
}

type ARPLayerRequest struct {
	SrcMAC    net.HardwareAddr `json:"sm"`
	SrcIP     net.IP           `json:"si"`
	DstMAC    net.HardwareAddr `json:"dm"`
	DstIP     net.IP           `json:"di"`
	ArpOpcode uint16           `json:"o"`
}

func main() {
	// Load .env file (if there is one) and set jwtSecret
	_ = godotenv.Load()
	jwtSecret = []byte(os.Getenv("JWT_SIGNING_KEY"))
	if len(jwtSecret) <= 0 {
		panic("no JWT_SIGNING_KEY set")
	}

	testMAC, _ := net.ParseMAC("00:00:5e:00:53:01")
	testIP := net.ParseIP("192.0.2.1")
	testdata := ARPLayerRequest{
		SrcMAC:    testMAC,
		SrcIP:     testIP,
		DstMAC:    testMAC,
		DstIP:     testIP,
		ArpOpcode: 2,
	}
	// testdataJson, _ := json.Marshal(testdata)
	fmt.Printf("\nTestdata: %+v\n", testdata)

	// Init Gin
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	v1 := r.Group("/v1")
	{
		v1.Use(authMiddleware())

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
			// Check that user is Pro
			if proUser, ok := c.Get("proUser"); !ok || proUser == false {
				c.AbortWithStatus(401)
				return
			}

			var req ARPLayerRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.AbortWithStatus(http.StatusBadRequest)
				return
			}

			packet := networking.CreatePacket(req.SrcMAC, req.SrcIP, req.DstMAC, req.DstIP, req.ArpOpcode)
			// fmt.Printf("packet: %v \n", packet)
			// packetMarshalled, err := json.Marshal(packet)
			// if err != nil {
			// 	c.AbortWithStatus(http.StatusInternalServerError)
			// 	return
			// }

			c.JSON(http.StatusOK, gin.H{
				"packet": packet,
			})
		})
	}

	r.Run() // listen and serve on 0.0.0.0:8080
}
