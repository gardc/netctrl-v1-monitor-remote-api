package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"log"
	"net"
	"netctrl.io/monitor/remote-api/networking"
	"os"
	"strings"
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

		if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			c.Next()
		} else {
			c.AbortWithStatus(401)
			return
		}
	}
}

func main() {
	// Load .env file (if there is one) and set jwtSecret
	_ = godotenv.Load()
	jwtSecret = []byte(os.Getenv("JWT_SIGNING_KEY"))
	if len(jwtSecret) <= 0 {
		panic("no JWT_SIGNING_KEY set")
	}

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

	}

	r.Run() // listen and serve on 0.0.0.0:8080

}
