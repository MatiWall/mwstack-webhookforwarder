package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)


var argoeventsWebhook string = "http://webhook-eventsource-svc.argo.svc.cluster.local:12000/build" // FQDN for webhook service

func readSecret() []byte {
	dat, err := os.ReadFile("webhook-secret.txt")
	if err != nil {
		fmt.Print(err)
	}
	return dat
}

func apiMiddleware(secret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("github-webhook-secret", secret)
		c.Next()
	}
}

func test(c *gin.Context) {
	c.String(http.StatusOK, "Working")
}

func verifySignature(c *gin.Context) ([]byte, bool) {
	secret, exists := c.Get("github-webhook-secret")
	if !exists {
		fmt.Println("Secret does not exists")
		return nil, false
	}

	secret = string(secret.([]uint8))

	gotHash := strings.Split(c.GetHeader("X-Hub-Signature-256"), "=")

	if gotHash[0] != "sha256" {
		return nil, false
	}

	body, err := io.ReadAll(c.Request.Body)
	fmt.Println(body)
	if err != nil {
		fmt.Println("Failed reading body when verifying signature")
		return nil, false
	}

	hash := hmac.New(sha256.New, []byte(secret.(string)))

	_, err = hash.Write(body)
	if err != nil {
		fmt.Println("Failed to compute hmac")
		return nil, false
	}

	expectedHash := hex.EncodeToString(hash.Sum(nil))
	receivedHash := gotHash[1]
	return body, receivedHash == expectedHash

}

func forwardWebhook(c *gin.Context) {

	body, ok := verifySignature(c)
	if !ok {
		c.AbortWithStatus(401)
	}
	fmt.Println("Forwarding message: \n %s",  string(body[:]))
	
	http.Post(argoeventsWebhook, "application/json",  bytes.NewReader(body))
	c.String(http.StatusOK, "Successfully forwarded")
}

func main() {
	fmt.Println("Starting webhook forwarder")
	secret := readSecret()
	//fmt.Println(string(secret[:]))
	router := gin.Default()
	router.SetTrustedProxies(nil)

	router.Use(apiMiddleware(secret))
	router.POST("/forward", forwardWebhook)
	router.GET("/", test)
	router.Run("0.0.0.0:8080")
}
