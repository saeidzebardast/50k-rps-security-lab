// Gin the way most tutorials end: r.Run(":8080").
package main

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"lab/gin/internal/lab"
)

// Same nested-quantifier pattern as the other vulnerable apps. Go's regexp
// is RE2 (linear time), so this one is NOT exploitable -- the lab shows it.
var slug = regexp.MustCompile(`^([a-z0-9]+-?)*$`)

type orderRequest struct {
	SKU string `json:"sku" binding:"required,max=64"`
	Qty int    `json:"qty" binding:"required,min=1,max=100"`
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New() // MISTAKE: trusts every proxy -> c.ClientIP() is forgeable
	r.Use(gin.Recovery())
	limiter := lab.NewLimiter(5, time.Minute)

	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	r.GET("/search", func(c *gin.Context) {
		q := c.Query("q")
		c.JSON(http.StatusOK, gin.H{"q": q, "valid": slug.MatchString(q)})
	})

	r.POST("/orders", func(c *gin.Context) {
		var req orderRequest
		// MISTAKE: no MaxBytesReader -- a 500 MB body lands in RAM.
		if err := c.ShouldBindJSON(&req); err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		// MISTAKE: context.Background() -- keeps working after the client left.
		_ = saveOrder(context.Background())
		c.Status(http.StatusAccepted)
	})

	r.POST("/login", func(c *gin.Context) {
		if limiter.Limited(c.ClientIP()) {
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}
		var cr lab.Credentials
		if err := c.ShouldBindJSON(&cr); err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		if cr.Username == "alice" && bcrypt.CompareHashAndPassword(lab.AliceHash, []byte(cr.Password)) == nil {
			c.Status(http.StatusOK)
			return
		}
		c.Status(http.StatusUnauthorized)
	})

	r.POST("/hash", func(c *gin.Context) {
		var cr lab.Credentials
		_ = c.ShouldBindJSON(&cr)
		h, _ := bcrypt.GenerateFromPassword([]byte(cr.Password), 10)
		c.JSON(http.StatusOK, gin.H{"hash": string(h)})
	})

	// MISTAKE: zero-value http.Server -- no read, header, write or idle timeouts.
	_ = r.Run(":8080")
}

func saveOrder(ctx context.Context) error {
	select {
	case <-time.After(5 * time.Millisecond):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
