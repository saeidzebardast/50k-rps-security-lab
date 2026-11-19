// The hardened Gin server from the article, plus the /search, /login and
// /hash routes the attack harness uses. Changes from the article's listing
// are marked "LAB:".
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"lab/gin/internal/lab"
)

const maxBodyBytes = 64 << 10 // 64 KiB: the largest valid order is far smaller

// limitBody caps the request body before any handler or binder reads it.
func limitBody(n int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		// LAB: reject an oversized Content-Length up front instead of
		// reading 64 KiB of it first.
		if c.Request.ContentLength > n {
			c.Header("Connection", "close")
			c.AbortWithStatus(http.StatusRequestEntityTooLarge)
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, n)
		c.Next()
	}
}

type orderRequest struct {
	SKU string `json:"sku" binding:"required,max=64"`
	Qty int    `json:"qty" binding:"required,min=1,max=100"`
}

var slug = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery(), limitBody(maxBodyBytes))

	// Gin trusts every proxy by default. Only our load balancer subnet
	// is allowed to tell us who the client is via X-Forwarded-For.
	// LAB: configurable; "none" means nothing sits in front of us.
	proxies := []string{"10.20.0.0/16"}
	if v := os.Getenv("TRUSTED_PROXIES"); v == "none" {
		proxies = nil
	} else if v != "" {
		proxies = strings.Split(v, ",")
	}
	if err := r.SetTrustedProxies(proxies); err != nil {
		log.Fatal(err)
	}

	r.POST("/orders", func(c *gin.Context) {
		var req orderRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				c.AbortWithStatus(http.StatusRequestEntityTooLarge)
				return
			}
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		// Tie downstream work to the client. If the client goes away or
		// the budget runs out, the goroutine stops instead of leaking.
		ctx, cancel := context.WithTimeout(c.Request.Context(), 800*time.Millisecond)
		defer cancel()

		if err := saveOrder(ctx, req); err != nil {
			c.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		c.Status(http.StatusAccepted)
	})

	// LAB: routes below are not in the article's listing.
	limiter := lab.NewLimiter(5, time.Minute)
	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.GET("/search", func(c *gin.Context) {
		q := c.Query("q")
		if len(q) > 64 {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		c.JSON(http.StatusOK, gin.H{"q": q, "valid": slug.MatchString(q)})
	})
	r.POST("/login", func(c *gin.Context) {
		var cr lab.Credentials
		if err := c.ShouldBindJSON(&cr); err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		if limiter.Limited("ip:"+c.ClientIP()) || limiter.Limited("user:"+cr.Username) {
			c.AbortWithStatus(http.StatusTooManyRequests)
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
		if err := c.ShouldBindJSON(&cr); err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		h, _ := bcrypt.GenerateFromPassword([]byte(cr.Password), 10)
		c.JSON(http.StatusOK, gin.H{"hash": string(h)})
	})

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           r,
		ReadHeaderTimeout: 2 * time.Second,  // slow header senders (Slowloris)
		ReadTimeout:       5 * time.Second,  // slow body senders
		WriteTimeout:      10 * time.Second, // slow readers on the response
		IdleTimeout:       60 * time.Second, // parked keep-alive connections
		MaxHeaderBytes:    16 << 10,         // 16 KiB instead of the 1 MiB default
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("forced shutdown: %v", err)
	}
}

// saveOrder stands in for a real database call that honors ctx.
func saveOrder(ctx context.Context, req orderRequest) error {
	select {
	case <-time.After(5 * time.Millisecond):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
