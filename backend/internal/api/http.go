package api

import (
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func NewRouter(
	targetHandler *TargetHandler,
	scanHandler *ScanHandler,
) *gin.Engine {
	router := gin.New()

	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	router.Use(cors.New(cors.Config{
		AllowOrigins: []string{
			"http://localhost:3000",
			"http://localhost:5173",
		},
		AllowMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowHeaders: []string{
			"Origin",
			"Content-Type",
			"Accept",
			"Authorization",
		},
	}))

	api := router.Group("/api")

	targets := api.Group("/targets")
	{
		targets.POST("", targetHandler.Create)
		targets.GET("", targetHandler.List)
		targets.GET("/:id", targetHandler.Get)
		targets.PUT("/:id", targetHandler.Update)
		targets.DELETE("/:id", targetHandler.Delete)
	}

	scans := api.Group("/scans")
	{
		scans.POST("/:targetID", scanHandler.Scan)
		scans.GET("/recent", scanHandler.ListRecent)
		scans.GET("/targets/:targetID/latest", scanHandler.GetLatest)
	}

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

	return router
}
