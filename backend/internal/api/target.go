package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"certificate-radar/internal/domain"
	"certificate-radar/internal/repository"
)

type TargetService interface {
	Create(
		ctx context.Context,
		input string,
		owner string,
		criticality domain.ServiceCriticality,
	) (domain.Target, error)

	Get(
		ctx context.Context,
		id string,
	) (domain.Target, error)

	List(
		ctx context.Context,
	) ([]domain.Target, error)

	Update(
		ctx context.Context,
		target domain.Target,
	) error

	Delete(
		ctx context.Context,
		id string,
	) error
}

type TargetHandler struct {
	service TargetService
}

func NewTargetHandler(
	targetService TargetService,
) *TargetHandler {
	return &TargetHandler{
		service: targetService,
	}
}

type createTargetRequest struct {
	Target      string `json:"target" binding:"required"`
	Owner       string `json:"owner"`
	Criticality string `json:"criticality"`
}

type targetResponse struct {
	ID          string `json:"id"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	ServerName  string `json:"server_name"`
	Enabled     bool   `json:"enabled"`
	Owner       string `json:"owner"`
	Criticality string `json:"criticality"`
}

type updateTargetRequest struct {
	Owner       *string `json:"owner"`
	Criticality *string `json:"criticality"`
	Enabled     *bool   `json:"enabled"`
}

func toTargetResponse(target domain.Target) targetResponse {
	return targetResponse{
		ID:          target.ID,
		Address:     target.Address,
		Port:        target.Port,
		ServerName:  target.ServerName,
		Enabled:     target.Enabled,
		Owner:       target.Owner,
		Criticality: string(target.Criticality),
	}
}

func (h *TargetHandler) Create(c *gin.Context) {
	var request createTargetRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	criticality := domain.CriticalityLow

	if strings.TrimSpace(request.Criticality) != "" {
		criticality = domain.ServiceCriticality(
			strings.ToUpper(strings.TrimSpace(request.Criticality)),
		)
	}

	target, err := h.service.Create(
		c.Request.Context(),
		request.Target,
		request.Owner,
		criticality,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, toTargetResponse(target))
}

func (h *TargetHandler) Delete(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))

	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "target ID is empty",
		})
		return
	}

	if err := h.service.Delete(
		c.Request.Context(),
		id,
	); err != nil {
		if errors.Is(err, repository.ErrTargetNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "target not found",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *TargetHandler) List(c *gin.Context) {
	targets, err := h.service.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	response := make([]targetResponse, 0, len(targets))

	for _, target := range targets {
		response = append(
			response,
			toTargetResponse(target),
		)
	}

	c.JSON(http.StatusOK, response)
}

func (h *TargetHandler) Get(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))

	target, err := h.service.Get(
		c.Request.Context(),
		id,
	)
	if err != nil {
		if errors.Is(err, repository.ErrTargetNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "target not found",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, toTargetResponse(target))
}

func (h *TargetHandler) Update(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))

	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "target ID is empty",
		})
		return
	}

	target, err := h.service.Get(
		c.Request.Context(),
		id,
	)
	if err != nil {
		if errors.Is(err, repository.ErrTargetNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "target not found",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	var request updateTargetRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	if request.Owner != nil {
		target.Owner = strings.TrimSpace(*request.Owner)
	}

	if request.Criticality != nil {
		target.Criticality = domain.ServiceCriticality(
			strings.ToUpper(
				strings.TrimSpace(*request.Criticality),
			),
		)
	}

	if request.Enabled != nil {
		target.Enabled = *request.Enabled
	}

	if err := h.service.Update(
		c.Request.Context(),
		target,
	); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(
		http.StatusOK,
		toTargetResponse(target),
	)
}
