package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"certificate-radar/internal/domain"
	"certificate-radar/internal/target"
)

type TargetService struct {
	repository TargetRepository
}

func NewTargetService(
	repository TargetRepository,
) *TargetService {
	return &TargetService{
		repository: repository,
	}
}

func (s *TargetService) Create(
	ctx context.Context,
	input string,
	owner string,
	criticality domain.ServiceCriticality,
) (domain.Target, error) {
	t, err := target.Parse(input)
	if err != nil {
		return domain.Target{}, fmt.Errorf(
			"parse target: %w",
			err,
		)
	}

	t.ID, err = generateID()
	if err != nil {
		return domain.Target{}, fmt.Errorf(
			"generate target ID: %w",
			err,
		)
	}

	t.Owner = strings.TrimSpace(owner)
	t.Criticality = criticality

	if err := validateTarget(t); err != nil {
		return domain.Target{}, err
	}

	if err := s.repository.Create(ctx, t); err != nil {
		return domain.Target{}, fmt.Errorf(
			"create target: %w",
			err,
		)
	}

	return t, nil
}

func (s *TargetService) Get(
	ctx context.Context,
	id string,
) (domain.Target, error) {
	id = strings.TrimSpace(id)

	if id == "" {
		return domain.Target{}, fmt.Errorf(
			"target ID is empty",
		)
	}

	return s.repository.Get(ctx, id)
}

func (s *TargetService) List(
	ctx context.Context,
) ([]domain.Target, error) {
	return s.repository.List(ctx)
}

func (s *TargetService) Delete(
	ctx context.Context,
	id string,
) error {
	id = strings.TrimSpace(id)

	if id == "" {
		return fmt.Errorf("target ID is empty")
	}

	if err := s.repository.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete target: %w", err)
	}

	return nil
}

func (s *TargetService) Update(
	ctx context.Context,
	t domain.Target,
) error {
	if err := validateTarget(t); err != nil {
		return err
	}

	if err := s.repository.Update(ctx, t); err != nil {
		return fmt.Errorf(
			"update target: %w",
			err,
		)
	}

	return nil
}

func validateTarget(t domain.Target) error {
	if strings.TrimSpace(t.ID) == "" {
		return fmt.Errorf("target ID is empty")
	}

	if strings.TrimSpace(t.Address) == "" {
		return fmt.Errorf("target address is empty")
	}

	if t.Port < 1 || t.Port > 65535 {
		return fmt.Errorf(
			"target port %d is out of range",
			t.Port,
		)
	}

	if strings.TrimSpace(t.ServerName) == "" {
		return fmt.Errorf(
			"target server name is empty",
		)
	}

	if !validCriticality(t.Criticality) {
		return fmt.Errorf(
			"invalid target criticality %q",
			t.Criticality,
		)
	}

	return nil
}

func validCriticality(
	criticality domain.ServiceCriticality,
) bool {
	switch criticality {
	case domain.CriticalityLow,
		domain.CriticalityMedium,
		domain.CriticalityHigh,
		domain.CriticalityCritical:
		return true

	default:
		return false
	}
}

func generateID() (string, error) {
	buf := make([]byte, 16)

	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return hex.EncodeToString(buf), nil
}
