package domain

type ChainStatus string

const (
	ChainValid   ChainStatus = "VALID"
	ChainInvalid ChainStatus = "INVALID"
	ChainUnknown ChainStatus = "UNKNOWN"
)

type ChainResult struct {
	Status ChainStatus
	Error  string
}
