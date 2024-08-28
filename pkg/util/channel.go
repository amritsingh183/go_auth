package util

// GenericChannel ...
type GenericChannel struct {
	Done  chan bool
	Error error
}
