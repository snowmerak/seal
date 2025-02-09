package cert

import "errors"

var masterKeyIsNotSetError = errors.New("master key is not set")

func IsMasterKeyIsNotSetError(err error) bool {
	return errors.Is(err, masterKeyIsNotSetError)
}
