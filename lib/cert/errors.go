package cert

import "errors"

var masterKeyIsNotSetError = errors.New("master key is not set")

func IsMasterKeyIsNotSetError(err error) bool {
	return errors.Is(err, masterKeyIsNotSetError)
}

var (
	keyIsTooShortError = errors.New("key length is less than needed bytes")
)

func IsKeyIsTooShortError(err error) bool {
	return errors.Is(err, keyIsTooShortError)
}
