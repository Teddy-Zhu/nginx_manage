package fault

type Error struct {
	Status        int
	Code, Message string
	Data          any
}

func (e *Error) Error() string { return e.Message }
func Invalid(message string) error {
	return &Error{Status: 400, Code: "VALIDATION_FAILED", Message: message}
}
func Conflict(message string) error { return &Error{Status: 409, Code: "CONFLICT", Message: message} }
func NotFound(message string) error { return &Error{Status: 404, Code: "NOT_FOUND", Message: message} }
func Unavailable(message string) error {
	return &Error{Status: 503, Code: "CAPABILITY_UNAVAILABLE", Message: message}
}
