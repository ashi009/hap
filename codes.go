package hapv2

type Status int32

const (
	StatusOK                        Status = 0      // This specifies a success for the request.
	StatusInsufficientPrivileges    Status = -70401 // Request denied due to insufficient privileges.
	StatusCommunicationFailure      Status = -70402 // Unable to communicate with requested service, e.g. the power to the accessory was turned off.
	StatusBusy                      Status = -70403 // Resource is busy, try again.
	StatusWriteFailure              Status = -70404 // Cannot write to read only characteristic.
	StatusReadFailure               Status = -70405 // Cannot read from a write only characteristic.
	StatusNotificationUnsuppored    Status = -70406 // Notification is not supported for characteristic.
	StatusOutOfResource             Status = -70407 // Out of resources to process request.
	StatusTimeout                   Status = -70408 // Operation timed out.
	StatusResourceNotFound          Status = -70409 // Resource does not exist.
	StatusInvalidValue              Status = -70410 // Accessory received an invalid value in a write request.
	StatusInsufficientAuthorization Status = -70411 // Insufficient Authorization.
)
