package launchsvc

import "fmt"

// Status mirrors SMAppServiceStatus.
type Status int

const (
	// NotRegistered: the service is not registered (SMAppServiceStatusNotRegistered).
	NotRegistered Status = 0
	// Enabled: the service is registered and allowed to run (SMAppServiceStatusEnabled).
	Enabled Status = 1
	// RequiresApproval: registered, but the user must approve it in System
	// Settings > Login Items (SMAppServiceStatusRequiresApproval).
	RequiresApproval Status = 2
	// NotFound: the plist was not found in the app bundle (SMAppServiceStatusNotFound).
	NotFound Status = 3
)

// String returns a human-readable name for the status.
func (s Status) String() string {
	switch s {
	case NotRegistered:
		return "not registered"
	case Enabled:
		return "enabled"
	case RequiresApproval:
		return "requires approval"
	case NotFound:
		return "not found"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}
