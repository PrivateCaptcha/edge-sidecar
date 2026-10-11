package privatecaptcha

type VerifyCode int

const (
	VerifyNoError           VerifyCode = 0
	VerifyErrorOther        VerifyCode = 1
	DuplicateSolutionsError VerifyCode = 2
	InvalidSolutionError    VerifyCode = 3
	ParseResponseError      VerifyCode = 4
	PuzzleExpiredError      VerifyCode = 5
	InvalidPropertyError    VerifyCode = 6
	WrongOwnerError         VerifyCode = 7
	VerifiedBeforeError     VerifyCode = 8
	MaintenanceModeError    VerifyCode = 9
	TestPropertyError       VerifyCode = 10
	IntegrityError          VerifyCode = 11
	OrgScopeError           VerifyCode = 12
	// Add new fields _above_
	VERIFY_CODES_COUNT
)

func (verr VerifyCode) String() string {
	switch verr {
	case VerifyNoError:
		return ""
	case VerifyErrorOther:
		return "error-other"
	case DuplicateSolutionsError:
		return "solution-duplicates"
	case InvalidSolutionError:
		return "solution-invalid"
	case ParseResponseError:
		return "solution-bad-format"
	case PuzzleExpiredError:
		return "puzzle-expired"
	case InvalidPropertyError:
		return "property-invalid"
	case WrongOwnerError:
		return "property-owner-mismatch"
	case VerifiedBeforeError:
		return "solution-verified-before"
	case MaintenanceModeError:
		return "maintenance-mode"
	case TestPropertyError:
		return "property-test"
	case IntegrityError:
		return "integrity-error"
	case OrgScopeError:
		return "property-org-scope"
	default:
		return "error"
	}
}

type VerifyOutput struct {
	Success   bool              `json:"success"`
	Code      VerifyCode        `json:"code"`
	Origin    string            `json:"origin,omitempty"`
	Timestamp string            `json:"timestamp,omitempty"`
	EdgeToken string            `json:"edge_token,omitempty"`
	requestID string            `json:"-"`
	attempt   int               `json:"-"`
	metadata  map[string]string `json:"-"`
}

func (vr *VerifyOutput) OK() bool {
	if vr == nil {
		return false
	}

	return vr.Success && (vr.Code == VerifyNoError)
}

func (vr *VerifyOutput) RequestID() string {
	if vr == nil {
		return ""
	}

	return vr.requestID
}

func (vr *VerifyOutput) Error() string {
	if vr == nil {
		return ""
	}

	return vr.Code.String()
}

func (vr *VerifyOutput) Metadata(key string) string {
	if (vr == nil) || (vr.metadata == nil) {
		return ""
	}

	if v, ok := vr.metadata[key]; ok {
		return v
	}

	return ""
}
