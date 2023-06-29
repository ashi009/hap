package pairing

import (
	"crypto/sha512"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type Method uint8

const (
	MethodSetup         Method = 0
	MethodSetupWithAuth Method = 1
	MethodVerify        Method = 2
	MethodAdd           Method = 3
	MethodRemove        Method = 4
	MethodList          Method = 5
)

type State uint8

const (
	StateM1 State = 1
	StateM2 State = 2
	StateM3 State = 3
	StateM4 State = 4
	StateM5 State = 5
	StateM6 State = 6
)

type FeatureFlag uint8

const (
	FeatureFlagSupportApplkeAuthnCoproc FeatureFlag = 1 << 0
	FeatureFlagSupportSoftwareAuthn     FeatureFlag = 1 << 1
)

type Error uint8 // tlv:"07"

const (
	ErrorReserved       Error = 0x00
	ErrorUnknown        Error = 0x01 // Generic error to handle unexpected errors.
	ErrorAuthentication Error = 0x02 // Setup code or signature verification failed.
	ErrorBackoff        Error = 0x03 // Client must look at the retry delay TLV item and wait that many seconds before retrying.
	ErrorMaxPeers       Error = 0x04 // Server cannot accept any more s.
	ErrorMaxTries       Error = 0x05 // Server reached its maximum number of authentication at-tempts.
	ErrorUnavailable    Error = 0x06 // Server  method is unavailable.
	ErrorBusy           Error = 0x07 // Server is busy and cannot accept a  request at this time.
)

func (e Error) Error() string {
	switch e {
	case ErrorReserved:
		return "reserved"
	case ErrorUnknown:
		return "unknown"
	case ErrorAuthentication:
		return "authentication"
	case ErrorBackoff:
		return "backoff"
	case ErrorMaxPeers:
		return "max peers"
	case ErrorMaxTries:
		return "max tries"
	case ErrorUnavailable:
		return "unavailable"
	case ErrorBusy:
		return "busy"
	default:
		return fmt.Sprintf("unknown error (%d)", uint8(e))
	}
}

type Flag uint32

const (
	FlagTransient Flag = 1 << 4  // Pair setup M1-M4 without exchanging public keys
	FlagSplit     Flag = 1 << 24 // When set FlagTransient save the SRP verifier used in this session, and when only FlagSplit is set, use the saved verifier from previous session.
)

/*
Method - 00 - uint8 // Method to use for pairing. See Table 5-14 (page 63).
Identifier - 01 - string // Identifier for authentication.
Salt - 02 - []byte // 16+ []byte of random salt.
PublicKey - 03 - []byte // Curve25519, SRP public key, or signed Ed25519 key.
Proof - 04 - []byte // Ed25519 or SRP proof.
EncryptedData - 05 - []byte // Encrypted data with auth tag at end.
State - 06 - uing8 // State of the pairing process. 1=M1, 2=M2, etc.
Error - 07 - uint8 // Error code. Must only be present if error code is not 0. See Table 5-16 (page 64).
RetryDelay - 08 - integer // Seconds to delay until retrying a setup code.
Certificate - 09 - []byte // X.509 Certificate.
Signature - 0A - []byte // Ed25519 or Apple Authentication Coprocessor signature.
Permissions - 0B - integer // Bit value describing permissions of the controller being added. None (0x00) : Regular user Bit 1 (0x01): Admin that is able to add and remove pairings against the accessory.
FragmentData - 0C - bvtes // Non-last fragment of data. If length is O, it's an ACK.
FragmentLast - OD - []byte // Last fragment of data.
Flags - 13 - uint32 // Pairing Type Flags (32 bit unsigned integer). See Table 5-18 (page 65)
Separator - FF - null // Zero-length TV that separates different TLVs in a list.
*/

type Permissions uint8

const (
	PermissionsRegularUser Permissions = 0
	PermissionsAdmin       Permissions = 1
)

type SRPStartRequest struct {
	State State `tlv:"06"` // 0x01

	Method Method `tlv:"00"`
	Flags  Flag   `tlv:"13"`
}

type SRPStartResponse struct {
	State State `tlv:"06"`
	// Error Error `tlv:"07"`

	PublicKey []byte `tlv:"03"`
	Salt      []byte `tlv:"02"`
	Flags     Flag   `tlv:"13"`
}

type SRPVerifyRequest struct {
	State State `tlv:"06"`

	PublicKey []byte `tlv:"03"`
	Proof     []byte `tlv:"04"`
}

type SRPVerifyResponse struct {
	State State `tlv:"06"`
	// Error Error `tlv:"07"`

	Proof         []byte `tlv:"04"`
	EncryptedData []byte `tlv:"05"`
}

type ExchangeRequest struct {
	State State `tlv:"06"`

	EncryptedData []byte `tlv:"05"` // AEAD encrypted tlv8-encoded PairInfo
}

type ExchangeResponse struct {
	State State `tlv:"06"`
	// Error Error `tlv:"07"`

	EncryptedData []byte `tlv:"05"` // AEAD encrypted tlv8-encoded PairInfo
}

type PairInfo struct {
	PairingID         string      `tlv:"01"`
	LongTermPublicKey []byte      `tlv:"03"`
	Signature         []byte      `tlv:"0A"`
	Permissions       Permissions `tlv:"0B"`
}

type SetupCode uint32

func (c SetupCode) String() string {
	t := fmt.Sprintf("%08d", c)
	return t[:3] + "-" + t[3:5] + "-" + t[5:]
}

type SetupPayload struct {
	Version           uint8 // 0b000
	AccessoryCategory uint8
	WACSupport        bool
	BLETransport      bool
	IPTransport       bool
	Paired            bool
	SetupCode         SetupCode
	SetupID           string
}

func (p SetupPayload) URL() string {
	r := uint64(0)
	r |= uint64(p.AccessoryCategory) << 31
	if p.WACSupport {
		r |= 1 << 30
	}
	if p.BLETransport {
		r |= 1 << 29
	}
	if p.IPTransport || p.WACSupport {
		r |= 1 << 28
	}
	if p.Paired {
		r |= 1 << 27
	}
	r |= uint64(p.SetupCode & 0x7ffffff)
	s := strings.ToUpper(strconv.FormatUint(r, 36))
	if len(s) < 9 {
		s = strings.Repeat("0", 9-len(s)) + s
	}
	return "X-HM://" + s + p.SetupID
}

func SetupHash(setupID, deviceID string) []byte {
	h := sha512.New()
	io.WriteString(h, setupID)
	io.WriteString(h, deviceID)
	return h.Sum(nil)[:4]
}

// type accessoryPairingSession struct {
// 	state         State
// 	paired        bool
// 	authnAttempts int
// }

// func (s *accessoryPairingSession) SRPStart(req *PairingSRPStartRequest) (*PairingSRPStartResponse, error) {
// 	if s.state != StateM0 {
// 		return nil, ErrorBusy
// 	}
// 	if s.paired {
// 		return nil, ErrorUnavailable
// 	}
// 	if s.authnAttempts > 100 {
// 		return nil, ErrorMaxTries
// 	}
// }

type ErrorResponse struct {
	State State `tlv:"06"`
	Error Error `tlv:"07"`
}

type VerifyStartRequest struct {
	State     State  `tlv:"06"`
	PublicKey []byte `tlv:"03"`
}

type VerifyStartResponse struct {
	State         State  `tlv:"06"`
	PublicKey     []byte `tlv:"03"`
	EncryptedData []byte `tlv:"05"`
}

type VerifyFinishRequest struct {
	State         State  `tlv:"06"`
	EncryptedData []byte `tlv:"05"`
}

type VerifyFinishResponse struct {
	State State `tlv:"06"`
}

type AddPairingRequest struct {
	State  State  `tlv:"06"`
	Method Method `tlv:"00"`

	PairInfo
}

type AddPairingResponse struct {
	State State `tlv:"06"`
	Error Error `tlv:"07"`
}

type RemovePairingRequest struct {
	State  State  `tlv:"06"`
	Method Method `tlv:"00"`

	PairInfo
}

type RemovePairingResponse struct {
	State State `tlv:"06"`
	Error Error `tlv:"07"`
}

type ListPairingRequest struct {
	State  State  `tlv:"06"`
	Method Method `tlv:"00"`
}

type ListPairingResponse struct {
	State State       `tlv:"06"`
	Pairs []*PairInfo `tlv:"FF"`
}
