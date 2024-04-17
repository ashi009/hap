package main

import (
	"encoding/base64"
	"fmt"
	"hapv2/pairing"
)

/*
$ dns-sd -h
dns-sd -E                          (Enumerate recommended registration domains)
dns-sd -F                          (Enumerate recommended browsing     domains)
dns-sd -R <Name> <Type> <Domain> <Port> [<TXT>...]         (Register a service)
*/

type StatusFlag uint32

const (
	StatusFlagNotPaired StatusFlag = 1 << iota
	StatusFlagWIFINotConfigured
	StatusFlagProblemDetected
	StatusFlagInsecureSetup
	StatusFlagLowBattery
)

type Service struct {
	// Current configuration number. Required.
	// Must update when an accessory, service, or characteristic is added or
	// removed on the accessory server. Accessories must increment the config
	// number after a firmware update. This must have a range of 1-65535 and wrap
	// to 1 when it overflows. This value must persist across reboots, power
	// cycles, etc.
	ConfigNumber uint32 `txt:"c#"`
	// Pairing Feature flags. Required if non-zero. See Table 5-15 (page 63).
	FeatureFlags pairing.FeatureFlag `txt:"ff"`
	// DeviceID of the accessory. The Device ID must be formatted as
	// "XX:XX:XX:XX:XX:XX", where "XX" is a hexadecimal string representing a
	// byte. Required. This value is also used as the accessory's Pairing
	// Identifier.
	DeviceID string `txt:"id"`
	// Model name of the accessory (e.g. "Device1,1"). Required.
	Model string `txt:"md"`
	// ProtocolVersion "X.Y" (e.g. "1.0"). Required if value is not "1.0".
	// 1.1 for IP accessories.
	ProtocolVersion string `txt:"pv"`
	// Current state number. Required.
	// This must have a value of "1".
	StateNumber uint32 `txt:"s#"`
	// Status flags (e.g. "Ox04" for bit 3). Value should be an unsigned integer.
	// See Table 6-8 (page 72). Required.
	StatusFlags StatusFlag `txt:"sf"`
	// Accessory Category Identifier. Required. Indicates the category that best
	// describes the primary function of the accessory. This must have a range of
	// 1-65535. This must take values defined in "14-1 Accessory Categories" (page
	// 271). This must persist across reboots, power cycles, etc.
	CategoryID uint32 `txt:"ci"`
	// Setup Hash. See ("4.2.3 Setup Hash" (page 33)) Required if the accessory supports enhanced setup payload information.
	SetupHash []byte `txt:"sh"`
}

func (s *Service) TextRecords() []string {
	return []string{
		fmt.Sprintf("c#=%d", s.ConfigNumber),
		fmt.Sprintf("ff=%d", s.FeatureFlags),
		fmt.Sprintf("id=%s", s.DeviceID),
		fmt.Sprintf("md=%s", s.Model),
		fmt.Sprintf("pv=%s", s.ProtocolVersion),
		fmt.Sprintf("s#=%d", 1),
		fmt.Sprintf("sf=%d", s.StatusFlags),
		fmt.Sprintf("ci=%d", s.CategoryID),
		fmt.Sprintf("sh=%s", base64.StdEncoding.EncodeToString(s.SetupHash)),
	}
}
