package pairing

import (
	"encoding/hex"
	"hapv2/encoding/tlv8"
	"testing"
)

func TestUnmarshal(t *testing.T) {
	b, _ := hex.DecodeString("000104060101012439333435454436362d383545442d344646312d424339382d413842453445364435394131")
	var req AddPairingRequest
	if err := tlv8.Unmarshal(b, &req); err != nil {
		t.Error(err)
	}
}

func TestMarshal(t *testing.T) {
	resp := ListPairingResponse{
		State: StateM2,
		Pairs: []*PairInfo{
			{PairingID: "wtf"},
			{PairingID: "wtf2"},
		},
	}
	b, err := tlv8.Marshal(resp)
	if err != nil {
		t.Error(err)
	}
	t.Logf("%x", b)
	t.Error()
}
