package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/golang/glog"
	"github.com/kr/pretty"
)

func getAccessories(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile("accessories.json")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/hap+json")
	w.Write(b)
}

func handleCharacteristics(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		getCharacteriestics(w, r)
	case http.MethodPut:
		updateCharacteristics(w, r)
	}
}

type Permission string

const (
	PermissionPairedRead              Permission = "pr"
	PermissionPairedWrite             Permission = "pw"
	PermissionEvents                  Permission = "ev"
	PermissionAdditionalAuthorization Permission = "aa"
	PermissionTimedWrite              Permission = "tw"
	PermissionHidden                  Permission = "hd"
	PermissionWriteResponse           Permission = "wr"
)

type Format string

const (
	FormatBool   Format = "bool"
	FormatUint8  Format = "uint8"
	FormatUint16 Format = "uint16"
	FormatUint32 Format = "uint32"
	FormatUint64 Format = "uint64"
	FormatInt    Format = "int"   // int32
	FormatFloat  Format = "float" // float64
	FormatString Format = "string"
	FormatTLV8   Format = "tlv8" // []byte (base64 encoded)
	FormatData   Format = "data" // []byte (base64 encoded)
)

type Unit string

const (
	UnitCelsius    Unit = "celsius"
	UnitPercentage Unit = "percentage"
	UnitArcDegree  Unit = "arcdegrees"
	UnitLux        Unit = "lux"
	UnitSeconds    Unit = "seconds"
)

type CharacteristicDescriptor struct {
	Type               string   `json:"type"`
	Permissions        []string `json:"perms"`
	Value              any      `json:"value,omitempty"`
	EventNotifications bool     `json:"ev,omitempty"`
}

type CharacteristicMetadata struct {
	Format           Format    `json:"format"`
	Description      string    `json:"description,omitempty"`
	Unit             Unit      `json:"unit,omitempty"`
	MinValue         float64   `json:"minValue,omitempty"`
	MaxValue         float64   `json:"maxValue,omitempty"`
	StepValue        float64   `json:"minStep,omitempty"`
	MaxLength        uint64    `json:"maxLen,omitempty"`
	MaxDataLength    uint64    `json:"maxDataLen,omitempty"`
	ValidValues      []string  `json:"valid-values,omitempty"`
	ValidValuesRange []float64 `json:"valid-values-range,omitempty"`
}

type Characteristic struct {
	AID    uint64          `json:"aid"`
	IID    uint64          `json:"iid"`
	Value  json.RawMessage `json:"value"`
	Status int             `json:"status,omitempty"` // Output only
}

type UpdateCharacteristicsRequest struct {
	Characteristics []*Characteristic `json:"characteristics"`
}

type UpdateCharacteristicsResponse struct {
	Characteristics []*Characteristic `json:"characteristics"`
}

func updateCharacteristics(w http.ResponseWriter, r *http.Request) {
	var req UpdateCharacteristicsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	glog.Infof("updateCharacteristics: \n%s", pretty.Sprint(req))
	w.WriteHeader(http.StatusNoContent)
	// resp := &UpdateCharacteristicsResponse{
	// 	Characteristics: make([]*Characteristic, len(req.Characteristics)),
	// }
	// for i, c := range req.Characteristics {
	// 	resp.Characteristics[i] = &Characteristic{
	// 		AID:   c.AID,
	// 		IID:   c.IID,
	// 		Value: c.Value,
	// 	}
	// }
	// if err := json.NewEncoder(w).Encode(resp); err != nil {
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// }
}

type CharacteristicID struct {
	AID uint64 `json:"aid"`
	IID uint64 `json:"iid"`
}

type GetCharacteristicsRequest struct {
	IDs                   []CharacteristicID `query:"id"`
	IncludeMetaProperties bool               `query:"meta"`
	IncludePermsProperty  bool               `query:"perms"`
	IncludeTypeProperty   bool               `query:"type"`
	IncludeEventProperty  bool               `query:"ev"`
}

func parseGetCharacteristicsRequest(q url.Values) (*GetCharacteristicsRequest, error) {
	req := GetCharacteristicsRequest{
		IncludeMetaProperties: q.Get("meta") == "1",
		IncludePermsProperty:  q.Get("perms") == "1",
		IncludeTypeProperty:   q.Get("type") == "1",
		IncludeEventProperty:  q.Get("ev") == "1",
	}
	for _, t := range strings.Split(q.Get("id"), ",") {
		p := strings.SplitN(t, ".", 2)
		if len(p) != 2 {
			return nil, fmt.Errorf("invalid id: %q", t)
		}
		var id CharacteristicID
		var err error
		if id.AID, err = strconv.ParseUint(p[0], 10, 64); err != nil {
			return nil, err
		}
		if id.IID, err = strconv.ParseUint(p[1], 10, 64); err != nil {
			return nil, err
		}
		req.IDs = append(req.IDs, id)
	}
	return &req, nil
}

func getCharacteriestics(w http.ResponseWriter, r *http.Request) {
	req, err := parseGetCharacteristicsRequest(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	glog.Infof("getCharacteristics: \n%s", pretty.Sprint(req))
	_ = req
	w.WriteHeader(http.StatusOK)
}
