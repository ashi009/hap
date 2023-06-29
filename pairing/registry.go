package pairing

import (
	"context"
	"errors"
	"fmt"
	"hapv2/encoding/tlv8"
	"sort"
	"sync"
)

var (
	ErrAlreadyPaired = errors.New("already paired")
	ErrUnknownPeer   = errors.New("unknown peer")
)

type Registry struct {
	mu    sync.Mutex
	peers map[string]*PairInfo
}

func NewRegistry() *Registry {
	return &Registry{
		peers: make(map[string]*PairInfo),
	}
}

type pairEditRequest struct {
	State  State  `tlv:"06"`
	Method Method `tlv:"00"`
}

func (r *Registry) Handle(ctx context.Context, req []byte) ([]byte, error) {
	var pr pairEditRequest
	if err := tlv8.Unmarshal(req, &pr); err != nil {
		return nil, err
	}
	switch pr.Method {
	case MethodAdd:
		var sreq AddPairingRequest
		if err := tlv8.Unmarshal(req, &sreq); err != nil {
			return nil, err
		}
		sresp, err := r.handleAdd(&sreq)
		if err != nil {
			return nil, err
		}
		return tlv8.Marshal(sresp)
	case MethodRemove:
		var sreq RemovePairingRequest
		if err := tlv8.Unmarshal(req, &sreq); err != nil {
			return nil, err
		}
		sresp, err := r.handleRemove(&sreq)
		if err != nil {
			return nil, err
		}
		return tlv8.Marshal(sresp)
	case MethodList:
		var sreq ListPairingRequest
		if err := tlv8.Unmarshal(req, &sreq); err != nil {
			return nil, err
		}
		sresp, err := r.handleList(&sreq)
		if err != nil {
			return nil, err
		}
		return tlv8.Marshal(sresp)
	default:
		return nil, fmt.Errorf("unknown method: %v", pr.Method)
	}
}

func (r *Registry) Get(id string) (*PairInfo, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.peers[id]
	return p, ok
}

func (r *Registry) handleAdd(req *AddPairingRequest) (*AddPairingResponse, error) {
	if err := r.Add(&req.PairInfo); err != nil {
		return nil, err
	}
	return &AddPairingResponse{
		State: StateM2,
	}, nil
}

func (r *Registry) Add(p *PairInfo) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.peers[p.PairingID]; ok {
		return ErrAlreadyPaired
	}
	r.peers[p.PairingID] = p
	return nil
}

func (r *Registry) handleRemove(req *RemovePairingRequest) (*RemovePairingResponse, error) {
	if err := r.Remove(req.PairingID); err != nil {
		return nil, err
	}
	return &RemovePairingResponse{
		State: StateM2,
	}, nil
}

func (r *Registry) Remove(pairingID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.peers[pairingID]; !ok {
		return ErrUnknownPeer
	}
	delete(r.peers, pairingID)
	return nil
}

func (r *Registry) handleList(req *ListPairingRequest) (*ListPairingResponse, error) {
	return &ListPairingResponse{
		State: StateM2,
		Pairs: r.List(),
	}, nil
}

func (r *Registry) List() []*PairInfo {
	r.mu.Lock()
	var peers []*PairInfo
	for _, p := range r.peers {
		peers = append(peers, p)
	}
	r.mu.Unlock()
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].PairingID < peers[j].PairingID
	})
	return peers
}
