package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	api "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type PeerView struct {
	Address string `json:"address"`
	ASN     uint32 `json:"asn"`
	State   string `json:"state"`
}
type BGPView struct {
	Connected bool       `json:"connected"`
	ASN       uint32     `json:"asn"`
	RouterID  string     `json:"router_id"`
	Peers     []PeerView `json:"peers"`
	Error     string     `json:"error,omitempty"`
}

// Backend is deliberately separate from collection and HTTP. A daemon failure
// cannot block the flow receiver, and tests can exercise the full lifecycle.
type Backend interface {
	Status(context.Context) (BGPView, error)
	Paths(context.Context, string) ([]*api.Path, error)
	Add(context.Context, *Route) ([]byte, error)
	Delete(context.Context, *Route) error
	Close() error
}
type grpcBGP struct {
	conn   *grpc.ClientConn
	client api.GoBgpServiceClient
}

func connectBGP(endpoint string) (Backend, error) {
	c, e := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if e != nil {
		return nil, e
	}
	return &grpcBGP{c, api.NewGoBgpServiceClient(c)}, nil
}
func (g *grpcBGP) Close() error { return g.conn.Close() }
func (g *grpcBGP) Status(ctx context.Context) (BGPView, error) {
	v := BGPView{Peers: []PeerView{}}
	global, e := g.client.GetBgp(ctx, &api.GetBgpRequest{})
	if e != nil {
		return v, e
	}
	v.ASN = global.GetGlobal().GetAsn()
	v.RouterID = global.GetGlobal().GetRouterId()
	stream, e := g.client.ListPeer(ctx, &api.ListPeerRequest{})
	if e != nil {
		return v, e
	}
	for {
		p, e := stream.Recv()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return v, e
		}
		s := p.GetPeer().GetState()
		v.Peers = append(v.Peers, PeerView{s.GetNeighborAddress(), s.GetPeerAsn(), strings.TrimPrefix(s.GetSessionState().String(), "SESSION_STATE_")})
	}
	v.Connected = true
	return v, nil
}
func family(prefix netip.Prefix) *api.Family {
	afi := api.Family_AFI_IP
	if prefix.Addr().Is6() {
		afi = api.Family_AFI_IP6
	}
	return &api.Family{Afi: afi, Safi: api.Family_SAFI_UNICAST}
}
func (g *grpcBGP) Paths(ctx context.Context, prefix string) ([]*api.Path, error) {
	p, e := netip.ParsePrefix(prefix)
	if e != nil {
		return nil, e
	}
	stream, e := g.client.ListPath(ctx, &api.ListPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Family: family(p), Prefixes: []*api.TableLookupPrefix{{Prefix: prefix}}})
	if e != nil {
		return nil, e
	}
	var paths []*api.Path
	for {
		r, e := stream.Recv()
		if errors.Is(e, io.EOF) {
			return paths, nil
		}
		if e != nil {
			return nil, e
		}
		if r.GetDestination().GetPrefix() == prefix {
			paths = append(paths, r.GetDestination().GetPaths()...)
		}
	}
}
func communities(values []string) ([]uint32, []*api.LargeCommunity, error) {
	if len(values) == 0 || len(values) > 16 {
		return nil, nil, errors.New("Community 需填寫 1–16 組")
	}
	var standard []uint32
	var large []*api.LargeCommunity
	for _, value := range values {
		parts := strings.Split(value, ":")
		if len(parts) != 2 && len(parts) != 3 {
			return nil, nil, fmt.Errorf("Community 格式錯誤：%s", value)
		}
		nums := make([]uint32, len(parts))
		bits := 16
		if len(parts) == 3 {
			bits = 32
		}
		for i, s := range parts {
			n, e := strconv.ParseUint(s, 10, bits)
			if e != nil {
				return nil, nil, fmt.Errorf("Community 數值錯誤：%s", value)
			}
			nums[i] = uint32(n)
		}
		if len(nums) == 2 {
			standard = append(standard, nums[0]<<16|nums[1])
		} else {
			large = append(large, &api.LargeCommunity{GlobalAdmin: nums[0], LocalData1: nums[1], LocalData2: nums[2]})
		}
	}
	return standard, large, nil
}
func routePath(r *Route) (*api.Path, error) {
	p, e := netip.ParsePrefix(r.Prefix)
	if e != nil {
		return nil, e
	}
	std, large, e := communities(r.Communities)
	if e != nil {
		return nil, e
	}
	nlri := &api.NLRI{Nlri: &api.NLRI_Prefix{Prefix: &api.IPAddressPrefix{Prefix: p.Addr().String(), PrefixLen: uint32(p.Bits())}}}
	attrs := []*api.Attribute{{Attr: &api.Attribute_Origin{Origin: &api.OriginAttribute{Origin: 0}}}}
	if p.Addr().Is4() {
		attrs = append(attrs, &api.Attribute{Attr: &api.Attribute_NextHop{NextHop: &api.NextHopAttribute{NextHop: r.NextHop}}})
	} else {
		attrs = append(attrs, &api.Attribute{Attr: &api.Attribute_MpReach{MpReach: &api.MpReachNLRIAttribute{Family: family(p), NextHops: []string{r.NextHop}, Nlris: []*api.NLRI{nlri}}}})
	}
	if len(std) > 0 {
		attrs = append(attrs, &api.Attribute{Attr: &api.Attribute_Communities{Communities: &api.CommunitiesAttribute{Communities: std}}})
	}
	if len(large) > 0 {
		attrs = append(attrs, &api.Attribute{Attr: &api.Attribute_LargeCommunities{LargeCommunities: &api.LargeCommunitiesAttribute{Communities: large}}})
	}
	return &api.Path{Family: family(p), Nlri: nlri, Pattrs: attrs, Identifier: r.Identifier}, nil
}
func (g *grpcBGP) Add(ctx context.Context, r *Route) ([]byte, error) {
	p, e := routePath(r)
	if e != nil {
		return nil, e
	}
	res, e := g.client.AddPath(ctx, &api.AddPathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL, Path: p})
	if e != nil {
		return nil, e
	}
	if len(res.Uuid) == 0 {
		return nil, errors.New("GoBGP 未回傳路由 UUID")
	}
	return res.Uuid, nil
}
func (g *grpcBGP) Delete(ctx context.Context, r *Route) error {
	req := &api.DeletePathRequest{TableType: api.TableType_TABLE_TYPE_GLOBAL}
	if len(r.UUID) > 0 {
		req.Uuid = r.UUID
	} else {
		// ListPath in GoBGP v4 omits UUIDs. Recover an interrupted AddPath through
		// its persisted nonzero identifier, never through a prefix-only deletion.
		if r.Identifier == 0 {
			return errors.New("缺少路由識別，拒絕廣泛撤回")
		}
		path, e := routePath(r)
		if e != nil {
			return e
		}
		req.Path = path
	}
	_, e := g.client.DeletePath(ctx, req)
	return e
}
