package webrtc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/AlexxIT/go2rtc/pkg/webrtc"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kinesisvideo"
	"github.com/aws/aws-sdk-go-v2/service/kinesisvideo/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesisvideosignaling"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
	"github.com/gorilla/websocket"
	pion "github.com/pion/webrtc/v3"
)

type kinesisCredentialClientOpts struct {
	SessionDescriptionModifier func(*pion.SessionDescription) ([]byte, error)
	MediaModifier              func() ([]*core.Media, error)
}

func kinesisCredentialClient(rawURL string, query url.Values, format string, opts *kinesisCredentialClientOpts) (core.Producer, error) {
	channelName := query.Get("channelName")
	accessKeyId := query.Get("accessKeyId")
	secretAccessKey := query.Get("secretAccessKey")
	sessionToken := query.Get("sessionToken")
	clientId := query.Get("clientId")
	region := query.Get("region")
	natTraversal, ok := parseNATTraversal(query.Get("natTraversal"))
	if !ok {
		natTraversal = NATTraversalDisable
	}

	// Create KVS client
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKeyId, secretAccessKey, sessionToken)))
	if err != nil {
		return nil, err
	}
	kinesisvideoClient := kinesisvideo.NewFromConfig(cfg)

	// Get signaling channel ARN
	describeSignalingChannelResponse, err := kinesisvideoClient.DescribeSignalingChannel(context.TODO(), &kinesisvideo.DescribeSignalingChannelInput{
		ChannelName: &channelName,
	})
	if err != nil {
		return nil, err
	}

	channelARN := describeSignalingChannelResponse.ChannelInfo.ChannelARN
	log.Trace().Msgf("[webrtc] kinesis channelARN: %s", *channelARN)

	// Get signaling channel endpoints
	getSignalingChannelEndpoint, err := kinesisvideoClient.GetSignalingChannelEndpoint(context.TODO(), &kinesisvideo.GetSignalingChannelEndpointInput{
		ChannelARN: channelARN,
		SingleMasterChannelEndpointConfiguration: &types.SingleMasterChannelEndpointConfiguration{
			Protocols: []types.ChannelProtocol{types.ChannelProtocolHttps, types.ChannelProtocolWss},
			Role:      types.ChannelRoleViewer,
		},
	})
	if err != nil {
		return nil, err
	}

	signalingChannelEndpointDict := make(map[types.ChannelProtocol]string)
	for _, v := range getSignalingChannelEndpoint.ResourceEndpointList {
		signalingChannelEndpointDict[v.Protocol] = *v.ResourceEndpoint
		log.Trace().Msgf("[webrtc] kinesis signalingChannelEndpoint: %s %s", v.Protocol, *v.ResourceEndpoint)
	}

	// Get ICE server configuration
	var iceServers []pion.ICEServer

	// Don't add stun if user selects TURN only or NAT traversal disabled
	if natTraversal == NATTraversalStunOnly || natTraversal == NATTraversalStunTurn {
		iceServers = append(iceServers, pion.ICEServer{URLs: []string{fmt.Sprintf("stun:stun.kinesisvideo.%s.amazonaws.com:443", region)}, CredentialType: pion.ICECredentialType(-1)})
	}

	// Don't add turn if user selects STUN only or NAT traversal disabled
	if natTraversal == NATTraversalTurnOnly || natTraversal == NATTraversalStunTurn {
		kinesisvideosignalingClient := kinesisvideosignaling.NewFromConfig(cfg)
		getIceServerConfigResponse, err := kinesisvideosignalingClient.GetIceServerConfig(context.TODO(), &kinesisvideosignaling.GetIceServerConfigInput{
			ChannelARN: channelARN,
		}, func(options *kinesisvideosignaling.Options) {
			endpoint := signalingChannelEndpointDict[types.ChannelProtocolHttps]
			options.EndpointResolverV2 = &kinesisvideosignalingEndpointResolverV2{URL: endpoint}
		})
		if err != nil {
			return nil, err
		}
		for _, v := range getIceServerConfigResponse.IceServerList {
			iceServers = append(iceServers, pion.ICEServer{
				URLs:       v.Uris,
				Username:   *v.Username,
				Credential: v.Password,
			})
		}
	}
	log.Trace().Msgf("[webrtc] kinesis iceServers: %s", iceServers)

	requestSigner := NewSigV4RequestSigner(region, aws.Credentials{
		AccessKeyID:     accessKeyId,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
	})
	signedUrl := requestSigner.getSignedURL(signalingChannelEndpointDict[types.ChannelProtocolWss], url.Values{
		"X-Amz-ChannelARN": []string{*channelARN},
		"X-Amz-ClientId":   []string{clientId},
	}, time.Now().UTC())

	log.Trace().Msgf("[webrtc] kinesis signedUrl: %s", signedUrl)

	// 1. Connect to signalign server
	conn, _, err := websocket.DefaultDialer.Dial(signedUrl, nil)
	if err != nil {
		return nil, err
	}

	// 2. Load ICEServers from query param (base64 json)
	conf := pion.Configuration{}
	conf.ICEServers = iceServers

	// close websocket when we ready return Producer or connection error
	defer conn.Close()

	// 3. Create Peer Connection
	api, err := webrtc.NewAPI()
	if err != nil {
		return nil, err
	}

	pc, err := api.NewPeerConnection(conf)
	if err != nil {
		return nil, err
	}

	// protect from sending ICE candidate before Offer
	var sendOffer core.Waiter

	// protect from blocking on errors
	defer sendOffer.Done(nil)

	// waiter will wait PC error or WS error or nil (connection OK)
	var connState core.Waiter

	req := kinesisRequest{
		ClientID: query.Get("client_id"),
	}

	prod := webrtc.NewConn(pc)
	prod.FormatName = format
	prod.Mode = core.ModeActiveProducer
	prod.Protocol = "ws"
	prod.URL = rawURL
	prod.Listen(func(msg any) {
		switch msg := msg.(type) {
		case *pion.ICECandidate:
			_ = sendOffer.Wait()

			req.Action = "ICE_CANDIDATE"
			req.Payload, _ = json.Marshal(msg.ToJSON())
			if err = conn.WriteJSON(&req); err != nil {
				connState.Done(err)
				return
			}

			log.Trace().Msgf("[webrtc] kinesis send: %s", req)

		case pion.PeerConnectionState:
			switch msg {
			case pion.PeerConnectionStateConnecting:
			case pion.PeerConnectionStateConnected:
				connState.Done(nil)
			default:
				connState.Done(errors.New("webrtc: " + msg.String()))
			}
		}
	})

	medias := []*core.Media{
		{Kind: core.KindVideo, Direction: core.DirectionRecvonly},
		{Kind: core.KindAudio, Direction: core.DirectionRecvonly},
	}
	if opts.MediaModifier != nil {
		medias, err = opts.MediaModifier()
		if err != nil {
			return nil, err
		}
	}

	// 4. Create offer
	offer, err := prod.CreateOffer(medias)
	if err != nil {
		return nil, err
	}

	// 5. Send offer
	req.Action = "SDP_OFFER"

	sessionDescription := pion.SessionDescription{
		Type: pion.SDPTypeOffer,
		SDP:  offer,
	}
	if opts.SessionDescriptionModifier != nil {
		req.Payload, _ = opts.SessionDescriptionModifier(&sessionDescription)
	} else {
		req.Payload, _ = json.Marshal(sessionDescription)
	}
	if err = conn.WriteJSON(req); err != nil {
		return nil, err
	}

	log.Trace().Msgf("[webrtc] kinesis send: %s", req)

	sendOffer.Done(nil)

	go func() {
		var err error

		// will be closed when conn will be closed
		for {
			var res kinesisResponse
			if err = conn.ReadJSON(&res); err != nil {
				// some buggy messages from Amazon servers
				if errors.Is(err, io.ErrUnexpectedEOF) {
					continue
				}
				break
			}

			log.Trace().Msgf("[webrtc] kinesis recv: %s", res)

			switch res.Type {
			case "SDP_ANSWER":
				// 6. Get answer
				var sd pion.SessionDescription
				if err = json.Unmarshal(res.Payload, &sd); err != nil {
					break
				}

				if err = prod.SetAnswer(sd.SDP); err != nil {
					break
				}

			case "ICE_CANDIDATE":
				// 7. Continue to receiving candidates
				var ci pion.ICECandidateInit
				if err = json.Unmarshal(res.Payload, &ci); err != nil {
					break
				}

				if err = prod.AddCandidate(ci.Candidate); err != nil {
					break
				}
			}
		}

		connState.Done(err)
	}()

	if err = connState.Wait(); err != nil {
		return nil, err
	}

	return prod, nil
}

type NATTraversal int

const (
	NATTraversalDisable NATTraversal = iota
	NATTraversalStunOnly
	NATTraversalTurnOnly
	NATTraversalStunTurn
)

func parseNATTraversal(str string) (NATTraversal, bool) {
	var (
		natTraversalMap = map[string]NATTraversal{
			"stun":     NATTraversalStunOnly,
			"turn":     NATTraversalTurnOnly,
			"stunturn": NATTraversalStunTurn,
			"disable":  NATTraversalDisable,
		}
	)
	c, ok := natTraversalMap[strings.ToLower(str)]
	return c, ok
}

type kinesisvideosignalingEndpointResolverV2 struct {
	URL string
}

func (r *kinesisvideosignalingEndpointResolverV2) ResolveEndpoint(
	ctx context.Context, params kinesisvideosignaling.EndpointParameters,
) (
	endpoint smithyendpoints.Endpoint, err error,
) {
	uri, err := url.Parse(r.URL)
	if err != nil {
		return endpoint, fmt.Errorf("failed to parse uri: %s", r.URL)
	}
	return smithyendpoints.Endpoint{
		URI:     *uri,
		Headers: http.Header{},
	}, nil
}
