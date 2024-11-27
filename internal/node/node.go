package node

import (
	"context"
	"errors"
	"net"
	"pizdec/internal/algorithms"
	"pizdec/internal/ipc"

	"google.golang.org/grpc"
)

type IPCServerInstance struct {
	ipc.UnimplementedIPCServer

	KnownPeers []ipc.IPCClient
	Profile    *ipc.UserProfile
}

func (s IPCServerInstance) ReceiveMessage(ctx context.Context, req *ipc.ReceiveMessageRequest) (*ipc.ReceiveMessageResponse, error) {
	encryptedText, err := algorithms.RSA_Encrypt([]byte(req.Message), s.Profile.EncryptionPrivateKey)

	if err != nil {
		return nil, err
	}

	signatureText, err := algorithms.ECDSA_Sign([]byte(req.Message), s.Profile.SignaturePrivateKey)

	if err != nil {
		return nil, err
	}

	for i := range s.KnownPeers {
		_, err := s.KnownPeers[i].ReceiveMessage(ctx, &ipc.ReceiveMessageRequest{
			Message:   string(encryptedText),
			Signature: signatureText,
		})

		if err != nil {
			return nil, errors.New("delivery failed (not all targets received the message yet)")
		}
	}

	return &ipc.ReceiveMessageResponse{}, nil
}
func (s IPCServerInstance) BroadcastProfileInformation(ctx context.Context, req *ipc.BroadcastProfileInformationRequest) (*ipc.BroadcastProfileInformationResponse, error) {
	return &ipc.BroadcastProfileInformationResponse{
		UserID:              s.Profile.UserID,
		Username:            s.Profile.Username,
		EncryptionPublicKey: s.Profile.EncryptionPublicKey,
		SignaturePublicKey:  s.Profile.SignaturePublicKey,
		AvatarPhoto:         s.Profile.AvatarPhoto,
	}, nil
}

func StartNode() {
	l, err := net.Listen("tcp", ":10000")

	if err != nil {
		return
	}

	server := grpc.NewServer()
	ipc.RegisterIPCServer(server, IPCServerInstance{})
	if err := server.Serve(l); err != nil {
		return
	}
}
