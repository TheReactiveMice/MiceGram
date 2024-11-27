// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.28.2
// source: internal/protobuf/ipc.proto

package ipc

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	IPC_ReceiveMessage_FullMethodName              = "/IPC/ReceiveMessage"
	IPC_BroadcastProfileInformation_FullMethodName = "/IPC/BroadcastProfileInformation"
)

// IPCClient is the client API for IPC service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type IPCClient interface {
	ReceiveMessage(ctx context.Context, in *ReceiveMessageRequest, opts ...grpc.CallOption) (*ReceiveMessageResponse, error)
	BroadcastProfileInformation(ctx context.Context, in *BroadcastProfileInformationRequest, opts ...grpc.CallOption) (*BroadcastProfileInformationResponse, error)
}

type iPCClient struct {
	cc grpc.ClientConnInterface
}

func NewIPCClient(cc grpc.ClientConnInterface) IPCClient {
	return &iPCClient{cc}
}

func (c *iPCClient) ReceiveMessage(ctx context.Context, in *ReceiveMessageRequest, opts ...grpc.CallOption) (*ReceiveMessageResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ReceiveMessageResponse)
	err := c.cc.Invoke(ctx, IPC_ReceiveMessage_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iPCClient) BroadcastProfileInformation(ctx context.Context, in *BroadcastProfileInformationRequest, opts ...grpc.CallOption) (*BroadcastProfileInformationResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(BroadcastProfileInformationResponse)
	err := c.cc.Invoke(ctx, IPC_BroadcastProfileInformation_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// IPCServer is the server API for IPC service.
// All implementations must embed UnimplementedIPCServer
// for forward compatibility.
type IPCServer interface {
	ReceiveMessage(context.Context, *ReceiveMessageRequest) (*ReceiveMessageResponse, error)
	BroadcastProfileInformation(context.Context, *BroadcastProfileInformationRequest) (*BroadcastProfileInformationResponse, error)
	mustEmbedUnimplementedIPCServer()
}

// UnimplementedIPCServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedIPCServer struct{}

func (UnimplementedIPCServer) ReceiveMessage(context.Context, *ReceiveMessageRequest) (*ReceiveMessageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReceiveMessage not implemented")
}
func (UnimplementedIPCServer) BroadcastProfileInformation(context.Context, *BroadcastProfileInformationRequest) (*BroadcastProfileInformationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BroadcastProfileInformation not implemented")
}
func (UnimplementedIPCServer) mustEmbedUnimplementedIPCServer() {}
func (UnimplementedIPCServer) testEmbeddedByValue()             {}

// UnsafeIPCServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to IPCServer will
// result in compilation errors.
type UnsafeIPCServer interface {
	mustEmbedUnimplementedIPCServer()
}

func RegisterIPCServer(s grpc.ServiceRegistrar, srv IPCServer) {
	// If the following call pancis, it indicates UnimplementedIPCServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&IPC_ServiceDesc, srv)
}

func _IPC_ReceiveMessage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReceiveMessageRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IPCServer).ReceiveMessage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: IPC_ReceiveMessage_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IPCServer).ReceiveMessage(ctx, req.(*ReceiveMessageRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IPC_BroadcastProfileInformation_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(BroadcastProfileInformationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IPCServer).BroadcastProfileInformation(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: IPC_BroadcastProfileInformation_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IPCServer).BroadcastProfileInformation(ctx, req.(*BroadcastProfileInformationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// IPC_ServiceDesc is the grpc.ServiceDesc for IPC service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var IPC_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "IPC",
	HandlerType: (*IPCServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ReceiveMessage",
			Handler:    _IPC_ReceiveMessage_Handler,
		},
		{
			MethodName: "BroadcastProfileInformation",
			Handler:    _IPC_BroadcastProfileInformation_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "internal/protobuf/ipc.proto",
}
