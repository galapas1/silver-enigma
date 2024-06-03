// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: ninjapanda/v1/routes.proto

package ninjapanda_v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Route struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RouteId    string  `protobuf:"bytes,1,opt,name=route_id,json=routeId,proto3" json:"route_id,omitempty"`
	MachineId  string  `protobuf:"bytes,2,opt,name=machine_id,json=machineId,proto3" json:"machine_id,omitempty"`
	Prefix     string  `protobuf:"bytes,3,opt,name=prefix,proto3" json:"prefix,omitempty"`
	Advertised bool    `protobuf:"varint,4,opt,name=advertised,proto3" json:"advertised,omitempty"`
	Enabled    bool    `protobuf:"varint,5,opt,name=enabled,proto3" json:"enabled,omitempty"`
	IsPrimary  bool    `protobuf:"varint,6,opt,name=is_primary,json=isPrimary,proto3" json:"is_primary,omitempty"`
	CreatedAt  string  `protobuf:"bytes,7,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	UpdatedAt  string  `protobuf:"bytes,8,opt,name=updated_at,json=updatedAt,proto3" json:"updated_at,omitempty"`
	DeletedAt  *string `protobuf:"bytes,9,opt,name=deleted_at,json=deletedAt,proto3,oneof" json:"deleted_at,omitempty"`
}

func (x *Route) Reset() {
	*x = Route{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_routes_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Route) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Route) ProtoMessage() {}

func (x *Route) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_routes_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Route.ProtoReflect.Descriptor instead.
func (*Route) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_routes_proto_rawDescGZIP(), []int{0}
}

func (x *Route) GetRouteId() string {
	if x != nil {
		return x.RouteId
	}
	return ""
}

func (x *Route) GetMachineId() string {
	if x != nil {
		return x.MachineId
	}
	return ""
}

func (x *Route) GetPrefix() string {
	if x != nil {
		return x.Prefix
	}
	return ""
}

func (x *Route) GetAdvertised() bool {
	if x != nil {
		return x.Advertised
	}
	return false
}

func (x *Route) GetEnabled() bool {
	if x != nil {
		return x.Enabled
	}
	return false
}

func (x *Route) GetIsPrimary() bool {
	if x != nil {
		return x.IsPrimary
	}
	return false
}

func (x *Route) GetCreatedAt() string {
	if x != nil {
		return x.CreatedAt
	}
	return ""
}

func (x *Route) GetUpdatedAt() string {
	if x != nil {
		return x.UpdatedAt
	}
	return ""
}

func (x *Route) GetDeletedAt() string {
	if x != nil && x.DeletedAt != nil {
		return *x.DeletedAt
	}
	return ""
}

type GetRoutesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetRoutesRequest) Reset() {
	*x = GetRoutesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_routes_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetRoutesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetRoutesRequest) ProtoMessage() {}

func (x *GetRoutesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_routes_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetRoutesRequest.ProtoReflect.Descriptor instead.
func (*GetRoutesRequest) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_routes_proto_rawDescGZIP(), []int{1}
}

type GetRoutesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Routes []*Route `protobuf:"bytes,1,rep,name=routes,proto3" json:"routes,omitempty"`
}

func (x *GetRoutesResponse) Reset() {
	*x = GetRoutesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_routes_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetRoutesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetRoutesResponse) ProtoMessage() {}

func (x *GetRoutesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_routes_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetRoutesResponse.ProtoReflect.Descriptor instead.
func (*GetRoutesResponse) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_routes_proto_rawDescGZIP(), []int{2}
}

func (x *GetRoutesResponse) GetRoutes() []*Route {
	if x != nil {
		return x.Routes
	}
	return nil
}

type EnableRouteRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RouteId string `protobuf:"bytes,1,opt,name=route_id,json=routeId,proto3" json:"route_id,omitempty"`
}

func (x *EnableRouteRequest) Reset() {
	*x = EnableRouteRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_routes_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EnableRouteRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnableRouteRequest) ProtoMessage() {}

func (x *EnableRouteRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_routes_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnableRouteRequest.ProtoReflect.Descriptor instead.
func (*EnableRouteRequest) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_routes_proto_rawDescGZIP(), []int{3}
}

func (x *EnableRouteRequest) GetRouteId() string {
	if x != nil {
		return x.RouteId
	}
	return ""
}

type EnableRouteResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *EnableRouteResponse) Reset() {
	*x = EnableRouteResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_routes_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EnableRouteResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnableRouteResponse) ProtoMessage() {}

func (x *EnableRouteResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_routes_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnableRouteResponse.ProtoReflect.Descriptor instead.
func (*EnableRouteResponse) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_routes_proto_rawDescGZIP(), []int{4}
}

type DisableRouteRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RouteId string `protobuf:"bytes,1,opt,name=route_id,json=routeId,proto3" json:"route_id,omitempty"`
}

func (x *DisableRouteRequest) Reset() {
	*x = DisableRouteRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_routes_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DisableRouteRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DisableRouteRequest) ProtoMessage() {}

func (x *DisableRouteRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_routes_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DisableRouteRequest.ProtoReflect.Descriptor instead.
func (*DisableRouteRequest) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_routes_proto_rawDescGZIP(), []int{5}
}

func (x *DisableRouteRequest) GetRouteId() string {
	if x != nil {
		return x.RouteId
	}
	return ""
}

type DisableRouteResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DisableRouteResponse) Reset() {
	*x = DisableRouteResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_routes_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DisableRouteResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DisableRouteResponse) ProtoMessage() {}

func (x *DisableRouteResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_routes_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DisableRouteResponse.ProtoReflect.Descriptor instead.
func (*DisableRouteResponse) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_routes_proto_rawDescGZIP(), []int{6}
}

type GetMachineRoutesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MachineId string `protobuf:"bytes,1,opt,name=machine_id,json=machineId,proto3" json:"machine_id,omitempty"`
}

func (x *GetMachineRoutesRequest) Reset() {
	*x = GetMachineRoutesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_routes_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetMachineRoutesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetMachineRoutesRequest) ProtoMessage() {}

func (x *GetMachineRoutesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_routes_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetMachineRoutesRequest.ProtoReflect.Descriptor instead.
func (*GetMachineRoutesRequest) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_routes_proto_rawDescGZIP(), []int{7}
}

func (x *GetMachineRoutesRequest) GetMachineId() string {
	if x != nil {
		return x.MachineId
	}
	return ""
}

type GetMachineRoutesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Routes []*Route `protobuf:"bytes,1,rep,name=routes,proto3" json:"routes,omitempty"`
}

func (x *GetMachineRoutesResponse) Reset() {
	*x = GetMachineRoutesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_routes_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetMachineRoutesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetMachineRoutesResponse) ProtoMessage() {}

func (x *GetMachineRoutesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_routes_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetMachineRoutesResponse.ProtoReflect.Descriptor instead.
func (*GetMachineRoutesResponse) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_routes_proto_rawDescGZIP(), []int{8}
}

func (x *GetMachineRoutesResponse) GetRoutes() []*Route {
	if x != nil {
		return x.Routes
	}
	return nil
}

type CreateMachineRoutesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MachineId string   `protobuf:"bytes,1,opt,name=machine_id,json=machineId,proto3" json:"machine_id,omitempty"`
	Routes    []*Route `protobuf:"bytes,2,rep,name=routes,proto3" json:"routes,omitempty"`
}

func (x *CreateMachineRoutesRequest) Reset() {
	*x = CreateMachineRoutesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_routes_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateMachineRoutesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateMachineRoutesRequest) ProtoMessage() {}

func (x *CreateMachineRoutesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_routes_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateMachineRoutesRequest.ProtoReflect.Descriptor instead.
func (*CreateMachineRoutesRequest) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_routes_proto_rawDescGZIP(), []int{9}
}

func (x *CreateMachineRoutesRequest) GetMachineId() string {
	if x != nil {
		return x.MachineId
	}
	return ""
}

func (x *CreateMachineRoutesRequest) GetRoutes() []*Route {
	if x != nil {
		return x.Routes
	}
	return nil
}

type CreateMachineRoutesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Routes []*Route `protobuf:"bytes,2,rep,name=routes,proto3" json:"routes,omitempty"`
}

func (x *CreateMachineRoutesResponse) Reset() {
	*x = CreateMachineRoutesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_routes_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateMachineRoutesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateMachineRoutesResponse) ProtoMessage() {}

func (x *CreateMachineRoutesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_routes_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateMachineRoutesResponse.ProtoReflect.Descriptor instead.
func (*CreateMachineRoutesResponse) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_routes_proto_rawDescGZIP(), []int{10}
}

func (x *CreateMachineRoutesResponse) GetRoutes() []*Route {
	if x != nil {
		return x.Routes
	}
	return nil
}

type UpdateMachineRoutesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MachineId string   `protobuf:"bytes,1,opt,name=machine_id,json=machineId,proto3" json:"machine_id,omitempty"`
	Routes    []*Route `protobuf:"bytes,2,rep,name=routes,proto3" json:"routes,omitempty"`
}

func (x *UpdateMachineRoutesRequest) Reset() {
	*x = UpdateMachineRoutesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_routes_proto_msgTypes[11]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateMachineRoutesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateMachineRoutesRequest) ProtoMessage() {}

func (x *UpdateMachineRoutesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_routes_proto_msgTypes[11]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateMachineRoutesRequest.ProtoReflect.Descriptor instead.
func (*UpdateMachineRoutesRequest) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_routes_proto_rawDescGZIP(), []int{11}
}

func (x *UpdateMachineRoutesRequest) GetMachineId() string {
	if x != nil {
		return x.MachineId
	}
	return ""
}

func (x *UpdateMachineRoutesRequest) GetRoutes() []*Route {
	if x != nil {
		return x.Routes
	}
	return nil
}

type UpdateMachineRoutesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Routes []*Route `protobuf:"bytes,2,rep,name=routes,proto3" json:"routes,omitempty"`
}

func (x *UpdateMachineRoutesResponse) Reset() {
	*x = UpdateMachineRoutesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_routes_proto_msgTypes[12]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateMachineRoutesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateMachineRoutesResponse) ProtoMessage() {}

func (x *UpdateMachineRoutesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_routes_proto_msgTypes[12]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateMachineRoutesResponse.ProtoReflect.Descriptor instead.
func (*UpdateMachineRoutesResponse) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_routes_proto_rawDescGZIP(), []int{12}
}

func (x *UpdateMachineRoutesResponse) GetRoutes() []*Route {
	if x != nil {
		return x.Routes
	}
	return nil
}

type DeleteMachineRouteRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MachineId string `protobuf:"bytes,1,opt,name=machine_id,json=machineId,proto3" json:"machine_id,omitempty"`
	RouteId   string `protobuf:"bytes,2,opt,name=route_id,json=routeId,proto3" json:"route_id,omitempty"`
}

func (x *DeleteMachineRouteRequest) Reset() {
	*x = DeleteMachineRouteRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_routes_proto_msgTypes[13]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteMachineRouteRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteMachineRouteRequest) ProtoMessage() {}

func (x *DeleteMachineRouteRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_routes_proto_msgTypes[13]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteMachineRouteRequest.ProtoReflect.Descriptor instead.
func (*DeleteMachineRouteRequest) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_routes_proto_rawDescGZIP(), []int{13}
}

func (x *DeleteMachineRouteRequest) GetMachineId() string {
	if x != nil {
		return x.MachineId
	}
	return ""
}

func (x *DeleteMachineRouteRequest) GetRouteId() string {
	if x != nil {
		return x.RouteId
	}
	return ""
}

type DeleteMachineRouteResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DeleteMachineRouteResponse) Reset() {
	*x = DeleteMachineRouteResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_routes_proto_msgTypes[14]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteMachineRouteResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteMachineRouteResponse) ProtoMessage() {}

func (x *DeleteMachineRouteResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_routes_proto_msgTypes[14]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteMachineRouteResponse.ProtoReflect.Descriptor instead.
func (*DeleteMachineRouteResponse) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_routes_proto_rawDescGZIP(), []int{14}
}

var File_ninjapanda_v1_routes_proto protoreflect.FileDescriptor

var file_ninjapanda_v1_routes_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2f, 0x76, 0x31, 0x2f,
	0x72, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0d, 0x6e, 0x69,
	0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x22, 0xa3, 0x02, 0x0a, 0x05,
	0x52, 0x6f, 0x75, 0x74, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x5f, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x49, 0x64,
	0x12, 0x1d, 0x0a, 0x0a, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x49, 0x64, 0x12,
	0x16, 0x0a, 0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x12, 0x1e, 0x0a, 0x0a, 0x61, 0x64, 0x76, 0x65, 0x72,
	0x74, 0x69, 0x73, 0x65, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x61, 0x64, 0x76,
	0x65, 0x72, 0x74, 0x69, 0x73, 0x65, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x65, 0x6e, 0x61, 0x62, 0x6c,
	0x65, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65,
	0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x69, 0x73, 0x5f, 0x70, 0x72, 0x69, 0x6d, 0x61, 0x72, 0x79, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x69, 0x73, 0x50, 0x72, 0x69, 0x6d, 0x61, 0x72, 0x79,
	0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x07,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12,
	0x1d, 0x0a, 0x0a, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x08, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x09, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x12, 0x22,
	0x0a, 0x0a, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x09, 0x20, 0x01,
	0x28, 0x09, 0x48, 0x00, 0x52, 0x09, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x41, 0x74, 0x88,
	0x01, 0x01, 0x42, 0x0d, 0x0a, 0x0b, 0x5f, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x64, 0x5f, 0x61,
	0x74, 0x22, 0x12, 0x0a, 0x10, 0x47, 0x65, 0x74, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x41, 0x0a, 0x11, 0x47, 0x65, 0x74, 0x52, 0x6f, 0x75, 0x74,
	0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2c, 0x0a, 0x06, 0x72, 0x6f,
	0x75, 0x74, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x6e, 0x69, 0x6e,
	0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x6f, 0x75, 0x74, 0x65,
	0x52, 0x06, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x22, 0x2f, 0x0a, 0x12, 0x45, 0x6e, 0x61, 0x62,
	0x6c, 0x65, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x19,
	0x0a, 0x08, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x07, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x49, 0x64, 0x22, 0x15, 0x0a, 0x13, 0x45, 0x6e, 0x61,
	0x62, 0x6c, 0x65, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x22, 0x30, 0x0a, 0x13, 0x44, 0x69, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x52, 0x6f, 0x75, 0x74, 0x65,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x19, 0x0a, 0x08, 0x72, 0x6f, 0x75, 0x74, 0x65,
	0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x72, 0x6f, 0x75, 0x74, 0x65,
	0x49, 0x64, 0x22, 0x16, 0x0a, 0x14, 0x44, 0x69, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x52, 0x6f, 0x75,
	0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x38, 0x0a, 0x17, 0x47, 0x65,
	0x74, 0x4d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65,
	0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6d, 0x61, 0x63, 0x68, 0x69,
	0x6e, 0x65, 0x49, 0x64, 0x22, 0x48, 0x0a, 0x18, 0x47, 0x65, 0x74, 0x4d, 0x61, 0x63, 0x68, 0x69,
	0x6e, 0x65, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x2c, 0x0a, 0x06, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x14, 0x2e, 0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31,
	0x2e, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x52, 0x06, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x22, 0x69,
	0x0a, 0x1a, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x4d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x52,
	0x6f, 0x75, 0x74, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a,
	0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x09, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x49, 0x64, 0x12, 0x2c, 0x0a, 0x06, 0x72,
	0x6f, 0x75, 0x74, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x6e, 0x69,
	0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x6f, 0x75, 0x74,
	0x65, 0x52, 0x06, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x22, 0x4b, 0x0a, 0x1b, 0x43, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x4d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x73,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2c, 0x0a, 0x06, 0x72, 0x6f, 0x75, 0x74,
	0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x6e, 0x69, 0x6e, 0x6a, 0x61,
	0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x52, 0x06,
	0x72, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x22, 0x69, 0x0a, 0x1a, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65,
	0x4d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x5f,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e,
	0x65, 0x49, 0x64, 0x12, 0x2c, 0x0a, 0x06, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x18, 0x02, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61,
	0x2e, 0x76, 0x31, 0x2e, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x52, 0x06, 0x72, 0x6f, 0x75, 0x74, 0x65,
	0x73, 0x22, 0x4b, 0x0a, 0x1b, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x4d, 0x61, 0x63, 0x68, 0x69,
	0x6e, 0x65, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x2c, 0x0a, 0x06, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x14, 0x2e, 0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31,
	0x2e, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x52, 0x06, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x73, 0x22, 0x55,
	0x0a, 0x19, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x4d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x52,
	0x6f, 0x75, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x6d,
	0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x09, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x49, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x72, 0x6f,
	0x75, 0x74, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x72, 0x6f,
	0x75, 0x74, 0x65, 0x49, 0x64, 0x22, 0x1c, 0x0a, 0x1a, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x4d,
	0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x42, 0x0f, 0x5a, 0x0d, 0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64,
	0x61, 0x2e, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ninjapanda_v1_routes_proto_rawDescOnce sync.Once
	file_ninjapanda_v1_routes_proto_rawDescData = file_ninjapanda_v1_routes_proto_rawDesc
)

func file_ninjapanda_v1_routes_proto_rawDescGZIP() []byte {
	file_ninjapanda_v1_routes_proto_rawDescOnce.Do(func() {
		file_ninjapanda_v1_routes_proto_rawDescData = protoimpl.X.CompressGZIP(file_ninjapanda_v1_routes_proto_rawDescData)
	})
	return file_ninjapanda_v1_routes_proto_rawDescData
}

var file_ninjapanda_v1_routes_proto_msgTypes = make([]protoimpl.MessageInfo, 15)
var file_ninjapanda_v1_routes_proto_goTypes = []interface{}{
	(*Route)(nil),                       // 0: ninjapanda.v1.Route
	(*GetRoutesRequest)(nil),            // 1: ninjapanda.v1.GetRoutesRequest
	(*GetRoutesResponse)(nil),           // 2: ninjapanda.v1.GetRoutesResponse
	(*EnableRouteRequest)(nil),          // 3: ninjapanda.v1.EnableRouteRequest
	(*EnableRouteResponse)(nil),         // 4: ninjapanda.v1.EnableRouteResponse
	(*DisableRouteRequest)(nil),         // 5: ninjapanda.v1.DisableRouteRequest
	(*DisableRouteResponse)(nil),        // 6: ninjapanda.v1.DisableRouteResponse
	(*GetMachineRoutesRequest)(nil),     // 7: ninjapanda.v1.GetMachineRoutesRequest
	(*GetMachineRoutesResponse)(nil),    // 8: ninjapanda.v1.GetMachineRoutesResponse
	(*CreateMachineRoutesRequest)(nil),  // 9: ninjapanda.v1.CreateMachineRoutesRequest
	(*CreateMachineRoutesResponse)(nil), // 10: ninjapanda.v1.CreateMachineRoutesResponse
	(*UpdateMachineRoutesRequest)(nil),  // 11: ninjapanda.v1.UpdateMachineRoutesRequest
	(*UpdateMachineRoutesResponse)(nil), // 12: ninjapanda.v1.UpdateMachineRoutesResponse
	(*DeleteMachineRouteRequest)(nil),   // 13: ninjapanda.v1.DeleteMachineRouteRequest
	(*DeleteMachineRouteResponse)(nil),  // 14: ninjapanda.v1.DeleteMachineRouteResponse
}
var file_ninjapanda_v1_routes_proto_depIdxs = []int32{
	0, // 0: ninjapanda.v1.GetRoutesResponse.routes:type_name -> ninjapanda.v1.Route
	0, // 1: ninjapanda.v1.GetMachineRoutesResponse.routes:type_name -> ninjapanda.v1.Route
	0, // 2: ninjapanda.v1.CreateMachineRoutesRequest.routes:type_name -> ninjapanda.v1.Route
	0, // 3: ninjapanda.v1.CreateMachineRoutesResponse.routes:type_name -> ninjapanda.v1.Route
	0, // 4: ninjapanda.v1.UpdateMachineRoutesRequest.routes:type_name -> ninjapanda.v1.Route
	0, // 5: ninjapanda.v1.UpdateMachineRoutesResponse.routes:type_name -> ninjapanda.v1.Route
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_ninjapanda_v1_routes_proto_init() }
func file_ninjapanda_v1_routes_proto_init() {
	if File_ninjapanda_v1_routes_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ninjapanda_v1_routes_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Route); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ninjapanda_v1_routes_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetRoutesRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ninjapanda_v1_routes_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetRoutesResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ninjapanda_v1_routes_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EnableRouteRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ninjapanda_v1_routes_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EnableRouteResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ninjapanda_v1_routes_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DisableRouteRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ninjapanda_v1_routes_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DisableRouteResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ninjapanda_v1_routes_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetMachineRoutesRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ninjapanda_v1_routes_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetMachineRoutesResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ninjapanda_v1_routes_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateMachineRoutesRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ninjapanda_v1_routes_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateMachineRoutesResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ninjapanda_v1_routes_proto_msgTypes[11].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateMachineRoutesRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ninjapanda_v1_routes_proto_msgTypes[12].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateMachineRoutesResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ninjapanda_v1_routes_proto_msgTypes[13].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteMachineRouteRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ninjapanda_v1_routes_proto_msgTypes[14].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteMachineRouteResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_ninjapanda_v1_routes_proto_msgTypes[0].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_ninjapanda_v1_routes_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   15,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ninjapanda_v1_routes_proto_goTypes,
		DependencyIndexes: file_ninjapanda_v1_routes_proto_depIdxs,
		MessageInfos:      file_ninjapanda_v1_routes_proto_msgTypes,
	}.Build()
	File_ninjapanda_v1_routes_proto = out.File
	file_ninjapanda_v1_routes_proto_rawDesc = nil
	file_ninjapanda_v1_routes_proto_goTypes = nil
	file_ninjapanda_v1_routes_proto_depIdxs = nil
}