// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: ninjapanda/v1/preauthkey.proto

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

type PreAuthKeyStatus int32

const (
	PreAuthKeyStatus_PRE_AUTH_KEY_STATUS_UNSPECIFIED PreAuthKeyStatus = 0
	PreAuthKeyStatus_PRE_AUTH_KEY_STATUS_VALID       PreAuthKeyStatus = 1
	PreAuthKeyStatus_PRE_AUTH_KEY_STATUS_EXPIRED     PreAuthKeyStatus = 2
	PreAuthKeyStatus_PRE_AUTH_KEY_STATUS_REVOKED     PreAuthKeyStatus = 3
	PreAuthKeyStatus_PRE_AUTH_KEY_STATUS_DEPLETED    PreAuthKeyStatus = 4
)

// Enum value maps for PreAuthKeyStatus.
var (
	PreAuthKeyStatus_name = map[int32]string{
		0: "PRE_AUTH_KEY_STATUS_UNSPECIFIED",
		1: "PRE_AUTH_KEY_STATUS_VALID",
		2: "PRE_AUTH_KEY_STATUS_EXPIRED",
		3: "PRE_AUTH_KEY_STATUS_REVOKED",
		4: "PRE_AUTH_KEY_STATUS_DEPLETED",
	}
	PreAuthKeyStatus_value = map[string]int32{
		"PRE_AUTH_KEY_STATUS_UNSPECIFIED": 0,
		"PRE_AUTH_KEY_STATUS_VALID":       1,
		"PRE_AUTH_KEY_STATUS_EXPIRED":     2,
		"PRE_AUTH_KEY_STATUS_REVOKED":     3,
		"PRE_AUTH_KEY_STATUS_DEPLETED":    4,
	}
)

func (x PreAuthKeyStatus) Enum() *PreAuthKeyStatus {
	p := new(PreAuthKeyStatus)
	*p = x
	return p
}

func (x PreAuthKeyStatus) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (PreAuthKeyStatus) Descriptor() protoreflect.EnumDescriptor {
	return file_ninjapanda_v1_preauthkey_proto_enumTypes[0].Descriptor()
}

func (PreAuthKeyStatus) Type() protoreflect.EnumType {
	return &file_ninjapanda_v1_preauthkey_proto_enumTypes[0]
}

func (x PreAuthKeyStatus) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use PreAuthKeyStatus.Descriptor instead.
func (PreAuthKeyStatus) EnumDescriptor() ([]byte, []int) {
	return file_ninjapanda_v1_preauthkey_proto_rawDescGZIP(), []int{0}
}

type PreAuthKey struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PreAuthKeyId string           `protobuf:"bytes,1,opt,name=pre_auth_key_id,json=preAuthKeyId,proto3" json:"pre_auth_key_id,omitempty"`
	Namespace    string           `protobuf:"bytes,2,opt,name=namespace,proto3" json:"namespace,omitempty"`
	Key          *string          `protobuf:"bytes,3,opt,name=key,proto3,oneof" json:"key,omitempty"`
	Prefix       string           `protobuf:"bytes,4,opt,name=prefix,proto3" json:"prefix,omitempty"`
	ReuseCount   uint64           `protobuf:"varint,5,opt,name=reuse_count,json=reuseCount,proto3" json:"reuse_count,omitempty"`
	UsedCount    uint64           `protobuf:"varint,6,opt,name=used_count,json=usedCount,proto3" json:"used_count,omitempty"`
	Ephemeral    bool             `protobuf:"varint,7,opt,name=ephemeral,proto3" json:"ephemeral,omitempty"`
	Expiration   *string          `protobuf:"bytes,8,opt,name=expiration,proto3,oneof" json:"expiration,omitempty"`
	CreatedAt    string           `protobuf:"bytes,9,opt,name=created_at,json=createdAt,proto3" json:"created_at,omitempty"`
	RevokedAt    *string          `protobuf:"bytes,10,opt,name=revoked_at,json=revokedAt,proto3,oneof" json:"revoked_at,omitempty"`
	Status       PreAuthKeyStatus `protobuf:"varint,11,opt,name=status,proto3,enum=ninjapanda.v1.PreAuthKeyStatus" json:"status,omitempty"`
	AclTags      []string         `protobuf:"bytes,12,rep,name=acl_tags,json=aclTags,proto3" json:"acl_tags,omitempty"`
}

func (x *PreAuthKey) Reset() {
	*x = PreAuthKey{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_preauthkey_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PreAuthKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PreAuthKey) ProtoMessage() {}

func (x *PreAuthKey) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_preauthkey_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PreAuthKey.ProtoReflect.Descriptor instead.
func (*PreAuthKey) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_preauthkey_proto_rawDescGZIP(), []int{0}
}

func (x *PreAuthKey) GetPreAuthKeyId() string {
	if x != nil {
		return x.PreAuthKeyId
	}
	return ""
}

func (x *PreAuthKey) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

func (x *PreAuthKey) GetKey() string {
	if x != nil && x.Key != nil {
		return *x.Key
	}
	return ""
}

func (x *PreAuthKey) GetPrefix() string {
	if x != nil {
		return x.Prefix
	}
	return ""
}

func (x *PreAuthKey) GetReuseCount() uint64 {
	if x != nil {
		return x.ReuseCount
	}
	return 0
}

func (x *PreAuthKey) GetUsedCount() uint64 {
	if x != nil {
		return x.UsedCount
	}
	return 0
}

func (x *PreAuthKey) GetEphemeral() bool {
	if x != nil {
		return x.Ephemeral
	}
	return false
}

func (x *PreAuthKey) GetExpiration() string {
	if x != nil && x.Expiration != nil {
		return *x.Expiration
	}
	return ""
}

func (x *PreAuthKey) GetCreatedAt() string {
	if x != nil {
		return x.CreatedAt
	}
	return ""
}

func (x *PreAuthKey) GetRevokedAt() string {
	if x != nil && x.RevokedAt != nil {
		return *x.RevokedAt
	}
	return ""
}

func (x *PreAuthKey) GetStatus() PreAuthKeyStatus {
	if x != nil {
		return x.Status
	}
	return PreAuthKeyStatus_PRE_AUTH_KEY_STATUS_UNSPECIFIED
}

func (x *PreAuthKey) GetAclTags() []string {
	if x != nil {
		return x.AclTags
	}
	return nil
}

type CreatePreAuthKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Namespace  string   `protobuf:"bytes,1,opt,name=namespace,proto3" json:"namespace,omitempty"`
	Prefix     string   `protobuf:"bytes,2,opt,name=prefix,proto3" json:"prefix,omitempty"`
	ReuseCount uint64   `protobuf:"varint,3,opt,name=reuse_count,json=reuseCount,proto3" json:"reuse_count,omitempty"`
	Ephemeral  bool     `protobuf:"varint,4,opt,name=ephemeral,proto3" json:"ephemeral,omitempty"`
	Expiration *string  `protobuf:"bytes,5,opt,name=expiration,proto3,oneof" json:"expiration,omitempty"`
	AclTags    []string `protobuf:"bytes,6,rep,name=acl_tags,json=aclTags,proto3" json:"acl_tags,omitempty"`
}

func (x *CreatePreAuthKeyRequest) Reset() {
	*x = CreatePreAuthKeyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_preauthkey_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreatePreAuthKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreatePreAuthKeyRequest) ProtoMessage() {}

func (x *CreatePreAuthKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_preauthkey_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreatePreAuthKeyRequest.ProtoReflect.Descriptor instead.
func (*CreatePreAuthKeyRequest) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_preauthkey_proto_rawDescGZIP(), []int{1}
}

func (x *CreatePreAuthKeyRequest) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

func (x *CreatePreAuthKeyRequest) GetPrefix() string {
	if x != nil {
		return x.Prefix
	}
	return ""
}

func (x *CreatePreAuthKeyRequest) GetReuseCount() uint64 {
	if x != nil {
		return x.ReuseCount
	}
	return 0
}

func (x *CreatePreAuthKeyRequest) GetEphemeral() bool {
	if x != nil {
		return x.Ephemeral
	}
	return false
}

func (x *CreatePreAuthKeyRequest) GetExpiration() string {
	if x != nil && x.Expiration != nil {
		return *x.Expiration
	}
	return ""
}

func (x *CreatePreAuthKeyRequest) GetAclTags() []string {
	if x != nil {
		return x.AclTags
	}
	return nil
}

type CreatePreAuthKeyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PreAuthKey *PreAuthKey `protobuf:"bytes,1,opt,name=pre_auth_key,json=preAuthKey,proto3" json:"pre_auth_key,omitempty"`
}

func (x *CreatePreAuthKeyResponse) Reset() {
	*x = CreatePreAuthKeyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_preauthkey_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreatePreAuthKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreatePreAuthKeyResponse) ProtoMessage() {}

func (x *CreatePreAuthKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_preauthkey_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreatePreAuthKeyResponse.ProtoReflect.Descriptor instead.
func (*CreatePreAuthKeyResponse) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_preauthkey_proto_rawDescGZIP(), []int{2}
}

func (x *CreatePreAuthKeyResponse) GetPreAuthKey() *PreAuthKey {
	if x != nil {
		return x.PreAuthKey
	}
	return nil
}

type ExpirePreAuthKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Namespace    string `protobuf:"bytes,1,opt,name=namespace,proto3" json:"namespace,omitempty"`
	PreAuthKeyId string `protobuf:"bytes,2,opt,name=pre_auth_key_id,json=preAuthKeyId,proto3" json:"pre_auth_key_id,omitempty"`
}

func (x *ExpirePreAuthKeyRequest) Reset() {
	*x = ExpirePreAuthKeyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_preauthkey_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ExpirePreAuthKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ExpirePreAuthKeyRequest) ProtoMessage() {}

func (x *ExpirePreAuthKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_preauthkey_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ExpirePreAuthKeyRequest.ProtoReflect.Descriptor instead.
func (*ExpirePreAuthKeyRequest) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_preauthkey_proto_rawDescGZIP(), []int{3}
}

func (x *ExpirePreAuthKeyRequest) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

func (x *ExpirePreAuthKeyRequest) GetPreAuthKeyId() string {
	if x != nil {
		return x.PreAuthKeyId
	}
	return ""
}

type ExpirePreAuthKeyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PreAuthKey *PreAuthKey `protobuf:"bytes,1,opt,name=pre_auth_key,json=preAuthKey,proto3" json:"pre_auth_key,omitempty"`
}

func (x *ExpirePreAuthKeyResponse) Reset() {
	*x = ExpirePreAuthKeyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_preauthkey_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ExpirePreAuthKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ExpirePreAuthKeyResponse) ProtoMessage() {}

func (x *ExpirePreAuthKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_preauthkey_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ExpirePreAuthKeyResponse.ProtoReflect.Descriptor instead.
func (*ExpirePreAuthKeyResponse) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_preauthkey_proto_rawDescGZIP(), []int{4}
}

func (x *ExpirePreAuthKeyResponse) GetPreAuthKey() *PreAuthKey {
	if x != nil {
		return x.PreAuthKey
	}
	return nil
}

type RevokePreAuthKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Namespace    string `protobuf:"bytes,1,opt,name=namespace,proto3" json:"namespace,omitempty"`
	PreAuthKeyId string `protobuf:"bytes,2,opt,name=pre_auth_key_id,json=preAuthKeyId,proto3" json:"pre_auth_key_id,omitempty"`
}

func (x *RevokePreAuthKeyRequest) Reset() {
	*x = RevokePreAuthKeyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_preauthkey_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RevokePreAuthKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RevokePreAuthKeyRequest) ProtoMessage() {}

func (x *RevokePreAuthKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_preauthkey_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RevokePreAuthKeyRequest.ProtoReflect.Descriptor instead.
func (*RevokePreAuthKeyRequest) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_preauthkey_proto_rawDescGZIP(), []int{5}
}

func (x *RevokePreAuthKeyRequest) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

func (x *RevokePreAuthKeyRequest) GetPreAuthKeyId() string {
	if x != nil {
		return x.PreAuthKeyId
	}
	return ""
}

type RevokePreAuthKeyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PreAuthKey *PreAuthKey `protobuf:"bytes,1,opt,name=pre_auth_key,json=preAuthKey,proto3" json:"pre_auth_key,omitempty"`
}

func (x *RevokePreAuthKeyResponse) Reset() {
	*x = RevokePreAuthKeyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_preauthkey_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RevokePreAuthKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RevokePreAuthKeyResponse) ProtoMessage() {}

func (x *RevokePreAuthKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_preauthkey_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RevokePreAuthKeyResponse.ProtoReflect.Descriptor instead.
func (*RevokePreAuthKeyResponse) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_preauthkey_proto_rawDescGZIP(), []int{6}
}

func (x *RevokePreAuthKeyResponse) GetPreAuthKey() *PreAuthKey {
	if x != nil {
		return x.PreAuthKey
	}
	return nil
}

type ListPreAuthKeysRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Namespace string `protobuf:"bytes,1,opt,name=namespace,proto3" json:"namespace,omitempty"`
}

func (x *ListPreAuthKeysRequest) Reset() {
	*x = ListPreAuthKeysRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_preauthkey_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListPreAuthKeysRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListPreAuthKeysRequest) ProtoMessage() {}

func (x *ListPreAuthKeysRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_preauthkey_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListPreAuthKeysRequest.ProtoReflect.Descriptor instead.
func (*ListPreAuthKeysRequest) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_preauthkey_proto_rawDescGZIP(), []int{7}
}

func (x *ListPreAuthKeysRequest) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

type ListPreAuthKeysResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PreAuthKeys []*PreAuthKey `protobuf:"bytes,1,rep,name=pre_auth_keys,json=preAuthKeys,proto3" json:"pre_auth_keys,omitempty"`
}

func (x *ListPreAuthKeysResponse) Reset() {
	*x = ListPreAuthKeysResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_preauthkey_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListPreAuthKeysResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListPreAuthKeysResponse) ProtoMessage() {}

func (x *ListPreAuthKeysResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_preauthkey_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListPreAuthKeysResponse.ProtoReflect.Descriptor instead.
func (*ListPreAuthKeysResponse) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_preauthkey_proto_rawDescGZIP(), []int{8}
}

func (x *ListPreAuthKeysResponse) GetPreAuthKeys() []*PreAuthKey {
	if x != nil {
		return x.PreAuthKeys
	}
	return nil
}

var File_ninjapanda_v1_preauthkey_proto protoreflect.FileDescriptor

var file_ninjapanda_v1_preauthkey_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2f, 0x76, 0x31, 0x2f,
	0x70, 0x72, 0x65, 0x61, 0x75, 0x74, 0x68, 0x6b, 0x65, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x0d, 0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x22,
	0xc0, 0x03, 0x0a, 0x0a, 0x50, 0x72, 0x65, 0x41, 0x75, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x12, 0x25,
	0x0a, 0x0f, 0x70, 0x72, 0x65, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x69,
	0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x70, 0x72, 0x65, 0x41, 0x75, 0x74, 0x68,
	0x4b, 0x65, 0x79, 0x49, 0x64, 0x12, 0x1c, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61,
	0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70,
	0x61, 0x63, 0x65, 0x12, 0x15, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09,
	0x48, 0x00, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x88, 0x01, 0x01, 0x12, 0x16, 0x0a, 0x06, 0x70, 0x72,
	0x65, 0x66, 0x69, 0x78, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x70, 0x72, 0x65, 0x66,
	0x69, 0x78, 0x12, 0x1f, 0x0a, 0x0b, 0x72, 0x65, 0x75, 0x73, 0x65, 0x5f, 0x63, 0x6f, 0x75, 0x6e,
	0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0a, 0x72, 0x65, 0x75, 0x73, 0x65, 0x43, 0x6f,
	0x75, 0x6e, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x75, 0x73, 0x65, 0x64, 0x5f, 0x63, 0x6f, 0x75, 0x6e,
	0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x04, 0x52, 0x09, 0x75, 0x73, 0x65, 0x64, 0x43, 0x6f, 0x75,
	0x6e, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x65, 0x70, 0x68, 0x65, 0x6d, 0x65, 0x72, 0x61, 0x6c, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x65, 0x70, 0x68, 0x65, 0x6d, 0x65, 0x72, 0x61, 0x6c,
	0x12, 0x23, 0x0a, 0x0a, 0x65, 0x78, 0x70, 0x69, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x09, 0x48, 0x01, 0x52, 0x0a, 0x65, 0x78, 0x70, 0x69, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x88, 0x01, 0x01, 0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64,
	0x5f, 0x61, 0x74, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x63, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x64, 0x41, 0x74, 0x12, 0x22, 0x0a, 0x0a, 0x72, 0x65, 0x76, 0x6f, 0x6b, 0x65, 0x64, 0x5f,
	0x61, 0x74, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x48, 0x02, 0x52, 0x09, 0x72, 0x65, 0x76, 0x6f,
	0x6b, 0x65, 0x64, 0x41, 0x74, 0x88, 0x01, 0x01, 0x12, 0x37, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x1f, 0x2e, 0x6e, 0x69, 0x6e, 0x6a, 0x61,
	0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x65, 0x41, 0x75, 0x74, 0x68,
	0x4b, 0x65, 0x79, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x12, 0x19, 0x0a, 0x08, 0x61, 0x63, 0x6c, 0x5f, 0x74, 0x61, 0x67, 0x73, 0x18, 0x0c, 0x20,
	0x03, 0x28, 0x09, 0x52, 0x07, 0x61, 0x63, 0x6c, 0x54, 0x61, 0x67, 0x73, 0x42, 0x06, 0x0a, 0x04,
	0x5f, 0x6b, 0x65, 0x79, 0x42, 0x0d, 0x0a, 0x0b, 0x5f, 0x65, 0x78, 0x70, 0x69, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x42, 0x0d, 0x0a, 0x0b, 0x5f, 0x72, 0x65, 0x76, 0x6f, 0x6b, 0x65, 0x64, 0x5f,
	0x61, 0x74, 0x22, 0xdd, 0x01, 0x0a, 0x17, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x50, 0x72, 0x65,
	0x41, 0x75, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1c,
	0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x12, 0x16, 0x0a, 0x06,
	0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x70, 0x72,
	0x65, 0x66, 0x69, 0x78, 0x12, 0x1f, 0x0a, 0x0b, 0x72, 0x65, 0x75, 0x73, 0x65, 0x5f, 0x63, 0x6f,
	0x75, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0a, 0x72, 0x65, 0x75, 0x73, 0x65,
	0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x65, 0x70, 0x68, 0x65, 0x6d, 0x65, 0x72,
	0x61, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x65, 0x70, 0x68, 0x65, 0x6d, 0x65,
	0x72, 0x61, 0x6c, 0x12, 0x23, 0x0a, 0x0a, 0x65, 0x78, 0x70, 0x69, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x0a, 0x65, 0x78, 0x70, 0x69, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x88, 0x01, 0x01, 0x12, 0x19, 0x0a, 0x08, 0x61, 0x63, 0x6c, 0x5f,
	0x74, 0x61, 0x67, 0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x09, 0x52, 0x07, 0x61, 0x63, 0x6c, 0x54,
	0x61, 0x67, 0x73, 0x42, 0x0d, 0x0a, 0x0b, 0x5f, 0x65, 0x78, 0x70, 0x69, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x22, 0x57, 0x0a, 0x18, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x50, 0x72, 0x65, 0x41,
	0x75, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3b,
	0x0a, 0x0c, 0x70, 0x72, 0x65, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64,
	0x61, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x65, 0x41, 0x75, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x52,
	0x0a, 0x70, 0x72, 0x65, 0x41, 0x75, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x22, 0x5e, 0x0a, 0x17, 0x45,
	0x78, 0x70, 0x69, 0x72, 0x65, 0x50, 0x72, 0x65, 0x41, 0x75, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70,
	0x61, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73,
	0x70, 0x61, 0x63, 0x65, 0x12, 0x25, 0x0a, 0x0f, 0x70, 0x72, 0x65, 0x5f, 0x61, 0x75, 0x74, 0x68,
	0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x70,
	0x72, 0x65, 0x41, 0x75, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x49, 0x64, 0x22, 0x57, 0x0a, 0x18, 0x45,
	0x78, 0x70, 0x69, 0x72, 0x65, 0x50, 0x72, 0x65, 0x41, 0x75, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3b, 0x0a, 0x0c, 0x70, 0x72, 0x65, 0x5f, 0x61,
	0x75, 0x74, 0x68, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e,
	0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72,
	0x65, 0x41, 0x75, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x52, 0x0a, 0x70, 0x72, 0x65, 0x41, 0x75, 0x74,
	0x68, 0x4b, 0x65, 0x79, 0x22, 0x5e, 0x0a, 0x17, 0x52, 0x65, 0x76, 0x6f, 0x6b, 0x65, 0x50, 0x72,
	0x65, 0x41, 0x75, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x1c, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x12, 0x25, 0x0a,
	0x0f, 0x70, 0x72, 0x65, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x70, 0x72, 0x65, 0x41, 0x75, 0x74, 0x68, 0x4b,
	0x65, 0x79, 0x49, 0x64, 0x22, 0x57, 0x0a, 0x18, 0x52, 0x65, 0x76, 0x6f, 0x6b, 0x65, 0x50, 0x72,
	0x65, 0x41, 0x75, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x3b, 0x0a, 0x0c, 0x70, 0x72, 0x65, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x6b, 0x65, 0x79,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61,
	0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x65, 0x41, 0x75, 0x74, 0x68, 0x4b, 0x65,
	0x79, 0x52, 0x0a, 0x70, 0x72, 0x65, 0x41, 0x75, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x22, 0x36, 0x0a,
	0x16, 0x4c, 0x69, 0x73, 0x74, 0x50, 0x72, 0x65, 0x41, 0x75, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x73,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73,
	0x70, 0x61, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65,
	0x73, 0x70, 0x61, 0x63, 0x65, 0x22, 0x58, 0x0a, 0x17, 0x4c, 0x69, 0x73, 0x74, 0x50, 0x72, 0x65,
	0x41, 0x75, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x3d, 0x0a, 0x0d, 0x70, 0x72, 0x65, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x6b, 0x65, 0x79,
	0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70,
	0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x72, 0x65, 0x41, 0x75, 0x74, 0x68, 0x4b,
	0x65, 0x79, 0x52, 0x0b, 0x70, 0x72, 0x65, 0x41, 0x75, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x73, 0x2a,
	0xba, 0x01, 0x0a, 0x10, 0x50, 0x72, 0x65, 0x41, 0x75, 0x74, 0x68, 0x4b, 0x65, 0x79, 0x53, 0x74,
	0x61, 0x74, 0x75, 0x73, 0x12, 0x23, 0x0a, 0x1f, 0x50, 0x52, 0x45, 0x5f, 0x41, 0x55, 0x54, 0x48,
	0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f, 0x55, 0x4e, 0x53, 0x50,
	0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x1d, 0x0a, 0x19, 0x50, 0x52, 0x45,
	0x5f, 0x41, 0x55, 0x54, 0x48, 0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53,
	0x5f, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x10, 0x01, 0x12, 0x1f, 0x0a, 0x1b, 0x50, 0x52, 0x45, 0x5f,
	0x41, 0x55, 0x54, 0x48, 0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x5f,
	0x45, 0x58, 0x50, 0x49, 0x52, 0x45, 0x44, 0x10, 0x02, 0x12, 0x1f, 0x0a, 0x1b, 0x50, 0x52, 0x45,
	0x5f, 0x41, 0x55, 0x54, 0x48, 0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55, 0x53,
	0x5f, 0x52, 0x45, 0x56, 0x4f, 0x4b, 0x45, 0x44, 0x10, 0x03, 0x12, 0x20, 0x0a, 0x1c, 0x50, 0x52,
	0x45, 0x5f, 0x41, 0x55, 0x54, 0x48, 0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x53, 0x54, 0x41, 0x54, 0x55,
	0x53, 0x5f, 0x44, 0x45, 0x50, 0x4c, 0x45, 0x54, 0x45, 0x44, 0x10, 0x04, 0x42, 0x0f, 0x5a, 0x0d,
	0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ninjapanda_v1_preauthkey_proto_rawDescOnce sync.Once
	file_ninjapanda_v1_preauthkey_proto_rawDescData = file_ninjapanda_v1_preauthkey_proto_rawDesc
)

func file_ninjapanda_v1_preauthkey_proto_rawDescGZIP() []byte {
	file_ninjapanda_v1_preauthkey_proto_rawDescOnce.Do(func() {
		file_ninjapanda_v1_preauthkey_proto_rawDescData = protoimpl.X.CompressGZIP(file_ninjapanda_v1_preauthkey_proto_rawDescData)
	})
	return file_ninjapanda_v1_preauthkey_proto_rawDescData
}

var file_ninjapanda_v1_preauthkey_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_ninjapanda_v1_preauthkey_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_ninjapanda_v1_preauthkey_proto_goTypes = []interface{}{
	(PreAuthKeyStatus)(0),            // 0: ninjapanda.v1.PreAuthKeyStatus
	(*PreAuthKey)(nil),               // 1: ninjapanda.v1.PreAuthKey
	(*CreatePreAuthKeyRequest)(nil),  // 2: ninjapanda.v1.CreatePreAuthKeyRequest
	(*CreatePreAuthKeyResponse)(nil), // 3: ninjapanda.v1.CreatePreAuthKeyResponse
	(*ExpirePreAuthKeyRequest)(nil),  // 4: ninjapanda.v1.ExpirePreAuthKeyRequest
	(*ExpirePreAuthKeyResponse)(nil), // 5: ninjapanda.v1.ExpirePreAuthKeyResponse
	(*RevokePreAuthKeyRequest)(nil),  // 6: ninjapanda.v1.RevokePreAuthKeyRequest
	(*RevokePreAuthKeyResponse)(nil), // 7: ninjapanda.v1.RevokePreAuthKeyResponse
	(*ListPreAuthKeysRequest)(nil),   // 8: ninjapanda.v1.ListPreAuthKeysRequest
	(*ListPreAuthKeysResponse)(nil),  // 9: ninjapanda.v1.ListPreAuthKeysResponse
}
var file_ninjapanda_v1_preauthkey_proto_depIdxs = []int32{
	0, // 0: ninjapanda.v1.PreAuthKey.status:type_name -> ninjapanda.v1.PreAuthKeyStatus
	1, // 1: ninjapanda.v1.CreatePreAuthKeyResponse.pre_auth_key:type_name -> ninjapanda.v1.PreAuthKey
	1, // 2: ninjapanda.v1.ExpirePreAuthKeyResponse.pre_auth_key:type_name -> ninjapanda.v1.PreAuthKey
	1, // 3: ninjapanda.v1.RevokePreAuthKeyResponse.pre_auth_key:type_name -> ninjapanda.v1.PreAuthKey
	1, // 4: ninjapanda.v1.ListPreAuthKeysResponse.pre_auth_keys:type_name -> ninjapanda.v1.PreAuthKey
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_ninjapanda_v1_preauthkey_proto_init() }
func file_ninjapanda_v1_preauthkey_proto_init() {
	if File_ninjapanda_v1_preauthkey_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ninjapanda_v1_preauthkey_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PreAuthKey); i {
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
		file_ninjapanda_v1_preauthkey_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreatePreAuthKeyRequest); i {
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
		file_ninjapanda_v1_preauthkey_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreatePreAuthKeyResponse); i {
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
		file_ninjapanda_v1_preauthkey_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ExpirePreAuthKeyRequest); i {
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
		file_ninjapanda_v1_preauthkey_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ExpirePreAuthKeyResponse); i {
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
		file_ninjapanda_v1_preauthkey_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RevokePreAuthKeyRequest); i {
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
		file_ninjapanda_v1_preauthkey_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RevokePreAuthKeyResponse); i {
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
		file_ninjapanda_v1_preauthkey_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListPreAuthKeysRequest); i {
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
		file_ninjapanda_v1_preauthkey_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ListPreAuthKeysResponse); i {
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
	file_ninjapanda_v1_preauthkey_proto_msgTypes[0].OneofWrappers = []interface{}{}
	file_ninjapanda_v1_preauthkey_proto_msgTypes[1].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_ninjapanda_v1_preauthkey_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ninjapanda_v1_preauthkey_proto_goTypes,
		DependencyIndexes: file_ninjapanda_v1_preauthkey_proto_depIdxs,
		EnumInfos:         file_ninjapanda_v1_preauthkey_proto_enumTypes,
		MessageInfos:      file_ninjapanda_v1_preauthkey_proto_msgTypes,
	}.Build()
	File_ninjapanda_v1_preauthkey_proto = out.File
	file_ninjapanda_v1_preauthkey_proto_rawDesc = nil
	file_ninjapanda_v1_preauthkey_proto_goTypes = nil
	file_ninjapanda_v1_preauthkey_proto_depIdxs = nil
}
