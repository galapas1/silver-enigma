// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        (unknown)
// source: ninjapanda/v1/acl_policy.proto

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

type ACLPolicy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AclpolicyId string            `protobuf:"bytes,1,opt,name=aclpolicy_id,json=aclpolicyId,proto3" json:"aclpolicy_id,omitempty"`
	Order       uint64            `protobuf:"varint,2,opt,name=order,proto3" json:"order,omitempty"`
	Hosts       map[string]string `protobuf:"bytes,3,rep,name=hosts,proto3" json:"hosts,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Groups      []*MapFieldEntry  `protobuf:"bytes,4,rep,name=groups,proto3" json:"groups,omitempty"`
	Tags        []*MapFieldEntry  `protobuf:"bytes,5,rep,name=tags,proto3" json:"tags,omitempty"`
	Acls        []*ACL            `protobuf:"bytes,6,rep,name=acls,proto3" json:"acls,omitempty"`
	Tests       []*ACLTest        `protobuf:"bytes,7,rep,name=tests,proto3" json:"tests,omitempty"`
}

func (x *ACLPolicy) Reset() {
	*x = ACLPolicy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ACLPolicy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ACLPolicy) ProtoMessage() {}

func (x *ACLPolicy) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ACLPolicy.ProtoReflect.Descriptor instead.
func (*ACLPolicy) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_acl_policy_proto_rawDescGZIP(), []int{0}
}

func (x *ACLPolicy) GetAclpolicyId() string {
	if x != nil {
		return x.AclpolicyId
	}
	return ""
}

func (x *ACLPolicy) GetOrder() uint64 {
	if x != nil {
		return x.Order
	}
	return 0
}

func (x *ACLPolicy) GetHosts() map[string]string {
	if x != nil {
		return x.Hosts
	}
	return nil
}

func (x *ACLPolicy) GetGroups() []*MapFieldEntry {
	if x != nil {
		return x.Groups
	}
	return nil
}

func (x *ACLPolicy) GetTags() []*MapFieldEntry {
	if x != nil {
		return x.Tags
	}
	return nil
}

func (x *ACLPolicy) GetAcls() []*ACL {
	if x != nil {
		return x.Acls
	}
	return nil
}

func (x *ACLPolicy) GetTests() []*ACLTest {
	if x != nil {
		return x.Tests
	}
	return nil
}

type ACL struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Action       string   `protobuf:"bytes,1,opt,name=action,proto3" json:"action,omitempty"`
	Order        uint64   `protobuf:"varint,2,opt,name=order,proto3" json:"order,omitempty"`
	Protocol     string   `protobuf:"bytes,3,opt,name=protocol,proto3" json:"protocol,omitempty"`
	Port         string   `protobuf:"bytes,4,opt,name=port,proto3" json:"port,omitempty"`
	Sources      []string `protobuf:"bytes,5,rep,name=sources,proto3" json:"sources,omitempty"`
	Destinations []string `protobuf:"bytes,6,rep,name=destinations,proto3" json:"destinations,omitempty"`
}

func (x *ACL) Reset() {
	*x = ACL{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ACL) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ACL) ProtoMessage() {}

func (x *ACL) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ACL.ProtoReflect.Descriptor instead.
func (*ACL) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_acl_policy_proto_rawDescGZIP(), []int{1}
}

func (x *ACL) GetAction() string {
	if x != nil {
		return x.Action
	}
	return ""
}

func (x *ACL) GetOrder() uint64 {
	if x != nil {
		return x.Order
	}
	return 0
}

func (x *ACL) GetProtocol() string {
	if x != nil {
		return x.Protocol
	}
	return ""
}

func (x *ACL) GetPort() string {
	if x != nil {
		return x.Port
	}
	return ""
}

func (x *ACL) GetSources() []string {
	if x != nil {
		return x.Sources
	}
	return nil
}

func (x *ACL) GetDestinations() []string {
	if x != nil {
		return x.Destinations
	}
	return nil
}

type ACLTest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Source []string `protobuf:"bytes,1,rep,name=source,proto3" json:"source,omitempty"`
	Accept []string `protobuf:"bytes,2,rep,name=accept,proto3" json:"accept,omitempty"`
	Deny   []string `protobuf:"bytes,3,rep,name=deny,proto3" json:"deny,omitempty"`
}

func (x *ACLTest) Reset() {
	*x = ACLTest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ACLTest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ACLTest) ProtoMessage() {}

func (x *ACLTest) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ACLTest.ProtoReflect.Descriptor instead.
func (*ACLTest) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_acl_policy_proto_rawDescGZIP(), []int{2}
}

func (x *ACLTest) GetSource() []string {
	if x != nil {
		return x.Source
	}
	return nil
}

func (x *ACLTest) GetAccept() []string {
	if x != nil {
		return x.Accept
	}
	return nil
}

func (x *ACLTest) GetDeny() []string {
	if x != nil {
		return x.Deny
	}
	return nil
}

type GetACLPolicyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AclpolicyId string `protobuf:"bytes,1,opt,name=aclpolicy_id,json=aclpolicyId,proto3" json:"aclpolicy_id,omitempty"`
}

func (x *GetACLPolicyRequest) Reset() {
	*x = GetACLPolicyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetACLPolicyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetACLPolicyRequest) ProtoMessage() {}

func (x *GetACLPolicyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetACLPolicyRequest.ProtoReflect.Descriptor instead.
func (*GetACLPolicyRequest) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_acl_policy_proto_rawDescGZIP(), []int{3}
}

func (x *GetACLPolicyRequest) GetAclpolicyId() string {
	if x != nil {
		return x.AclpolicyId
	}
	return ""
}

type GetACLPolicyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AclPolicy *ACLPolicy `protobuf:"bytes,1,opt,name=acl_policy,json=aclPolicy,proto3" json:"acl_policy,omitempty"`
}

func (x *GetACLPolicyResponse) Reset() {
	*x = GetACLPolicyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetACLPolicyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetACLPolicyResponse) ProtoMessage() {}

func (x *GetACLPolicyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetACLPolicyResponse.ProtoReflect.Descriptor instead.
func (*GetACLPolicyResponse) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_acl_policy_proto_rawDescGZIP(), []int{4}
}

func (x *GetACLPolicyResponse) GetAclPolicy() *ACLPolicy {
	if x != nil {
		return x.AclPolicy
	}
	return nil
}

type CreateACLPolicyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AclPolicy *ACLPolicy `protobuf:"bytes,1,opt,name=acl_policy,json=aclPolicy,proto3" json:"acl_policy,omitempty"`
}

func (x *CreateACLPolicyRequest) Reset() {
	*x = CreateACLPolicyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateACLPolicyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateACLPolicyRequest) ProtoMessage() {}

func (x *CreateACLPolicyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateACLPolicyRequest.ProtoReflect.Descriptor instead.
func (*CreateACLPolicyRequest) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_acl_policy_proto_rawDescGZIP(), []int{5}
}

func (x *CreateACLPolicyRequest) GetAclPolicy() *ACLPolicy {
	if x != nil {
		return x.AclPolicy
	}
	return nil
}

type CreateACLPolicyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AclPolicy *ACLPolicy `protobuf:"bytes,1,opt,name=acl_policy,json=aclPolicy,proto3" json:"acl_policy,omitempty"`
}

func (x *CreateACLPolicyResponse) Reset() {
	*x = CreateACLPolicyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateACLPolicyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateACLPolicyResponse) ProtoMessage() {}

func (x *CreateACLPolicyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateACLPolicyResponse.ProtoReflect.Descriptor instead.
func (*CreateACLPolicyResponse) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_acl_policy_proto_rawDescGZIP(), []int{6}
}

func (x *CreateACLPolicyResponse) GetAclPolicy() *ACLPolicy {
	if x != nil {
		return x.AclPolicy
	}
	return nil
}

type UpdateACLPolicyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AclPolicies []*ACLPolicy `protobuf:"bytes,1,rep,name=acl_policies,json=aclPolicies,proto3" json:"acl_policies,omitempty"`
}

func (x *UpdateACLPolicyRequest) Reset() {
	*x = UpdateACLPolicyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateACLPolicyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateACLPolicyRequest) ProtoMessage() {}

func (x *UpdateACLPolicyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateACLPolicyRequest.ProtoReflect.Descriptor instead.
func (*UpdateACLPolicyRequest) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_acl_policy_proto_rawDescGZIP(), []int{7}
}

func (x *UpdateACLPolicyRequest) GetAclPolicies() []*ACLPolicy {
	if x != nil {
		return x.AclPolicies
	}
	return nil
}

type UpdateACLPolicyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AclPolicies []*ACLPolicy `protobuf:"bytes,1,rep,name=acl_policies,json=aclPolicies,proto3" json:"acl_policies,omitempty"`
}

func (x *UpdateACLPolicyResponse) Reset() {
	*x = UpdateACLPolicyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpdateACLPolicyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpdateACLPolicyResponse) ProtoMessage() {}

func (x *UpdateACLPolicyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpdateACLPolicyResponse.ProtoReflect.Descriptor instead.
func (*UpdateACLPolicyResponse) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_acl_policy_proto_rawDescGZIP(), []int{8}
}

func (x *UpdateACLPolicyResponse) GetAclPolicies() []*ACLPolicy {
	if x != nil {
		return x.AclPolicies
	}
	return nil
}

type DeleteACLPolicyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AclpolicyId string `protobuf:"bytes,1,opt,name=aclpolicy_id,json=aclpolicyId,proto3" json:"aclpolicy_id,omitempty"`
}

func (x *DeleteACLPolicyRequest) Reset() {
	*x = DeleteACLPolicyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteACLPolicyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteACLPolicyRequest) ProtoMessage() {}

func (x *DeleteACLPolicyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteACLPolicyRequest.ProtoReflect.Descriptor instead.
func (*DeleteACLPolicyRequest) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_acl_policy_proto_rawDescGZIP(), []int{9}
}

func (x *DeleteACLPolicyRequest) GetAclpolicyId() string {
	if x != nil {
		return x.AclpolicyId
	}
	return ""
}

type DeleteACLPolicyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DeleteACLPolicyResponse) Reset() {
	*x = DeleteACLPolicyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteACLPolicyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteACLPolicyResponse) ProtoMessage() {}

func (x *DeleteACLPolicyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteACLPolicyResponse.ProtoReflect.Descriptor instead.
func (*DeleteACLPolicyResponse) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_acl_policy_proto_rawDescGZIP(), []int{10}
}

type ACLOrder struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AclpolicyId string `protobuf:"bytes,1,opt,name=aclpolicy_id,json=aclpolicyId,proto3" json:"aclpolicy_id,omitempty"`
	Order       uint64 `protobuf:"varint,2,opt,name=order,proto3" json:"order,omitempty"`
}

func (x *ACLOrder) Reset() {
	*x = ACLOrder{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[11]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ACLOrder) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ACLOrder) ProtoMessage() {}

func (x *ACLOrder) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[11]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ACLOrder.ProtoReflect.Descriptor instead.
func (*ACLOrder) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_acl_policy_proto_rawDescGZIP(), []int{11}
}

func (x *ACLOrder) GetAclpolicyId() string {
	if x != nil {
		return x.AclpolicyId
	}
	return ""
}

func (x *ACLOrder) GetOrder() uint64 {
	if x != nil {
		return x.Order
	}
	return 0
}

type ReorderACLPolicyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AclOrder []*ACLOrder `protobuf:"bytes,1,rep,name=acl_order,json=aclOrder,proto3" json:"acl_order,omitempty"`
}

func (x *ReorderACLPolicyRequest) Reset() {
	*x = ReorderACLPolicyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[12]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReorderACLPolicyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReorderACLPolicyRequest) ProtoMessage() {}

func (x *ReorderACLPolicyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[12]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReorderACLPolicyRequest.ProtoReflect.Descriptor instead.
func (*ReorderACLPolicyRequest) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_acl_policy_proto_rawDescGZIP(), []int{12}
}

func (x *ReorderACLPolicyRequest) GetAclOrder() []*ACLOrder {
	if x != nil {
		return x.AclOrder
	}
	return nil
}

type ReorderACLPolicyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *ReorderACLPolicyResponse) Reset() {
	*x = ReorderACLPolicyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[13]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReorderACLPolicyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReorderACLPolicyResponse) ProtoMessage() {}

func (x *ReorderACLPolicyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ninjapanda_v1_acl_policy_proto_msgTypes[13]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReorderACLPolicyResponse.ProtoReflect.Descriptor instead.
func (*ReorderACLPolicyResponse) Descriptor() ([]byte, []int) {
	return file_ninjapanda_v1_acl_policy_proto_rawDescGZIP(), []int{13}
}

var File_ninjapanda_v1_acl_policy_proto protoreflect.FileDescriptor

var file_ninjapanda_v1_acl_policy_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2f, 0x76, 0x31, 0x2f,
	0x61, 0x63, 0x6c, 0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x0d, 0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x1a,
	0x23, 0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2f, 0x76, 0x31, 0x2f, 0x6d,
	0x61, 0x70, 0x5f, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x5f, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xf7, 0x02, 0x0a, 0x09, 0x41, 0x43, 0x4c, 0x50, 0x6f, 0x6c, 0x69,
	0x63, 0x79, 0x12, 0x21, 0x0a, 0x0c, 0x61, 0x63, 0x6c, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x5f,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x61, 0x63, 0x6c, 0x70, 0x6f, 0x6c,
	0x69, 0x63, 0x79, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x04, 0x52, 0x05, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x12, 0x39, 0x0a, 0x05, 0x68,
	0x6f, 0x73, 0x74, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x6e, 0x69, 0x6e,
	0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x43, 0x4c, 0x50, 0x6f,
	0x6c, 0x69, 0x63, 0x79, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52,
	0x05, 0x68, 0x6f, 0x73, 0x74, 0x73, 0x12, 0x34, 0x0a, 0x06, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73,
	0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61,
	0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x61, 0x70, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x52, 0x06, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x12, 0x30, 0x0a, 0x04,
	0x74, 0x61, 0x67, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x6e, 0x69, 0x6e,
	0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x61, 0x70, 0x46, 0x69,
	0x65, 0x6c, 0x64, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x04, 0x74, 0x61, 0x67, 0x73, 0x12, 0x26,
	0x0a, 0x04, 0x61, 0x63, 0x6c, 0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x6e,
	0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x43, 0x4c,
	0x52, 0x04, 0x61, 0x63, 0x6c, 0x73, 0x12, 0x2c, 0x0a, 0x05, 0x74, 0x65, 0x73, 0x74, 0x73, 0x18,
	0x07, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e,
	0x64, 0x61, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x43, 0x4c, 0x54, 0x65, 0x73, 0x74, 0x52, 0x05, 0x74,
	0x65, 0x73, 0x74, 0x73, 0x1a, 0x38, 0x0a, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0xa1,
	0x01, 0x0a, 0x03, 0x41, 0x43, 0x4c, 0x12, 0x16, 0x0a, 0x06, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x14,
	0x0a, 0x05, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x05, 0x6f,
	0x72, 0x64, 0x65, 0x72, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c,
	0x12, 0x12, 0x0a, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x70, 0x6f, 0x72, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x18,
	0x05, 0x20, 0x03, 0x28, 0x09, 0x52, 0x07, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x12, 0x22,
	0x0a, 0x0c, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x06,
	0x20, 0x03, 0x28, 0x09, 0x52, 0x0c, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x22, 0x4d, 0x0a, 0x07, 0x41, 0x43, 0x4c, 0x54, 0x65, 0x73, 0x74, 0x12, 0x16, 0x0a,
	0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x06, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x18,
	0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x06, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x12, 0x12, 0x0a,
	0x04, 0x64, 0x65, 0x6e, 0x79, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x04, 0x64, 0x65, 0x6e,
	0x79, 0x22, 0x38, 0x0a, 0x13, 0x47, 0x65, 0x74, 0x41, 0x43, 0x4c, 0x50, 0x6f, 0x6c, 0x69, 0x63,
	0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x21, 0x0a, 0x0c, 0x61, 0x63, 0x6c, 0x70,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x61, 0x63, 0x6c, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x49, 0x64, 0x22, 0x4f, 0x0a, 0x14, 0x47,
	0x65, 0x74, 0x41, 0x43, 0x4c, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x37, 0x0a, 0x0a, 0x61, 0x63, 0x6c, 0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63,
	0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70,
	0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x43, 0x4c, 0x50, 0x6f, 0x6c, 0x69, 0x63,
	0x79, 0x52, 0x09, 0x61, 0x63, 0x6c, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x22, 0x51, 0x0a, 0x16,
	0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x41, 0x43, 0x4c, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x37, 0x0a, 0x0a, 0x61, 0x63, 0x6c, 0x5f, 0x70, 0x6f,
	0x6c, 0x69, 0x63, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x6e, 0x69, 0x6e,
	0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x43, 0x4c, 0x50, 0x6f,
	0x6c, 0x69, 0x63, 0x79, 0x52, 0x09, 0x61, 0x63, 0x6c, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x22,
	0x52, 0x0a, 0x17, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x41, 0x43, 0x4c, 0x50, 0x6f, 0x6c, 0x69,
	0x63, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x37, 0x0a, 0x0a, 0x61, 0x63,
	0x6c, 0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18,
	0x2e, 0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x2e, 0x41,
	0x43, 0x4c, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x09, 0x61, 0x63, 0x6c, 0x50, 0x6f, 0x6c,
	0x69, 0x63, 0x79, 0x22, 0x55, 0x0a, 0x16, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x41, 0x43, 0x4c,
	0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x3b, 0x0a,
	0x0c, 0x61, 0x63, 0x6c, 0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x69, 0x65, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61,
	0x2e, 0x76, 0x31, 0x2e, 0x41, 0x43, 0x4c, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x0b, 0x61,
	0x63, 0x6c, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x69, 0x65, 0x73, 0x22, 0x56, 0x0a, 0x17, 0x55, 0x70,
	0x64, 0x61, 0x74, 0x65, 0x41, 0x43, 0x4c, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3b, 0x0a, 0x0c, 0x61, 0x63, 0x6c, 0x5f, 0x70, 0x6f, 0x6c,
	0x69, 0x63, 0x69, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x6e, 0x69,
	0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x43, 0x4c, 0x50,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x0b, 0x61, 0x63, 0x6c, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x69,
	0x65, 0x73, 0x22, 0x3b, 0x0a, 0x16, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x41, 0x43, 0x4c, 0x50,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x21, 0x0a, 0x0c,
	0x61, 0x63, 0x6c, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0b, 0x61, 0x63, 0x6c, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x49, 0x64, 0x22,
	0x19, 0x0a, 0x17, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x41, 0x43, 0x4c, 0x50, 0x6f, 0x6c, 0x69,
	0x63, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x43, 0x0a, 0x08, 0x41, 0x43,
	0x4c, 0x4f, 0x72, 0x64, 0x65, 0x72, 0x12, 0x21, 0x0a, 0x0c, 0x61, 0x63, 0x6c, 0x70, 0x6f, 0x6c,
	0x69, 0x63, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x61, 0x63,
	0x6c, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x6f, 0x72, 0x64,
	0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x05, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x22,
	0x4f, 0x0a, 0x17, 0x52, 0x65, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x41, 0x43, 0x4c, 0x50, 0x6f, 0x6c,
	0x69, 0x63, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x34, 0x0a, 0x09, 0x61, 0x63,
	0x6c, 0x5f, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x17, 0x2e,
	0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x43,
	0x4c, 0x4f, 0x72, 0x64, 0x65, 0x72, 0x52, 0x08, 0x61, 0x63, 0x6c, 0x4f, 0x72, 0x64, 0x65, 0x72,
	0x22, 0x1a, 0x0a, 0x18, 0x52, 0x65, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x41, 0x43, 0x4c, 0x50, 0x6f,
	0x6c, 0x69, 0x63, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x0f, 0x5a, 0x0d,
	0x6e, 0x69, 0x6e, 0x6a, 0x61, 0x70, 0x61, 0x6e, 0x64, 0x61, 0x2e, 0x76, 0x31, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ninjapanda_v1_acl_policy_proto_rawDescOnce sync.Once
	file_ninjapanda_v1_acl_policy_proto_rawDescData = file_ninjapanda_v1_acl_policy_proto_rawDesc
)

func file_ninjapanda_v1_acl_policy_proto_rawDescGZIP() []byte {
	file_ninjapanda_v1_acl_policy_proto_rawDescOnce.Do(func() {
		file_ninjapanda_v1_acl_policy_proto_rawDescData = protoimpl.X.CompressGZIP(file_ninjapanda_v1_acl_policy_proto_rawDescData)
	})
	return file_ninjapanda_v1_acl_policy_proto_rawDescData
}

var file_ninjapanda_v1_acl_policy_proto_msgTypes = make([]protoimpl.MessageInfo, 15)
var file_ninjapanda_v1_acl_policy_proto_goTypes = []interface{}{
	(*ACLPolicy)(nil),                // 0: ninjapanda.v1.ACLPolicy
	(*ACL)(nil),                      // 1: ninjapanda.v1.ACL
	(*ACLTest)(nil),                  // 2: ninjapanda.v1.ACLTest
	(*GetACLPolicyRequest)(nil),      // 3: ninjapanda.v1.GetACLPolicyRequest
	(*GetACLPolicyResponse)(nil),     // 4: ninjapanda.v1.GetACLPolicyResponse
	(*CreateACLPolicyRequest)(nil),   // 5: ninjapanda.v1.CreateACLPolicyRequest
	(*CreateACLPolicyResponse)(nil),  // 6: ninjapanda.v1.CreateACLPolicyResponse
	(*UpdateACLPolicyRequest)(nil),   // 7: ninjapanda.v1.UpdateACLPolicyRequest
	(*UpdateACLPolicyResponse)(nil),  // 8: ninjapanda.v1.UpdateACLPolicyResponse
	(*DeleteACLPolicyRequest)(nil),   // 9: ninjapanda.v1.DeleteACLPolicyRequest
	(*DeleteACLPolicyResponse)(nil),  // 10: ninjapanda.v1.DeleteACLPolicyResponse
	(*ACLOrder)(nil),                 // 11: ninjapanda.v1.ACLOrder
	(*ReorderACLPolicyRequest)(nil),  // 12: ninjapanda.v1.ReorderACLPolicyRequest
	(*ReorderACLPolicyResponse)(nil), // 13: ninjapanda.v1.ReorderACLPolicyResponse
	nil,                              // 14: ninjapanda.v1.ACLPolicy.HostsEntry
	(*MapFieldEntry)(nil),            // 15: ninjapanda.v1.MapFieldEntry
}
var file_ninjapanda_v1_acl_policy_proto_depIdxs = []int32{
	14, // 0: ninjapanda.v1.ACLPolicy.hosts:type_name -> ninjapanda.v1.ACLPolicy.HostsEntry
	15, // 1: ninjapanda.v1.ACLPolicy.groups:type_name -> ninjapanda.v1.MapFieldEntry
	15, // 2: ninjapanda.v1.ACLPolicy.tags:type_name -> ninjapanda.v1.MapFieldEntry
	1,  // 3: ninjapanda.v1.ACLPolicy.acls:type_name -> ninjapanda.v1.ACL
	2,  // 4: ninjapanda.v1.ACLPolicy.tests:type_name -> ninjapanda.v1.ACLTest
	0,  // 5: ninjapanda.v1.GetACLPolicyResponse.acl_policy:type_name -> ninjapanda.v1.ACLPolicy
	0,  // 6: ninjapanda.v1.CreateACLPolicyRequest.acl_policy:type_name -> ninjapanda.v1.ACLPolicy
	0,  // 7: ninjapanda.v1.CreateACLPolicyResponse.acl_policy:type_name -> ninjapanda.v1.ACLPolicy
	0,  // 8: ninjapanda.v1.UpdateACLPolicyRequest.acl_policies:type_name -> ninjapanda.v1.ACLPolicy
	0,  // 9: ninjapanda.v1.UpdateACLPolicyResponse.acl_policies:type_name -> ninjapanda.v1.ACLPolicy
	11, // 10: ninjapanda.v1.ReorderACLPolicyRequest.acl_order:type_name -> ninjapanda.v1.ACLOrder
	11, // [11:11] is the sub-list for method output_type
	11, // [11:11] is the sub-list for method input_type
	11, // [11:11] is the sub-list for extension type_name
	11, // [11:11] is the sub-list for extension extendee
	0,  // [0:11] is the sub-list for field type_name
}

func init() { file_ninjapanda_v1_acl_policy_proto_init() }
func file_ninjapanda_v1_acl_policy_proto_init() {
	if File_ninjapanda_v1_acl_policy_proto != nil {
		return
	}
	file_ninjapanda_v1_map_field_entry_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_ninjapanda_v1_acl_policy_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ACLPolicy); i {
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
		file_ninjapanda_v1_acl_policy_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ACL); i {
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
		file_ninjapanda_v1_acl_policy_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ACLTest); i {
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
		file_ninjapanda_v1_acl_policy_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetACLPolicyRequest); i {
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
		file_ninjapanda_v1_acl_policy_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetACLPolicyResponse); i {
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
		file_ninjapanda_v1_acl_policy_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateACLPolicyRequest); i {
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
		file_ninjapanda_v1_acl_policy_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateACLPolicyResponse); i {
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
		file_ninjapanda_v1_acl_policy_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateACLPolicyRequest); i {
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
		file_ninjapanda_v1_acl_policy_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpdateACLPolicyResponse); i {
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
		file_ninjapanda_v1_acl_policy_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteACLPolicyRequest); i {
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
		file_ninjapanda_v1_acl_policy_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteACLPolicyResponse); i {
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
		file_ninjapanda_v1_acl_policy_proto_msgTypes[11].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ACLOrder); i {
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
		file_ninjapanda_v1_acl_policy_proto_msgTypes[12].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReorderACLPolicyRequest); i {
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
		file_ninjapanda_v1_acl_policy_proto_msgTypes[13].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReorderACLPolicyResponse); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_ninjapanda_v1_acl_policy_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   15,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ninjapanda_v1_acl_policy_proto_goTypes,
		DependencyIndexes: file_ninjapanda_v1_acl_policy_proto_depIdxs,
		MessageInfos:      file_ninjapanda_v1_acl_policy_proto_msgTypes,
	}.Build()
	File_ninjapanda_v1_acl_policy_proto = out.File
	file_ninjapanda_v1_acl_policy_proto_rawDesc = nil
	file_ninjapanda_v1_acl_policy_proto_goTypes = nil
	file_ninjapanda_v1_acl_policy_proto_depIdxs = nil
}
