package ninjapanda

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"github.com/prometheus/common/model"

	"github.com/rs/zerolog/log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"gorm.io/gorm"

	ocodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/Optm-Main/ztmesh-core/types/key"
	"github.com/Optm-Main/ztmesh-core/ztcfg"

	v1 "optm.com/ninja-panda/gen/go/ninjapanda/v1"
)

type ninjapandaV1APIServer struct { // v1.NinjapandaServiceServer
	v1.UnimplementedNinjapandaServiceServer
	np *Ninjapanda
}

func newNinjapandaV1APIServer(np *Ninjapanda) v1.NinjapandaServiceServer {
	return ninjapandaV1APIServer{
		np: np,
	}
}

func (api ninjapandaV1APIServer) GetRelayMap(
	ctx context.Context,
	request *v1.RelayMapRequest,
) (*v1.RelayMapResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetRelayMap")
	span.SetStatus(ocodes.Ok, "")

	relayMapProto := relayMapToProto(api.np.RELAYMap)

	return relayMapProto, nil
}

func (api ninjapandaV1APIServer) RefreshRelayMap(
	ctx context.Context,
	request *v1.RelayMapRequest,
) (*v1.RelayMapResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("RefreshRelayMap")
	span.SetStatus(ocodes.Ok, "")

	api.np.RefreshRelayMap()
	api.np.HARefreshRelays()

	relayMapProto := relayMapToProto(api.np.RELAYMap)

	return relayMapProto, nil
}

func (api ninjapandaV1APIServer) CheckHealth(
	ctx context.Context,
	request *v1.CheckHealthRequest,
) (*v1.CheckHealthResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("pingDB")
	err := api.np.pingDB(ctx)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.SetStatus(ocodes.Ok, "")

	return &v1.CheckHealthResponse{Server: &v1.HealthCheck{
		Status: "online",
	}}, nil
}

func (api ninjapandaV1APIServer) GetNamespace(
	ctx context.Context,
	request *v1.GetNamespaceRequest,
) (*v1.GetNamespaceResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetNamespace")
	namespace, err := api.np.GetNamespace(request.GetName())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.SetStatus(ocodes.Ok, "")

	return &v1.GetNamespaceResponse{Namespace: namespace.toProto()}, nil
}

func (api ninjapandaV1APIServer) CreateNamespace(
	ctx context.Context,
	request *v1.CreateNamespaceRequest,
) (*v1.CreateNamespaceResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("CreateNamespace")
	namespace, err := api.np.CreateNamespace(request.GetName())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	namespace.ExternalId = request.GetExternalId()

	durStr := request.GetDefaultMachineKeyTtl()
	namespace.DefaultMachineKeyTtl = time.Duration(0)
	if len(durStr) > 0 {
		span.AddEvent("ParseDuration")
		duration, err := model.ParseDuration(durStr)
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, err
		}
		namespace.DefaultMachineKeyTtl = time.Duration(duration)
	}

	span.AddEvent("RefreshNamespace")
	api.np.RefreshNamespace(namespace)

	span.SetStatus(ocodes.Ok, "")

	return &v1.CreateNamespaceResponse{Namespace: namespace.toProto()}, nil
}

func (api ninjapandaV1APIServer) UpdateNamespace(
	ctx context.Context,
	request *v1.UpdateNamespaceRequest,
) (*v1.UpdateNamespaceResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetNamespace")

	namespace, err := api.np.GetNamespace(request.GetName())
	if err != nil {
		if err == ErrNamespaceNotFound {
			span.AddEvent("CreateNamespace")
			namespace, err = api.np.CreateNamespace(request.GetName())
			if err != nil {
				span.SetStatus(ocodes.Error, err.Error())
				span.RecordError(err)

				return nil, err
			}
		} else {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, err
		}
	}

	namespace.ExternalId = request.GetExternalId()

	durStr := request.GetDefaultMachineKeyTtl()
	namespace.DefaultMachineKeyTtl = time.Duration(0)
	if len(durStr) > 0 {
		span.AddEvent("ParseDuration")
		duration, err := model.ParseDuration(durStr)
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, err
		}
		namespace.DefaultMachineKeyTtl = time.Duration(duration)
	}

	span.AddEvent("RefreshNamespace")
	api.np.RefreshNamespace(namespace)

	span.SetStatus(ocodes.Ok, "")

	return &v1.UpdateNamespaceResponse{Namespace: namespace.toProto()}, nil
}

func (api ninjapandaV1APIServer) PatchNamespace(
	ctx context.Context,
	request *v1.PatchNamespaceRequest,
) (*v1.PatchNamespaceResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("PatchNamespace")

	existingNamespace, err := api.np.GetNamespace(request.GetOriginalName())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	newNamespaceDef := &Namespace{
		Name:                 request.GetNamespace().GetName(),
		ExternalId:           request.GetNamespace().GetExternalId(),
		DefaultMachineKeyTtl: time.Duration(0),
	}

	durStr := request.GetNamespace().GetDefaultMachineKeyTtl()
	if len(durStr) > 0 {
		span.AddEvent("ParseDuration")
		duration, err := model.ParseDuration(durStr)
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, err
		}
		newNamespaceDef.DefaultMachineKeyTtl = time.Duration(duration)
	}

	mask, _ := MaskFromPaths(request.FieldMask.Paths, func(f string) string {
		return logtags.GetFieldName(logtags.namespace, f)
	})

	StructToStruct(mask, newNamespaceDef, existingNamespace)

	err = api.np.RefreshNamespace(existingNamespace)

	return &v1.PatchNamespaceResponse{
		Namespace: existingNamespace.toProto(),
	}, err
}

func (api ninjapandaV1APIServer) RenameNamespace(
	ctx context.Context,
	request *v1.RenameNamespaceRequest,
) (*v1.RenameNamespaceResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("RenameNamespace")
	err := api.np.RenameNamespace(request.GetOldName(), request.GetNewName())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.AddEvent("GetNamespace")
	namespace, err := api.np.GetNamespace(request.GetNewName())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.SetStatus(ocodes.Ok, "")

	return &v1.RenameNamespaceResponse{Namespace: namespace.toProto()}, nil
}

func (api ninjapandaV1APIServer) DeleteNamespace(
	ctx context.Context,
	request *v1.DeleteNamespaceRequest,
) (*v1.DeleteNamespaceResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("DestroyNamespace")
	err := api.np.DestroyNamespace(request.GetName())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.SetStatus(ocodes.Ok, "")

	return &v1.DeleteNamespaceResponse{}, nil
}

func (api ninjapandaV1APIServer) ListNamespaces(
	ctx context.Context,
	request *v1.ListNamespacesRequest,
) (*v1.ListNamespacesResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("ListNamespaces")
	namespaces, err := api.np.ListNamespaces()
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	response := make([]*v1.Namespace, len(namespaces))
	for index, namespace := range namespaces {
		response[index] = namespace.toProto()
	}

	span.SetStatus(ocodes.Ok, "")

	return &v1.ListNamespacesResponse{Namespaces: response}, nil
}

func (api ninjapandaV1APIServer) CreatePreAuthKey(
	ctx context.Context,
	request *v1.CreatePreAuthKeyRequest,
) (*v1.CreatePreAuthKeyResponse, error) {
	span := trace.SpanFromContext(ctx)

	var expiration time.Time
	var expirationP *time.Time = nil
	if len(request.GetExpiration()) > 0 {
		expiration = ParseTime(request.GetExpiration()).AsTime()
		expirationP = &expiration
	}

	for _, tag := range request.AclTags {
		err := validateTag(tag)
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return &v1.CreatePreAuthKeyResponse{
				PreAuthKey: nil,
			}, status.Error(codes.InvalidArgument, err.Error())
		}
	}

	span.AddEvent("CreatePreAuthKey")
	preAuthKey, err := api.np.CreatePreAuthKey(
		request.GetNamespace(),
		request.GetPrefix(),
		request.GetReuseCount(),
		request.GetEphemeral(),
		expirationP,
		request.AclTags,
	)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.SetStatus(ocodes.Ok, "")

	return &v1.CreatePreAuthKeyResponse{PreAuthKey: preAuthKey.toProto(true)}, nil
}

func (api ninjapandaV1APIServer) ExpirePreAuthKey(
	ctx context.Context,
	request *v1.ExpirePreAuthKeyRequest,
) (*v1.ExpirePreAuthKeyResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetPreAuthKey")
	preAuthKey, err := api.np.GetPreAuthKey(
		request.GetNamespace(),
		request.PreAuthKeyId,
	)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.preAuthKey, "PreAuthKeyId"), request.GetPreAuthKeyId()).
			Str(logtags.GetTag(logtags.namespace, "Name"), request.GetNamespace()).
			Msg("Could not retrieve preauthkey by id")

		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	pak, err := api.np.ExpirePreAuthKey(preAuthKey)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "expire-preauth-key", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "ExpirePreAuthKey",
			StartTime: &requestStartTime,
		})

	return &v1.ExpirePreAuthKeyResponse{PreAuthKey: pak.toProto(false)}, nil
}

func (api ninjapandaV1APIServer) RevokePreAuthKey(
	ctx context.Context,
	request *v1.RevokePreAuthKeyRequest,
) (*v1.RevokePreAuthKeyResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetPreAuthKey")
	preAuthKey, err := api.np.GetPreAuthKey(
		request.GetNamespace(),
		request.PreAuthKeyId,
	)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.preAuthKey, "PreAuthKeyId"), request.GetPreAuthKeyId()).
			Str(logtags.GetTag(logtags.namespace, "Name"), request.GetNamespace()).
			Msg("Could not retrieve preauthkey by id")

		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.AddEvent("RevokePreAuthKey")
	pak, err := api.np.RevokePreAuthKey(preAuthKey)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "revoke-preauth-key", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "RevokePreAuthKey",
			StartTime: &requestStartTime,
		})

	return &v1.RevokePreAuthKeyResponse{PreAuthKey: pak.toProto(false)}, nil
}

func (api ninjapandaV1APIServer) ListPreAuthKeys(
	ctx context.Context,
	request *v1.ListPreAuthKeysRequest,
) (*v1.ListPreAuthKeysResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("ListPreAuthKeys")
	preAuthKeys, err := api.np.ListPreAuthKeys(request.GetNamespace())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	response := make([]*v1.PreAuthKey, len(preAuthKeys))
	for index, key := range preAuthKeys {
		response[index] = key.toProto(false)
	}

	span.SetStatus(ocodes.Ok, "")

	return &v1.ListPreAuthKeysResponse{PreAuthKeys: response}, nil
}

func (api ninjapandaV1APIServer) RegisterMachine(
	ctx context.Context,
	request *v1.RegisterMachineRequest,
) (*v1.RegisterMachineResponse, error) {
	span := trace.SpanFromContext(ctx)

	correlationId := request.GetCorrelationId()
	namespaceName := request.GetNamespace()

	log.Trace().
		Caller().
		Str(logtags.MakeTag("correlationId"), correlationId).
		Str(logtags.GetTag(logtags.namespace, "Name"), namespaceName).
		Msg("Registering machine")

	span.AddEvent("RegisterMachineFromAuthCallback")
	machine, err := api.np.RegisterMachineFromAuthCallback(
		correlationId,
		namespaceName,
		nil,
		RegisterMethodAPI,
	)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		// REVIEW: is there a better way to detect license check failure
		if strings.Contains("per", err.Error()) {
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	machineProto := &v1.RegisterMachineResponse{
		Machine: machine.toProto(),
	}
	machineProto.Machine.UserInfo = &v1.UserInfo{}

	span.AddEvent("GetUserProfileByMachineId")
	userProfile, _ := api.np.GetUserProfileByMachineId(
		machine.MachineId,
		!IncludeTaggedDevice,
	)
	if userProfile != nil {
		machineProto.Machine.UserInfo = userProfile.toProto()
	}

	return machineProto, nil
}

func (api ninjapandaV1APIServer) GetMachine(
	ctx context.Context,
	request *v1.GetMachineRequest,
) (*v1.GetMachineResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetMachineByMachineId")
	machine, err := api.np.GetMachineByMachineId(request.GetMachineId())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	machineProto := &v1.GetMachineResponse{
		Machine: machine.toProto(),
	}

	if !machineProto.Machine.Online { // new clients will benefit from this check
		machineProto.Machine.Online = api.np.notifier.IsConnected(
			machineProto.Machine.MachineKey,
		)
	}

	machineProto.Machine.UserInfo = &v1.UserInfo{}

	span.AddEvent("GetUserProfileByMachineId")
	userProfile, _ := api.np.GetUserProfileByMachineId(
		machine.MachineId,
		!IncludeTaggedDevice,
	)
	if userProfile != nil {
		machineProto.Machine.UserInfo = userProfile.toProto()
	}

	span.SetStatus(ocodes.Ok, "")

	return machineProto, nil
}

func (api ninjapandaV1APIServer) SetTags(
	ctx context.Context,
	request *v1.SetTagsRequest,
) (*v1.SetTagsResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetMachineByMachineId")
	machine, err := api.np.GetMachineByMachineId(request.GetMachineId())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	for _, tag := range request.GetTags() {
		err := validateTag(tag)
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return &v1.SetTagsResponse{
				Machine: nil,
			}, status.Error(codes.InvalidArgument, err.Error())
		}
	}

	span.AddEvent("SetTags")
	err = api.np.SetTags(machine, request.GetTags())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return &v1.SetTagsResponse{
			Machine: nil,
		}, status.Error(codes.Internal, err.Error())
	}

	log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Strs(logtags.MakeTag("tags"), request.GetTags()).
		Msg("Changing tags of machine")

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "machine-tag-change", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "MachineTagChange",
			StartTime: &requestStartTime,
		})

	return &v1.SetTagsResponse{Machine: machine.toProto()}, nil
}

func validateTag(tag string) error {
	if strings.Index(tag, "tag:") != 0 {
		return fmt.Errorf("tag must start with the string 'tag:'")
	}
	if strings.ToLower(tag) != tag {
		return fmt.Errorf("tag should be lowercase")
	}
	if len(strings.Fields(tag)) > 1 {
		return fmt.Errorf("tag should not contains space")
	}

	return nil
}

func (api ninjapandaV1APIServer) DeleteMachine(
	ctx context.Context,
	request *v1.DeleteMachineRequest,
) (*v1.DeleteMachineResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetMachineByMachineId")
	machine, err := api.np.GetMachineByMachineId(request.GetMachineId())
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	span.AddEvent("DeleteMachine")
	err = api.np.DeleteMachine(
		machine,
	)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "delete-machine", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "DeleteMachine",
			StartTime: &requestStartTime,
		})

	return &v1.DeleteMachineResponse{MachineId: machine.MachineId}, nil
}

func (api ninjapandaV1APIServer) ExpireMachine(
	ctx context.Context,
	request *v1.ExpireMachineRequest,
) (*v1.ExpireMachineResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetMachineByMachineId")
	machine, err := api.np.GetMachineByMachineId(request.GetMachineId())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	span.AddEvent("ExpireMachine")
	api.np.ExpireMachine(
		machine,
	)

	log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Time(logtags.GetTag(logtags.machine, "Expiry"), *machine.Expiry).
		Msg("machine expired")

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "expire-machine", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "ExpireMachine",
			StartTime: &requestStartTime,
		})

	return &v1.ExpireMachineResponse{Machine: machine.toProto()}, nil
}

func (api ninjapandaV1APIServer) RenameMachine(
	ctx context.Context,
	request *v1.RenameMachineRequest,
) (*v1.RenameMachineResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetMachineByMachineId")
	machine, err := api.np.GetMachineByMachineId(request.GetMachineId())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	span.AddEvent("RenameMachine")
	err = api.np.RenameMachine(
		machine,
		request.GetNewName(),
	)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	log.Trace().
		Caller().
		Str(logtags.GetTag(logtags.machine, "Hostname"), machine.Hostname).
		Str(logtags.MakeTag("NewName"), request.GetNewName()).
		Msg("machine renamed")

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "rename-machine", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "RenameMachine",
			StartTime: &requestStartTime,
		})

	return &v1.RenameMachineResponse{Machine: machine.toProto()}, nil
}

func (api ninjapandaV1APIServer) ListMachines(
	ctx context.Context,
	request *v1.ListMachinesRequest,
) (*v1.ListMachinesResponse, error) {
	span := trace.SpanFromContext(ctx)

	if request.GetNamespace() != "" {
		span.AddEvent("ListMachinesInNamespace")
		machines, err := api.np.ListMachinesInNamespace(request.GetNamespace())
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}

		response := make([]*v1.Machine, len(machines))
		for index, machine := range machines {
			machineProto := machine.toProto()

			if !machineProto.Online { // new clients will benefit from this check
				machineProto.Online = api.np.notifier.IsConnected(
					machineProto.MachineKey,
				)
			}
			machineProto.UserInfo = &v1.UserInfo{}
			span.AddEvent("GetUserProfileByMachineId")
			userProfile, _ := api.np.GetUserProfileByMachineId(
				machine.MachineId,
				!IncludeTaggedDevice,
			)
			if userProfile != nil {
				machineProto.UserInfo = userProfile.toProto()
			}
			response[index] = machineProto
		}

		span.SetStatus(ocodes.Ok, "")

		return &v1.ListMachinesResponse{Machines: response}, nil
	}

	span.AddEvent("ListMachines")
	machines, err := api.np.ListMachines()
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	response := make([]*v1.Machine, len(machines))
	for index, machine := range machines {
		m := machine.toProto()
		if !m.Online { // new clients will benefit from this check
			m.Online = api.np.notifier.IsConnected(
				m.MachineKey,
			)
		}
		m.UserInfo = &v1.UserInfo{}
		validTags, invalidTags := getTags(
			api.np.aclPolicy,
			machine,
			api.np.cfg.OIDC.StripEmaildomain,
		)
		m.InvalidTags = invalidTags
		m.ValidTags = validTags

		span.AddEvent("GetUserProfileByMachineId")
		userProfile, _ := api.np.GetUserProfileByMachineId(
			machine.MachineId,
			!IncludeTaggedDevice,
		)
		if userProfile != nil {
			m.UserInfo = userProfile.toProto()
		}
		response[index] = m
	}

	span.SetStatus(ocodes.Ok, "")

	return &v1.ListMachinesResponse{Machines: response}, nil
}

func (api ninjapandaV1APIServer) MoveMachine(
	ctx context.Context,
	request *v1.MoveMachineRequest,
) (*v1.MoveMachineResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetMachineByMachineId")
	machine, err := api.np.GetMachineByMachineId(request.GetMachineId())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	span.AddEvent("SetMachineNamespace")
	err = api.np.SetMachineNamespace(machine, request.GetNamespace())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "move-machine", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "MoveMachine",
			StartTime: &requestStartTime,
		})

	return &v1.MoveMachineResponse{Machine: machine.toProto()}, nil
}

func (api ninjapandaV1APIServer) AuthorizeMachine(
	ctx context.Context,
	request *v1.AuthorizeMachineRequest,
) (*v1.AuthorizeMachineResponse, error) {
	span := trace.SpanFromContext(ctx)

	log.Debug().
		Caller().
		Interface(logtags.GetTag(logtags.userProfile, ""), request).
		Msg("AuthorizeMachine entered")

	correlationId := request.GetCorrelationId()
	namespaceName := request.GetNamespace()

	span.AddEvent("RegisterMachineFromAuthCallback")
	machine, err := api.np.RegisterMachineFromAuthCallback(
		correlationId,
		namespaceName,
		nil,
		RegisterMethodCallback)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		log.Error().
			Caller().
			Err(err).
			Str(logtags.MakeTag("correlationId"), correlationId).
			Str(logtags.GetTag(logtags.namespace, "Name"), namespaceName).
			Msg("Failed to authorize machine")

		// REVIEW: is there a better way to detect license check failure
		if strings.Contains(err.Error(), "per") {
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	bypassLicenseCheck := false

	span.AddEvent("GetUserProfileByMachineId")
	userProfile, _ := api.np.GetUserProfileByMachineId(
		machine.MachineId,
		!IncludeTaggedDevice,
	)
	if userProfile != nil {
		// machine exists for a user... no need to license check
		bypassLicenseCheck = true
	}

	if userProfile == nil {
		/// machine is not associate with user profile, see if user profile is known
		span.AddEvent("GetUserProfileByUserProfileId")
		userProfile, _ = api.np.GetUserProfileByUserProfileId(
			request.GetUserInfo().GetUserInfoId(),
		)
	}

	if userProfile != nil {
		// update existing user profile details...
		if userProfile.UserProfileId == request.GetUserInfo().GetUserInfoId() {
			userProfile.LoginName = request.GetUserInfo().GetEmail()
			userProfile.DisplayName = request.GetUserInfo().GetDisplayName()
			userProfile.FirstName = request.GetUserInfo().GetFirstName()
			userProfile.LastName = request.GetUserInfo().GetLastName()

			userProfile, _ = api.np.UpdateUserProfile(userProfile)
		} else {
			// TODO: need to support this flow
			return nil, status.Error(codes.Canceled, "machine reassignment not supported")
		}
	}

	if userProfile == nil {
		// user profile unknown, create one
		userProfile = &UserProfile{
			UserProfileId: request.GetUserInfo().GetUserInfoId(),
			LoginName:     request.GetUserInfo().GetEmail(),
			DisplayName:   request.GetUserInfo().GetDisplayName(),
			FirstName:     request.GetUserInfo().GetFirstName(),
			LastName:      request.GetUserInfo().GetLastName(),
			CreatedAt:     time.Now().UTC(),
		}

		span.AddEvent("CreateUserProfile")
		userProfile, err = api.np.UpdateUserProfile(userProfile)
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
	}

	// see if user is allowed another machine
	if !bypassLicenseCheck {
		allowed, err := api.np.grpcCheckLicense(userProfile, machine, MachinesPerUser)
		if !allowed || err != nil {
			span.SetStatus(
				ocodes.Error,
				fmt.Sprintf("%s license violation", MachinesPerUser),
			)

			log.Error().
				Caller().
				Err(err).
				Str(logtags.GetTag(logtags.machine, "MachineId"), machine.MachineId).
				Str(logtags.GetTag(logtags.userProfile, "UserProfileId"), userProfile.UserProfileId).
				Msg(fmt.Sprintf("%s license violation", MachinesPerUser))

			return nil, status.Error(codes.PermissionDenied, err.Error())
		}

		/// add machine to user profile
		userProfile.UserMachines = append(
			userProfile.UserMachines,
			UserMachine{
				MachineId: machine.MachineId,
				UserId:    userProfile.ID,
			},
		)
		span.AddEvent("UpdateUserProfile")
		userProfile, err = api.np.UpdateUserProfile(userProfile)
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
	}

	machineProto := machine.toProto()
	machineProto.UserInfo = userProfile.toProto()

	span.SetStatus(ocodes.Ok, "")

	return &v1.AuthorizeMachineResponse{
		Machine: machineProto,
	}, nil
}

func (api ninjapandaV1APIServer) GetRoutes(
	ctx context.Context,
	request *v1.GetRoutesRequest,
) (*v1.GetRoutesResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetRoutes")
	routes, err := api.np.GetRoutes()
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	span.SetStatus(ocodes.Ok, "")

	return &v1.GetRoutesResponse{
		Routes: Routes(routes).toProto(),
	}, nil
}

func (api ninjapandaV1APIServer) EnableRoute(
	ctx context.Context,
	request *v1.EnableRouteRequest,
) (*v1.EnableRouteResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	span.AddEvent("EnableRoute")
	_, err := api.np.EnableRoute(request.GetRouteId())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "enable-route", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "EnableRoute",
			StartTime: &requestStartTime,
		})

	return &v1.EnableRouteResponse{}, nil
}

func (api ninjapandaV1APIServer) DisableRoute(
	ctx context.Context,
	request *v1.DisableRouteRequest,
) (*v1.DisableRouteResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	span.AddEvent("DisableRoute")
	err := api.np.DisableRoute(request.GetRouteId())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "disable-route", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "DisableRoute",
			StartTime: &requestStartTime,
		})

	return &v1.DisableRouteResponse{}, nil
}

func (api ninjapandaV1APIServer) GetMachineRoutes(
	ctx context.Context,
	request *v1.GetMachineRoutesRequest,
) (*v1.GetMachineRoutesResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetMachineByMachineId")
	machine, err := api.np.GetMachineByMachineId(request.GetMachineId())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	span.AddEvent("GetMachineRoutes")
	routes, err := api.np.GetMachineRoutes(machine)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	span.SetStatus(ocodes.Ok, "")

	return &v1.GetMachineRoutesResponse{
		Routes: Routes(routes).toProto(),
	}, nil
}

func (api ninjapandaV1APIServer) CreateMachineRoutes(
	ctx context.Context,
	request *v1.CreateMachineRoutesRequest,
) (*v1.CreateMachineRoutesResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetMachineByMachineId")
	machine, err := api.np.GetMachineByMachineId(request.GetMachineId())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(
			codes.FailedPrecondition,
			fmt.Errorf(
				"failed to find machine for machine_id %s: %w",
				request.GetMachineId(),
				err,
			).Error())
	}

	routes := make(Routes, len(request.GetRoutes()))
	routeIds := make([]string, len(request.GetRoutes()))
	var knownRouteIds []string

	for indx, r := range request.GetRoutes() {
		if len(r.RouteId) == 0 {
			routeId, _ := uuid.NewV4()
			r.RouteId = routeId.String()
		} else {
			knownRouteIds = append(knownRouteIds, r.RouteId)
		}
		prefix, err := netip.ParsePrefix(r.GetPrefix())
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, status.Error(
				codes.FailedPrecondition,
				fmt.Errorf("failed to parse prefix %s: %w", r.GetPrefix(), err).Error(),
			)
		}
		routeIds[indx] = r.RouteId
		routes[indx] = Route{
			RouteId:    r.RouteId,
			MachineId:  machine.MachineId,
			Prefix:     IPPrefix(prefix),
			Advertised: r.GetAdvertised(),
			Enabled:    r.GetEnabled(),
			IsPrimary:  r.GetIsPrimary(),
		}
	}

	// Need to merge these incoming route-updates with the ones that may have already been created
	knownRoutes, err := api.np.GetRoutesByRouteId(knownRouteIds)
	if len(knownRoutes) > 0 {
		for indexR := range routes {
			for indexK := range knownRoutes {
				// On match, propagate known ID's back to the input object
				if knownRoutes[indexK].RouteId == routes[indexR].RouteId {
					routes[indexR].ID = knownRoutes[indexK].ID
					routes[indexR].CreatedAt = knownRoutes[indexK].CreatedAt
					break
				}
			}
		}
	}

	err = api.np.CreateMachineRoutes(routes)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(
			codes.FailedPrecondition,
			fmt.Errorf("failed to create machine routes: %w", err).Error(),
		)
	}

	routes, err = api.np.GetRoutesByRouteId(routeIds)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(
			codes.FailedPrecondition,
			fmt.Errorf("failed to read machine routes: %w", err).Error())
	}

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "create-machine-route", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "CreateMachineRoute",
			StartTime: &requestStartTime,
		})

	return &v1.CreateMachineRoutesResponse{
		Routes: Routes(routes).toProto(),
	}, nil
}

func (api ninjapandaV1APIServer) UpdateMachineRoutes(
	ctx context.Context,
	request *v1.UpdateMachineRoutesRequest,
) (*v1.UpdateMachineRoutesResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetMachineByMachineId")
	machine, err := api.np.GetMachineByMachineId(request.GetMachineId())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, status.Error(
			codes.FailedPrecondition,
			fmt.Errorf(
				"failed to find machine for machine_id %s: %w",
				request.GetMachineId(),
				err,
			).Error())
	}

	routes := make(Routes, 0)
	for _, r := range request.GetRoutes() {
		span.AddEvent("GetMachineRouteByRouteId")
		existingRoute, err := api.np.GetMachineRouteByRouteId(r.GetRouteId())
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, status.Error(
				codes.FailedPrecondition,
				fmt.Errorf(
					"failed to find route with route_id %s: %w",
					r.GetRouteId(),
					err,
				).Error())
		}
		if machine.MachineId != existingRoute.MachineId {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, status.Error(
				codes.FailedPrecondition,
				fmt.Errorf(
					"route %s not assigned not machine %s",
					r.GetRouteId(),
					machine.MachineId,
				).Error())
		}
		prefix, err := netip.ParsePrefix(r.GetPrefix())
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, status.Error(
				codes.FailedPrecondition,
				fmt.Errorf("failed to parse prefix %s: %w", r.GetPrefix(), err).Error(),
			)
		}

		existingRoute.Prefix = IPPrefix(prefix)
		existingRoute.Advertised = r.GetAdvertised()
		existingRoute.Enabled = r.GetEnabled()
		existingRoute.IsPrimary = r.GetIsPrimary()

		routes = append(routes, *existingRoute)
	}

	span.AddEvent("pdateMachineRoutes")
	err = api.np.UpdateMachineRoutes(routes)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, fmt.Errorf("failed to update machine routes: %w", err)
	}

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "update-machine-route", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "UpdateMachineRoute",
			StartTime: &requestStartTime,
		})

	return &v1.UpdateMachineRoutesResponse{
		Routes: Routes(routes).toProto(),
	}, nil
}

func (api ninjapandaV1APIServer) DeleteMachineRoute(
	ctx context.Context,
	request *v1.DeleteMachineRouteRequest,
) (*v1.DeleteMachineRouteResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetMachineByMachineId")
	_, err := api.np.GetMachineByMachineId(request.GetMachineId())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.AddEvent("GetMachineRouteByRouteId")
	route, err := api.np.GetMachineRouteByRouteId(request.GetRouteId())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, fmt.Errorf(
			"failed to find route with route_id %s: %w",
			request.GetRouteId(),
			err,
		)
	}

	span.AddEvent("DeleteMachineRoute")
	err = api.np.DeleteMachineRoute(route)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "delete-machine-route", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "DeleteMachineRoute",
			StartTime: &requestStartTime,
		})

	return &v1.DeleteMachineRouteResponse{}, nil
}

func (api ninjapandaV1APIServer) CreateApiKey(
	ctx context.Context,
	request *v1.CreateApiKeyRequest,
) (*v1.CreateApiKeyResponse, error) {
	span := trace.SpanFromContext(ctx)

	var expiration time.Time
	var expirationP *time.Time
	if len(request.GetExpiration()) > 0 {
		expiration = ParseTime(request.GetExpiration()).AsTime()
		expirationP = &expiration
		log.Trace().
			Caller().
			Str(logtags.MakeTag("requestExpiration"), request.GetExpiration()).
			Str(logtags.MakeTag("expirationParsed"), expiration.String()).
			Msg("CreateApiKey called")
	}

	span.AddEvent("CreateAPIKey")
	apiKey, _, err := api.np.CreateAPIKey(expirationP)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.SetStatus(ocodes.Ok, "")

	return &v1.CreateApiKeyResponse{ApiKey: apiKey}, nil
}

func (api ninjapandaV1APIServer) ExpireApiKey(
	ctx context.Context,
	request *v1.ExpireApiKeyRequest,
) (*v1.ExpireApiKeyResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	var apiKey *APIKey
	var err error

	span.AddEvent("GetAPIKey")
	apiKey, err = api.np.GetAPIKey(request.Prefix)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.AddEvent("ExpireAPIKey")
	err = api.np.ExpireAPIKey(apiKey)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "expire-api-key", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "ExpireAPIKey",
			StartTime: &requestStartTime,
		})

	return &v1.ExpireApiKeyResponse{}, nil
}

func (api ninjapandaV1APIServer) ListApiKeys(
	ctx context.Context,
	request *v1.ListApiKeysRequest,
) (*v1.ListApiKeysResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("ListAPIKeys")
	apiKeys, err := api.np.ListAPIKeys()
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	response := make([]*v1.ApiKey, len(apiKeys))
	for index, key := range apiKeys {
		response[index] = key.toProto()
	}

	span.SetStatus(ocodes.Ok, "")

	return &v1.ListApiKeysResponse{ApiKeys: response}, nil
}

// The following service calls are for testing and debugging
func (api ninjapandaV1APIServer) DebugCreateMachine(
	ctx context.Context,
	request *v1.DebugCreateMachineRequest,
) (*v1.DebugCreateMachineResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetNamespace")
	namespace, err := api.np.GetNamespace(request.GetNamespace())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	routes, err := stringToIPPrefix(request.GetRoutes())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	log.Trace().
		Caller().
		Interface(logtags.GetTag(logtags.route, ""), routes).
		Interface(logtags.MakeTag("requestRoutes"), request.GetRoutes()).
		Send()

	hostinfo := ztcfg.Hostinfo{
		RoutableIPs: routes,
		OS:          "TestOS",
		Hostname:    "DebugTestMachine",
	}

	span.AddEvent("GenerateGivenName")
	givenName, err := api.np.GenerateGivenName(
		request.GetKey(),
		namespace.ID,
		request.GetName(),
	)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	newMachine := Machine{
		MachineKey: request.GetKey(),
		Hostname:   request.GetName(),
		GivenName:  givenName,
		Namespace:  *namespace,

		NodeKey:              request.GetKey(),
		Expiry:               &time.Time{},
		LastSeen:             &time.Time{},
		LastSuccessfulUpdate: &time.Time{},

		HostInfo: HostInfo(hostinfo),
	}

	nodeKey := key.NodePublic{}
	err = nodeKey.UnmarshalText([]byte(request.GetKey()))
	if err != nil {
		span.SetStatus(ocodes.Error, "can not add machine for debug. invalid node key")
		span.RecordError(err)
		log.Error().
			Err(err).
			Str(logtags.GetTag(logtags.machine, "NodeKey"), request.GetKey()).
			Msg("can not add machine for debug. invalid node key")
	}

	cid, _ := uuid.NewV4()
	correlationId := "debug:" + cid.String()

	span.AddEvent("StoreMachineRegistration")
	api.np.registrationCache.StoreMachineRegistration(
		ctx,
		correlationId,
		MachineRegistrationStatus{
			Status:  "pending-debug",
			Machine: newMachine,
		},
		registerCacheExpiration,
	)

	span.SetStatus(ocodes.Ok, "")

	return &v1.DebugCreateMachineResponse{Machine: newMachine.toProto()}, nil
}

func (api ninjapandaV1APIServer) GetACLPolicy(
	ctx context.Context,
	request *v1.GetACLPolicyRequest,
) (*v1.GetACLPolicyResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetACLPolicyByACLPolicyID")
	aclPolicy, err := api.np.GetACLPolicyByACLPolicyID(request.GetAclpolicyId())
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.aclPolicy, "ACLPolicyKey"), request.GetAclpolicyId()).
			Msg("Could not retrieve aclpolicy by id")

		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.SetStatus(ocodes.Ok, "")

	return &v1.GetACLPolicyResponse{AclPolicy: aclPolicy.toProto()}, nil
}

func aclProtoToModel(aclPolicy *v1.ACLPolicy) (*ACLPolicy, error) {
	newPolicy := &ACLPolicy{
		ACLPolicyKey: aclPolicy.GetAclpolicyId(),
		Order:        aclPolicy.GetOrder(),
		Groups:       make(Groups),
		Hosts:        make(Hosts),
		TagOwners:    make(TagOwners),
		ACLs:         make([]ACL, 0),
		Tests:        make([]ACLTest, 0),
	}

	for _, v := range aclPolicy.GetGroups() {
		newPolicy.Groups[v.Key] = append(newPolicy.Groups[v.Key], v.Values...)
	}

	hostBytes, _ := json.Marshal(aclPolicy.GetHosts())
	newPolicy.Hosts.UnmarshalJSON(hostBytes)

	for _, v := range aclPolicy.GetTags() {
		newPolicy.TagOwners[v.Key] = append(newPolicy.TagOwners[v.Key], v.Values...)
	}

	for index, v := range aclPolicy.GetAcls() {
		_, _, err := ParseProtocol(v.GetProtocol())
		if err != nil {
			log.Error().
				Caller().
				Msgf("Error parsing ACL Rule %d. protocol unknown %s", index, v.GetProtocol())

			return nil, err
		}
		acl := ACL{
			Order:        v.GetOrder(),
			Action:       v.GetAction(),
			Protocol:     v.GetProtocol(),
			Sources:      make([]string, 0),
			Destinations: make([]string, 0),
		}
		for _, s := range v.Sources {
			acl.Sources = append(acl.Sources, s)
		}
		destPort := ""
		if len(v.GetPort()) > 0 {
			if v.GetPort() != "*" {
				_, err := strconv.ParseUint(v.GetPort(), Base10, BitSize16)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", ErrInvalidPortFormat, err)
				}
			}
			destPort = fmt.Sprintf(":%s", v.GetPort())
		}
		for _, dest := range v.Destinations {
			acl.Destinations = append(
				acl.Destinations,
				fmt.Sprintf("%s%s", dest, destPort),
			)
		}

		newPolicy.ACLs = append(newPolicy.ACLs, acl)
	}

	return newPolicy, nil
}

func (api ninjapandaV1APIServer) CreateACLPolicy(
	ctx context.Context,
	request *v1.CreateACLPolicyRequest,
) (*v1.CreateACLPolicyResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	if len(request.GetAclPolicy().GetAclpolicyId()) < 1 {
		span.SetStatus(ocodes.Error, "Invalid Request: missing aclpolicy_id")

		return nil, fmt.Errorf("Invalid Request: missing aclpolicy_id")
	}

	span.AddEvent("GetACLPolicyByACLPolicyID")
	existingAclPolicy, _ := api.np.GetACLPolicyByACLPolicyID(
		request.GetAclPolicy().GetAclpolicyId(),
	)

	if existingAclPolicy != nil {
		span.SetStatus(ocodes.Error, "Invalid Request: aclpolicy_id already in use")

		return nil, fmt.Errorf("Invalid Request: aclpolicy_id already in use")
	}

	newPolicy, err := aclProtoToModel(request.GetAclPolicy())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.AddEvent("CreateACLPolicy")
	aclPolicy, err := api.np.CreateACLPolicy(newPolicy)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.aclPolicy, "ACLPolicyKey"), request.GetAclPolicy().GetAclpolicyId()).
			Interface(logtags.GetTag(logtags.aclPolicy, ""), request).
			Msg("Could not create aclpolicy")

		span.AddEvent("DeleteAclPolicy")
		api.np.DeleteAclPolicy(newPolicy)

		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.AddEvent("HAUpdatePolicies")
	api.np.HAUpdatePolicies()

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "create-acl-policy", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "CreateACLPolicy",
			StartTime: &requestStartTime,
		})

	return &v1.CreateACLPolicyResponse{AclPolicy: aclPolicy.toProto()}, nil
}

func (api ninjapandaV1APIServer) UpdateACLPolicy(
	ctx context.Context,
	request *v1.UpdateACLPolicyRequest,
) (*v1.UpdateACLPolicyResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	for _, v1aclPolicy := range request.GetAclPolicies() {
		_, err := api.np.GetACLPolicyByACLPolicyID(v1aclPolicy.GetAclpolicyId())
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, err
		}
	}

	response := &v1.UpdateACLPolicyResponse{AclPolicies: make([]*v1.ACLPolicy, 0)}
	for _, v1aclPolicy := range request.GetAclPolicies() {
		aPolicy, err := aclProtoToModel(v1aclPolicy)
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, err
		}

		span.AddEvent("UpdateACLPolicy")
		aclPolicy, err := api.np.UpdateAclPolicy(aPolicy)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Str(logtags.GetTag(logtags.aclPolicy, "ACLPolicyKey"), v1aclPolicy.GetAclpolicyId()).
				Interface(logtags.GetTag(logtags.aclPolicy, ""), v1aclPolicy).
				Msg("Could not update aclpolicy")

			return nil, err
		}

		response.AclPolicies = append(response.AclPolicies, aclPolicy.toProto())
	}

	span.AddEvent("HAUpdatePolicies")
	api.np.HAUpdatePolicies()

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "update-acl-policy", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "UpdateACLPolicy",
			StartTime: &requestStartTime,
		})

	return response, nil
}

func (api ninjapandaV1APIServer) ReorderACLPolicy(
	ctx context.Context,
	request *v1.ReorderACLPolicyRequest,
) (*v1.ReorderACLPolicyResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	// one pass to validate policyId values...
	for _, v1aclPolicy := range request.GetAclOrder() {
		span.AddEvent("GetACLPolicyByACLPolicyID (pass 1)")
		_, err := api.np.GetACLPolicyByACLPolicyID(v1aclPolicy.AclpolicyId)
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, err
		}
	}

	// ...one pass to apply the update
	for _, v1aclPolicy := range request.GetAclOrder() {
		span.AddEvent("GetACLPolicyByACLPolicyID (pass 2)")
		aclPolicy, err := api.np.GetACLPolicyByACLPolicyID(
			v1aclPolicy.AclpolicyId,
		)
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, err
		}

		aclPolicy.Order = v1aclPolicy.Order

		span.AddEvent("UpdateACLPolicy")
		err = api.np.UpdateACLPolicy(*aclPolicy)
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, err
		}
	}

	span.AddEvent("HAUpdatePolicies")
	api.np.HAUpdatePolicies()

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "reorder-acl-policy", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "ReOrderACLPolicy",
			StartTime: &requestStartTime,
		})

	return &v1.ReorderACLPolicyResponse{}, nil
}

func (api ninjapandaV1APIServer) DeleteACLPolicy(
	ctx context.Context,
	request *v1.DeleteACLPolicyRequest,
) (*v1.DeleteACLPolicyResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetACLPolicyByACLPolicyID")
	aclPolicy, err := api.np.GetACLPolicyByACLPolicyID(request.GetAclpolicyId())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.AddEvent("DeleteAclPolicy")
	err = api.np.DeleteAclPolicy(
		aclPolicy,
	)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.aclPolicy, "ACLPolicyKey"), request.GetAclpolicyId()).
			Msg("Could not delete aclpolicy")

		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.AddEvent("HAUpdatePolicies")
	api.np.HAUpdatePolicies()

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "delete-acl-policy", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "DeleteACLPolicy",
			StartTime: &requestStartTime,
		})

	return &v1.DeleteACLPolicyResponse{}, nil
}

func (api ninjapandaV1APIServer) GetDnsConfigByNamespace(
	ctx context.Context,
	request *v1.GetDnsConfigByNamespaceRequest,
) (*v1.GetDnsConfigByNamespaceResponse, error) {
	span := trace.SpanFromContext(ctx)

	if request.GetNamespace() != "" {
		span.AddEvent("GetDNSConfigByNamespace")
		dnsConfig, err := api.np.GetDNSConfigByNamespace(request.GetNamespace())
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, err
		}

		span.SetStatus(ocodes.Ok, "")

		return &v1.GetDnsConfigByNamespaceResponse{DnsConfig: dnsConfig.toProto()}, nil
	}

	span.SetStatus(ocodes.Error, "Malformed request, namespace required")

	return nil, fmt.Errorf("Malformed request, namespace required")
}

func (api ninjapandaV1APIServer) CreateDnsConfig(
	ctx context.Context,
	request *v1.CreateDnsConfigRequest,
) (*v1.CreateDnsConfigResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetNamespace")
	namespace, err := api.np.GetNamespace(request.GetDnsConfig().GetNamespace())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.AddEvent("GetDNSConfigByNamespace")
	dnsConfig, err := api.np.GetDNSConfigByNamespace(namespace.Name)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}
	if dnsConfig != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, fmt.Errorf(
			"dns config already exists for namespace %s",
			namespace.Name,
		)
	}

	newDnsConfig := DNSConfig{
		NamespaceID:      namespace.ID,
		Namespace:        *namespace,
		OverrideLocalDNS: request.GetDnsConfig().GetUseLocal(),
		MagicDNS:         request.GetDnsConfig().GetEnableMagicDns(),
	}

	newDnsConfig.Nameservers = make(Nameservers, 0)
	for _, v := range request.GetDnsConfig().GetNameserverIpAddrs() {
		ipAddr, err := netip.ParseAddr(v)
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, fmt.Errorf("Invalid IP address specified: %s", v)
		}
		newDnsConfig.Nameservers = append(newDnsConfig.Nameservers, ipAddr)
	}

	newDnsConfig.RestrictedNameservers = make(RestrictedNameservers)
	for _, v := range request.GetDnsConfig().GetSearchDomainNs() {
		for _, e := range v.Values {
			ipAddr, err := netip.ParseAddr(e)
			if err != nil {
				span.SetStatus(ocodes.Error, err.Error())
				span.RecordError(err)

				return nil, fmt.Errorf("Invalid IP address specified: %s", e)
			}
			newDnsConfig.RestrictedNameservers[v.Key] = append(
				newDnsConfig.RestrictedNameservers[v.Key],
				ipAddr,
			)
		}
	}

	span.AddEvent("SaveDNSConfig")
	dnsConfig, err = api.np.SaveDNSConfig(newDnsConfig)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "create-dns-policy", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "CreateDNSPolicy",
			StartTime: &requestStartTime,
		})

	return &v1.CreateDnsConfigResponse{DnsConfig: dnsConfig.toProto()}, nil
}

func (api ninjapandaV1APIServer) UpdateDnsConfig(
	ctx context.Context,
	request *v1.UpdateDnsConfigRequest,
) (*v1.UpdateDnsConfigResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetNamespace")
	namespace, err := api.np.GetNamespace(request.GetDnsConfig().GetNamespace())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.AddEvent("GetDNSConfigByNamespace")
	dnsConfig, err := api.np.GetDNSConfigByNamespace(namespace.Name)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}
	if dnsConfig == nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, fmt.Errorf(
			"dns config does not exist for namespace %s",
			namespace.Name,
		)
	}

	dnsConfig.OverrideLocalDNS = request.GetDnsConfig().GetUseLocal()
	dnsConfig.MagicDNS = request.GetDnsConfig().GetEnableMagicDns()

	dnsConfig.Nameservers = make(Nameservers, 0)
	for _, v := range request.GetDnsConfig().GetNameserverIpAddrs() {
		ipAddr, err := netip.ParseAddr(v)
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, fmt.Errorf("Invalid IP address specified: %s", v)
		}
		dnsConfig.Nameservers = append(dnsConfig.Nameservers, ipAddr)
	}

	dnsConfig.RestrictedNameservers = make(RestrictedNameservers)
	for _, v := range request.GetDnsConfig().GetSearchDomainNs() {
		for _, e := range v.Values {
			ipAddr, err := netip.ParseAddr(e)
			if err != nil {
				span.SetStatus(ocodes.Error, err.Error())
				span.RecordError(err)

				return nil, fmt.Errorf("Invalid IP address specified: %s", e)
			}
			dnsConfig.RestrictedNameservers[v.Key] = append(
				dnsConfig.RestrictedNameservers[v.Key],
				ipAddr,
			)
		}
	}

	span.AddEvent("SaveDNSConfig")
	dnsConfig, err = api.np.SaveDNSConfig(*dnsConfig)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "update-dns-policy", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "UpdateDNSPolicy",
			StartTime: &requestStartTime,
		})

	return &v1.UpdateDnsConfigResponse{DnsConfig: dnsConfig.toProto()}, nil
}

func (api ninjapandaV1APIServer) OverrideLocalDns(
	ctx context.Context,
	request *v1.OverrideLocalDnsRequest,
) (*v1.OverrideLocalDnsResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetNamespace")
	namespace, err := api.np.GetNamespace(request.GetNamespace())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.AddEvent("GetDNSConfigByNamespace")
	dnsConfig, err := api.np.GetDNSConfigByNamespace(namespace.Name)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	dnsConfig.OverrideLocalDNS = request.GetUseLocal()

	span.AddEvent("SaveDNSConfig")
	_, err = api.np.SaveDNSConfig(*dnsConfig)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "override-local-dns", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "OverrideLocalDNS",
			StartTime: &requestStartTime,
		})

	return &v1.OverrideLocalDnsResponse{DnsConfig: dnsConfig.toProto()}, nil
}

func (api ninjapandaV1APIServer) DomainNameServers(
	ctx context.Context,
	request *v1.DomainNameServersRequest,
) (*v1.DomainNameServersResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetNamespace")
	namespace, err := api.np.GetNamespace(request.GetNamespace())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.AddEvent("GetDNSConfigByNamespace")
	dnsConfig, err := api.np.GetDNSConfigByNamespace(namespace.Name)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	dnsConfig.Nameservers = make(Nameservers, 0)
	for _, v := range request.GetIpAddrs() {
		ipAddr, err := netip.ParseAddr(v)
		if err != nil {
			span.SetStatus(ocodes.Error, err.Error())
			span.RecordError(err)

			return nil, fmt.Errorf("Invalid IP address specified: %s", v)
		}
		dnsConfig.Nameservers = append(dnsConfig.Nameservers, ipAddr)
	}

	span.AddEvent("SaveDNSConfig")
	_, err = api.np.SaveDNSConfig(*dnsConfig)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.SetStatus(ocodes.Ok, "")

	return &v1.DomainNameServersResponse{DnsConfig: dnsConfig.toProto()}, nil
}

func (api ninjapandaV1APIServer) MagicDns(
	ctx context.Context,
	request *v1.MagicDnsRequest,
) (*v1.MagicDnsResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetNamespace")
	namespace, err := api.np.GetNamespace(request.GetNamespace())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.AddEvent("GetDNSConfigByNamespace")
	dnsConfig, err := api.np.GetDNSConfigByNamespace(namespace.Name)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	dnsConfig.MagicDNS = request.GetEnable()

	span.AddEvent("SaveDNSConfig")
	dnsConfig, err = api.np.SaveDNSConfig(*dnsConfig)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.SetStatus(ocodes.Ok, "")

	return &v1.MagicDnsResponse{DnsConfig: dnsConfig.toProto()}, nil
}

func (api ninjapandaV1APIServer) SplitDns(
	ctx context.Context,
	request *v1.SplitDnsRequest,
) (*v1.SplitDnsResponse, error) {
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetNamespace")
	namespace, err := api.np.GetNamespace(request.GetNamespace())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.AddEvent("GetDNSConfigByNamespace")
	dnsConfig, err := api.np.GetDNSConfigByNamespace(namespace.Name)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	dnsConfig.RestrictedNameservers = make(RestrictedNameservers)
	for _, v := range request.GetSearchDomainNs() {
		for _, e := range v.Values {
			ipAddr, err := netip.ParseAddr(e)
			if err != nil {
				span.SetStatus(ocodes.Error, err.Error())
				span.RecordError(err)

				return nil, fmt.Errorf("Invalid IP address specified: %s", e)
			}
			dnsConfig.RestrictedNameservers[v.Key] = append(
				dnsConfig.RestrictedNameservers[v.Key],
				ipAddr,
			)
		}
	}

	span.AddEvent("SaveDNSConfig")
	_, err = api.np.SaveDNSConfig(*dnsConfig)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.SetStatus(ocodes.Ok, "")

	return &v1.SplitDnsResponse{DnsConfig: dnsConfig.toProto()}, nil
}

func (api ninjapandaV1APIServer) DeleteDnsConfig(
	ctx context.Context,
	request *v1.DeleteDnsConfigRequest,
) (*v1.DeleteDnsConfigResponse, error) {
	requestStartTime := time.Now()
	span := trace.SpanFromContext(ctx)

	span.AddEvent("GetNamespace")
	namespace, err := api.np.GetNamespace(request.GetNamespace())
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.AddEvent("GetDNSConfigByNamespace")
	_, err = api.np.GetDNSConfigByNamespace(namespace.Name)
	if err != nil {
		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.AddEvent("DeleteDnsConfig")
	err = api.np.DeleteDnsConfig(namespace.ID)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str(logtags.GetTag(logtags.namespace, "Name"), request.GetNamespace()).
			Msg("Could not delete dns config")

		span.SetStatus(ocodes.Error, err.Error())
		span.RecordError(err)

		return nil, err
	}

	span.SetStatus(ocodes.Ok, "")

	ctx = NotifyCtx(context.Background(), "delete-dns-config", "na")
	api.np.notifier.NotifyAll(ctx,
		StateUpdate{
			Type:      StateFullUpdate,
			Message:   "DeleteDNSConfig",
			StartTime: &requestStartTime,
		})

	return &v1.DeleteDnsConfigResponse{}, nil
}

func relayMapToProto(relayMap *ztcfg.RELAYMap) *v1.RelayMapResponse {
	relayMapProto := &v1.RelayMapResponse{
		RelayMap: &v1.RelayMap{
			Relays: &v1.Relays{
				Regions: make(map[string]*v1.Region),
			},
		},
	}
	for _, region := range relayMap.Regions {
		regionId := strconv.FormatUint(uint64(region.RegionID), 10)
		relayMapProto.RelayMap.Relays.Regions[regionId] = &v1.Region{
			RegionID:   uint32(region.RegionID),
			RegionCode: region.RegionCode,
			RegionName: region.RegionName,
			Nodes:      make([]*v1.Node, 0),
		}
		for _, node := range region.Nodes {
			relayMapProto.RelayMap.Relays.Regions[regionId].Nodes = append(
				relayMapProto.RelayMap.Relays.Regions[regionId].Nodes,
				&v1.Node{
					Name:     node.Name,
					RegionID: uint32(node.RegionID),
					HostName: node.HostName,
					IPv4:     node.IPv4,
				},
			)
		}
	}

	return relayMapProto
}

func (api ninjapandaV1APIServer) mustEmbedUnimplementedNinjapandaServiceServer() {}
