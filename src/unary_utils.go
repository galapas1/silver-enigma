package ninjapanda

import (
	"bytes"
	"context"
	"path"
	"strings"
	"time"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

var (
	Marshaller     = &jsonpb.Marshaler{}
	TimestampLog   = true
	ServiceField   = "service"
	ServiceLog     = true
	MethodField    = "method"
	MethodLog      = true
	DurationField  = "dur"
	DurationLog    = true
	IPField        = "ip"
	IPLog          = true
	MetadataField  = "md"
	MetadataLog    = true
	UserAgentField = "ua"
	UserAgentLog   = true
	ReqField       = "req"
	ReqLog         = true
	RespField      = "resp"
	RespLog        = true
	MaxSize        = 2048000
	CodeField      = "code"
	MsgField       = "msg"
	DetailsField   = "details"
)

func LogIncomingCall(
	ctx context.Context,
	logger *zerolog.Event,
	method string,
	t time.Time,
	req interface{},
) {
	LogTimestamp(logger, t)
	LogService(logger, method)
	LogMethod(logger, method)
	LogDuration(logger, t)
	LogRequest(logger, req)
	LogIncomingMetadata(ctx, logger)
}

func LogTimestamp(logger *zerolog.Event, t time.Time) {
	if TimestampLog {
		*logger = *logger.Time(zerolog.TimestampFieldName, t)
	}
}

func LogService(logger *zerolog.Event, method string) {
	if ServiceLog {
		*logger = *logger.Str(ServiceField, path.Dir(method)[1:])
	}
}

func LogMethod(logger *zerolog.Event, method string) {
	if MethodLog {
		*logger = *logger.Str(MethodField, path.Base(method))
	}
}

func LogDuration(logger *zerolog.Event, t time.Time) {
	if DurationLog {
		*logger = *logger.Dur(DurationField, time.Since(t))
	}
}

func LogIP(ctx context.Context, logger *zerolog.Event) {
	if IPLog {
		if p, ok := peer.FromContext(ctx); ok {
			*logger = *logger.Str(IPField, p.Addr.String())
		}
	}
}

func LogRequest(e *zerolog.Event, req interface{}) {
	if ReqLog {
		if b := GetRawJSON(req); b != nil {
			*e = *e.RawJSON(ReqField, b.Bytes())
		}
	}
}

func LogResponse(e *zerolog.Event, resp interface{}) {
	if RespLog {
		if b := GetRawJSON(resp); b != nil {
			*e = *e.RawJSON(RespField, b.Bytes())
		}
	}
}

func GetRawJSON(i interface{}) *bytes.Buffer {
	if pb, ok := i.(proto.Message); ok {
		b := &bytes.Buffer{}
		if err := Marshaller.Marshal(b, pb); err == nil && b.Len() < MaxSize {
			return b
		}
	}
	return nil
}

func LogIncomingMetadata(ctx context.Context, e *zerolog.Event) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if MetadataLog {
			*e = *e.Dict(MetadataField, LogMetadata(&md))
			return
		} else if UserAgentLog {
			LogUserAgent(e, &md)
		}
	}
}

func LogMetadata(md *metadata.MD) *zerolog.Event {
	dict := zerolog.Dict()
	for i := range *md {
		dict = dict.Str(i, strings.Join(md.Get(i), ","))
	}

	return dict
}

func LogUserAgent(logger *zerolog.Event, md *metadata.MD) {
	if ua := strings.Join(md.Get("user-agent"), ""); ua != "" {
		*logger = *logger.Str(UserAgentField, ua)
	}
}

func LogStatusError(logger *zerolog.Event, err error) {
	statusErr := status.Convert(err)
	*logger = *logger.
		Err(err).
		Str(CodeField, statusErr.Code().String()).
		Str(MsgField, statusErr.Message()).
		Interface(DetailsField, statusErr.Details())
}
