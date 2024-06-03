package ninjapanda

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"google.golang.org/grpc"
)

func NewUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return NewUnaryServerInterceptorWithLogger(&log.Logger)
}

func NewUnaryServerInterceptorWithLogger(
	log *zerolog.Logger,
) grpc.UnaryServerInterceptor {
	return func(ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		nowInUtc := time.Now().UTC()

		resp, err := handler(ctx, req)
		if log.Error().Enabled() {
			if err != nil {
				logger := log.Error()
				LogIncomingCall(ctx, logger, info.FullMethod, nowInUtc, req)
				LogStatusError(logger, err)
				logger.Send()
			} else if log.Info().Enabled() {
				logger := log.Info()
				LogIncomingCall(ctx, logger, info.FullMethod, nowInUtc, req)
				LogResponse(logger, resp)
				logger.Send()
			}
		}

		return resp, err
	}
}
