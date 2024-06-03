package ninjapanda

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"google.golang.org/grpc/metadata"

	v1 "optm.com/ninja-panda/gen/go/license/v1"
)

func (np *Ninjapanda) grpcCheckLicense(
	userProfile *UserProfile,
	machine *Machine,
	licenseKey string,
) (bool, error) {
	if np.grpcLicenseServiceClient == nil {
		return true, nil
	}

	namespace := machine.Namespace
	if len(namespace.ExternalId) == 0 {
		return false, fmt.Errorf(
			"failed to find externalId of namespace for machine",
		)
	}

	var count int
	var err error
	switch licenseKey {
	case MachinesPerUser:
		if userProfile == nil {
			return false, fmt.Errorf(
				"internal error: missing user profile",
			)
		}
		count, err = np.CountMachinesForUser(userProfile)
	case MachinesPerOrg:
		if machine == nil {
			return false, fmt.Errorf(
				"internal error: missing machine",
			)
		}
		count, err = np.CountMachinesInNamespace(machine)
	default:
		return false, fmt.Errorf(
			"internal error: unsupported license key, %s", licenseKey,
		)
	}
	if err != nil {
		return false, err
	}

	chkCxt := new(v1.LicenseCheckContext)
	chkCxt.Count = int32(count) + 1

	licenseCheck := new(v1.LicenseCheck)
	licenseCheck.SeqId = 1
	licenseCheck.Key = licenseKey
	licenseCheck.Context = chkCxt

	chkReq := new(v1.LicenseCheckRequest)
	chkReq.Licenses = append(chkReq.Licenses, licenseCheck)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ctx = metadata.AppendToOutgoingContext(
		ctx,
		"tenantId",
		namespace.ExternalId,
	)

	chkResp, err := np.grpcLicenseServiceClient.Check(ctx, chkReq)
	if err != nil {
		return false, fmt.Errorf("Error performing license check, %v", err)
	}

	for _, ans := range chkResp.GetAnswers() {
		log.Debug().
			Caller().
			Int32(logtags.MakeTag("SeqId"), ans.GetSeqId()).
			Str(logtags.MakeTag("licenseKey"), licenseKey).
			Int(logtags.MakeTag("count"), count).
			Bool(logtags.MakeTag("allowed"), ans.GetAllowed()).
			Str(logtags.MakeTag("MessageId"), ans.GetMessageId()).
			Msg("license server answer")

		if !ans.Allowed {
			return false, Error(ans.GetMessageId())
		}
	}

	return true, nil
}
