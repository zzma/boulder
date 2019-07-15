// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package wrappers wraps the GRPC calls in the core interfaces.
package grpc

import (
	"context"
	"net"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/zzma/boulder/core"
	corepb "github.com/zzma/boulder/core/proto"
	"github.com/zzma/boulder/revocation"
	sapb "github.com/zzma/boulder/sa/proto"
)

// StorageAuthorityClientWrapper is the gRPC version of a core.StorageAuthority client
type StorageAuthorityClientWrapper struct {
	inner sapb.StorageAuthorityClient
}

func NewStorageAuthorityClient(inner sapb.StorageAuthorityClient) *StorageAuthorityClientWrapper {
	return &StorageAuthorityClientWrapper{inner}
}

func (sac StorageAuthorityClientWrapper) GetRegistration(ctx context.Context, regID int64) (core.Registration, error) {
	response, err := sac.inner.GetRegistration(ctx, &sapb.RegistrationID{Id: &regID})
	if err != nil {
		return core.Registration{}, err
	}

	if response == nil || !registrationValid(response) {
		return core.Registration{}, errIncompleteResponse
	}

	return pbToRegistration(response)
}

func (sac StorageAuthorityClientWrapper) GetRegistrationByKey(ctx context.Context, key *jose.JSONWebKey) (core.Registration, error) {
	keyBytes, err := key.MarshalJSON()
	if err != nil {
		return core.Registration{}, err
	}

	response, err := sac.inner.GetRegistrationByKey(ctx, &sapb.JSONWebKey{Jwk: keyBytes})
	if err != nil {
		return core.Registration{}, err
	}

	if response == nil || !registrationValid(response) {
		return core.Registration{}, errIncompleteResponse
	}

	return pbToRegistration(response)
}

func (sac StorageAuthorityClientWrapper) GetAuthorization(ctx context.Context, authID string) (core.Authorization, error) {
	response, err := sac.inner.GetAuthorization(ctx, &sapb.AuthorizationID{Id: &authID})
	if err != nil {
		return core.Authorization{}, err
	}

	if response == nil || !authorizationValid(response) {
		return core.Authorization{}, errIncompleteResponse
	}

	return PBToAuthz(response)
}

func (sac StorageAuthorityClientWrapper) GetValidAuthorizations(ctx context.Context, regID int64, domains []string, now time.Time) (map[string]*core.Authorization, error) {
	nowUnix := now.UnixNano()

	response, err := sac.inner.GetValidAuthorizations(ctx, &sapb.GetValidAuthorizationsRequest{
		RegistrationID: &regID,
		Domains:        domains,
		Now:            &nowUnix,
	})
	if err != nil {
		return nil, err
	}

	if response == nil {
		return nil, errIncompleteResponse
	}

	auths := make(map[string]*core.Authorization, len(response.Valid))
	for _, element := range response.Valid {
		if element == nil || element.Domain == nil || !authorizationValid(element.Authz) {
			return nil, errIncompleteResponse
		}
		authz, err := PBToAuthz(element.Authz)
		if err != nil {
			return nil, err
		}
		auths[*element.Domain] = &authz
	}
	return auths, nil
}

func (sac StorageAuthorityClientWrapper) GetCertificate(ctx context.Context, serial string) (core.Certificate, error) {
	response, err := sac.inner.GetCertificate(ctx, &sapb.Serial{Serial: &serial})
	if err != nil {
		return core.Certificate{}, err
	}

	return pbToCert(response)
}

func (sac StorageAuthorityClientWrapper) GetCertificateStatus(ctx context.Context, serial string) (core.CertificateStatus, error) {
	response, err := sac.inner.GetCertificateStatus(ctx, &sapb.Serial{Serial: &serial})
	if err != nil {
		return core.CertificateStatus{}, err
	}

	if response == nil || response.Serial == nil || response.Status == nil || response.OcspLastUpdated == nil || response.RevokedDate == nil || response.RevokedReason == nil || response.LastExpirationNagSent == nil || response.OcspResponse == nil || response.NotAfter == nil || response.IsExpired == nil {
		return core.CertificateStatus{}, errIncompleteResponse
	}

	return core.CertificateStatus{
		Serial:                *response.Serial,
		Status:                core.OCSPStatus(*response.Status),
		OCSPLastUpdated:       time.Unix(0, *response.OcspLastUpdated),
		RevokedDate:           time.Unix(0, *response.RevokedDate),
		RevokedReason:         revocation.Reason(*response.RevokedReason),
		LastExpirationNagSent: time.Unix(0, *response.LastExpirationNagSent),
		OCSPResponse:          response.OcspResponse,
		NotAfter:              time.Unix(0, *response.NotAfter),
		IsExpired:             *response.IsExpired,
	}, nil
}

func (sac StorageAuthorityClientWrapper) CountCertificatesByNames(ctx context.Context, domains []string, earliest, latest time.Time) ([]*sapb.CountByNames_MapElement, error) {
	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()

	response, err := sac.inner.CountCertificatesByNames(ctx, &sapb.CountCertificatesByNamesRequest{
		Names: domains,
		Range: &sapb.Range{
			Earliest: &earliestNano,
			Latest:   &latestNano,
		},
	})
	if err != nil {
		return nil, err
	}

	if response == nil || response.CountByNames == nil {
		return nil, errIncompleteResponse
	}

	return response.CountByNames, nil
}

func (sac StorageAuthorityClientWrapper) CountRegistrationsByIP(ctx context.Context, ip net.IP, earliest, latest time.Time) (int, error) {
	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()

	response, err := sac.inner.CountRegistrationsByIP(ctx, &sapb.CountRegistrationsByIPRequest{
		Range: &sapb.Range{
			Earliest: &earliestNano,
			Latest:   &latestNano,
		},
		Ip: ip,
	})
	if err != nil {
		return 0, err
	}

	if response == nil || response.Count == nil {
		return 0, errIncompleteResponse
	}

	return int(*response.Count), nil
}

func (sac StorageAuthorityClientWrapper) CountRegistrationsByIPRange(ctx context.Context, ip net.IP, earliest, latest time.Time) (int, error) {
	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()

	response, err := sac.inner.CountRegistrationsByIPRange(ctx, &sapb.CountRegistrationsByIPRequest{
		Range: &sapb.Range{
			Earliest: &earliestNano,
			Latest:   &latestNano,
		},
		Ip: ip,
	})
	if err != nil {
		return 0, err
	}

	if response == nil || response.Count == nil {
		return 0, errIncompleteResponse
	}

	return int(*response.Count), nil
}

func (sac StorageAuthorityClientWrapper) CountPendingAuthorizations(ctx context.Context, regID int64) (int, error) {
	response, err := sac.inner.CountPendingAuthorizations(ctx, &sapb.RegistrationID{Id: &regID})
	if err != nil {
		return 0, err
	}

	if response == nil || response.Count == nil {
		return 0, errIncompleteResponse
	}

	return int(*response.Count), nil
}

func (sac StorageAuthorityClientWrapper) CountOrders(ctx context.Context, acctID int64, earliest, latest time.Time) (int, error) {
	earliestNano := earliest.UnixNano()
	latestNano := latest.UnixNano()

	response, err := sac.inner.CountOrders(ctx, &sapb.CountOrdersRequest{
		AccountID: &acctID,
		Range: &sapb.Range{
			Earliest: &earliestNano,
			Latest:   &latestNano,
		},
	})
	if err != nil {
		return 0, err
	}

	if response == nil || response.Count == nil {
		return 0, errIncompleteResponse
	}

	return int(*response.Count), nil
}

func (sac StorageAuthorityClientWrapper) CountInvalidAuthorizations(ctx context.Context, request *sapb.CountInvalidAuthorizationsRequest) (*sapb.Count, error) {
	return sac.inner.CountInvalidAuthorizations(ctx, request)
}

func (sac StorageAuthorityClientWrapper) GetPendingAuthorization(ctx context.Context, request *sapb.GetPendingAuthorizationRequest) (*core.Authorization, error) {
	authzPB, err := sac.inner.GetPendingAuthorization(ctx, request)
	if err != nil {
		return nil, err
	}
	authz, err := PBToAuthz(authzPB)
	if err != nil {
		return nil, err
	}
	return &authz, nil
}

func (sac StorageAuthorityClientWrapper) CountFQDNSets(ctx context.Context, window time.Duration, domains []string) (int64, error) {
	windowNanos := window.Nanoseconds()

	response, err := sac.inner.CountFQDNSets(ctx, &sapb.CountFQDNSetsRequest{
		Window:  &windowNanos,
		Domains: domains,
	})
	if err != nil {
		return 0, err
	}

	if response == nil || response.Count == nil {
		return 0, errIncompleteResponse
	}

	return *response.Count, nil
}

func (sac StorageAuthorityClientWrapper) PreviousCertificateExists(
	ctx context.Context,
	req *sapb.PreviousCertificateExistsRequest,
) (*sapb.Exists, error) {
	exists, err := sac.inner.PreviousCertificateExists(ctx, req)
	if err != nil {
		return nil, err
	}
	if exists == nil || exists.Exists == nil {
		return nil, errIncompleteResponse
	}
	return exists, err
}

func (sac StorageAuthorityClientWrapper) FQDNSetExists(ctx context.Context, domains []string) (bool, error) {
	response, err := sac.inner.FQDNSetExists(ctx, &sapb.FQDNSetExistsRequest{Domains: domains})
	if err != nil {
		return false, err
	}

	if response == nil || response.Exists == nil {
		return false, errIncompleteResponse
	}

	return *response.Exists, nil
}

func (sac StorageAuthorityClientWrapper) NewRegistration(ctx context.Context, reg core.Registration) (core.Registration, error) {
	regPB, err := registrationToPB(reg)
	if err != nil {
		return core.Registration{}, err
	}

	response, err := sac.inner.NewRegistration(ctx, regPB)
	if err != nil {
		return core.Registration{}, err
	}

	if response == nil || !registrationValid(response) {
		return core.Registration{}, errIncompleteResponse
	}

	return pbToRegistration(response)
}

func (sac StorageAuthorityClientWrapper) UpdateRegistration(ctx context.Context, reg core.Registration) error {
	regPB, err := registrationToPB(reg)
	if err != nil {
		return err
	}

	_, err = sac.inner.UpdateRegistration(ctx, regPB)
	if err != nil {
		return err
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) NewPendingAuthorization(ctx context.Context, authz core.Authorization) (core.Authorization, error) {
	authPB, err := AuthzToPB(authz)
	if err != nil {
		return core.Authorization{}, err
	}

	response, err := sac.inner.NewPendingAuthorization(ctx, authPB)
	if err != nil {
		return core.Authorization{}, err
	}

	if response == nil || !authorizationValid(response) {
		return core.Authorization{}, errIncompleteResponse
	}

	return PBToAuthz(response)
}

func (sac StorageAuthorityClientWrapper) FinalizeAuthorization(ctx context.Context, authz core.Authorization) error {
	authPB, err := AuthzToPB(authz)
	if err != nil {
		return err
	}

	_, err = sac.inner.FinalizeAuthorization(ctx, authPB)
	if err != nil {
		return err
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) AddCertificate(
	ctx context.Context,
	der []byte,
	regID int64,
	ocspResponse []byte,
	issued *time.Time) (string, error) {
	issuedTS := int64(0)
	if issued != nil {
		issuedTS = issued.UnixNano()
	}
	response, err := sac.inner.AddCertificate(ctx, &sapb.AddCertificateRequest{
		Der:    der,
		RegID:  &regID,
		Ocsp:   ocspResponse,
		Issued: &issuedTS,
	})
	if err != nil {
		return "", err
	}

	if response == nil || response.Digest == nil {
		return "", errIncompleteResponse
	}

	return *response.Digest, nil
}

func (sac StorageAuthorityClientWrapper) DeactivateRegistration(ctx context.Context, id int64) error {
	_, err := sac.inner.DeactivateRegistration(ctx, &sapb.RegistrationID{Id: &id})
	if err != nil {
		return err
	}

	return nil
}

func (sac StorageAuthorityClientWrapper) DeactivateAuthorization(ctx context.Context, id string) error {
	_, err := sac.inner.DeactivateAuthorization(ctx, &sapb.AuthorizationID{Id: &id})
	if err != nil {
		return err
	}

	return nil
}

func (sas StorageAuthorityClientWrapper) NewOrder(ctx context.Context, request *corepb.Order) (*corepb.Order, error) {
	resp, err := sas.inner.NewOrder(ctx, request)
	if err != nil {
		return nil, err
	}
	if resp == nil || !orderValid(resp) {
		return nil, errIncompleteResponse
	}
	return resp, nil
}

func (sac StorageAuthorityClientWrapper) SetOrderProcessing(ctx context.Context, order *corepb.Order) error {
	if _, err := sac.inner.SetOrderProcessing(ctx, order); err != nil {
		return err
	}
	return nil
}

func (sac StorageAuthorityClientWrapper) SetOrderError(ctx context.Context, order *corepb.Order) error {
	_, err := sac.inner.SetOrderError(ctx, order)
	return err
}

func (sac StorageAuthorityClientWrapper) FinalizeOrder(ctx context.Context, order *corepb.Order) error {
	if _, err := sac.inner.FinalizeOrder(ctx, order); err != nil {
		return err
	}
	return nil
}

func (sas StorageAuthorityClientWrapper) GetOrder(ctx context.Context, request *sapb.OrderRequest) (*corepb.Order, error) {
	resp, err := sas.inner.GetOrder(ctx, request)
	if err != nil {
		return nil, err
	}
	if resp == nil || !orderValid(resp) {
		return nil, errIncompleteResponse
	}
	return resp, nil
}

func (sas StorageAuthorityClientWrapper) GetOrderForNames(
	ctx context.Context,
	request *sapb.GetOrderForNamesRequest) (*corepb.Order, error) {
	resp, err := sas.inner.GetOrderForNames(ctx, request)
	if err != nil {
		return nil, err
	}
	// If there is an order response, it must be a valid order
	if resp == nil || !orderValid(resp) {
		return nil, errIncompleteResponse
	}
	return resp, nil
}

func (sas StorageAuthorityClientWrapper) GetValidOrderAuthorizations(
	ctx context.Context,
	request *sapb.GetValidOrderAuthorizationsRequest) (map[string]*core.Authorization, error) {
	resp, err := sas.inner.GetValidOrderAuthorizations(ctx, request)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errIncompleteResponse
	}

	// If there were no authorizations, return nil
	if resp.Authz == nil {
		return nil, nil
	}

	// Otherwise check the authorizations are valid and convert them from protobuf
	// form before returning a map of results to the caller
	auths := make(map[string]*core.Authorization, len(resp.Authz))
	for _, element := range resp.Authz {
		if element == nil || element.Domain == nil || !authorizationValid(element.Authz) {
			return nil, errIncompleteResponse
		}
		authz, err := PBToAuthz(element.Authz)
		if err != nil {
			return nil, err
		}
		auths[*element.Domain] = &authz
	}
	return auths, nil
}

func (sas StorageAuthorityClientWrapper) GetAuthorizations(ctx context.Context, req *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error) {
	resp, err := sas.inner.GetAuthorizations(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errIncompleteResponse
	}
	for _, element := range resp.Authz {
		if element == nil || element.Domain == nil || !authorizationValid(element.Authz) {
			return nil, errIncompleteResponse
		}
	}
	return resp, nil
}

func (sas StorageAuthorityClientWrapper) AddPendingAuthorizations(ctx context.Context, req *sapb.AddPendingAuthorizationsRequest) (*sapb.AuthorizationIDs, error) {
	resp, err := sas.inner.AddPendingAuthorizations(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Ids == nil {
		return nil, errIncompleteResponse
	}
	return resp, nil
}

func (sas StorageAuthorityClientWrapper) GetAuthorization2(ctx context.Context, req *sapb.AuthorizationID2) (*corepb.Authorization, error) {
	resp, err := sas.inner.GetAuthorization2(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp == nil || !authorizationValid(resp) {
		return nil, errIncompleteResponse
	}
	return resp, nil
}

func (sas StorageAuthorityClientWrapper) RevokeCertificate(ctx context.Context, req *sapb.RevokeCertificateRequest) error {
	_, err := sas.inner.RevokeCertificate(ctx, req)
	return err
}

func (sas StorageAuthorityClientWrapper) NewAuthorizations2(ctx context.Context, req *sapb.AddPendingAuthorizationsRequest) (*sapb.Authorization2IDs, error) {
	resp, err := sas.inner.NewAuthorizations2(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Ids == nil {
		return nil, errIncompleteResponse
	}
	return resp, nil
}

func (sas StorageAuthorityClientWrapper) GetAuthorizations2(ctx context.Context, req *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error) {
	resp, err := sas.inner.GetAuthorizations2(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errIncompleteResponse
	}
	return resp, nil
}

func (sas StorageAuthorityClientWrapper) FinalizeAuthorization2(ctx context.Context, req *sapb.FinalizeAuthorizationRequest) error {
	if req == nil || req.ValidationRecords == nil || req.Status == nil || req.Attempted == nil || req.Expires == nil || req.Id == nil {
		return errIncompleteRequest
	}

	_, err := sas.inner.FinalizeAuthorization2(ctx, req)
	return err
}

func (sas StorageAuthorityClientWrapper) GetPendingAuthorization2(ctx context.Context, req *sapb.GetPendingAuthorizationRequest) (*corepb.Authorization, error) {
	if req == nil || req.RegistrationID == nil || req.IdentifierValue == nil || req.ValidUntil == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.GetPendingAuthorization2(ctx, req)
}

func (sas StorageAuthorityClientWrapper) CountPendingAuthorizations2(ctx context.Context, req *sapb.RegistrationID) (*sapb.Count, error) {
	if req == nil || req.Id == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.CountPendingAuthorizations2(ctx, req)
}

func (sas StorageAuthorityClientWrapper) GetValidOrderAuthorizations2(ctx context.Context, req *sapb.GetValidOrderAuthorizationsRequest) (*sapb.Authorizations, error) {
	if req == nil || req.AcctID == nil || req.Id == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.GetValidOrderAuthorizations2(ctx, req)
}

func (sas StorageAuthorityClientWrapper) CountInvalidAuthorizations2(ctx context.Context, req *sapb.CountInvalidAuthorizationsRequest) (*sapb.Count, error) {
	if req == nil || req.RegistrationID == nil || req.Hostname == nil || req.Range == nil || req.Range.Earliest == nil || req.Range.Latest == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.CountInvalidAuthorizations2(ctx, req)
}

func (sas StorageAuthorityClientWrapper) GetValidAuthorizations2(ctx context.Context, req *sapb.GetValidAuthorizationsRequest) (*sapb.Authorizations, error) {
	if req == nil || req.Domains == nil || req.RegistrationID == nil || req.Now == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.GetValidAuthorizations2(ctx, req)
}

func (sas StorageAuthorityClientWrapper) DeactivateAuthorization2(ctx context.Context, req *sapb.AuthorizationID2) (*corepb.Empty, error) {
	_, err := sas.inner.DeactivateAuthorization2(ctx, req)
	return nil, err
}

// StorageAuthorityServerWrapper is the gRPC version of a core.ServerAuthority server
type StorageAuthorityServerWrapper struct {
	// TODO(#3119): Don't use core.StorageAuthority
	inner core.StorageAuthority
}

func NewStorageAuthorityServer(inner core.StorageAuthority) *StorageAuthorityServerWrapper {
	return &StorageAuthorityServerWrapper{inner}
}

func (sas StorageAuthorityServerWrapper) GetRegistration(ctx context.Context, request *sapb.RegistrationID) (*corepb.Registration, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	reg, err := sas.inner.GetRegistration(ctx, *request.Id)
	if err != nil {
		return nil, err
	}

	return registrationToPB(reg)
}

func (sas StorageAuthorityServerWrapper) GetRegistrationByKey(ctx context.Context, request *sapb.JSONWebKey) (*corepb.Registration, error) {
	if request == nil || request.Jwk == nil {
		return nil, errIncompleteRequest
	}

	var jwk jose.JSONWebKey
	err := jwk.UnmarshalJSON(request.Jwk)
	if err != nil {
		return nil, err
	}

	reg, err := sas.inner.GetRegistrationByKey(ctx, &jwk)
	if err != nil {
		return nil, err
	}

	return registrationToPB(reg)
}

func (sas StorageAuthorityServerWrapper) GetAuthorization(ctx context.Context, request *sapb.AuthorizationID) (*corepb.Authorization, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	authz, err := sas.inner.GetAuthorization(ctx, *request.Id)
	if err != nil {
		return nil, err
	}

	return AuthzToPB(authz)
}

func (sas StorageAuthorityServerWrapper) GetValidAuthorizations(ctx context.Context, request *sapb.GetValidAuthorizationsRequest) (*sapb.ValidAuthorizations, error) {
	if request == nil || request.RegistrationID == nil || request.Domains == nil || request.Now == nil {
		return nil, errIncompleteRequest
	}

	valid, err := sas.inner.GetValidAuthorizations(ctx, *request.RegistrationID, request.Domains, time.Unix(0, *request.Now))
	if err != nil {
		return nil, err
	}

	resp := &sapb.ValidAuthorizations{}
	for k, v := range valid {
		authzPB, err := AuthzToPB(*v)
		if err != nil {
			return nil, err
		}
		// Make a copy of k because it will be reassigned with each loop.
		kCopy := k
		resp.Valid = append(resp.Valid, &sapb.ValidAuthorizations_MapElement{Domain: &kCopy, Authz: authzPB})
	}

	return resp, nil
}

func (sas StorageAuthorityServerWrapper) GetCertificate(ctx context.Context, request *sapb.Serial) (*corepb.Certificate, error) {
	if request == nil || request.Serial == nil {
		return nil, errIncompleteRequest
	}

	cert, err := sas.inner.GetCertificate(ctx, *request.Serial)
	if err != nil {
		return nil, err
	}

	return certToPB(cert), nil
}

func (sas StorageAuthorityServerWrapper) GetCertificateStatus(ctx context.Context, request *sapb.Serial) (*sapb.CertificateStatus, error) {
	if request == nil || request.Serial == nil {
		return nil, errIncompleteRequest
	}

	certStatus, err := sas.inner.GetCertificateStatus(ctx, *request.Serial)
	if err != nil {
		return nil, err
	}

	ocspLastUpdatedNano := certStatus.OCSPLastUpdated.UnixNano()
	revokedDateNano := certStatus.RevokedDate.UnixNano()
	lastExpirationNagSentNano := certStatus.LastExpirationNagSent.UnixNano()
	notAfterNano := certStatus.NotAfter.UnixNano()
	reason := int64(certStatus.RevokedReason)
	status := string(certStatus.Status)

	return &sapb.CertificateStatus{
		Serial:                &certStatus.Serial,
		Status:                &status,
		OcspLastUpdated:       &ocspLastUpdatedNano,
		RevokedDate:           &revokedDateNano,
		RevokedReason:         &reason,
		LastExpirationNagSent: &lastExpirationNagSentNano,
		OcspResponse:          certStatus.OCSPResponse,
		NotAfter:              &notAfterNano,
		IsExpired:             &certStatus.IsExpired,
	}, nil
}

func (sas StorageAuthorityServerWrapper) CountCertificatesByNames(ctx context.Context, request *sapb.CountCertificatesByNamesRequest) (*sapb.CountByNames, error) {
	if request == nil || request.Range == nil || request.Range.Earliest == nil || request.Range.Latest == nil || request.Names == nil {
		return nil, errIncompleteRequest
	}

	byNames, err := sas.inner.CountCertificatesByNames(ctx, request.Names, time.Unix(0, *request.Range.Earliest), time.Unix(0, *request.Range.Latest))
	if err != nil {
		return nil, err
	}

	return &sapb.CountByNames{CountByNames: byNames}, nil
}

func (sas StorageAuthorityServerWrapper) CountRegistrationsByIP(ctx context.Context, request *sapb.CountRegistrationsByIPRequest) (*sapb.Count, error) {
	if request == nil || request.Ip == nil || request.Range == nil || request.Range.Earliest == nil || request.Range.Latest == nil {
		return nil, errIncompleteRequest
	}

	count, err := sas.inner.CountRegistrationsByIP(
		ctx,
		net.IP(request.Ip),
		time.Unix(0, *request.Range.Earliest),
		time.Unix(0, *request.Range.Latest))
	if err != nil {
		return nil, err
	}

	castedCount := int64(count)
	return &sapb.Count{Count: &castedCount}, nil
}

func (sas StorageAuthorityServerWrapper) CountRegistrationsByIPRange(ctx context.Context, request *sapb.CountRegistrationsByIPRequest) (*sapb.Count, error) {
	if request == nil || request.Ip == nil || request.Range == nil || request.Range.Earliest == nil || request.Range.Latest == nil {
		return nil, errIncompleteRequest
	}

	count, err := sas.inner.CountRegistrationsByIPRange(
		ctx,
		net.IP(request.Ip),
		time.Unix(0, *request.Range.Earliest),
		time.Unix(0, *request.Range.Latest))
	if err != nil {
		return nil, err
	}

	castedCount := int64(count)
	return &sapb.Count{Count: &castedCount}, nil
}

func (sas StorageAuthorityServerWrapper) CountPendingAuthorizations(ctx context.Context, request *sapb.RegistrationID) (*sapb.Count, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	count, err := sas.inner.CountPendingAuthorizations(ctx, *request.Id)
	if err != nil {
		return nil, err
	}

	castedCount := int64(count)
	return &sapb.Count{Count: &castedCount}, nil
}

func (sas StorageAuthorityServerWrapper) CountOrders(ctx context.Context, request *sapb.CountOrdersRequest) (*sapb.Count, error) {
	if request == nil || request.AccountID == nil || request.Range == nil || request.Range.Earliest == nil || request.Range.Latest == nil {
		return nil, errIncompleteRequest
	}

	count, err := sas.inner.CountOrders(ctx,
		*request.AccountID,
		time.Unix(0, *request.Range.Earliest),
		time.Unix(0, *request.Range.Latest),
	)
	if err != nil {
		return nil, err
	}

	castedCount := int64(count)
	return &sapb.Count{Count: &castedCount}, nil
}

func (sas StorageAuthorityServerWrapper) CountInvalidAuthorizations(ctx context.Context, request *sapb.CountInvalidAuthorizationsRequest) (*sapb.Count, error) {
	return sas.inner.CountInvalidAuthorizations(ctx, request)
}

func (sas StorageAuthorityServerWrapper) GetPendingAuthorization(ctx context.Context, request *sapb.GetPendingAuthorizationRequest) (*corepb.Authorization, error) {
	authz, err := sas.inner.GetPendingAuthorization(ctx, request)
	if err != nil {
		return nil, err
	}
	authzPB, err := AuthzToPB(*authz)
	if err != nil {
		return nil, err
	}
	return authzPB, err
}

func (sas StorageAuthorityServerWrapper) CountFQDNSets(ctx context.Context, request *sapb.CountFQDNSetsRequest) (*sapb.Count, error) {
	if request == nil || request.Window == nil || request.Domains == nil {
		return nil, errIncompleteRequest
	}

	window := time.Duration(*request.Window)

	count, err := sas.inner.CountFQDNSets(ctx, window, request.Domains)
	if err != nil {
		return nil, err
	}

	castedCount := int64(count)
	return &sapb.Count{Count: &castedCount}, nil
}

func (sas StorageAuthorityServerWrapper) FQDNSetExists(ctx context.Context, request *sapb.FQDNSetExistsRequest) (*sapb.Exists, error) {
	if request == nil || request.Domains == nil {
		return nil, errIncompleteRequest
	}

	exists, err := sas.inner.FQDNSetExists(ctx, request.Domains)
	if err != nil {
		return nil, err
	}

	return &sapb.Exists{Exists: &exists}, nil
}

func (sac StorageAuthorityServerWrapper) PreviousCertificateExists(
	ctx context.Context,
	req *sapb.PreviousCertificateExistsRequest,
) (*sapb.Exists, error) {
	if req == nil || req.Domain == nil || req.RegID == nil {
		return nil, errIncompleteRequest
	}
	return sac.inner.PreviousCertificateExists(ctx, req)
}

func (sas StorageAuthorityServerWrapper) NewRegistration(ctx context.Context, request *corepb.Registration) (*corepb.Registration, error) {
	if request == nil || !registrationValid(request) {
		return nil, errIncompleteRequest
	}

	reg, err := pbToRegistration(request)
	if err != nil {
		return nil, err
	}

	newReg, err := sas.inner.NewRegistration(ctx, reg)
	if err != nil {
		return nil, err
	}

	return registrationToPB(newReg)
}

func (sas StorageAuthorityServerWrapper) UpdateRegistration(ctx context.Context, request *corepb.Registration) (*corepb.Empty, error) {
	if request == nil || !registrationValid(request) {
		return nil, errIncompleteRequest
	}

	reg, err := pbToRegistration(request)
	if err != nil {
		return nil, err
	}

	err = sas.inner.UpdateRegistration(ctx, reg)
	if err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) NewPendingAuthorization(ctx context.Context, request *corepb.Authorization) (*corepb.Authorization, error) {
	if request == nil || !authorizationValid(request) {
		return nil, errIncompleteRequest
	}

	authz, err := PBToAuthz(request)
	if err != nil {
		return nil, err
	}

	newAuthz, err := sas.inner.NewPendingAuthorization(ctx, authz)
	if err != nil {
		return nil, err
	}

	return AuthzToPB(newAuthz)
}

func (sas StorageAuthorityServerWrapper) FinalizeAuthorization(ctx context.Context, request *corepb.Authorization) (*corepb.Empty, error) {
	if request == nil || !authorizationValid(request) {
		return nil, errIncompleteRequest
	}

	authz, err := PBToAuthz(request)
	if err != nil {
		return nil, err
	}

	err = sas.inner.FinalizeAuthorization(ctx, authz)
	if err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) AddCertificate(ctx context.Context, request *sapb.AddCertificateRequest) (*sapb.AddCertificateResponse, error) {
	if request == nil || request.Der == nil || request.RegID == nil || request.Issued == nil {
		return nil, errIncompleteRequest
	}

	reqIssued := time.Unix(0, *request.Issued)
	digest, err := sas.inner.AddCertificate(ctx, request.Der, *request.RegID, request.Ocsp, &reqIssued)
	if err != nil {
		return nil, err
	}

	return &sapb.AddCertificateResponse{Digest: &digest}, nil
}

func (sas StorageAuthorityServerWrapper) DeactivateRegistration(ctx context.Context, request *sapb.RegistrationID) (*corepb.Empty, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	err := sas.inner.DeactivateRegistration(ctx, *request.Id)
	if err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) DeactivateAuthorization(ctx context.Context, request *sapb.AuthorizationID) (*corepb.Empty, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	err := sas.inner.DeactivateAuthorization(ctx, *request.Id)
	if err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) NewOrder(ctx context.Context, request *corepb.Order) (*corepb.Order, error) {
	if request == nil || !newOrderValid(request) {
		return nil, errIncompleteRequest
	}

	return sas.inner.NewOrder(ctx, request)
}

func (sas StorageAuthorityServerWrapper) SetOrderProcessing(ctx context.Context, order *corepb.Order) (*corepb.Empty, error) {
	if order == nil || !orderValid(order) {
		return nil, errIncompleteRequest
	}

	if err := sas.inner.SetOrderProcessing(ctx, order); err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) SetOrderError(ctx context.Context, order *corepb.Order) (*corepb.Empty, error) {
	if order == nil || !orderValid(order) {
		return nil, errIncompleteRequest
	}

	if err := sas.inner.SetOrderError(ctx, order); err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) FinalizeOrder(ctx context.Context, order *corepb.Order) (*corepb.Empty, error) {
	if order == nil || !orderValid(order) || order.CertificateSerial == nil {
		return nil, errIncompleteRequest
	}

	if err := sas.inner.FinalizeOrder(ctx, order); err != nil {
		return nil, err
	}

	return &corepb.Empty{}, nil
}

func (sas StorageAuthorityServerWrapper) GetOrder(ctx context.Context, request *sapb.OrderRequest) (*corepb.Order, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.GetOrder(ctx, request)
}

func (sas StorageAuthorityServerWrapper) GetOrderForNames(
	ctx context.Context,
	request *sapb.GetOrderForNamesRequest) (*corepb.Order, error) {
	if request == nil || request.AcctID == nil || len(request.Names) == 0 {
		return nil, errIncompleteRequest
	}
	return sas.inner.GetOrderForNames(ctx, request)
}

func (sas StorageAuthorityServerWrapper) GetValidOrderAuthorizations(
	ctx context.Context,
	request *sapb.GetValidOrderAuthorizationsRequest) (*sapb.Authorizations, error) {
	if request == nil || request.Id == nil || request.AcctID == nil {
		return nil, errIncompleteRequest
	}

	authzs, err := sas.inner.GetValidOrderAuthorizations(ctx, request)
	if err != nil {
		return nil, err
	}

	resp := &sapb.Authorizations{}
	for k, v := range authzs {
		authzPB, err := AuthzToPB(*v)
		if err != nil {
			return nil, err
		}
		// Make a copy of k because it will be reassigned with each loop.
		kCopy := k
		resp.Authz = append(resp.Authz, &sapb.Authorizations_MapElement{Domain: &kCopy, Authz: authzPB})
	}

	return resp, nil
}

func (sas StorageAuthorityServerWrapper) GetAuthorizations(ctx context.Context, request *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error) {
	if request == nil || request.RegistrationID == nil || request.Domains == nil || request.Now == nil || request.RequireV2Authzs == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.GetAuthorizations(ctx, request)
}

func (sas StorageAuthorityServerWrapper) AddPendingAuthorizations(ctx context.Context, request *sapb.AddPendingAuthorizationsRequest) (*sapb.AuthorizationIDs, error) {
	if request == nil || request.Authz == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.AddPendingAuthorizations(ctx, request)
}

func (sas StorageAuthorityServerWrapper) GetAuthorization2(ctx context.Context, request *sapb.AuthorizationID2) (*corepb.Authorization, error) {
	if request == nil || request.Id == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.GetAuthorization2(ctx, request)
}

func (sas StorageAuthorityServerWrapper) RevokeCertificate(ctx context.Context, req *sapb.RevokeCertificateRequest) (*corepb.Empty, error) {
	if req == nil || req.Serial == nil || req.Reason == nil || req.Date == nil || req.Response == nil {
		return nil, errIncompleteRequest
	}
	return &corepb.Empty{}, sas.inner.RevokeCertificate(ctx, req)
}

func (sas StorageAuthorityServerWrapper) NewAuthorizations2(ctx context.Context, req *sapb.AddPendingAuthorizationsRequest) (*sapb.Authorization2IDs, error) {
	if req == nil || req.Authz == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.NewAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) GetAuthorizations2(ctx context.Context, req *sapb.GetAuthorizationsRequest) (*sapb.Authorizations, error) {
	if req == nil || req.Domains == nil || req.RequireV2Authzs == nil || req.RegistrationID == nil || req.Now == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.GetAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) FinalizeAuthorization2(ctx context.Context, req *sapb.FinalizeAuthorizationRequest) (*corepb.Empty, error) {
	if req == nil || req.Status == nil || req.Attempted == nil || req.Expires == nil || req.Id == nil {
		return nil, errIncompleteRequest
	}

	return &corepb.Empty{}, sas.inner.FinalizeAuthorization2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) GetPendingAuthorization2(ctx context.Context, req *sapb.GetPendingAuthorizationRequest) (*corepb.Authorization, error) {
	if req == nil || req.RegistrationID == nil || req.IdentifierValue == nil || req.ValidUntil == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.GetPendingAuthorization2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) CountPendingAuthorizations2(ctx context.Context, req *sapb.RegistrationID) (*sapb.Count, error) {
	if req == nil || req.Id == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.CountPendingAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) GetValidOrderAuthorizations2(ctx context.Context, req *sapb.GetValidOrderAuthorizationsRequest) (*sapb.Authorizations, error) {
	if req == nil || req.AcctID == nil || req.Id == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.GetValidOrderAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) CountInvalidAuthorizations2(ctx context.Context, req *sapb.CountInvalidAuthorizationsRequest) (*sapb.Count, error) {
	if req == nil || req.RegistrationID == nil || req.Hostname == nil || req.Range == nil || req.Range.Earliest == nil || req.Range.Latest == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.CountInvalidAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) GetValidAuthorizations2(ctx context.Context, req *sapb.GetValidAuthorizationsRequest) (*sapb.Authorizations, error) {
	if req == nil || req.Domains == nil || req.RegistrationID == nil || req.Now == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.GetValidAuthorizations2(ctx, req)
}

func (sas StorageAuthorityServerWrapper) DeactivateAuthorization2(ctx context.Context, req *sapb.AuthorizationID2) (*corepb.Empty, error) {
	if req == nil || req.Id == nil {
		return nil, errIncompleteRequest
	}

	return sas.inner.DeactivateAuthorization2(ctx, req)
}
