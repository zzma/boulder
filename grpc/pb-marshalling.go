// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package grpc

import (
	"net"
	"time"

	"google.golang.org/grpc/codes"
	"gopkg.in/square/go-jose.v2"

	"github.com/zzma/boulder/core"
	corepb "github.com/zzma/boulder/core/proto"
	"github.com/zzma/boulder/identifier"
	"github.com/zzma/boulder/probs"
	sapb "github.com/zzma/boulder/sa/proto"
	vapb "github.com/zzma/boulder/va/proto"
)

var ErrMissingParameters = CodedError(codes.FailedPrecondition, "required RPC parameter was missing")

// This file defines functions to translate between the protobuf types and the
// code types.

func authzMetaToPB(authz core.Authorization) (*vapb.AuthzMeta, error) {
	return &vapb.AuthzMeta{
		Id:    &authz.ID,
		RegID: &authz.RegistrationID,
	}, nil
}

func pbToAuthzMeta(in *vapb.AuthzMeta) (core.Authorization, error) {
	if in == nil || in.Id == nil || in.RegID == nil {
		return core.Authorization{}, ErrMissingParameters
	}
	return core.Authorization{
		ID:             *in.Id,
		RegistrationID: *in.RegID,
	}, nil
}

func jwkToString(jwk *jose.JSONWebKey) (string, error) {
	bytes, err := jwk.MarshalJSON()
	return string(bytes), err
}

func stringToJWK(in string) (*jose.JSONWebKey, error) {
	var jwk = new(jose.JSONWebKey)
	err := jwk.UnmarshalJSON([]byte(in))
	if err != nil {
		return nil, err
	}
	return jwk, nil
}

func ProblemDetailsToPB(prob *probs.ProblemDetails) (*corepb.ProblemDetails, error) {
	if prob == nil {
		// nil problemDetails is valid
		return nil, nil
	}
	pt := string(prob.Type)
	st := int32(prob.HTTPStatus)
	return &corepb.ProblemDetails{
		ProblemType: &pt,
		Detail:      &prob.Detail,
		HttpStatus:  &st,
	}, nil
}

func PBToProblemDetails(in *corepb.ProblemDetails) (*probs.ProblemDetails, error) {
	if in == nil {
		// nil problemDetails is valid
		return nil, nil
	}
	if in.ProblemType == nil || in.Detail == nil {
		return nil, ErrMissingParameters
	}
	prob := &probs.ProblemDetails{
		Type:   probs.ProblemType(*in.ProblemType),
		Detail: *in.Detail,
	}
	if in.HttpStatus != nil {
		prob.HTTPStatus = int(*in.HttpStatus)
	}
	return prob, nil
}

func ChallengeToPB(challenge core.Challenge) (*corepb.Challenge, error) {
	st := string(challenge.Status)
	prob, err := ProblemDetailsToPB(challenge.Error)
	if err != nil {
		return nil, err
	}
	recordAry := make([]*corepb.ValidationRecord, len(challenge.ValidationRecord))
	for i, v := range challenge.ValidationRecord {
		recordAry[i], err = ValidationRecordToPB(v)
		if err != nil {
			return nil, err
		}
	}
	return &corepb.Challenge{
		Id:                &challenge.ID,
		Type:              &challenge.Type,
		Status:            &st,
		Token:             &challenge.Token,
		KeyAuthorization:  &challenge.ProvidedKeyAuthorization,
		Error:             prob,
		Validationrecords: recordAry,
	}, nil
}

func pbToChallenge(in *corepb.Challenge) (challenge core.Challenge, err error) {
	if in == nil {
		return core.Challenge{}, ErrMissingParameters
	}
	if in.Type == nil || in.Status == nil || in.Token == nil {
		return core.Challenge{}, ErrMissingParameters
	}
	var recordAry []core.ValidationRecord
	if len(in.Validationrecords) > 0 {
		recordAry = make([]core.ValidationRecord, len(in.Validationrecords))
		for i, v := range in.Validationrecords {
			recordAry[i], err = PBToValidationRecord(v)
			if err != nil {
				return core.Challenge{}, err
			}
		}
	}
	prob, err := PBToProblemDetails(in.Error)
	if err != nil {
		return core.Challenge{}, err
	}
	ch := core.Challenge{
		Type:             *in.Type,
		Status:           core.AcmeStatus(*in.Status),
		Token:            *in.Token,
		Error:            prob,
		ValidationRecord: recordAry,
	}
	if in.Id != nil {
		ch.ID = *in.Id
	}
	if in.KeyAuthorization != nil {
		ch.ProvidedKeyAuthorization = *in.KeyAuthorization
	}
	return ch, nil
}

func ValidationRecordToPB(record core.ValidationRecord) (*corepb.ValidationRecord, error) {
	addrs := make([][]byte, len(record.AddressesResolved))
	addrsTried := make([][]byte, len(record.AddressesTried))
	var err error
	for i, v := range record.AddressesResolved {
		addrs[i] = []byte(v)
	}
	for i, v := range record.AddressesTried {
		addrsTried[i] = []byte(v)
	}
	addrUsed, err := record.AddressUsed.MarshalText()
	if err != nil {
		return nil, err
	}
	return &corepb.ValidationRecord{
		Hostname:          &record.Hostname,
		Port:              &record.Port,
		AddressesResolved: addrs,
		AddressUsed:       addrUsed,
		Url:               &record.URL,
		AddressesTried:    addrsTried,
	}, nil
}

func PBToValidationRecord(in *corepb.ValidationRecord) (record core.ValidationRecord, err error) {
	if in == nil {
		return core.ValidationRecord{}, ErrMissingParameters
	}
	if in.AddressUsed == nil || in.Hostname == nil || in.Port == nil || in.Url == nil {
		return core.ValidationRecord{}, ErrMissingParameters
	}
	addrs := make([]net.IP, len(in.AddressesResolved))
	for i, v := range in.AddressesResolved {
		addrs[i] = net.IP(v)
	}
	addrsTried := make([]net.IP, len(in.AddressesTried))
	for i, v := range in.AddressesTried {
		addrsTried[i] = net.IP(v)
	}
	var addrUsed net.IP
	err = addrUsed.UnmarshalText(in.AddressUsed)
	if err != nil {
		return
	}
	return core.ValidationRecord{
		Hostname:          *in.Hostname,
		Port:              *in.Port,
		AddressesResolved: addrs,
		AddressUsed:       addrUsed,
		URL:               *in.Url,
		AddressesTried:    addrsTried,
	}, nil
}

func ValidationResultToPB(records []core.ValidationRecord, prob *probs.ProblemDetails) (*vapb.ValidationResult, error) {
	recordAry := make([]*corepb.ValidationRecord, len(records))
	var err error
	for i, v := range records {
		recordAry[i], err = ValidationRecordToPB(v)
		if err != nil {
			return nil, err
		}
	}
	marshalledProbs, err := ProblemDetailsToPB(prob)
	if err != nil {
		return nil, err
	}
	return &vapb.ValidationResult{
		Records:  recordAry,
		Problems: marshalledProbs,
	}, nil
}

func pbToValidationResult(in *vapb.ValidationResult) ([]core.ValidationRecord, *probs.ProblemDetails, error) {
	if in == nil {
		return nil, nil, ErrMissingParameters
	}
	recordAry := make([]core.ValidationRecord, len(in.Records))
	var err error
	for i, v := range in.Records {
		recordAry[i], err = PBToValidationRecord(v)
		if err != nil {
			return nil, nil, err
		}
	}
	prob, err := PBToProblemDetails(in.Problems)
	if err != nil {
		return nil, nil, err
	}
	return recordAry, prob, nil
}

func performValidationReqToArgs(in *vapb.PerformValidationRequest) (domain string, challenge core.Challenge, authz core.Authorization, err error) {
	if in == nil {
		err = ErrMissingParameters
		return
	}
	if in.Domain == nil {
		err = ErrMissingParameters
		return
	}
	domain = *in.Domain
	challenge, err = pbToChallenge(in.Challenge)
	if err != nil {
		return
	}
	authz, err = pbToAuthzMeta(in.Authz)
	if err != nil {
		return
	}

	return domain, challenge, authz, nil
}

func argsToPerformValidationRequest(domain string, challenge core.Challenge, authz core.Authorization) (*vapb.PerformValidationRequest, error) {
	pbChall, err := ChallengeToPB(challenge)
	if err != nil {
		return nil, err
	}
	authzMeta, err := authzMetaToPB(authz)
	if err != nil {
		return nil, err
	}
	return &vapb.PerformValidationRequest{
		Domain:    &domain,
		Challenge: pbChall,
		Authz:     authzMeta,
	}, nil

}

func registrationToPB(reg core.Registration) (*corepb.Registration, error) {
	keyBytes, err := reg.Key.MarshalJSON()
	if err != nil {
		return nil, err
	}
	ipBytes, err := reg.InitialIP.MarshalText()
	if err != nil {
		return nil, err
	}
	createdAt := reg.CreatedAt.UnixNano()
	status := string(reg.Status)
	var contacts []string
	// Since the default value of corepb.Registration.Contact is a slice
	// we need a indicator as to if the value is actually important on
	// the other side (pb -> reg).
	contactsPresent := reg.Contact != nil
	if reg.Contact != nil {
		contacts = *reg.Contact
	}
	return &corepb.Registration{
		Id:              &reg.ID,
		Key:             keyBytes,
		Contact:         contacts,
		ContactsPresent: &contactsPresent,
		Agreement:       &reg.Agreement,
		InitialIP:       ipBytes,
		CreatedAt:       &createdAt,
		Status:          &status,
	}, nil
}

func pbToRegistration(pb *corepb.Registration) (core.Registration, error) {
	var key jose.JSONWebKey
	err := key.UnmarshalJSON(pb.Key)
	if err != nil {
		return core.Registration{}, err
	}
	var initialIP net.IP
	err = initialIP.UnmarshalText(pb.InitialIP)
	if err != nil {
		return core.Registration{}, err
	}
	var contacts *[]string
	if *pb.ContactsPresent {
		if len(pb.Contact) != 0 {
			contacts = &pb.Contact
		} else {
			// When gRPC creates an empty slice it is actually a nil slice. Since
			// certain things boulder uses, like encoding/json, differentiate between
			// these we need to de-nil these slices. Without this we are unable to
			// properly do registration updates as contacts would always be removed
			// as we use the difference between a nil and empty slice in ra.mergeUpdate.
			empty := []string{}
			contacts = &empty
		}
	}
	return core.Registration{
		ID:        *pb.Id,
		Key:       &key,
		Contact:   contacts,
		Agreement: *pb.Agreement,
		InitialIP: initialIP,
		CreatedAt: time.Unix(0, *pb.CreatedAt),
		Status:    core.AcmeStatus(*pb.Status),
	}, nil
}

func AuthzToPB(authz core.Authorization) (*corepb.Authorization, error) {
	challs := make([]*corepb.Challenge, len(authz.Challenges))
	for i, c := range authz.Challenges {
		pbChall, err := ChallengeToPB(c)
		if err != nil {
			return nil, err
		}
		challs[i] = pbChall
	}
	status := string(authz.Status)
	var expires int64
	if authz.Expires != nil {
		expires = authz.Expires.UTC().UnixNano()
	}
	return &corepb.Authorization{
		Id:             &authz.ID,
		Identifier:     &authz.Identifier.Value,
		RegistrationID: &authz.RegistrationID,
		Status:         &status,
		Expires:        &expires,
		Challenges:     challs,
		V2:             &authz.V2,
	}, nil
}

func PBToAuthz(pb *corepb.Authorization) (core.Authorization, error) {
	challs := make([]core.Challenge, len(pb.Challenges))
	for i, c := range pb.Challenges {
		chall, err := pbToChallenge(c)
		if err != nil {
			return core.Authorization{}, err
		}
		challs[i] = chall
	}
	expires := time.Unix(0, *pb.Expires).UTC()
	v2 := false
	if pb.V2 != nil {
		v2 = *pb.V2
	}
	authz := core.Authorization{
		Identifier:     identifier.ACMEIdentifier{Type: identifier.DNS, Value: *pb.Identifier},
		RegistrationID: *pb.RegistrationID,
		Status:         core.AcmeStatus(*pb.Status),
		Expires:        &expires,
		Challenges:     challs,
		V2:             v2,
	}
	if pb.Id != nil {
		authz.ID = *pb.Id
	}
	return authz, nil
}

func registrationValid(reg *corepb.Registration) bool {
	return !(reg.Id == nil || reg.Key == nil || reg.Agreement == nil || reg.InitialIP == nil || reg.CreatedAt == nil || reg.Status == nil || reg.ContactsPresent == nil)
}

// orderValid checks that a corepb.Order is valid. In addition to the checks
// from `newOrderValid` it ensures the order ID, the BeganProcessing fields
// and the Created field are not nil.
func orderValid(order *corepb.Order) bool {
	return order.Id != nil && order.BeganProcessing != nil && order.Created != nil && newOrderValid(order)
}

// newOrderValid checks that a corepb.Order is valid. It allows for a nil
// `order.Id` because the order has not been assigned an ID yet when it is being
// created initially. It allows `order.BeganProcessing` to be nil because
// `sa.NewOrder` explicitly sets it to the default value. It allows
// `order.Created` to be nil because the SA populates this. It also allows
// `order.CertificateSerial` to be nil such that it can be used in places where
// the order has not been finalized yet.
func newOrderValid(order *corepb.Order) bool {
	return !(order.RegistrationID == nil || order.Expires == nil || (order.Authorizations == nil && order.V2Authorizations == nil) || order.Names == nil)
}

func authorizationValid(authz *corepb.Authorization) bool {
	return !(authz.Id == nil || authz.Identifier == nil || authz.RegistrationID == nil || authz.Status == nil || authz.Expires == nil)
}

func certToPB(cert core.Certificate) *corepb.Certificate {
	issued, expires := cert.Issued.UnixNano(), cert.Expires.UnixNano()
	return &corepb.Certificate{
		RegistrationID: &cert.RegistrationID,
		Serial:         &cert.Serial,
		Digest:         &cert.Digest,
		Der:            cert.DER,
		Issued:         &issued,
		Expires:        &expires,
	}
}

func pbToCert(pb *corepb.Certificate) (core.Certificate, error) {
	if pb == nil || pb.RegistrationID == nil || pb.Serial == nil || pb.Digest == nil || pb.Der == nil || pb.Issued == nil || pb.Expires == nil {
		return core.Certificate{}, errIncompleteResponse
	}
	return core.Certificate{
		RegistrationID: *pb.RegistrationID,
		Serial:         *pb.Serial,
		Digest:         *pb.Digest,
		DER:            pb.Der,
		Issued:         time.Unix(0, *pb.Issued),
		Expires:        time.Unix(0, *pb.Expires),
	}, nil
}

// PBToAuthzMap converts a protobuf map of domains mapped to protobuf authorizations to a
// golang map[string]*core.Authorization.
func PBToAuthzMap(pb *sapb.Authorizations) (map[string]*core.Authorization, error) {
	m := make(map[string]*core.Authorization, len(pb.Authz))
	for _, v := range pb.Authz {
		authz, err := PBToAuthz(v.Authz)
		if err != nil {
			return nil, err
		}
		m[*v.Domain] = &authz
	}
	return m, nil
}
