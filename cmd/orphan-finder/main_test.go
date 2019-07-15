package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/zzma/boulder/core"
	berrors "github.com/zzma/boulder/errors"
	blog "github.com/zzma/boulder/log"
	"github.com/zzma/boulder/test"
)

var log = blog.UseMock()

type mockSA struct {
	certificate core.Certificate
	clk         clock.FakeClock
}

func (m *mockSA) AddCertificate(ctx context.Context, der []byte, regID int64, _ []byte, issued *time.Time) (string, error) {
	m.certificate.DER = der
	m.certificate.RegistrationID = regID

	if issued == nil {
		m.certificate.Issued = m.clk.Now()
	} else {
		m.certificate.Issued = *issued
	}

	return "", nil
}

func (m *mockSA) GetCertificate(ctx context.Context, s string) (core.Certificate, error) {
	if m.certificate.DER != nil {
		return m.certificate, nil
	}
	return core.Certificate{}, berrors.NotFoundError("no cert stored")
}

func checkNoErrors(t *testing.T) {
	logs := log.GetAllMatching("ERR:")
	if len(logs) != 0 {
		t.Errorf("Found error logs:")
		for _, ll := range logs {
			t.Error(ll)
		}
	}
}

func TestParseLine(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC))
	sa := &mockSA{}

	// Set an example backdate duration (this is normally read from config)
	backdateDuration = time.Hour

	testCertDER := "3082045b30820343a003020102021300ffa0160630d618b2eb5c0510824b14274856300d06092a864886f70d01010b0500301f311d301b06035504030c146861707079206861636b65722066616b65204341301e170d3135313030333035323130305a170d3136303130313035323130305a3018311630140603550403130d6578616d706c652e636f2e626e30820122300d06092a864886f70d01010105000382010f003082010a02820101009ea3f1d21fade5596e36a6a77095a94758e4b72466b7444ada4f7c4cf6fde9b1d470b93b65c1fdd896917f248ccae49b57c80dc21c64b010699432130d059d2d8392346e8a179c7c947835549c64a7a5680c518faf0a5cbea48e684fca6304775c8fa9239c34f1d5cb2d063b098bd1c17183c7521efc884641b2f0b41402ac87c7076848d4347cef59dd5a9c174ad25467db933c95ef48c578ba762f527b21666a198fb5e1fe2d8299b4dceb1791e96ad075e3ecb057c776d764fad8f0829d43c32ddf985a3a36fade6966cec89468721a1ec47ab38eac8da4514060ded51d283a787b7c69971bda01f49f76baa41b1f9b4348aa4279e0fa55645d6616441f0d0203010001a382019530820191300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff04023000301d0603551d0e04160414369d0c100452b9eb3ffe7ae852e9e839a3ae5adb301f0603551d23041830168014fb784f12f96015832c9f177f3419b32e36ea4189306a06082b06010505070101045e305c302606082b06010505073001861a687474703a2f2f6c6f63616c686f73743a343030322f6f637370303206082b060105050730028626687474703a2f2f6c6f63616c686f73743a343030302f61636d652f6973737565722d6365727430180603551d110411300f820d6578616d706c652e636f2e626e30270603551d1f0420301e301ca01aa0188616687474703a2f2f6578616d706c652e636f6d2f63726c30630603551d20045c305a300a060667810c0102013000304c06032a03043045302206082b060105050702011616687474703a2f2f6578616d706c652e636f6d2f637073301f06082b0601050507020230130c11446f20576861742054686f752057696c74300d06092a864886f70d01010b05000382010100bbb4b994971cafa2e56e2258db46d88bfb361d8bfcd75521c03174e471eaa9f3ff2e719059bb57cc064079496d8550577c127baa84a18e792ddd36bf4f7b874b6d40d1d14288c15d38e4d6be25eb7805b1c3756b3735702eb4585d1886bc8af2c14086d3ce506e55184913c83aaaa8dfe6160bd035e42cda6d97697ed3ee3124c9bf9620a9fe6602191c1b746533c1d4a30023bbe902cb4aa661901177ed924eb836c94cc062dd0ce439c4ece9ee1dfe0499a42cbbcb2ea7243c59f4df4fdd7058229bacf9a640632dbd776b21633137b2df1c41f0765a66f448777aeec7ed4c0cdeb9d8a2356ff813820a287e11d52efde1aa543b4ef2ee992a7a9d5ccf7da4"

	testCases := []struct {
		Name           string
		LogLine        string
		ExpectFound    bool
		ExpectAdded    bool
		ExpectNoErrors bool
	}{
		{
			Name:           "Empty line",
			LogLine:        "",
			ExpectFound:    false,
			ExpectAdded:    false,
			ExpectNoErrors: false,
		},
		{
			Name:           "Empty cert in line",
			LogLine:        "0000-00-00T00:00:00+00:00 hostname boulder-ca[pid]: [AUDIT] Failed RPC to store at SA, orphaning certificate: cert=[] err=[context deadline exceeded], regID=[1337], orderID=[0]",
			ExpectFound:    true,
			ExpectAdded:    false,
			ExpectNoErrors: false,
		},
		{
			Name:           "Invalid cert in line",
			LogLine:        "0000-00-00T00:00:00+00:00 hostname boulder-ca[pid]: [AUDIT] Failed RPC to store at SA, orphaning certificate: cert=[deadbeef] err=[context deadline exceeded], regID=[], orderID=[]",
			ExpectFound:    true,
			ExpectAdded:    false,
			ExpectNoErrors: false,
		},
		{
			Name:           "Valid cert in line",
			LogLine:        fmt.Sprintf("0000-00-00T00:00:00+00:00 hostname boulder-ca[pid]: [AUDIT] Failed RPC to store at SA, orphaning certificate: cert=[%s] err=[context deadline exceeded], regID=[1001], orderID=[0]", testCertDER),
			ExpectFound:    true,
			ExpectAdded:    true,
			ExpectNoErrors: true,
		},
		{
			Name:        "Already inserted cert in line",
			LogLine:     fmt.Sprintf("0000-00-00T00:00:00+00:00 hostname boulder-ca[pid]: [AUDIT] Failed RPC to store at SA, orphaning certificate: cert=[%s] err=[context deadline exceeded], regID=[1001], orderID=[0]", testCertDER),
			ExpectFound: true,
			// ExpectAdded is false because we have already added this cert in the
			// previous "Valid cert in line" test case.
			ExpectAdded:    false,
			ExpectNoErrors: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			log.Clear()
			found, added := parseLogLine(sa, log, tc.LogLine)
			test.AssertEquals(t, found, tc.ExpectFound)
			test.AssertEquals(t, added, tc.ExpectAdded)
			logs := log.GetAllMatching("ERR:")
			if tc.ExpectNoErrors {
				test.AssertEquals(t, len(logs), 0)
			}
		})
	}

	// Decode the test cert DER we added above to get the certificate serial
	der, _ := hex.DecodeString(testCertDER)
	testCert, _ := x509.ParseCertificate(der)
	testCertSerial := core.SerialToString(testCert.SerialNumber)

	// Fetch the certificate from the mock SA
	cert, err := sa.GetCertificate(context.Background(), testCertSerial)
	// It should not error
	test.AssertNotError(t, err, "Error getting test certificate from SA")
	// The orphan cert should have been added with the correct registration ID from the log line
	test.AssertEquals(t, cert.RegistrationID, int64(1001))
	// The Issued timestamp should be the certificate's NotBefore timestamp offset by the backdateDuration
	test.AssertEquals(t, cert.Issued, testCert.NotBefore.Add(backdateDuration))
}

func TestNotOrphan(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC))
	sa := &mockSA{}

	log.Clear()
	found, added := parseLogLine(sa, log, "cert=fakeout")
	test.AssertEquals(t, found, false)
	test.AssertEquals(t, added, false)
	checkNoErrors(t)
}
