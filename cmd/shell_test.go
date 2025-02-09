package cmd

import (
	"encoding/json"
	"fmt"
	"runtime"
	"testing"

	"github.com/zzma/boulder/core"
	blog "github.com/zzma/boulder/log"
	"github.com/zzma/boulder/test"
)

var (
	validPAConfig = []byte(`{
  "dbConnect": "dummyDBConnect",
  "enforcePolicyWhitelist": false,
  "challenges": { "http-01": true }
}`)
	invalidPAConfig = []byte(`{
  "dbConnect": "dummyDBConnect",
  "enforcePolicyWhitelist": false,
  "challenges": { "nonsense": true }
}`)
	noChallengesPAConfig = []byte(`{
  "dbConnect": "dummyDBConnect",
  "enforcePolicyWhitelist": false
}`)

	emptyChallengesPAConfig = []byte(`{
  "dbConnect": "dummyDBConnect",
  "enforcePolicyWhitelist": false,
  "challenges": {}
}`)
)

func TestPAConfigUnmarshal(t *testing.T) {
	var pc1 PAConfig
	err := json.Unmarshal(validPAConfig, &pc1)
	test.AssertNotError(t, err, "Failed to unmarshal PAConfig")
	test.AssertNotError(t, pc1.CheckChallenges(), "Flagged valid challenges as bad")

	var pc2 PAConfig
	err = json.Unmarshal(invalidPAConfig, &pc2)
	test.AssertNotError(t, err, "Failed to unmarshal PAConfig")
	test.AssertError(t, pc2.CheckChallenges(), "Considered invalid challenges as good")

	var pc3 PAConfig
	err = json.Unmarshal(noChallengesPAConfig, &pc3)
	test.AssertNotError(t, err, "Failed to unmarshal PAConfig")
	test.AssertError(t, pc3.CheckChallenges(), "Disallow empty challenges map")

	var pc4 PAConfig
	err = json.Unmarshal(emptyChallengesPAConfig, &pc4)
	test.AssertNotError(t, err, "Failed to unmarshal PAConfig")
	test.AssertError(t, pc4.CheckChallenges(), "Disallow empty challenges map")
}

func TestMysqlLogger(t *testing.T) {
	log := blog.UseMock()
	mLog := mysqlLogger{log}

	testCases := []struct {
		args     []interface{}
		expected string
	}{
		{
			[]interface{}{nil},
			`ERR: [AUDIT] [mysql] <nil>`,
		},
		{
			[]interface{}{""},
			`ERR: [AUDIT] [mysql] `,
		},
		{
			[]interface{}{"Sup ", 12345, " Sup sup"},
			`ERR: [AUDIT] [mysql] Sup 12345 Sup sup`,
		},
	}

	for _, tc := range testCases {
		// mysqlLogger proxies blog.AuditLogger to provide a Print() method
		mLog.Print(tc.args...)
		logged := log.GetAll()
		// Calling Print should produce the expected output
		test.AssertEquals(t, len(logged), 1)
		test.AssertEquals(t, logged[0], tc.expected)
		log.Clear()
	}
}

func TestCfsslLogger(t *testing.T) {
	log := blog.UseMock()
	cLog := cfsslLogger{log}

	testCases := []struct {
		msg, expected string
	}{
		{
			"",
			"ERR: [AUDIT] ",
		},
		{
			"Test",
			"ERR: [AUDIT] Test",
		},
	}

	for _, tc := range testCases {
		// cfsslLogger proxies blog.AuditLogger to provide Crit() and Emerg()
		// methods that are expected by CFSSL's logger
		cLog.Crit(tc.msg)
		cLog.Emerg(tc.msg)
		logged := log.GetAll()
		// Calling Crit and Emerg should produce two AuditErr outputs matching the
		// testCase expected output
		test.AssertEquals(t, len(logged), 2)
		test.AssertEquals(t, logged[0], tc.expected)
		test.AssertEquals(t, logged[1], tc.expected)
		log.Clear()
	}
}

func TestVersionString(t *testing.T) {
	core.BuildID = "TestBuildID"
	core.BuildTime = "RightNow!"
	core.BuildHost = "Localhost"

	versionStr := VersionString()
	expected := fmt.Sprintf("Versions: cmd.test=(TestBuildID RightNow!) Golang=(%s) BuildHost=(Localhost)", runtime.Version())
	test.AssertEquals(t, versionStr, expected)
}

func TestLoadCert(t *testing.T) {
	testCases := []struct {
		path        string
		expectedErr string
	}{
		{
			"",
			"Issuer certificate was not provided in config.",
		},
		{
			"../does/not/exist",
			"open ../does/not/exist: no such file or directory",
		},
		{
			"./testdata/key.pem",
			"Invalid certificate value returned",
		},
	}

	for _, tc := range testCases {
		_, err := LoadCert(tc.path)
		test.AssertError(t, err, fmt.Sprintf("LoadCert(%q) did not error", tc.path))
		test.AssertEquals(t, err.Error(), tc.expectedErr)
	}

	bytes, err := LoadCert("./testdata/cert.pem")
	test.AssertNotError(t, err, "LoadCert(\"./testdata/cert.pem\") errored")
	test.AssertNotEquals(t, len(bytes), 0)
}

func TestReadConfigFile(t *testing.T) {
	err := ReadConfigFile("", nil)
	test.AssertError(t, err, "ReadConfigFile('') did not error")

	type config struct {
		NotifyMailer struct {
			DBConfig
			PasswordConfig
			SMTPConfig
		}
	}
	var c config
	err = ReadConfigFile("../test/config/notify-mailer.json", &c)
	test.AssertNotError(t, err, "ReadConfigFile(../test/config/notify-mailer.json) errored")
	test.AssertEquals(t, c.NotifyMailer.SMTPConfig.Server, "localhost")
}
