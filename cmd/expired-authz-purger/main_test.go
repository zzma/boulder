package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/zzma/boulder/core"
	blog "github.com/zzma/boulder/log"
	"github.com/zzma/boulder/metrics"
	"github.com/zzma/boulder/sa"
	"github.com/zzma/boulder/sa/satest"
	"github.com/zzma/boulder/test"
	"github.com/zzma/boulder/test/vars"
)

func TestPurgeAuthzs(t *testing.T) {
	dbMap, err := sa.NewDbMap(vars.DBConnSAFullPerms, 0)
	if err != nil {
		t.Fatalf("Couldn't connect the database: %s", err)
	}
	log := blog.UseMock()
	fc := clock.NewFake()
	fc.Add(time.Hour)
	ssa, err := sa.NewSQLStorageAuthority(dbMap, fc, log, metrics.NewNoopScope(), 1)
	if err != nil {
		t.Fatalf("unable to create SQLStorageAuthority: %s", err)
	}
	cleanUp := test.ResetSATestDatabase(t)
	defer cleanUp()

	p := expiredAuthzPurger{log, fc, dbMap, 1}

	err = p.purge(
		"pendingAuthorizations",
		time.Time{},
		10,
		100,
		false,
		"",
		0,
	)
	test.AssertNotError(t, err, "purgeAuthzs failed")

	old, new := fc.Now().Add(-time.Hour), fc.Now().Add(time.Hour)

	reg := satest.CreateWorkingRegistration(t, ssa)
	_, err = ssa.NewPendingAuthorization(context.Background(), core.Authorization{
		RegistrationID: reg.ID,
		Expires:        &old,
		Challenges:     []core.Challenge{{ID: 1}},
	})
	test.AssertNotError(t, err, "NewPendingAuthorization failed")
	_, err = ssa.NewPendingAuthorization(context.Background(), core.Authorization{
		RegistrationID: reg.ID,
		Expires:        &old,
		Challenges:     []core.Challenge{{ID: 2}},
	})
	test.AssertNotError(t, err, "NewPendingAuthorization failed")
	_, err = ssa.NewPendingAuthorization(context.Background(), core.Authorization{
		RegistrationID: reg.ID,
		Expires:        &new,
		Challenges:     []core.Challenge{{ID: 3}},
	})
	test.AssertNotError(t, err, "NewPendingAuthorization failed")

	deletedStat.Reset()
	err = p.purge(
		"pendingAuthorizations",
		fc.Now(),
		10,
		100,
		false,
		"",
		0,
	)
	test.AssertNotError(t, err, "purgeAuthzs failed")
	count, err := dbMap.SelectInt("SELECT COUNT(1) FROM pendingAuthorizations")
	test.AssertNotError(t, err, "dbMap.SelectInt failed")
	test.AssertEquals(t, count, int64(1))
	count, err = dbMap.SelectInt("SELECT COUNT(1) FROM challenges")
	test.AssertNotError(t, err, "dbMap.SelectInt failed")
	test.AssertEquals(t, count, int64(1))
	test.AssertEquals(t, test.CountCounterVec("table", "pendingAuthorizations", deletedStat), 2)
	test.AssertEquals(t, test.CountCounterVec("table", "authz", deletedStat), 0)

	err = p.purge(
		"pendingAuthorizations",
		fc.Now().Add(time.Hour),
		10,
		100,
		false,
		"",
		0,
	)
	test.AssertNotError(t, err, "purgeAuthzs failed")
	count, err = dbMap.SelectInt("SELECT COUNT(1) FROM pendingAuthorizations")
	test.AssertNotError(t, err, "dbMap.SelectInt failed")
	test.AssertEquals(t, count, int64(0))
	count, err = dbMap.SelectInt("SELECT COUNT(1) FROM challenges")
	test.AssertNotError(t, err, "dbMap.SelectInt failed")
	test.AssertEquals(t, count, int64(0))
	test.AssertEquals(t, test.CountCounterVec("table", "pendingAuthorizations", deletedStat), 3)
	test.AssertEquals(t, test.CountCounterVec("table", "authz", deletedStat), 0)

}

type mockDeleter struct{}

func (md *mockDeleter) Exec(query string, args ...interface{}) (sql.Result, error) {
	return nil, nil
}

func (md *mockDeleter) Select(i interface{}, query string, args ...interface{}) ([]interface{}, error) {
	return nil, errors.New("not implemented")
}

func TestMaxDPS(t *testing.T) {
	log := blog.UseMock()
	md := &mockDeleter{}
	p := &expiredAuthzPurger{db: md, log: log}
	work := make(chan string, 2)
	work <- "a"
	work <- "b"
	close(work)
	start := time.Now()
	p.deleteAuthorizations(work, 1, 1, "", "")
	took := time.Since(start)
	test.Assert(t, took >= time.Second*2, fmt.Sprintf("deleteAuthorizations was faster than expected. wanted: 2s, got: %s", took))
}
