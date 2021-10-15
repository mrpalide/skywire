// Code generated by mockery v1.0.0. DO NOT EDIT.

package appserver

import (
	net "net"

	mock "github.com/stretchr/testify/mock"

	appcommon "github.com/skycoin/skywire/pkg/app/appcommon"
)

// MockProcManager is an autogenerated mock type for the ProcManager type
type MockProcManager struct {
	mock.Mock
}

// Addr provides a mock function with given fields:
func (_m *MockProcManager) Addr() net.Addr {
	ret := _m.Called()

	var r0 net.Addr
	if rf, ok := ret.Get(0).(func() net.Addr); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(net.Addr)
		}
	}

	return r0
}

// Close provides a mock function with given fields:
func (_m *MockProcManager) Close() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ConnectionsSummary provides a mock function with given fields: appName
func (_m *MockProcManager) ConnectionsSummary(appName string) ([]ConnectionSummary, error) {
	ret := _m.Called(appName)

	var r0 []ConnectionSummary
	if rf, ok := ret.Get(0).(func(string) []ConnectionSummary); ok {
		r0 = rf(appName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]ConnectionSummary)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(appName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DetailedStatus provides a mock function with given fields: appName
func (_m *MockProcManager) DetailedStatus(appName string) (string, error) {
	ret := _m.Called(appName)

	var r0 string
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(appName)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(appName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ProcByName provides a mock function with given fields: appName
func (_m *MockProcManager) ProcByName(appName string) (*Proc, bool) {
	ret := _m.Called(appName)

	var r0 *Proc
	if rf, ok := ret.Get(0).(func(string) *Proc); ok {
		r0 = rf(appName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*Proc)
		}
	}

	var r1 bool
	if rf, ok := ret.Get(1).(func(string) bool); ok {
		r1 = rf(appName)
	} else {
		r1 = ret.Get(1).(bool)
	}

	return r0, r1
}

// Range provides a mock function with given fields: next
func (_m *MockProcManager) Range(next func(string, *Proc) bool) {
	_m.Called(next)
}

// SetDetailedStatus provides a mock function with given fields: appName, status
func (_m *MockProcManager) SetDetailedStatus(appName string, status string) error {
	ret := _m.Called(appName, status)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(appName, status)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Start provides a mock function with given fields: conf
func (_m *MockProcManager) Start(conf appcommon.ProcConfig) (appcommon.ProcID, error) {
	ret := _m.Called(conf)

	var r0 appcommon.ProcID
	if rf, ok := ret.Get(0).(func(appcommon.ProcConfig) appcommon.ProcID); ok {
		r0 = rf(conf)
	} else {
		r0 = ret.Get(0).(appcommon.ProcID)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(appcommon.ProcConfig) error); ok {
		r1 = rf(conf)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Stats provides a mock function with given fields: appName
func (_m *MockProcManager) Stats(appName string) (AppStats, error) {
	ret := _m.Called(appName)

	var r0 AppStats
	if rf, ok := ret.Get(0).(func(string) AppStats); ok {
		r0 = rf(appName)
	} else {
		r0 = ret.Get(0).(AppStats)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(appName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Stop provides a mock function with given fields: appName
func (_m *MockProcManager) Stop(appName string) error {
	ret := _m.Called(appName)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(appName)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Wait provides a mock function with given fields: appName
func (_m *MockProcManager) Wait(appName string) error {
	ret := _m.Called(appName)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(appName)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
