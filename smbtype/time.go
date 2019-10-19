package smbtype

import (
	"time"
)

// Time interprets a slice of 8 bytes as a FILETIME struct and returns
// its value as a time.Time.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/2c57429b-fdd4-488f-b5fc-9e4cf020fcdf
func Time(v []byte) time.Time {
	// Combine the low and high 32-bit values into a single 64-bit value
	low := Uint32(v[0:4])
	high := Uint32(v[4:8])
	nsec := int64(high)<<32 | int64(low)

	// Sepcial handling for zeroed time
	if nsec == 0 {
		return time.Time{}
	}

	// Convert the epoch:
	// 100 ns intervals since 00:00:00 UTC, January 1, 1601
	// 100 ns intervals since 00:00:00 UTC, January 1, 1970
	nsec -= 116444736000000000

	// Convert 100 nanosecond intervals to nanoseconds
	nsec *= 100

	// Convert to time.Time
	return time.Unix(0, nsec)
}

// PutTime writes a slice of 8 bytes as a FILETIME struct with the value of t.
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/2c57429b-fdd4-488f-b5fc-9e4cf020fcdf
func PutTime(v []byte, t time.Time) {
	// Sepcial handling for zeroed time
	if t.IsZero() {
		v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7] = 0, 0, 0, 0, 0, 0, 0, 0
		return
	}

	// Convert to nanoseconds
	nsec := t.UnixNano()

	// Convert nanoseconds to 100 nanosecond intervals
	nsec /= 100

	// Convert the epoch:
	// 100 ns intervals since 00:00:00 UTC, January 1, 1970
	// 100 ns intervals since 00:00:00 UTC, January 1, 1601
	nsec += 116444736000000000

	// Write the 64-bit value as low and high 32-bit values
	PutUint32(v[0:4], uint32(nsec))
	PutUint32(v[4:8], uint32(nsec>>32))
}
