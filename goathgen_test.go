/*
 * Copyright (c) 2017 Richard B Tilley <btilley@gatech.edu>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package goathgen_test

import "fmt"
import "testing"
import "github.com/62726164/goathgen"

var b32Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
var bincode int
var counter int64
var hexSecret = "3132333435363738393031323334353637383930"
var hotp string
var seconds int64
var timeStep int64 = 30
var unixEpoch int64
var totp string

/*
 * TestXa and TestXb test the Base32 encoded secret
 * TestXc and TestXd test the Hex encoded secret
 *
 * Tests 1 through 6 are from Appendix B of RFC 6238
 *     https://tools.ietf.org/html/rfc6238
 *
 * Tests 7 through 27 are from Appendix C of RFC 4226
 *     https://www.ietf.org/rfc/rfc4226.txt
 */

// Test 1

func Test1a(t *testing.T) {
	bincode = 1094287082
	seconds = 59
	totp = "287082"
	binaryValue := goathgen.ToBinary(goathgen.Totp(b32Secret, seconds, timeStep, unixEpoch))
	if binaryValue != bincode {
		t.Error("Expected bincode", bincode, "got", binaryValue)
	}
}

func Test1b(t *testing.T) {
	truncatedValue := goathgen.Truncate(goathgen.ToBinary(goathgen.Totp(b32Secret, seconds, timeStep, unixEpoch)))
	finalValue := fmt.Sprintf("%06d", truncatedValue)
	if finalValue != totp {
		t.Error("Expected totp", totp, "got", finalValue)
	}
}

func Test1c(t *testing.T) {
	binaryValue := goathgen.ToBinary(goathgen.Totp(hexSecret, seconds, timeStep, unixEpoch))
	if binaryValue != bincode {
		t.Error("Expected bincode", bincode, "got", binaryValue)
	}
}

func Test1d(t *testing.T) {
	truncatedValue := goathgen.Truncate(goathgen.ToBinary(goathgen.Totp(hexSecret, seconds, timeStep, unixEpoch)))
	finalValue := fmt.Sprintf("%06d", truncatedValue)
	if finalValue != totp {
		t.Error("Expected totp", totp, "got", finalValue)
	}
}

// Test 2

func Test2a(t *testing.T) {
	bincode = 907081804
	seconds = 1111111109
	totp = "081804"
	binaryValue := goathgen.ToBinary(goathgen.Totp(b32Secret, seconds, timeStep, unixEpoch))
	if binaryValue != bincode {
		t.Error("Expected bincode", bincode, "got", binaryValue)
	}
}

func Test2b(t *testing.T) {
	truncatedValue := goathgen.Truncate(goathgen.ToBinary(goathgen.Totp(b32Secret, seconds, timeStep, unixEpoch)))
	finalValue := fmt.Sprintf("%06d", truncatedValue)
	if finalValue != totp {
		t.Error("Expected totp", totp, "got", finalValue)
	}
}

func Test2c(t *testing.T) {
	binaryValue := goathgen.ToBinary(goathgen.Totp(hexSecret, seconds, timeStep, unixEpoch))
	if binaryValue != bincode {
		t.Error("Expected bincode", bincode, "got", binaryValue)
	}
}

func Test2d(t *testing.T) {
	truncatedValue := goathgen.Truncate(goathgen.ToBinary(goathgen.Totp(hexSecret, seconds, timeStep, unixEpoch)))
	finalValue := fmt.Sprintf("%06d", truncatedValue)
	if finalValue != totp {
		t.Error("Expected totp", totp, "got", finalValue)
	}
}

// Test 3

func Test3a(t *testing.T) {
	bincode = 414050471
	seconds = 1111111111
	totp = "050471"
	binaryValue := goathgen.ToBinary(goathgen.Totp(b32Secret, seconds, timeStep, unixEpoch))
	if binaryValue != bincode {
		t.Error("Expected bincode", bincode, "got", binaryValue)
	}
}

func Test3b(t *testing.T) {
	truncatedValue := goathgen.Truncate(goathgen.ToBinary(goathgen.Totp(b32Secret, seconds, timeStep, unixEpoch)))
	finalValue := fmt.Sprintf("%06d", truncatedValue)
	if finalValue != totp {
		t.Error("Expected totp", totp, "got", finalValue)
	}
}

func Test3c(t *testing.T) {
	binaryValue := goathgen.ToBinary(goathgen.Totp(hexSecret, seconds, timeStep, unixEpoch))
	if binaryValue != bincode {
		t.Error("Expected bincode", bincode, "got", binaryValue)
	}
}

func Test3d(t *testing.T) {
	truncatedValue := goathgen.Truncate(goathgen.ToBinary(goathgen.Totp(hexSecret, seconds, timeStep, unixEpoch)))
	finalValue := fmt.Sprintf("%06d", truncatedValue)
	if finalValue != totp {
		t.Error("Expected totp", totp, "got", finalValue)
	}
}

// Test 4

func Test4a(t *testing.T) {
	bincode = 689005924
	seconds = 1234567890
	totp = "005924"
	binaryValue := goathgen.ToBinary(goathgen.Totp(b32Secret, seconds, timeStep, unixEpoch))
	if binaryValue != bincode {
		t.Error("Expected bincode", bincode, "got", binaryValue)
	}
}

func Test4b(t *testing.T) {
	truncatedValue := goathgen.Truncate(goathgen.ToBinary(goathgen.Totp(b32Secret, seconds, timeStep, unixEpoch)))
	finalValue := fmt.Sprintf("%06d", truncatedValue)
	if finalValue != totp {
		t.Error("Expected totp", totp, "got", finalValue)
	}
}

func Test4c(t *testing.T) {
	binaryValue := goathgen.ToBinary(goathgen.Totp(hexSecret, seconds, timeStep, unixEpoch))
	if binaryValue != bincode {
		t.Error("Expected bincode", bincode, "got", binaryValue)
	}
}

func Test4d(t *testing.T) {
	truncatedValue := goathgen.Truncate(goathgen.ToBinary(goathgen.Totp(hexSecret, seconds, timeStep, unixEpoch)))
	finalValue := fmt.Sprintf("%06d", truncatedValue)
	if finalValue != totp {
		t.Error("Expected totp", totp, "got", finalValue)
	}
}

// Test 5

func Test5a(t *testing.T) {
	bincode = 2069279037
	seconds = 2000000000
	totp = "279037"
	binaryValue := goathgen.ToBinary(goathgen.Totp(b32Secret, seconds, timeStep, unixEpoch))
	if binaryValue != bincode {
		t.Error("Expected bincode", bincode, "got", binaryValue)
	}
}

func Test5b(t *testing.T) {
	truncatedValue := goathgen.Truncate(goathgen.ToBinary(goathgen.Totp(b32Secret, seconds, timeStep, unixEpoch)))
	finalValue := fmt.Sprintf("%06d", truncatedValue)
	if finalValue != totp {
		t.Error("Expected totp", totp, "got", finalValue)
	}
}

func Test5c(t *testing.T) {
	binaryValue := goathgen.ToBinary(goathgen.Totp(hexSecret, seconds, timeStep, unixEpoch))
	if binaryValue != bincode {
		t.Error("Expected bincode", bincode, "got", binaryValue)
	}
}

func Test5d(t *testing.T) {
	truncatedValue := goathgen.Truncate(goathgen.ToBinary(goathgen.Totp(hexSecret, seconds, timeStep, unixEpoch)))
	finalValue := fmt.Sprintf("%06d", truncatedValue)
	if finalValue != totp {
		t.Error("Expected totp", totp, "got", finalValue)
	}
}

// Test 6

func Test6a(t *testing.T) {
	bincode = 1465353130
	seconds = 20000000000
	totp = "353130"
	binaryValue := goathgen.ToBinary(goathgen.Totp(b32Secret, seconds, timeStep, unixEpoch))
	if binaryValue != bincode {
		t.Error("Expected bincode", bincode, "got", binaryValue)
	}
}

func Test6b(t *testing.T) {
	truncatedValue := goathgen.Truncate(goathgen.ToBinary(goathgen.Totp(b32Secret, seconds, timeStep, unixEpoch)))
	finalValue := fmt.Sprintf("%06d", truncatedValue)
	if finalValue != totp {
		t.Error("Expected totp", totp, "got", finalValue)
	}
}

func Test6c(t *testing.T) {
	binaryValue := goathgen.ToBinary(goathgen.Totp(hexSecret, seconds, timeStep, unixEpoch))
	if binaryValue != bincode {
		t.Error("Expected bincode", bincode, "got", binaryValue)
	}
}

func Test6d(t *testing.T) {
	truncatedValue := goathgen.Truncate(goathgen.ToBinary(goathgen.Totp(hexSecret, seconds, timeStep, unixEpoch)))
	finalValue := fmt.Sprintf("%06d", truncatedValue)
	if finalValue != totp {
		t.Error("Expected totp", totp, "got", finalValue)
	}
}

// Test 7

func Test7a(t *testing.T) {
	bincode = 1284755224
	counter = 0
	hotp = "755224"
	binaryValue := goathgen.ToBinary(goathgen.Hotp(b32Secret, counter))
	if binaryValue != bincode {
		t.Error("Expected bincode", bincode, "got", binaryValue)
	}
}

func Test7b(t *testing.T) {
	truncatedValue := goathgen.Truncate(goathgen.ToBinary(goathgen.Hotp(b32Secret, counter)))
	finalValue := fmt.Sprintf("%06d", truncatedValue)
	if finalValue != hotp {
		t.Error("Expected hotp", hotp, "got", finalValue)
	}
}

func Test7c(t *testing.T) {
	binaryValue := goathgen.ToBinary(goathgen.Hotp(hexSecret, counter))
	if binaryValue != bincode {
		t.Error("Expected bincode", bincode, "got", binaryValue)
	}
}

func Test7d(t *testing.T) {
	truncatedValue := goathgen.Truncate(goathgen.ToBinary(goathgen.Hotp(hexSecret, counter)))
	finalValue := fmt.Sprintf("%06d", truncatedValue)
	if finalValue != hotp {
		t.Error("Expected hotp", hotp, "got", finalValue)
	}
}

// Test 8

func Test8a(t *testing.T) {
	bincode = 1094287082
	counter = 1
	hotp = "287082"
	binaryValue := goathgen.ToBinary(goathgen.Hotp(b32Secret, counter))
	if binaryValue != bincode {
		t.Error("Expected bincode", bincode, "got", binaryValue)
	}
}

func Test8b(t *testing.T) {
	truncatedValue := goathgen.Truncate(goathgen.ToBinary(goathgen.Hotp(b32Secret, counter)))
	finalValue := fmt.Sprintf("%06d", truncatedValue)
	if finalValue != hotp {
		t.Error("Expected hotp", hotp, "got", finalValue)
	}
}

func Test8c(t *testing.T) {
	binaryValue := goathgen.ToBinary(goathgen.Hotp(hexSecret, counter))
	if binaryValue != bincode {
		t.Error("Expected bincode", bincode, "got", binaryValue)
	}
}

func Test8d(t *testing.T) {
	truncatedValue := goathgen.Truncate(goathgen.ToBinary(goathgen.Hotp(hexSecret, counter)))
	finalValue := fmt.Sprintf("%06d", truncatedValue)
	if finalValue != hotp {
		t.Error("Expected hotp", hotp, "got", finalValue)
	}
}

// Test 9

func Test9a(t *testing.T) {
	bincode = 137359152
	counter = 2
	hotp = "359152"
	binaryValue := goathgen.ToBinary(goathgen.Hotp(b32Secret, counter))
	if binaryValue != bincode {
		t.Error("Expected bincode", bincode, "got", binaryValue)
	}
}

func Test9b(t *testing.T) {
	truncatedValue := goathgen.Truncate(goathgen.ToBinary(goathgen.Hotp(b32Secret, counter)))
	finalValue := fmt.Sprintf("%06d", truncatedValue)
	if finalValue != hotp {
		t.Error("Expected hotp", hotp, "got", finalValue)
	}
}

func Test9c(t *testing.T) {
	binaryValue := goathgen.ToBinary(goathgen.Hotp(hexSecret, counter))
	if binaryValue != bincode {
		t.Error("Expected bincode", bincode, "got", binaryValue)
	}
}

func Test9d(t *testing.T) {
	truncatedValue := goathgen.Truncate(goathgen.ToBinary(goathgen.Hotp(hexSecret, counter)))
	finalValue := fmt.Sprintf("%06d", truncatedValue)
	if finalValue != hotp {
		t.Error("Expected hotp", hotp, "got", finalValue)
	}
}
