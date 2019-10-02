/*
 * Copyright (c) 2016 Richard B Tilley <btilley@gatech.edu>
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

// Package goathgen provides simple Totp functionality per RFC 6238.
package goathgen

import "bytes"
import "crypto/sha1"
import "crypto/hmac"
import "encoding/base32"
import "encoding/binary"
import "encoding/hex"
import "fmt"
import "log"
import "strings"

// Debug should be set to true to see verbose debug information.
var Debug = false

// Hotp calculates and returns the hotp as a byte slice per RFC 4226.
func Hotp(secret string, counter int64) []byte {

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, counter)
	if err != nil {
		log.Fatal(err)
	}

	// ToUpper needed here for base32
	encoded := []byte(strings.ToUpper(secret))
	decoded := make([]byte, 64)

	var numBytes int

	numBytes, err = hex.Decode(decoded, encoded)
	if err != nil {
		numBytes, err = base32.StdEncoding.Decode(decoded, encoded)
		if err != nil {
			log.Fatal("The secret must be hex or base32 encoded!")
		}
	}

	mac160 := hmac.New(sha1.New, decoded)
	mac160.Write(buf.Bytes())

	if Debug {
		fmt.Println("----- hotp -----")
		fmt.Printf("counter: %d\n", counter)
		fmt.Printf("encoded secret: %s\n", secret)
		fmt.Printf("encoded array: %v\n", encoded)
		fmt.Printf("encoded len: %v\n", len(encoded))
		fmt.Printf("decoded array: %v\n", decoded)
		fmt.Printf("decoded len: %v\n", len(decoded))
		fmt.Printf("decoded secret: %s\n", decoded[:numBytes])
		fmt.Printf("mac160: %v\n", mac160.Sum(nil))
		fmt.Printf("mac160 len: %v\n", mac160.Size())
		fmt.Println("----- hotp -----")
	}

	return mac160.Sum(nil)
}

// Totp calculates and returns the totp as a byte slice per rfc 6238.
func Totp(secret string, timeNow int64, timeStep int64, unixEpoch int64) []byte {

	var timeCounter int64
	timeCounter = (timeNow - unixEpoch) / timeStep

	if Debug {
		fmt.Println("----- totp -----")
		fmt.Printf("timeNow: %d\n", timeNow)
		fmt.Printf("timeStep: %d\n", timeStep)
		fmt.Printf("unixEpoch: %d\n", unixEpoch)
		fmt.Printf("timeCounter: %d\n", timeCounter)
		fmt.Println("----- totp -----")
	}

	return Hotp(secret, timeCounter)
}

// ToBinary returns the bincode as an integer.
func ToBinary(hmac []byte) int {
	offset := hmac[len(hmac)-1] & 0xf

	bincode := int(((int(hmac[offset]) & 0x7f) << 24) |
		((int(hmac[offset+1]) & 0xff) << 16) |
		((int(hmac[offset+2]) & 0xff) << 8) |
		((int(hmac[offset+3]) & 0xff) << 0))

	if Debug {
		fmt.Println("----- to_binary -----")
		fmt.Printf("len: %d\n", len(hmac))
		fmt.Printf("offset: %d\n", offset)
		fmt.Printf("bincode: %d\n", bincode)
		fmt.Println("----- to_binary -----")
	}

	return bincode
}

// Truncate returns the truncated bincode as an integer.
func Truncate(bincode int) int {
	moduloBy := 1000000

	otp := bincode % moduloBy

	if Debug {
		fmt.Println("--- truncate ---")
		fmt.Printf("bincode: %d\n", bincode)
		fmt.Printf("modulo by: %d\n", moduloBy)
		fmt.Printf("otp: %d\n", otp)
		fmt.Println("--- truncate ---")
	}

	return otp
}
