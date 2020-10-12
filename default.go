package passlib

import (
	"fmt"
	"github.com/al45tair/passlib/abstract"
	"github.com/al45tair/passlib/hash/argon2"
	"github.com/al45tair/passlib/hash/bcrypt"
	"github.com/al45tair/passlib/hash/bcryptsha256"
	"github.com/al45tair/passlib/hash/pbkdf2"
	"github.com/al45tair/passlib/hash/scrypt"
	"github.com/al45tair/passlib/hash/sha2crypt"
	"time"
)

// This is the first and default set of defaults used by passlib. It prefers
// scrypt-sha256. It is now obsolete.
const Defaults20160922 = "20160922"

// This is the most up-to-date set of defaults preferred by passlib. It prefers
// Argon2i. You must opt into it by calling UseDefaults at startup.
const Defaults20180601 = "20180601"

// This value, when passed to UseDefaults, causes passlib to always use the
// very latest set of defaults. DO NOT use this unless you are sure that
// opportunistic hash upgrades will not cause breakage for your application
// when future versions of passlib are released. See func UseDefaults.
const DefaultsLatest = "latest"

// Scheme names
var schemes = map[string]abstract.Scheme{
	"argon2":        argon2.Crypter,
	"scrypt-sha256": scrypt.SHA256Crypter,
	"sha256-crypt":  sha2crypt.Crypter256,
	"sha512-crypt":  sha2crypt.Crypter512,
	"bcrypt":        bcrypt.Crypter,
	"bcrypt-sha256": bcryptsha256.Crypter,
	"pbkdf2-sha256": pbkdf2.SHA256Crypter,
	"pbkdf2-sha512": pbkdf2.SHA512Crypter,
	"pbkdr2-sha1":   pbkdf2.SHA1Crypter,
}

// Convert a scheme name into a scheme
func SchemeFromName(schemeName string) abstract.Scheme {
	scheme, ok := schemes[schemeName]
	if !ok {
		return nil
	}
	return scheme
}

// Convert a list of scheme names into a list of schemes
func SchemesFromNames(schemeNames []string) ([]abstract.Scheme, error) {
	result := make([]abstract.Scheme, len(schemeNames))
	for n, schemeName := range schemeNames {
		scheme, ok := schemes[schemeName]
		if !ok {
			return nil, fmt.Errorf("unknown scheme %q", schemeName)
		}
		result[n] = scheme
	}
	return result, nil
}

// Default schemes as of 2016-09-22.
var defaultSchemes20160922 = []abstract.Scheme{
	scrypt.SHA256Crypter,
	argon2.Crypter,
	sha2crypt.Crypter512,
	sha2crypt.Crypter256,
	bcryptsha256.Crypter,
	pbkdf2.SHA512Crypter,
	pbkdf2.SHA256Crypter,
	bcrypt.Crypter,
	pbkdf2.SHA1Crypter,
}

// Default schemes as of 2018-06-01.
var defaultSchemes20180601 = []abstract.Scheme{
	argon2.Crypter,
	scrypt.SHA256Crypter,
	sha2crypt.Crypter512,
	sha2crypt.Crypter256,
	bcryptsha256.Crypter,
	pbkdf2.SHA512Crypter,
	pbkdf2.SHA256Crypter,
	bcrypt.Crypter,
	pbkdf2.SHA1Crypter,
}

// The default schemes, most preferred first. The first scheme will be used to
// hash passwords, and any of the schemes may be used to verify existing
// passwords. The contents of this value may change with subsequent releases.
//
// If you want to change this, set DefaultSchemes to a slice to an
// abstract.Scheme array of your own construction, rather than mutating the
// array the slice points to.
//
// To see the default schemes used in the current release of passlib, see
// default.go. See also the UseDefaults function for more information on how
// the list of default schemes is determined. The default value of
// DefaultSchemes (the default defaults) won't change; you need to call
// UseDefaults to allow your application to upgrade to newer hashing schemes
// (or set DefaultSchemes manually, or create a custom context with its own
// schemes set).
var DefaultSchemes []abstract.Scheme

func init() {
	DefaultSchemes = defaultSchemes20160922
}

// It is strongly recommended that you DO NOT use this function, and that
// you instead always create a passlib.Context and call the methods of that
// struct, because the latter does not involve global behaviour.
func UseDefaults(date string) error {
	schemes, err := DefaultSchemesFromDate(date)
	if err != nil {
		return err
	}

	DefaultSchemes = schemes
	return nil
}

// Return the schemes corresponding to the specified date string
func DefaultSchemesFromDate(date string) ([]abstract.Scheme, error) {
	if date == "latest" {
		return defaultSchemes20180601, nil
	}

	t, err := time.ParseInLocation("20060102", date, time.UTC)
	if err != nil {
		return nil, fmt.Errorf("invalid time string passed to passlib.UseDefaults: %q", date)
	}

	if !t.Before(time.Date(2016, 9, 22, 0, 0, 0, 0, time.UTC)) {
		return defaultSchemes20180601, nil
	}

	return defaultSchemes20160922, nil
}

// Set the default schemes using a list of scheme names, rather than a date
func UseDefaultSchemes(schemeNames []string) error {
	schemes, err := SchemesFromNames(schemeNames)
	if err != nil {
		return err
	}

	DefaultSchemes = schemes
	return nil
}
