module github.com/fandigunawan/mtls-pkcs11

go 1.19

require (
	github.com/ThalesIgnite/crypto11 v1.2.5
	github.com/miekg/pkcs11 v1.1.1
	golang.org/x/term v0.19.0
)

require (
	github.com/pkg/errors v0.9.1 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	golang.org/x/sys v0.19.0 // indirect
)

//replace github.com/ThalesIgnite/crypto11 => ./vendor/github.com/ThalesIgnite/crypto11
