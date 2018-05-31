# goEncrypt
encryption microservice written in Go

it works by passing in an encryption key and a message to encrypt formatted as JSON

it returns the encrypted message and a random nonce formatted as JSON

for decryption check out this repo:

https://github.com/devincheca/goDecrypt

try it for yourself at:

52.15.115.81:3000

with a POST request with the following JSON:

{
	"Key": "20284538c7d678e53bff67494907fb6791c2098c0edd275f69d159f215b9f91b",
	"Message": "newKeyTest"
}
