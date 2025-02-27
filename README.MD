# Simple web application with device (id) binding

* Two step registration / authentication
* Client - Server communication 
  * Asymmetric Key Encryption (RSA)
  * Challenge uuid to avoid replay attacks
  * HTTPS (self signed certificate)
  * Uses single-use [PASETO](https://github.com/paragonie/paseto) token to grant access to protected resource
  * Signature validation (using request payload)

## How to test
### Use postman collection
#### 1st access
1) Registration init
2) Registration complete
3) Access Protected resource

#### Following accesses
1) Authentication init
2) Authentication complete
3) Access Protected resource