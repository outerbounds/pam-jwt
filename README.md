# Overview

`pam-jwt` is a PAM created to validate JWT tokens. It is mostly based on the code from https://github.com/salesforce/pam_oidc. This PAM takes in the issuer and audience we would like to match to the JWT tokens that will be passed in. It then validates these inputs match the claims in the token, that the token hasn't expired and has a valid signature before returning success.

## Usage

Example usage:

```
# inside /etc/pam.d/ssd  file
auth required /lib/security/pam_oidc.so issuer=https://issuer.example.com aud=https://foo.outerbounds.com/origin
```
