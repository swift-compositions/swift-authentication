# swift-authentication

Use this package on a server that signs people in with more than one factor. It covers a pending sign-in between the first and second factor, what a session records so a sensitive action can ask for a fresh factor (step-up), recovery codes, an authenticator app, and passkey challenges. It holds values and rules only. Time is a `Time.Instant` and randomness a `RandomNumberGenerator`, both passed in, and the server stores what these values say to store. Passkey ceremonies themselves are checked with swift-w3c-webauthn, and codes with swift-rfc-6238.

## Laws

- Every secret handed to a client is an `Authentication.Token` of 32 random bytes, written as 43 base64url characters. Only its `Authentication.Digest`, the SHA-256, is meant to be stored. Comparing a secret with a digest takes the same time wherever they differ.
- A first factor (an email code or a provider) that needs a second gives an `Authentication.Pending`, never a session. It lasts five minutes and allows five failed attempts. It is tied to the browser that began it by a second token, and only a second factor (a passkey, an authenticator app or a recovery code) completes it.
- `Authentication.Requirement.passkey` is met only by a passkey. `.secondFactor` is met by a passkey, or by a first factor together with a second. `.oneFactor` is met by any factor.
- `Authentication.Grant.isFresh(at:window:)` is true within five minutes after a second factor or a passkey, by default. A first factor never makes a session fresh.
- Recovery codes come ten at a time. Each is 80 random bits written `abcd-efgh-ijkl-mnop`, works once, and is matched regardless of case, spaces, hyphens, and 0 or 1 typed for o or l. Every stored digest is compared on each attempt.
- An authenticator app is RFC 6238 with HMAC-SHA-1, 6 digits, 30-second steps and a 20-byte secret, accepting one step either side. `verify` returns the step it accepted and refuses any step not after the last one accepted, so no code works twice. Its secret has to be readable by the server, so it is stored as it is, not as a digest.
- `uri(issuer:account:)` writes the `otpauth://totp/` address of Google's Key Uri Format, with the label and issuer percent-encoded as RFC 3986 unreserved characters.
- A passkey challenge lasts five minutes. Using it only once is the store's job.
- The contracts a store must meet will be declared with `@Interface` once swift-interface is in the Institute.
