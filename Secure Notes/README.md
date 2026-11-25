
## Proof of Concept: Offline PIN Recovery

After identifying the key-derivation logic and bundled cryptographic
parameters, I created a Kotlin Android application to reproduce the
decryption process and test every four-digit PIN.

I copied the ciphertext, salt, and IV from `config.properties` into
the PoC. The code excerpt below uses placeholders for those values;
running it requires replacing them with the extracted Base64 strings.

### Enumerating PIN Candidates

The PoC iterates from `0000` through `9999`, preserving leading zeros
with `String.format()`:

```kotlin
for (i in 0..9999) {
    val pin = String.format(Locale.US, "%04d", i)
    val secret = decryptSecret(pin)

    if (secret != null) {
        println("Valid PIN: $pin, Secret : $secret")
    }
}
```

For each candidate, the application:

1. Derives a 256-bit AES key using `PBKDF2WithHmacSHA1`, the extracted
   salt, and 10,000 iterations.
2. Initializes `AES/CBC/PKCS5Padding` with that key and the extracted IV.
3. Attempts to decrypt the bundled ciphertext.
4. Converts the resulting bytes to a UTF-8 string and logs the output
   when no exception occurs.

This approach runs locally in the PoC. It does not require a provider
query for each PIN attempt.

### Handling False Positives

Several incorrect PINs produced output containing unreadable characters.
The PoC logged these as “Valid PIN” because its success condition only
checked whether decryption returned a non-null string.

An incorrect key can occasionally produce bytes with acceptable padding.
Converting those bytes to a UTF-8 string does not establish that the
plaintext is correct.

I therefore treated these outputs as candidates and inspected them for
a recognizable lab flag.

### Recovered PIN and Secret

The candidate `2580` produced the following readable result:

```text
Valid PIN: 2580, Secret : CTF{D1d_y0u_gu3ss_1t!?}
```

![Logcat showing false-positive candidates and PIN 2580 producing the readable flag](screenshots/offline-pin-recovery.png)

This result demonstrates recovery of the secret by enumerating the
four-digit PIN space against the extracted ciphertext.

### Scope of This Result

Although the PoC also contains a `readContentProvider()` method, that
method was not invoked in this run. The screenshot demonstrates offline
decryption, rather than successful access through the exported provider.

## Demonstrated Impact

A researcher with access to the APK can extract the encrypted secret
and the parameters needed to test PIN candidates locally.

Because the key is derived from a four-digit PIN, the candidate space
contains only 10,000 possibilities. The configured PBKDF2 iterations
increase the cost per attempt but do not increase the PIN's entropy.

In this test, enumerating that space recovered the readable lab flag
without interacting with the original application's PIN-entry interface.
