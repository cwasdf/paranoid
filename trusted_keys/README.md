# Trusted Plugin Keys

This directory holds public keys used to verify plugin manifest signatures.

## Generate a keypair

```bash
# Generate an ECDSA P-256 private key
openssl ecparam -genkey -name prime256v1 -noout -out paranoid-publisher-01.pem

# Extract the public key
openssl ec -in paranoid-publisher-01.pem -pubout -out paranoid-publisher-01.pub

# Move the public key here
mv paranoid-publisher-01.pub trusted_keys/

# Keep the private key secure — never commit it
# Store paranoid-publisher-01.pem in a safe location outside this repo
```

## Sign a plugin manifest

```bash
# From the plugin directory:
openssl dgst -sha256 -sign /path/to/paranoid-publisher-01.pem \
  -out manifest.sig manifest.json
```

## Verify a signature manually

```bash
openssl dgst -sha256 -verify trusted_keys/paranoid-publisher-01.pub \
  -signature plugins/write-plugin/manifest.sig \
  plugins/write-plugin/manifest.json
```

## Update the plugin executable hash

After building/modifying a plugin executable, update the hash in its manifest:

```bash
shasum -a 256 plugins/write-plugin/plugin | awk '{print $1}'
# Paste the output into manifest.json under hash.executable
```

Then re-sign the manifest.
