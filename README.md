Get your hands on a private key.
First generate an Ethereum address and uncompressed public key:
```
cargo run generatekeypair <private key>
```
To sign anything using ECDSA(you can use the test image.jpg in the root directory too), first put the file in the root directory. You will also need to have the private and public key files created. Replace the <image.jpg> with your filename in the following command:
```
cargo run sign image.jpg <Private Key filename>
```
To verify the signature, first make sure the public key file has been created and replace <image.jpg> with your filename:
```
cargo run verify image.jpg <Public Key filename> ECDSA_Signature
```
It has a limitation, it is not able to sign or verify more than one file at the same time. You need to delete the "ECDSA_Signature" file before signing another file.
