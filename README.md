# Sign and unsigned bitcoin transaction

### Steps:
1. Create a makefile to build project including trezor crypto library
2. Derive a public key and private key @ derivation path (m/44'/1'/0'/0/0) from the mnemonics
3. Generate unsigned transaction from the CLI tool 
4. Parse the unsigned transaction to bitcoin unsigned transaction structure 
5. Double hash the unsigned transaction byte array using sha256 
6. Sign the above digest(output of double hash) using private key corresponding to the input of unsigned transaction. 
7. Convert the signature into DER format and then into script sig 
8. Add the script sig inside the input of the transaction  

### Output:
See the output.txt file

### Steps to run locally:
1. clone the repo: ```git clone https://github.com/Adititiwari02/sign-bitcoin.git```
2. cd into the repo: ```cd sign-bitcoin```
3. run the command: ```make```
