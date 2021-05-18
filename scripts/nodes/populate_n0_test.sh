#!/bin/bash
#
# In order to run this script, this public key / seed pair needs coins and a profile:
#
#     PK: tBCKUx4kf4PgXZ7CFauanC2b5qdPNiMFUDWSnW3uN8pQGxFnghuEPd
#
#     SEED (NOT SECURE - DO NOT USE OUTSIDE OF TESTING): 
#          garment dilemma tuna glory table route radio glance river board present warm

count=1
while [ $count -le 100 ]
do
  curl 'http://localhost:18001/submit-post?shared_secret=abcdef' \
    -H 'Connection: keep-alive' \
    -H 'Accept: application/json, text/plain, */*' \
    -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36' \
    -H 'Content-Type: application/json' \
    -H 'Origin: http://localhost:4200' \
    -H 'Sec-Fetch-Site: same-site' \
    -H 'Sec-Fetch-Mode: cors' \
    -H 'Sec-Fetch-Dest: empty' \
    -H 'Accept-Language: en-US,en;q=0.9' \
    --data-binary '{"UpdaterPublicKeyBase58Check":"tBCKUx4kf4PgXZ7CFauanC2b5qdPNiMFUDWSnW3uN8pQGxFnghuEPd","PostHashHexToModify":"","ParentStakeID":"","Title":"","BodyObj":{"Body":"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Fringilla est ullamcorper eget nulla facilisi etiam dignissim diam quis. Sit amet nulla facilisi morbi tempus iaculis urna id volutpat. Nulla at volutpat diam ut venenatis tellus in metus. Quam viverra orci sagittis eu volutpat odio."},"Sub":"","CreatorBasisPoints":0,"StakeMultipleBasisPoints":12500,"IsHidden":false,"MinFeeRateNanosPerKB":1000,"SeedInfo":{"HasPassword":false,"EncryptedSeedHex":"04fee8a54982dde7faabc3d6d5546fe1bc6767569726cd7cad8b6941eecb0d4ebe2f69295e0f430ec3a72cf947617b1a8f33270d6d57320879045d6e699bc75b73c0c4407f7a5528163caf7cc124bbf7af8ed13ff070cdd05baad056e023a3a6fbdbe010e918eee5e41310b5baa14a1d037276f3fbd33382cafe25991d11c019aeb3cf8d828af65bfd3c87b545efa7ab7a421fe05b7f82b5a42e8bee55d0bb32d2fb97008ecf6bd5b309c8bc82708b7757","PwSaltHex":"e6fe043874c6e829b6c8b90a88b669f0d610ab54b010e7faecf7f623430a2922","Pbkdf2Iterations":10,"BtcDepositAddress":"mxmd3yx8MkTSQ9J7KmBzvTeTCvsU2ckX26","IsTestnet":true},"Password":"","Sign":true,"Validate":true,"Broadcast":true}' \
    --compressed
  ((count++))
done

echo All done!
