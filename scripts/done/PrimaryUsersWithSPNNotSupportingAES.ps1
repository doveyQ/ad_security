[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName
)

$Global:self = @{
    ID = 152
    UUID = 'b608276e-3849-419d-bc34-6e5a362b3e79'
    Version = '1.124.1'
    CategoryID = 5
    ShortName = 'SI000152'
    Name = 'Primary users with SPN not supporting AES encryption on Kerberos'
    ScriptName = 'PrimaryUsersWithSPNNotSupportingAES'
    Description = 'This indicator shows all Primary users with SPNs that do not support AES-128 or AES-256 encryption type.'
    Weight = 5
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 5
    LikelihoodOfCompromise = 'AES encryption is stronger than RC4 encryption. Configuring primary users with SPN to support AES encryption will not mitigate attacks such as Kerberoasting but does force AES by default, meaning that it is possible to monitor for encryption downgrade attacks to RC4 (Kerberoasting attacks)'
    ResultMessage = 'Found {0} Primary users with SPN not supporting AES encryption'
    Remediation = 'Best practice is to enable AES encryption support on service accounts. Follow Microsoft guidance <a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos" target="_blank">here.</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'SamAccountName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'ServicePrincipalName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation', 'Credential Access') },
        @{ Name = 'ANSSI'; Tags = @('vuln3_kerberos_properties_encryption') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.5'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$outputObjects = [System.Collections.ArrayList]@()
$domain = Get-ADDomain -Identity $DomainName

$filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"

try {
    $results = Get-ADUser -LDAPFilter $filter -SearchBase $domain.DistinguishedName -SearchScope Subtree -Properties msDS-SupportedEncryptionTypes, servicePrincipalName, SamAccountName
    
    if ($results) {
        foreach ($result in $results) {
            if ($result.SamAccountName -ne "krbtgt") {
                $supportedEncryptionTypes = if ($result.PSObject.Properties["msDS-SupportedEncryptionTypes"]) {
                    $result."msDS-SupportedEncryptionTypes" 
                } 

                if (($supportedEncryptionTypes -ne 16) -and ($supportedEncryptionTypes -ne 8)){
                    
                    $thisOutput = [PSCustomObject][Ordered]@{
                        DistinguishedName = $result.DistinguishedName
                        ServicePrincipalName = ($result.ServicePrincipalName -join "; ")
                        SamAccountName = $result.SamAccountName
                        SupportedEncryptionTypes = $supportedEncryptionTypes
                    }
                    [void]$outputObjects.Add($thisOutput)
                }

            }
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count 
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count 
        }
    }
}
catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res