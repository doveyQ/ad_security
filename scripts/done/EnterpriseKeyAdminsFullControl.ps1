[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$DomainName
)

$Global:self = @{
    ID = 56
    UUID = 'ec4a80dc-bec8-4557-b19f-cc3d15ed5517'
    Version = '1.124.1'
    CategoryID = 1
    ShortName = 'SI000056'
    Name = 'Enterprise Key Admins with full access to domain'
    ScriptName = 'EnterpriseKeyAdminsFullControl'
    Description = 'This indicator looks for evidence of a bug in certain versions of Windows Server 2016 Adprep that granted undue access to the Enterprise Key Admins group.'
    Weight = 7
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 7
    LikelihoodOfCompromise = 'This issue was corrected in a subsequent release of Server 2016 and may not exist in your environment, but checking for it is definitely warranted, since it grants this group the ability to replicate all changes from AD (DCSync Attack).'
    ResultMessage = 'Found {0} domains where the Enterprise Key Admins group has full access.'
    Remediation = 'Ensure that users don''t have unnecessary permissions.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access', 'Lateral Movement', 'Privilege Escalation') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - User Account Permissions') },
        @{ Name = 'ANSSI'; Tags = @('vuln2_adupdate_bad') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$outputObjects = @()

try {
    $domainParts = $DomainName -split '\.'    
    $domainPart1 = $domainParts[0] | ForEach-Object { $_.ToUpper() }

    $adObjects = Get-ADObject -Filter * -Properties ntSecurityDescriptor

    foreach ($obj in $adObjects) {
        $accessList = $obj.ntSecurityDescriptor.Access

        if ($null -ne $accessList) {
            foreach ($access in $accessList) {
                if ($access.IdentityReference -eq "$($domainPart1)\Enterprise Key Admins" -and $access.ActiveDirectoryRights -contains 'GenericAll') {
                    $outputObjects += [PSCustomObject]@{
                        DistinguishedName = $obj.DistinguishedName
                        IdentityReference = $access.IdentityReference
                        Permissions = $access.ActiveDirectoryRights
                    }
                }
            }
        }
    }

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No objects found with GenericAll permissions for the Enterprise Key Admins."
        }
    }
}
catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ErrorMessage = $_.Exception.Message
    }
}

return $res
