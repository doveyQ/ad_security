#This script checks each domain to determine if the guest account is enabled in a domain
[CmdletBinding()]
param(
    [Parameter(Mandatory = "True")][string]$DomainName
)

$Global:self = @{
    ID = 12
    UUID = 'd14af45f-009c-4840-8e35-36a97c979a8c'
    Version = '1.124.1'
    CategoryID = 1
    ShortName = 'SI000012'
    Name = 'Built-in guest account is enabled'
    ScriptName = 'GuestAccountEnabled'
    Description = 'This indicator checks if the built-in Active Directory "guest" account is enabled. The guest account allows for accounts with no password access to the domain and is disabled in most AD environments.'
    Weight = 2
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 10
    LikelihoodOfCompromise = 'Attackers can take advantage of a guest account to enumerate open shares that are accessible to the "Everyone" setting, as is often the case. Additionally, attackers may utilize the limited access these accounts provide to conduct additional scanning for vulnerable users, shares and other network resources.'
    ResultMessage = 'Found {0} domains in which guest account is enabled.'
    Remediation = 'The guest account should be disabled to prevent the associated security risks.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'LastChanged'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'UserAccountControl'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Discovery', 'Reconnaissance') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Evict - Account Locking') },
        @{ Name = 'ANSSI'; Tags = @('vuln2_guest') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

$outputObjects = [System.Collections.ArrayList]@()

try {
    $DomainSID = (Get-ADDomain).DomainSID
    $GuestAccountSid = New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountGuestSid, $DomainSID)

    $GuestAccount = Get-ADUser -Filter { SID -eq $GuestAccountSid } -Properties Enabled, Modified | 
    Select-Object @{Name="DistinguishedName";Expression={$_.DistinguishedName}}, 
                  @{Name="Enabled";Expression={$_.Enabled}}, 
                  @{Name="Modified";Expression={$_.Modified.ToString('yyyy-MM-dd HH:mm:ss')}}

    $object = [PSCustomObject]@{
        DistinguishedName = $GuestAccount.DistinguishedName
        LastChanged = $GuestAccount.Modified
    }
    [void]$outputObjects.Add($object)

    if ($GuestAccount.Enabled -match "True") {
        $res = [PSCustomObject]@{
            Status         = "Failed"
            ResultMessage  = $self.ResultMessage -f $outputObjects.Count
            ResultObjects  = $outputObjects
            Remediation    = $self.Remediation
        }
    }
    else {
        $res = [PSCustomObject]@{
            Status        = "Passed"
            ResultMessage = "No guest account is enabled"
        }
    }
}
catch {
    $res = [PSCustomObject]@{
        Status  = "Error"
        Message = $_.Exception.Message
}}


return $res
