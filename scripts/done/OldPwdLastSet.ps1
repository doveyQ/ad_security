# This script looks for users that haven't changed their password in a while

[CmdletBinding()]
param(
    [Parameter(Mandatory = 'True')][string]$DomainName
)

$Global:self = @{
    ID = 37
    UUID = '4ef13866-3af9-477a-84d4-d2d7e39f3c0f'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000037'
    Name = 'Users with old passwords'
    ScriptName = 'OldPwdLastSet'
    Description = 'This indicator looks for user accounts whose password has not changed in over 180 days. This could make these account ripe for password guessing attacks.'
    Weight = 2
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 2
    LikelihoodOfCompromise = 'Stale passwords that aren''t changed over a long period of time and are not supported by multi-factor authentication are ripe targets for attackers. These present opportunities for attackers to move laterally through the environment or elevate privileges.'
    ResultMessage = 'The following {0} users were returned. Note the following: users with DaysSinceLastSet and ReplicationMetadata higher than {1} days have not changed passwords in over {1} days. Users with PwdLastSet over {1} days and ReplicationMetadata is N/A - permission was denied to read these users'' metadata. These users may be using smartcard for interactive logon instead of passwords - in which case it is ok that their passwords have not changed.'
    Remediation = 'Ensure that users change their password at least once every 6 months.<br><br>MITRE D3fend based on the reference: <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf" target="_blank">NIST.SP.800-63-3</a>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DaysSinceLastSet'; Type = 'Integer'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'PasswordLastSet'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'SamAccountName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access', 'Persistence') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - Strong Password Policy') }
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
    $thresholdDate = (Get-Date).AddDays(-90)

    $outputObjects = Get-ADUser -Filter { PasswordLastSet -lt $thresholdDate} -Property PasswordLastSet, LastLogonTimeStamp |         
        Select-Object @{Name='Active'; Expression={($_.LastLogonTimeStamp -gt (Get-Date).AddDays(-45))}}, 
            @{Name='DaysSinceLastSet'; Expression={(New-TimeSpan -Start $_.PasswordLastSet -End (Get-Date)).Days}}, 
            DistinguishedName, 
            LastLogonTimeStamp, 
            PasswordLastSet

    if ($outputObjects.Count -gt 0) {
        $res = [PSCustomObject]@{
            Status        = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count, 90
            ResultObjects = $outputObjects
            Remediation   = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status        = 'Passed'
            ResultMessage = "No users found with passwords unchanged for 90 days."
        }
    }
}
catch {
    $res = [PSCustomObject]@{
        Status        = 'Error'
        ResultMessage = $_.Exception.Message
    }
}
return $res