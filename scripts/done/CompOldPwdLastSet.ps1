# This script checks for computer objects that haven't changed their password in 90 days

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$DomainName
)

$Global:self = @{
    ID = 59
    UUID = '07362c0e-e675-4451-9d09-65ca46ab43a3'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000059'
    Name = 'Computers with password last set over 90 days ago'
    ScriptName = 'CompOldPwdLastSet'
    Description = 'This indicator looks for computer accounts that have not rotated their passwords in the last 90 days. These passwords should be changed automatically every 30 days by default.'
    Weight = 6
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 6
    LikelihoodOfCompromise = 'Computer accounts should automatically rotate their passwords every 30 days as they are prime targets for attackers. Objects that are not doing this could show evidence of tampering.'
    ResultMessage = 'Found {0} computers whose password has not changed in the last {1} days.'
    Remediation = 'Computers should change their passwords every 30 days, it should be investigated why they did not. Here are some suggestions to do to prevent it in the future:
        <li>Password Rotation: For each affected computer, initiate a manual password rotation process. Ensure that the new passwords are strong and comply with your organization''s password policy.</li>
        <li>Automated Password Rotation: Implement an automated password rotation solution or policy that aligns with industry best practices. Passwords should ideally be rotated every 30 days or according to your organization''s security policies.</li>
        <li>Review Password Policies: Evaluate your organization''s password policies to ensure they enforce regular password rotations. Adjust these policies as needed to meet your security requirements.</li>
        <br></br>
        Note: The ''Active'' column shows if the account was active in the past 45 days.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'Active'; Type = 'Boolean'; IsCollection = $false },
        @{ Name = 'DaysSinceLastSet'; Type = 'Integer'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'LastLogonTimeStamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'PasswordLastSet'; Type = 'DateTime'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Credential Access') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - Strong Password Policy') },
        @{ Name = 'ANSSI'; Tags = @('vuln2_password_change_server_no_change_90') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}

try {
    $thresholdDate = (Get-Date).AddDays(-90)

    $outputObjects = Get-ADComputer -Filter { PasswordLastSet -lt $thresholdDate } -Property PasswordLastSet, LastLogonTimeStamp |
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
            ResultMessage = "No computers found with passwords unchanged for 90 days."
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
