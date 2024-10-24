[CmdletBinding()]
param(
    [Parameter(Mandatory='True')][string]$DomainName
)

$Global:self = @{
    ID = 110
    UUID = '070e7b62-4784-4ca5-bdaa-82da2972e23a'
    Version = '1.124.1'
    CategoryID = 2
    ShortName = 'SI000110'
    Name = 'Ephemeral Admins'
    ScriptName = 'EphemeralAdmins'
    Description = 'This indicator looks for users which were added and removed from an admin group within a 48 hour span of time. Such short-lived accounts may indicate malicious activity.'
    Weight = 3
    Severity = 'Informational'
    Schedule = '1w'
    Impact = 3
    LikelihoodOfCompromise = 'In most environments, management of admin accounts is tightly controlled and audited. This indicator provides a fast method to create a list of ephemeral admins for investigation and review.'
    ResultMessage = 'Found {0} users who have been added & removed from an admin group within 48 hours.'
    Remediation = 'Confirm that any additions/removals from admin groups are valid and properly accounted for.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'EventTimestamp'; Type = 'DateTime'; IsCollection = $false },
        @{ Name = 'GroupDistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Member'; Type = 'String'; IsCollection = $false },
        @{ Name = 'Operation'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Persistence') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - User Account Permissions') }
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
    $privilegedGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Administrators",
        "Schema Admins",
        "Backup Operators",
        "Account Operators",
        "Server Operators",
        "Key Admins"
    )

    $currentTime = Get-Date
    $cutoffTime = $currentTime.AddHours(-48)

    foreach ($group in $privilegedGroups) {
        try {
            $groupMembers = Get-ADGroupMember -Identity $group -Server $DomainName

            foreach ($member in $groupMembers) {
                if ($member.objectClass -eq 'user' -and ($member.SamAccountName -ne 'Administrator')) {
                    # Get the user's last modified timestamp
                    $userDetails = Get-ADUser -Identity $member -Server $DomainName -Properties whenChanged

                    # Check if the user was modified in the last 48 hours
                    if ($userDetails.whenChanged -gt $cutoffTime) {
                        $outputObject = [PSCustomObject]@{
                            UserName = $member.SamAccountName
                            GroupName = $group
                            EventTimestamp = $userDetails.whenChanged
                            Operation = 'Added/Removed'
                        }
                        [void]$outputObjects.Add($outputObject)
                    }
                }
            }
        } catch {
            Write-Host "Error processing group '$group': $_"
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
            Status = "Passed"
            ResultMessage = "Found no user(s) who have been added & removed from an admin group within 48 hours."
        }
    }
} catch {
    $res = [PSCustomObject]@{
        Status = 'Error'
        ResultMessage = $_.Exception.Message
    }
}

return $res
