# PowerShell Script to Check Zerologon Vulnerability
param(
    [Parameter(Mandatory = $true)]
    [string]$DomainName
)

$Global:self = @{
    ID = 25
    UUID = 'f383d6e4-3088-4a82-b897-c7a84dfd825b'
    Version = '1.0.0'
    CategoryID = 2
    ShortName = 'SI000025'
    Name = 'Zerologon Vulnerability Check'
    ScriptName = 'CheckZerologon'
    Description = 'This script checks for the Zerologon vulnerability in domain controllers using a PowerShell detection script.'
    Weight = 10
    Severity = 'Critical'
    Schedule = '1d'
    Impact = 10
    LikelihoodOfCompromise = 'High'
    ResultMessage = 'Found {0} domain controllers vulnerable to Zerologon.'
    Remediation = 'Apply the latest security updates from Microsoft to patch the Zerologon vulnerability.'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'HostName'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
}

$outputObjects = @()

function Test-ZeroLogon {
    param (
        [string]$DomainController
    )

    try {
        $null = New-PSSession -ComputerName $DomainController -Credential (New-Object System.Management.Automation.PSCredential("Administrator", (ConvertTo-SecureString "" -AsPlainText -Force))) -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

try {
    $domainControllers = Get-ADDomainController -Filter * -Server $DomainName
    foreach ($dc in $domainControllers) {
        if (Test-ZeroLogon -DomainController $dc.HostName) {
            $outputObjects += [pscustomobject]@{ HostName = $dc.HostName }
        }
    }

    if ($outputObjects.Count -gt 0) {
        [pscustomobject]@{
            Status = "Failed"
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }
    } else {
        [pscustomobject]@{
            Status = "Passed"
            ResultMessage = "No evidence of Zerologon vulnerability found."
        }
    }
} catch {
    [pscustomobject]@{
        Status = "Error"
        ResultMessage = $_.Exception.Message
    }
}
