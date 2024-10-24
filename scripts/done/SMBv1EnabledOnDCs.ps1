[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$DomainName
)

$Global:self = @{
    ID = 155
    UUID = '66ee675e-4b5d-47a9-a364-a4477c1e73e5'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000155'
    Name = 'SMBv1 is enabled on Domain Controllers'
    ScriptName = 'SMBv1EnabledOnDCs'
    Description = 'This indicator looks for domain controllers where SMBv1 protocol is enabled.'
    Weight = 8
    Severity = 'Critical'
    Schedule = '1h'
    Impact = 8
    LikelihoodOfCompromise = 'SMBv1 is an old protocol, considered unsafe and susceptible to all kinds of attacks. It was publicly deprecated by Microsoft in 2014.'
    ResultMessage = 'Found {0} DCs with SMBv1 Enabled.'
    Remediation = 'Microsoft recommends to disable SMBv1 whenever possible on both client and server side. Do note, before disabling SMBv1 and to avoid additional errors, make sure best practices are followed regarding the usage of deprecated OS (Windows 2000, 2003, XP, CE), network printers using SMBv1 scan2shares functionalities, or software accessing Windows share with a custom implementation relying on SMBv1. <br>Read more <a href="https://techcommunity.microsoft.com/t5/storage-at-microsoft/stop-using-smb1/ba-p/425858" target="_blank">here.</a></br>'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'HostName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'State'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Privilege Escalation', 'Credential Access') }
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
    $attributes = "DistinguishedName", "DNSHostName"
    $dcs = Get-ADComputer -Filter { (PrimaryGroupID -eq 516) -or (PrimaryGroupID -eq 521) } -Properties $attributes -SearchBase (Get-ADDomain -Identity $DomainName).DistinguishedName

    foreach ($dc in $dcs) {
        $fqdn = $dc.DNSHostName
        $dn = $dc.DistinguishedName
        $smbConfig = Get-SmbServerConfiguration -CimSession $fqdn


        if ($smbConfig.EnableSMB1Protocol -eq $true){
            $thisOutput = [PSCustomObject][Ordered]@{
                HostName = $fqdn
                DistinguishedName = $dn
                SMBv1State = $smbConfig.EnableSMB1Protocol
            }
    
            [void]$outputObjects.Add($thisOutput)
        }
    }

        

    if ($outputObjects) {
        $res = [PSCustomObject]@{
            Status = 'Failed'
            ResultMessage = $self.ResultMessage -f $outputObjects.Count
            ResultObjects = $outputObjects
            Remediation = $self.Remediation
        }
    } else {
        $res = [PSCustomObject]@{
            Status = 'Passed'
            ResultMessage = "No DCs with SMBv1 enabled found."
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
