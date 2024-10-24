[CmdletBinding()]
param(
    [Parameter(Mandatory = "True")]
    [string]$DomainName
)

$Global:self = @{
    ID = 154
    UUID = '0d9236c4-98a1-4763-913b-783fdfe1de4c'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000154'
    Name = 'SMB Signing is not required on Domain Controllers'
    ScriptName = 'SmbSigningIsNotRequired'
    Description = 'This indicator looks for domain controllers where SMB signing is not required.'
    Weight = 8
    Severity = 'Critical'
    Schedule = '1h'
    Impact = 8
    LikelihoodOfCompromise = 'Unsigned network traffic is susceptible to attacks abusing the NTLM challenge-response protocol. A common example of such attacks is SMB Relay, where an attacker is positioned between the client and the server in order to capture data packets transmitted between the two, thus gaining unauthorized access to the server or other servers on the network.'
    ResultMessage = 'Found {0} DCs that do not require SMB Signing.'
    Remediation = 'The following Group Policies need to be enabled in order to enforce SMB Signing on DCs:
		<br>1. Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network server: Digitally sign communications (always): This policy controls whether the server providing SMB required signing. It determines if SMB signing will have to be negotiated prior to further communication.</br>
		<br>2. Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network server: Digitally sign communications (if client agrees): This policy determines if SMB server will negotiate SMB signing with clients that request it.</br>
    <br>Read more <a href="https://techcommunity.microsoft.com/t5/storage-at-microsoft/configure-smb-signing-with-confidence/ba-p/2418102" target="_blank">here</a></br>'
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
    $dcList = Get-ADDomainController -Filter * -Server $DomainName
    foreach ($dc in $dcList) {
        $smbConfig = Get-SmbServerConfiguration -CimSession $dc.HostName
        if (-not $smbConfig.RequireSecuritySignature) {
            $outputObject = [pscustomobject]@{
                DomainController = $dc.HostName
                RequiresSigning = $smbConfig.RequireSecuritySignature
            }
            [void]$outputObjects.Add($outputObject)
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
            ResultMessage = "All checked DCs require SMB Signing."
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
