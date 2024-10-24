# This script looks for outbound forest trusts that has Quarantine = no

[CmdletBinding()]
param(
    [Parameter(Mandatory,ParameterSetName='Execution')][string]$ForestName,
    [Parameter(Mandatory,ParameterSetName='Execution')][string[]]$DomainNames,
    [Parameter(ParameterSetName='Execution')]$StartAttackWindow,
    [Parameter(ParameterSetName='Execution')]$EndAttackWindow,
    [Parameter(ParameterSetName='Metadata',Mandatory)][switch]$Metadata
)

$Global:self = @{
    ID = 87
    UUID = '19a4b814-3561-4463-a083-2769fabf1490'
    Version = '1.124.1'
    CategoryID = 3
    ShortName = 'SI000087'
    Name = 'Domain trust to a third-party domain without quarantine'
    ScriptName = 'OutboundTrustWithoutQuarantine'
    Description = 'This indicator looks for outbound forest trusts that has Quarantine flag set to false, which means that the trusted domain is not subject to SID filtering.'
    Weight = 5
    Severity = 'Warning'
    Schedule = '1d'
    Impact = 5
    LikelihoodOfCompromise = 'An attacker having compromised the remote domain can spoof any user or machine on the local domain (except for accounts with a RID lower than 1000, excluding built-in accounts and groups). This attacker can therefore access every resource on the local domain. If a dangerous control path is exposed to any "spoofable" account (virtually any account other than the built-in ones), the attacker could also escalate his privileges up to "Domain Admins" and compromise the entire forest.'
    ResultMessage = 'Found {0} outbound trusts where Quarantine is disabled or SID history is enabled.'
    Remediation = 'Unless domain migration is currently ongoing, use the following command to enable Quarantine for external trusts:<br><br>NETDOM TRUST <ForestName> /domain:<TrustedForest> /Quarantine yes<br><br>And use the following command to disable SID history for forest trusts:<br><br>NETDOM TRUST <ForestName> /domain:<TrustedForest> /EnableSIDhistory:No'
    Types = @('IoE')
    DataSources = @('AD.LDAP')
    OutputFields = @(
        @{ Name = 'DistinguishedName'; Type = 'String'; IsCollection = $false },
        @{ Name = 'TrustAttributes'; Type = 'String'; IsCollection = $false },
        @{ Name = 'TrustedForest'; Type = 'String'; IsCollection = $false }
    )
    Targets = @('AD')
    Permissions = @()
    SecurityFrameworks = @(
        @{ Name = 'MITRE ATT&CK'; Tags = @('Lateral Movement') },
        @{ Name = 'MITRE D3FEND'; Tags = @('Harden - Domain Trust Policy') },
        @{ Name = 'ANSSI'; Tags = @('vuln1_trusts_domain_notfiltered') }
    )
    Products = @(
        @{ Name = 'HYD'; MinVersion = '1.0'; MaxVersion = '3.0'; Licenses = @('Cloud') },
        @{ Name = 'DSP'; MinVersion = '3.5'; MaxVersion = '10'; Licenses = @('DSP-I') },
        @{ Name = 'PK'; MinVersion = '1.4'; MaxVersion = '10'; Licenses = @('Community', 'Post-Breach', 'BPIR') }
    )
    IgnoreListSupport = $true
    Selected = 1
}
if($Metadata){ return $self | ConvertTo-Json -Depth 8 -Compress }

Import-Module -Name 'Semperis-Lib'
$outputObjects = [System.Collections.ArrayList]@()
$failedDomainCount = 0
try {
    if ($PSBoundParameters['ForestName'] -and $PSBoundParameters['DomainNames']) {
        $ForestName = $ForestName.ToLower()
        $DomainNames = ConvertTo-Lowercase -DomainNames $DomainNames
    }
    $res = New-Result


    $unavailableDomains = [System.Collections.ArrayList]@()
    foreach ($domain in $DomainNames) {
        if (-not (Confirm-DomainAvailability $domain)) {
            [void]$unavailableDomains.Add($domain)
            continue
        }
        $DN = Get-DN $domain

        # TrustAttributes 0x20 (32) flag means in-forest trusts, 0x04 (4) flag means TRUST_ATTRIBUTE_QUARANTINED_DOMAIN, TrustDirection 2 means outbound
        $results = Search-AD -dnsDomain $domain -attributes "trustattributes", "trustpartner" -baseDN $DN -scope "Subtree" `
            -filter "(&(objectCategory=TrustedDomain)(trustDirection:1.2.840.113556.1.4.803:=2)(!(trustAttributes:1.2.840.113556.1.4.803:=32))(|(&(!(trustAttributes:1.2.840.113556.1.4.803:=4))(!(trustAttributes:1.2.840.113556.1.4.803:=64))(!(trustAttributes:1.2.840.113556.1.4.803:=8)))(&(trustAttributes:1.2.840.113556.1.4.803:=8)(trustAttributes:1.2.840.113556.1.4.803:=64))))"

        foreach ($result in $results) {
            $failedDomainCount++
            if ($result.Attributes.'trustpartner') {
                $trustedForest = $result.Attributes.'trustpartner'.GetValues("string")[0]
            }
            $trustAttributes = $result.Attributes."trustattributes"[0]
            if ($trustAttributes -eq 0) {
                $attributesText = "$($trustAttributes)"
            }
            else {
                $attributesText = "$trustAttributes [$( (Get-TrustAttributesSet $trustAttributes) -join ", ")]"
            }
            $thisOutput = [PSCustomObject][Ordered] @{
                DistinguishedName = $DN
                TrustedForest = $trustedForest
                TrustAttributes = $attributesText
            }
            [void]$outputObjects.Add($thisOutput)
        }
    }

    # Count is the number of domains that failed the test
    if ($outputObjects){
        $configArgs = @{
            ScriptName = $self.ScriptName
            Path = $MyInvocation.MyCommand.ScriptBlock.File
            Fields = $outputObjects[0]
        }
        $config = Resolve-Configuration @configArgs
        $outputObjects | Set-IgnoredFlag -Configuration $config
        $scoreOutput = $outputObjects | Get-Score -Impact $self.Impact
        if($scoreOutput.Score -lt 100)
        {
            $res.ResultObjects = $outputObjects
            $res.ResultMessage = $self.ResultMessage -f $outputObjects.Count
            $res.Remediation = $self.Remediation
            $res.Status = 'Failed'
            $res.Score = $scoreOutput.Score
        }
        if ($scoreOutput.Ignoredcount -gt 0)
        {
            $res.ResultMessage += " ($($scoreOutput.Ignoredcount) Objects ignored)."
            $res.ResultObjects = $outputObjects
        }
    }

    # deal with unavailabile domains
    if ($unavailableDomains.Count -gt 0) {
        $res.Status = 'Error'
        $res.ResultMessage += " Failed to run because the following domains were unavailable: $($unavailableDomains -join ', ')"
    }
}
catch {
    return ConvertTo-ErrorResult $_
}
return $res

# SIG # Begin signature block
# MIIuDQYJKoZIhvcNAQcCoIIt/jCCLfoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAzPeYgQiXK3qF3
# LuP8Xwk4JonWkGBp1Vqv6Hgtfy9YR6CCE3wwggVyMIIDWqADAgECAhB2U/6sdUZI
# k/Xl10pIOk74MA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDAzMTgwMDAwMDBaFw00NTAzMTgwMDAwMDBaMFMx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQD
# EyBHbG9iYWxTaWduIENvZGUgU2lnbmluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBALYtxTDdeuirkD0DcrA6S5kWYbLl/6VnHTcc5X7s
# k4OqhPWjQ5uYRYq4Y1ddmwCIBCXp+GiSS4LYS8lKA/Oof2qPimEnvaFE0P31PyLC
# o0+RjbMFsiiCkV37WYgFC5cGwpj4LKczJO5QOkHM8KCwex1N0qhYOJbp3/kbkbuL
# ECzSx0Mdogl0oYCve+YzCgxZa4689Ktal3t/rlX7hPCA/oRM1+K6vcR1oW+9YRB0
# RLKYB+J0q/9o3GwmPukf5eAEh60w0wyNA3xVuBZwXCR4ICXrZ2eIq7pONJhrcBHe
# OMrUvqHAnOHfHgIB2DvhZ0OEts/8dLcvhKO/ugk3PWdssUVcGWGrQYP1rB3rdw1G
# R3POv72Vle2dK4gQ/vpY6KdX4bPPqFrpByWbEsSegHI9k9yMlN87ROYmgPzSwwPw
# jAzSRdYu54+YnuYE7kJuZ35CFnFi5wT5YMZkobacgSFOK8ZtaJSGxpl0c2cxepHy
# 1Ix5bnymu35Gb03FhRIrz5oiRAiohTfOB2FXBhcSJMDEMXOhmDVXR34QOkXZLaRR
# kJipoAc3xGUaqhxrFnf3p5fsPxkwmW8x++pAsufSxPrJ0PBQdnRZ+o1tFzK++Ol+
# A/Tnh3Wa1EqRLIUDEwIrQoDyiWo2z8hMoM6e+MuNrRan097VmxinxpI68YJj8S4O
# JGTfAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0G
# A1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzANBgkqhkiG9w0BAQwFAAOCAgEA
# Xiu6dJc0RF92SChAhJPuAW7pobPWgCXme+S8CZE9D/x2rdfUMCC7j2DQkdYc8pzv
# eBorlDICwSSWUlIC0PPR/PKbOW6Z4R+OQ0F9mh5byV2ahPwm5ofzdHImraQb2T07
# alKgPAkeLx57szO0Rcf3rLGvk2Ctdq64shV464Nq6//bRqsk5e4C+pAfWcAvXda3
# XaRcELdyU/hBTsz6eBolSsr+hWJDYcO0N6qB0vTWOg+9jVl+MEfeK2vnIVAzX9Rn
# m9S4Z588J5kD/4VDjnMSyiDN6GHVsWbcF9Y5bQ/bzyM3oYKJThxrP9agzaoHnT5C
# JqrXDO76R78aUn7RdYHTyYpiF21PiKAhoCY+r23ZYjAf6Zgorm6N1Y5McmaTgI0q
# 41XHYGeQQlZcIlEPs9xOOe5N3dkdeBBUO27Ql28DtR6yI3PGErKaZND8lYUkqP/f
# obDckUCu3wkzq7ndkrfxzJF0O2nrZ5cbkL/nx6BvcbtXv7ePWu16QGoWzYCELS/h
# AtQklEOzFfwMKxv9cW/8y7x1Fzpeg9LJsy8b1ZyNf1T+fn7kVqOHp53hWVKUQY9t
# W76GlZr/GnbdQNJRSnC0HzNjI3c/7CceWeQIh+00gkoPP/6gHcH1Z3NFhnj0qinp
# J4fGGdvGExTDOUmHTaCX4GUT9Z13Vunas1jHOvLAzYIwgga/MIIEp6ADAgECAhEA
# gU5CF6Epf+1azNQX+JGtdTANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJCRTEZ
# MBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEpMCcGA1UEAxMgR2xvYmFsU2lnbiBD
# b2RlIFNpZ25pbmcgUm9vdCBSNDUwHhcNMjQwNjE5MDMyNTExWhcNMzgwNzI4MDAw
# MDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEv
# MC0GA1UEAxMmR2xvYmFsU2lnbiBHQ0MgUjQ1IENvZGVTaWduaW5nIENBIDIwMjAw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDWQk3540/GI/RsHYGmMPdI
# Pc/Q5Y3lICKWB0Q1XQbPDx1wYOYmVPpTI2ACqF8CAveOyW49qXgFvY71TxkkmXzP
# ERabH3tr0qN7aGV3q9ixLD/TcgYyXFusUGcsJU1WBjb8wWJMfX2GFpWaXVS6UNCw
# f6JEGenWbmw+E8KfEdRfNFtRaDFjCvhb0N66WV8xr4loOEA+COhTZ05jtiGO792N
# hUFVnhy8N9yVoMRxpx8bpUluCiBZfomjWBWXACVp397CalBlTlP7a6GfGB6KDl9U
# Xr3gW8/yDATS3gihECb3svN6LsKOlsE/zqXa9FkojDdloTGWC46kdncVSYRmgiXn
# Qwp3UrGZUUL/obLdnNLcGNnBhqlAHUGXYoa8qP+ix2MXBv1mejaUASCJeB+Q9Hup
# Uk5qT1QGKoCvnsdQQvplCuMB9LFurA6o44EZqDjIngMohqR0p0eVfnJaKnsVahzE
# aeawvkAZmcvSfVVOIpwQ4KFbw7MueovE3vFLH4woeTBFf2wTtj0s/y1KiirsKA8t
# ytScmIpKbVo2LC/fusviQUoIdxiIrTVhlBLzpHLr7jaep1EnkTz3ohrM/Ifll+FR
# h2npIsyDwLcPRWwH4UNP1IxKzs9jsbWkEHr5DQwosGs0/iFoJ2/s+PomhFt1Qs2J
# JnlZnWurY3FikCUNCCDx/wIDAQABo4IBhjCCAYIwDgYDVR0PAQH/BAQDAgGGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE
# FNqzjcAkkKNrd9MMoFndIWdkdgt4MB8GA1UdIwQYMBaAFB8Av0aACvx4ObeltEPZ
# VlC7zpY7MIGTBggrBgEFBQcBAQSBhjCBgzA5BggrBgEFBQcwAYYtaHR0cDovL29j
# c3AuZ2xvYmFsc2lnbi5jb20vY29kZXNpZ25pbmdyb290cjQ1MEYGCCsGAQUFBzAC
# hjpodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9jb2Rlc2lnbmlu
# Z3Jvb3RyNDUuY3J0MEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xvYmFs
# c2lnbi5jb20vY29kZXNpZ25pbmdyb290cjQ1LmNybDAuBgNVHSAEJzAlMAgGBmeB
# DAEEATALBgkrBgEEAaAyATIwDAYKKwYBBAGgMgoEAjANBgkqhkiG9w0BAQsFAAOC
# AgEAMhDkvBelgxBAndOp/SfPRXKpxR9LM1lvLDIxeXGE1jZn1at0/NTyBjputdbL
# 8UKDlr193pUsGu1q40EcpsiJMcJZbIm8KiMDWVBHSf1vUw4qKMxIVO/zIxhbkjZO
# vKNj1MP7AA+A0SDCyuWWuvCaW6qkJXoZ2/rbe1NP+baj2WPVdV8BpSjbthgpFGV5
# nNu064iYFFNQYDEMZrNR427JKSZk8BTRc3jEhI0+FKWSWat5QUbqNM+BdkY6kXgZ
# c77+BvXXwYQ5oHBMCjUAXtgqMCQfMne24Xzfs0ZB4fptjePjC58vQNmlOg1kyb6M
# 0RrJZSA64gD6TnohN0FwmZ1QH5l7dZB0c01FpU5Yf912apBYiWaTZKP+VPdNquvl
# IO5114iyHQw8vKGSoFbkR/xnD+p4Kd+Po8fZ4zF4pwsplGscJ10hJ4fio+/IQJAu
# XBcoJdMBRBergNp8lKhbI/wgnpuRoZD/sw3lckQsRxXz1JFyJvnyBeMBZ/dptd4F
# tv4okIx/oSk7tyzaZCJplsT001cNKoXGu2horIvxUktkbqq4t+xNFBz6qBQ4zuwl
# 6+Ri3TX5uHsHXRtDZwIIaz2/JSODgZZzB+7+WFo8N9qg21/SnDpGkpzEJhwJMNol
# 5A4dkHPUHodOaYSBkc1lfuc1+oOAatM0HUaneAimeDIlZnowggc/MIIFJ6ADAgEC
# AgxsjPy20SAh5jGEkUUwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExLzAtBgNVBAMTJkdsb2JhbFNpZ24gR0ND
# IFI0NSBDb2RlU2lnbmluZyBDQSAyMDIwMB4XDTI0MDYwNDEzMDU0NVoXDTI3MDcx
# NTE0MzA0NFowgYoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgSmVyc2V5MRAw
# DgYDVQQHEwdIb2Jva2VuMRYwFAYDVQQKEw1TRU1QRVJJUyBJTkMuMRYwFAYDVQQD
# Ew1TRU1QRVJJUyBJTkMuMSQwIgYJKoZIhvcNAQkBFhVjb2Rlc2lnbkBzZW1wZXJp
# cy5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCNYiocFDfmQmq3
# ngxGCT305SbMYRrXTVpotaqQbcpoesQbYwj/Wq94RNeh7cAXSLaMaQt5YlyhAO/a
# ND5VxLBiWi9+Y2v8cGziq1XGTGSFV6Rwc0Go777qQP0lc76Q8qGijZNWqIWWSaE3
# cS57dIFwNAWnpWVtUhtfz3LJZ1ok7vP+UQT8zC5qfbM7pAxJ8T6vrsInAG5iClrw
# uspeuUmAaLbWMKHFn2yeLOXAbEqVSwn8R8gNUBVVSMkXKooXDU35fr5xGRBuSVtd
# nguHL7jAPuDu5btcOggLcCgD9fegjXQeKphZVdpdRchpXe3idFYHAVx21552cFfs
# hEHL4M4I3YcOC/5JJcyLMIHP63MXPzQbbZ3IZQ9++sIZora75v7Bynx04xl/2mO5
# Y2LGiu4DHs6rxgBYU8AnA5ncM/mcrEoG/Ce03z7nt7Mnl7KC3GjYBnx5XCwYc0sL
# r6sHLKJdsd3bjwL/watiUxV60+lW+t5Z1JYQGlBjHwMEfQYliZHMix2Pe+9KsMbk
# vLeHMGo31pUZqeBl7hEPCD0x5KqP4VrBNPySHDhJMk582TvJdoHCKZYfJHdkChHz
# ADIbvUcAE69bTFsTOp/ypC/yOTFrZFuBr6w30+x+9UVy4+jsx1MUoNBOLv6on1Mm
# YaTH5sp4/MoA6LkPG0h7ZJUq2qlNXwIDAQABo4IB0zCCAc8wDgYDVR0PAQH/BAQD
# AgeAMIGbBggrBgEFBQcBAQSBjjCBizBKBggrBgEFBQcwAoY+aHR0cDovL3NlY3Vy
# ZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NnY2NyNDVjb2Rlc2lnbmNhMjAyMC5j
# cnQwPQYIKwYBBQUHMAGGMWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2Nj
# cjQ1Y29kZXNpZ25jYTIwMjAwVgYDVR0gBE8wTTBBBgkrBgEEAaAyATIwNDAyBggr
# BgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8w
# CAYGZ4EMAQQBMAkGA1UdEwQCMAAwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2Ny
# bC5nbG9iYWxzaWduLmNvbS9nc2djY3I0NWNvZGVzaWduY2EyMDIwLmNybDAgBgNV
# HREEGTAXgRVjb2Rlc2lnbkBzZW1wZXJpcy5jb20wEwYDVR0lBAwwCgYIKwYBBQUH
# AwMwHwYDVR0jBBgwFoAU2rONwCSQo2t30wygWd0hZ2R2C3gwHQYDVR0OBBYEFD9A
# ijmjNjU3CNw8Unvu8bt4SgXDMA0GCSqGSIb3DQEBCwUAA4ICAQAQD+KrgTxd7wyL
# ivnLriAHzIjTtvC5k8ov1rWGJgajZsA3MWQJ91mRkZzpDGYdrXgoX0f8D3qxpujk
# POOsq8z8+AlM957IzpDoq6oqLapaw25ADPTsPhlSxzY49Y9/B6pLOMVwCCTjGXDl
# DwtHiJHEyUkV0icoXCxmSGSzT4fA8HHSDRf5xd1FTFtZ2CZFf40VN9ZjNXeNs602
# dI9t4LtsXY8Y6g+wxEKc9Iwhuitp+gdXnDQ312nKo3p8Hsx5TGwRTkPJNCNq+BYt
# ba7Z7fu9m3lowjm3SaRfxgkZhW4//V8licRnrsMA3U2X4SkuXCMlC9t3NITiSPq5
# uEyhqhueu7wZbOo6hr3+2j7Y5sDrHQ0g6GpvillfX+aiDuMwx1Oo+CmJezn7UIE8
# kFC934D8QEH/veD9GtVY1YOa4pXnn6d1Kd1tPPG4R5OXrjiRmwIU9c1UVR84t86m
# euqt+dOJo7L2i1RaNdcPLOExrzHZGZEUSZaizZxBN+XKWXDHWShq0zA+llH59l/R
# IbVZRUqt6c1MD/egPtsm0XGJABzhioGtjSmALmJiv4XWXg77pyhuy1SXELjOAW9W
# gLLv4xQaO4FiXHO/yqLwh+XawyLk+iKLx3Gch3nGR8MepeRfqTg85PthgPQklS5F
# VN+q9Y6t3yR/sUxkJCMAt0B9E7sFVDGCGecwghnjAgEBMGkwWTELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExLzAtBgNVBAMTJkdsb2JhbFNp
# Z24gR0NDIFI0NSBDb2RlU2lnbmluZyBDQSAyMDIwAgxsjPy20SAh5jGEkUUwDQYJ
# YIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAvBgkqhkiG9w0BCQQxIgQgHYa7Riv1S/7hZGozecbfDmPfXFLDcV3kXEp1lw9d
# eK4wDQYJKoZIhvcNAQEBBQAEggIAR/rANrfZbMs6dYNMhrcmYBcHRWr/4FN4n/pB
# dXVgjBZb69axaG2s8eBfUEKqrHEc+MFJojeO8IZCy0eex4t3Ki/YHWcIzp9ZcYKj
# tYDwb7zKz9s2xsmodOAimv2v1YAPVXyWMl2mR5V6o9WLztr8HoLx988IEm9RCxal
# aJ0Xp2WGW71qfzlolO6Jeoe7e7jOpTgadP7ns0AZ6ys++821mpeCPIwMLwkhBLhR
# S3KwzYXkfqhesumupCaMkMdpnEy2lZwKz5DLE2movTuIa5EYAFfx++otgWAXBHA3
# akUHIt1Li14ZnvSbod9MfMesk20DWhbfq8KOS3Ee+0Zr60661M2OJE3e58YxiLnT
# vhe6ULb+fjWWnbyqk2ew5oe6KnpzEVYXe1rViadhvPWmrZEs9ip59xAscfzBABIq
# BabqZryiYoaVhxIz7qE9w95azaAGmf2Gugwmb8vEGh93UKIDaNen2/kkgB50JxCN
# a63rdP8WTDZANtE6RtfrBzz12DtZJg3Z5QO/zWjg7CK6qTYJTIliqxgepM6QuQ7f
# ENQY1WOdLRPuL6yYiq2HpeswjSHtsXe4mtpxN95XHML0pLYVyRc7lgU+U/4m6g2f
# YUO9p/gv5j7E9lCPA6SCUJ2YdWuzRuG+cDq5qxh8iV0E/OFtIz2Dy+X9tUmvCjax
# cOlzRg6hghbIMIIWxAYKKwYBBAGCNwMDATGCFrQwghawBgkqhkiG9w0BBwKgghah
# MIIWnQIBAzENMAsGCWCGSAFlAwQCATCB5AYLKoZIhvcNAQkQAQSggdQEgdEwgc4C
# AQEGCSsGAQQBoDICAzAxMA0GCWCGSAFlAwQCAQUABCD8CmYK2ROsdk9saJQ6ixF/
# rbexlmXaDNG60ThSIAMr7wITfxwNTz5/elfD7b2EcYirJDsTzxgPMjAyNDA3MTAx
# NjEwNDhaMAMCAQGgYKReMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKDBBHbG9iYWxT
# aWduIG52LXNhMTIwMAYDVQQDDClHbG9iYWxzaWduIFRTQSBmb3IgQWR2YW5jZWQg
# LSBHNCAtIDIwMjMxMaCCElMwggZrMIIEU6ADAgECAhABGXV0ccmS10TfpZbruXAV
# MA0GCSqGSIb3DQEBCwUAMFsxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxT
# aWduIG52LXNhMTEwLwYDVQQDEyhHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBDQSAt
# IFNIQTM4NCAtIEc0MB4XDTIzMTEwMjEwMzAwMloXDTM0MTIwNDEwMzAwMlowXDEL
# MAkGA1UEBhMCQkUxGTAXBgNVBAoMEEdsb2JhbFNpZ24gbnYtc2ExMjAwBgNVBAMM
# KUdsb2JhbHNpZ24gVFNBIGZvciBBZHZhbmNlZCAtIEc0IC0gMjAyMzExMIIBojAN
# BgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAsjVGdKqDjdWWpzxI1cXKqN9Uvgir
# od9c6UnQYF61pRr3Q1hDlzz0Z2MIMjwZfyvZVUbV1IzAXM+kxaUauqcrziZCITzl
# u6Gjld1g6hJVru/O3DKE7aO14D9z0TW4m7vFRN3huOvzWa2J9nGPWgr6CpIFhA2X
# Ab8Fu/xYAbONydQFhaeQK26s09lO2qckNZZvqrOgQTvg+ecRjtVmAoAtPczPHqSW
# ixeA3Ew5GiR1LMV3FtmRgyZ/5xOLokVU5rZKd+fSLS7nsDxI2caN+3r0K7ymIkii
# 196teEeIDF+b9JFKBhz6A55qVh4rMOPzjlmwtB8eYTiGefmDg5SPCTBCM7QOt4iC
# GC0/14GLJ6Bp8dMFrsZFo8Ifm63pwMhP1+fGp0EyaP9ZylRc+7/ZHxbwUtLPuDWV
# pZHOox31dlKY7JFhiwmhrZmZ6KyUKJc4jAmuPJz4flGiN2rIcbodTw0mAVZ+V8N1
# QthT4GNj3X6eHahi6M7+mVlT9vMAiv2Tlc/RAgMBAAGjggGoMIIBpDAOBgNVHQ8B
# Af8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYEFMS+7oc8
# iXQO3rPuGRuFDM5BTn+dMFYGA1UdIARPME0wCAYGZ4EMAQQCMEEGCSsGAQQBoDIB
# HjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBv
# c2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5BggrBgEF
# BQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4
# NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2Nh
# Y2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn48tXRTkz
# pPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xvYmFsc2ln
# bi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG9w0BAQsFAAOCAgEA
# szLR6mf/29+ntDdEXe0evnYjyc4D7U3UauczjDxfIGLb7ulsODnlmXH7JpEfJ7Fz
# XAMZz2gy0NXmdnhKqjyXMtIV7nocMjxgp0HKuT7xQerD0/HH5b7eGsbBjiLf1oDl
# j/KssiGNeLbEiYyUvTJzuNiXRDzXZmwNHBBcXqiIQL2grk5aLWRPBiWlhMY4cMdU
# cxSNVxapMByoCUnfpQEGA78Ts3SUmweBrw1BkFUpsGCpVPo4IDPOCboOTGdYgYap
# 7YiGqZjjtuVGlyRHbEjREGrKcbI+XcM9LSGCa4Njb5fAkf77fZa5qsAczaWtkHiA
# 1n1tiSpAjqwl+uuINiN+hvL7tQbtKIMss9qaem9IERaUNrVFQJ2BNQ3FsYybO+Y8
# 6XoYUPk5ipJ3u5EibqC5WyoBQCjk0UipMI6ihhI3TclZmcemA3/hkQp9CvgLQg5x
# rvbPuuUx+PkfLfDgCoyEjKU5ozuw8zbZQ9WbmCQP0MLjJj6t4fv7HqveBvb7aEHs
# Md+pyR6MGfY+9h6YLtFggVsmdPRUTkAE37Ve1Pfu8A2Hb0BAp2nqKMihqU93Eokx
# aumag3eLqcVEM+63aU4stKe0lXib1qpALDYap0RDs1LYYMZzV7981jXTI6NgQiLW
# FhXOExrpzvXlz1q+rD9z6fpzvxnNopdmyhxgDaK9VMwwggZZMIIEQaADAgECAg0B
# 7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNp
# Z24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpH
# bG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFowWzELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEds
# b2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOvdYNfqUdSx2E6Y3w5
# I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt0ShKwSy7uXDycq6M
# 95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrEiPDul/bc
# 8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64VJmKqDGS
# O/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16ZevRVqkuvftYPbWF
# +lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv+GfqCL6P
# SXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm19m1W/oodCT4kDmcm
# x/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIGbxsY1TbqZK7O/fUF
# 5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMDAd6ZJflxbumcXQJM
# YDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/MiyTdtk8EWfusE/VKPY
# dgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9GbCX6oxQkW2vV4Z+
# EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQI
# MAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDDvWWWMB8GA1UdIwQY
# MBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAuBggrBgEF
# BQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2BgNVHR8E
# LzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3Js
# MEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5n
# bG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOCAgEAf+KI
# 2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYWaxlASSUIHuSb99ak
# DY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCyz+zCVmUdvX/23oLI
# t59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W8+o3V5SR
# GK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWzAlcfi5z8
# u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59eodaZzul9S5YszBZr
# GM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8oMWsr1EG8BHHHTDF
# UVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1If5iEO0dMPz2zOpI
# J3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDUY6qD6mxy
# YUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+Pvafnzka
# rqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+gfkNlKd9
# 8rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIIDa6ADAgECAg5F5rsD
# gzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWdu
# IFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xv
# YmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwxIDAeBgNV
# BAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWdu
# MRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRvf+kqzMaw
# iGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJf094YwjI
# ElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcxBsW+4m0y
# BqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQBzj/ZrJ3
# YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5dRC2Q8YHN
# V5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWqRfLgnTah
# b1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX85mEWP3fV
# 2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjplllnA8DX9
# ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R/98wEfmF
# zzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFltr+Mm9wT
# 6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEAAaNjMGEw
# DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK5sBaOT
# E+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1Og
# MA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tytok/oR3jW
# ZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7jpl4FkMT
# VlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh4OMd+tgH
# M3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR3VRGHE3b
# mZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6fWN7P9Bx
# gXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgbKCuobK1e
# bcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglIWYfrexRg
# emSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Qv4aW2Zla
# tJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98i0qhkHQl
# p7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU4fVmR3l3
# 1VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzWAtcKZ4MF
# WsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2Jh
# bFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENB
# IC0gU0hBMzg0IC0gRzQCEAEZdXRxyZLXRN+lluu5cBUwCwYJYIZIAWUDBAIBoIIB
# LTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0MR4wHDAL
# BglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcNAQkEMSIEIDUh9VSn
# Jp/XgJogOaJHMN52QGxkexWuGHim8hxc+S43MIGwBgsqhkiG9w0BCRACLzGBoDCB
# nTCBmjCBlwQgC3miOa5CEI3vVrNUBb+PzY5Zp0uE7uLew9lxweoXNOwwczBfpF0w
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAEZ
# dXRxyZLXRN+lluu5cBUwDQYJKoZIhvcNAQELBQAEggGAB9XyEa7/HeQB6Y/cGsr5
# eiR9IHEHhFcHZK16CuX1TFcVbPg4XeVbh3YV65HKksLfCCpYRw+V1JEa4o46alsn
# E4z3/TYGidRMxMbhc50at042HRe5pWnermkWlJyR+3y1XdrtBEiAbitZtn2tBZIF
# +tg1chLDzMfQ3zz2tPyjF/+FIvhrluBtYlwNm7W4+WlEuA/mNUx6D3kwdy87UU1s
# heUmTij/9L16TZE+OCjFO4HTNvgdfBUa2//5Rewtyhw5dn9xfwNrMOU34Wqftfv8
# buVXKu9K6wOowIgmwWL+I5FPoz7C6ybeuDS7Nmzmc308+KoV0RRqKGzigtSoKyep
# 06RFdjauR74yjKG5PqDvqq6oyTi1zyYzt0aAmSdeYCjyzrXdW6Izg8LojnesEHEM
# aqLsn3ve/8MIVe2Kzlsr+OZ5nt9LKZY9RTewtMmJqQc2kU71zP8UhLOCCfGvGrQD
# jJ5h+VgtGFebYU3sir9Q0wSjoI0ZiQ1UWYDlFU/NU5zU
# SIG # End signature block
