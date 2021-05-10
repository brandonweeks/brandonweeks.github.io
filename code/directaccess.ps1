# Parameters
$domain = $(Get-ADDomain).DNSRoot
$gpo = 'DirectAccess Server Settings'
$ruleName = 'DirectAccess Policy-DaServerToCorp'
$algorithms = @("RSA", "ECDSA256", "ECDSA384")

Set-StrictMode -Version latest

function equals ([CimInstance] $p1, [CimInstance] $p2) {
    if ($p1.AccountMapping -ne $p2.AccountMapping) {
        return $false
    }
    if ($p1.Authority -ne $p2.Authority) {
        return $false
    }
    if ($p1.ExtendedKeyUsage -ne $p2.ExtendedKeyUsage) {
        return $false
    }
    if ($p1.SubjectName -ne $p2.SubjectName) {
        return $false
    }
    if ($p1.SubjectNameType -ne $p2.SubjectNameType) {
        return $false
    }
    if ($p1.Caption -ne $p2.Caption) {
        return $false
    }
    if ($p1.CertName -ne $p2.CertName) {
        return $false
    }
    if ($p1.CertNameType -ne $p2.CertNameType) {
        return $false
    }
    if ($p1.CipherAlgorithm -ne $p2.CipherAlgorithm) {
        return $false
    }
    if ($p1.Description -ne $p2.Description) {
        return $false
    }
    if ($p1.EKUs -ne $p2.EKUs) {
        return $false
    }
    if ($p1.ElementName -ne $p2.ElementName) {
        return $false
    } 
    if ($p1.ExcludeCAName -ne $p2.ExcludeCAName) {
        return $false
    } 
    if ($p1.FollowRenewal -ne $p2.FollowRenewal) {
        return $false
    }
    if ($p1.GroupId -ne $p2.GroupId) {
        return $false
    }
    if ($p1.HashAlgorithm -ne $p2.HashAlgorithm) {
        return $false
    }
    if ($p1.InstanceID -ne $p2.InstanceID) {
        return $false
    }
    if ($p1.MapToAccount -ne $p2.MapToAccount) {
        return $false
    }
    if ($p1.MaxLifetimeKilobytes -ne $p2.MaxLifetimeKilobytes) {
        return $false
    }
    if ($p1.MaxLifetimeSeconds -ne $p2.MaxLifetimeSeconds) {
        return $false
    }
    if ($p1.OtherAuthenticationMethod -ne $p2.OtherAuthenticationMethod) {
        return $false
    }
    if ($p1.OtherCipherAlgorithm -ne $p2.OtherCipherAlgorithm) {
        return $false
    }
    if ($p1.OtherHashAlgorithm -ne $p2.OtherHashAlgorithm) {
        return $false
    }
    if ($p1.PSComputerName -ne $p2.PSComputerName) {
        return $false
    }
    if ($p1.SigningAlgorithm -ne $p2.SigningAlgorithm) {
        return $false
    }
    if ($p1.Thumbprint -ne $p2.Thumbprint) {
        return $false
    }
    if ($p1.TrustedCA -ne $p2.TrustedCA) {
        return $false
    }
    if ($p1.TrustedCAType -ne $p2.TrustedCAType) {
        return $false
    }
    if ($p1.ValidationCriteria -ne $p2.ValidationCriteria) {
        return $false
    }
    if ($p1.VendorID -ne $p2.VendorID) {
        return $false
    }
    if ($p1.AuthenticationMethod -ne $p2.AuthenticationMethod) {
        return $false
    }
    if ($p1.AuthorityType -ne $p2.AuthorityType) {
        return $false
    }
    if ($p1.Signing -ne $p2.Signing) {
        return $false
    }
    if ($p1.SubjectNameType -ne $p2.SubjectNameType) {
        return $false
    }
    return $true
}

function contains ($proposals, $proposal) {
    foreach ($p in $proposals) {
        if (equals $p $proposal) {
            return $true
        }
    }
    return $false
}

#Sanity check that the GPO exists.
Get-GPO -Name $gpo -Domain $domain -ErrorAction Stop | Out-Null

$rule = Get-NetIPsecRule -DisplayName $ruleName -PolicyStore "$domain\$gpo" -ErrorAction Stop 
$authSet = $rule | Get-NetIPsecPhase1AuthSet -ErrorAction Stop

$proposals = New-Object Collections.Generic.List[CimInstance]
foreach ($proposal in $authSet.Proposal) {
    if ($proposal.AuthenticationMethod -ne "MachineCert") {
        continue
    }

    foreach ($signing in $algorithms) {
        $newProposal = $proposal.Clone()
        $newProposal.Signing = $signing
        if (contains $proposals $newProposal) {
            continue
        }
        $proposals.Add($newProposal)
 
    }
}

$authSet | Set-NetIPsecPhase1AuthSet -Proposal $proposals