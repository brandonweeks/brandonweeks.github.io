$domain = $(Get-ADDomain).DNSRoot
$gpo = 'DirectAccess Server Settings'
$ruleName = 'DirectAccess Policy-DaServerToCorp'
$algorithms = @("RSA", "ECDSA256", "ECDSA384")

#Sanity check that the GPO exists.
Get-GPO -Name $gpo -Domain $domain -ErrorAction Stop | Out-Null

$rule = Get-NetIPsecRule -DisplayName $ruleName -PolicyStore "$domain\$gpo" -ErrorAction Stop 
$authSet = $rule | Get-NetIPsecPhase1AuthSet -ErrorAction Stop


# Collect proposals into a hash by Authority and then by Signing. There should
# only proposal per authority and signing combination, otherwise the exisiting
# proposals are too complex for this script to reason about.
$proposalsByAuthority = @{}
foreach ($proposal in $authSet.Proposal) {
    if ($proposal.AuthenticationMethod -ne "MachineCert") {
        Write-Host 'Only supported Authentication Method is MachineCert'
        return
    }
    if ($proposalsByAuthority.ContainsKey($proposal.Authority)) {
        if ($proposalsByAuthority[$proposal.Authority].ContainsKey($proposal.Signing)) {
            Write-Host 'Only one proposal proposal per Authority and Signing combination is supported'
            return
        }
        $proposalsByAuthority[$proposal.Authority][$proposal.Signing] = $proposal
    } else {
        $proposalsByAuthority[$proposal.Authority] = @{$proposal.Signing = $proposal}
    }
}

$proposals = New-Object Collections.Generic.List[CimInstance]
foreach ($v in $proposalsByAuthority.Values) {
    foreach ($alg in $algorithms) {
        $proposal = $($v.Values)[0].Clone()
        $proposal.Signing = $alg
        $proposals.Add($proposal)
    }
}

$authSet | Set-NetIPsecPhase1AuthSet -Proposal $proposals