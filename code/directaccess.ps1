function Set-NetIPsecPhase1AuthSetAlgorithms {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [System.String]
        $Domain = $(Get-ADDomain).DNSRoot,
    
        [System.String]
        $GPO = [string] 'DirectAccess Server Settings',
    
        [System.String]
        $RuleName = 'DirectAccess Policy-DaServerToCorp',
    
        [Parameter(mandatory = $true)]
        [System.String]
        $Authority,
    
        [ValidateSet("ECDSA256", "ECDSA384", "RSA")]
        [System.String[]]
        $Algorithm = @("RSA"),
    
        [Parameter(Mandatory = $false)]
        [switch]
        $Force
    )

    try {
        #Sanity check that the GPO exists.
        Get-GPO -Name $GPO -Domain $Domain | Out-Null
    }
    catch {
        throw
    }

    $rule = Get-NetIPsecRule -DisplayName $RuleName -PolicyStore "$domain\$gpo"
    $authSet = $rule | Get-NetIPsecPhase1AuthSet

    $proposalForAuthority = @()
    foreach ($p in $authSet.Proposal) {
        if ($p.Authority -ne $Authority) {
            continue
        }
        if ($p.AuthenticationMethod -ne "MachineCert") {
            Write-Error 'Only the MachineCert Authentication Method is supported'
            return
        }
        $proposalForAuthority += $p
    }

    if ((-not $Force) -and $proposalForAuthority.Count -gt 1) {
        Write-Error  "More than 1 proposal already exists for the authority, pass -Force to overwrite."
        return
    }

    $proposals = New-Object Collections.Generic.List[CimInstance]
    foreach ($alg in $Algorithm) {
        # If there is more than one proposal for the given authority, the
        # first proposal is used as the template. If the exisiting proposals
        # differ by more than the Signing field this could cause unintended 
        # results.
        $proposal = $proposalForAuthority[0].Clone()
        try {
            $proposal.Signing = $alg
        }
        catch [System.Management.Automation.SetValueInvocationException] {
            throw
        }
        $proposals.Add($proposal)
    }

    $authSet | Set-NetIPsecPhase1AuthSet -Proposal $proposals -PassThru -WhatIf:$WhatIfPreference 
}

Export-ModuleMember -Function Set-NetIPsecPhase1AuthSetAlgorithms