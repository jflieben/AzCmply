#Health that is only observable from inside workloads, read from Microsoft Defender for Cloud assessments

function Get-AssessmentFindings {
    #one finding per resource for the given assessment keys: Fail when any is Unhealthy, Pass when all reported ones are Healthy
    param([hashtable]$Keys, [string]$HealthyText, [string]$SubscriptionNotApplicable)
    $assessments = @(Get-IngestData 'defender/assessments' | Where-Object { $_ -and $Keys.ContainsKey(([string]$_.name).ToLowerInvariant()) })
    $byResource = [ordered]@{}
    foreach ($assessment in $assessments) {
        $resourceId = $assessment.properties.resourceDetails.Id
        if (-not $resourceId) { $resourceId = $assessment.id -replace '(?i)/providers/Microsoft\.Security/assessments/[^/]+$', '' }
        $key = $resourceId.ToLowerInvariant()
        if (-not $byResource.Contains($key)) { $byResource[$key] = [pscustomobject]@{ Id = $resourceId; Items = [System.Collections.Generic.List[object]]::new() } }
        $byResource[$key].Items.Add($assessment)
    }
    if (-not $byResource.Count) { return New-SubscriptionFinding (New-NotApplicable $SubscriptionNotApplicable) }
    foreach ($entry in $byResource.Values) {
        $unhealthy = @($entry.Items | Where-Object { $_.properties.status.code -eq 'Unhealthy' } | ForEach-Object { $Keys[([string]$_.name).ToLowerInvariant()] } | Sort-Object -Unique)
        $healthy = @($entry.Items | Where-Object { $_.properties.status.code -eq 'Healthy' })
        $evidence = [ordered]@{ unhealthy = $unhealthy; assessments = @($entry.Items | ForEach-Object { "$($Keys[([string]$_.name).ToLowerInvariant()]): $($_.properties.status.code)" } | Sort-Object) }
        $result = if ($unhealthy) { New-Fail ($unhealthy -join '; ') $evidence } elseif ($healthy) { New-Pass $HealthyText $evidence } else { New-NotApplicable 'Not applicable to this resource' $evidence }
        New-Finding -ResourceId $entry.Id -ResourceType ($entry.Id -replace '^.*/providers/([^/]+/[^/]+)/.*$', '$1') -Result $result
    }
}

Add-AzTest @{
    Id          = 'AZ-DFA-001'
    Title       = 'Endpoint detection and response is healthy with current antivirus signatures'
    Category    = 'Endpoint security'
    Service     = 'Microsoft Defender for Cloud'
    Severity    = 'High'
    Description = 'Reads the Defender for Cloud EDR assessments of machines: EDR configuration issues, antivirus component disabled, outdated signatures and scans older than 7 days.'
    Rationale   = 'An installed but misconfigured or outdated EDR gives a false sense of protection; outdated signatures miss known malware.'
    Remediation = 'Resolve the listed issues on each machine (enable real-time protection, restore signature updates, run scans), following the remediation steps in the Defender for Cloud recommendation.'
    References  = @('https://learn.microsoft.com/azure/defender-for-cloud/endpoint-detection-response')
    Frameworks  = @{ MCSB = @('ES-2', 'ES-3'); WAF = 'SE:10' }
    Defender    = @{ 'dc5357d0-3858-4d17-a1a3-072840bff5be' = 'EDR configuration issues should be resolved on virtual machines'; '506d18a1-d571-4341-aad5-a7d363c5bbd4' = 'Anti-Virus component in your EDR is off or partially configured'; 'aafa7d27-01ae-40c6-a56c-1d0ef04b1d71' = 'Anti-Virus component of your EDR uses outdated signatures'; 'd44de051-1862-48f8-8476-192aee854699' = 'Anti-Virus scans of your EDR are out of 7 days' }
    Requires    = @('defender/assessments')
    Run         = {
        Get-AssessmentFindings -Keys @{ 'dc5357d0-3858-4d17-a1a3-072840bff5be' = 'EDR configuration issues'; '506d18a1-d571-4341-aad5-a7d363c5bbd4' = 'antivirus off or partially configured'; 'aafa7d27-01ae-40c6-a56c-1d0ef04b1d71' = 'outdated antivirus signatures'; 'd44de051-1862-48f8-8476-192aee854699' = 'antivirus scans older than 7 days' } -HealthyText 'EDR and antivirus healthy' -SubscriptionNotApplicable 'Defender for Cloud reports no EDR assessments (requires Defender for Servers)'
    }
}

Add-AzTest @{
    Id          = 'AZ-DFA-002'
    Title       = 'Machines have system updates installed'
    Category    = 'Posture and vulnerability management'
    Service     = 'Microsoft Defender for Cloud'
    Severity    = 'High'
    Description = "Reads the Defender for Cloud assessment 'System updates should be installed on your machines' (Azure Update Manager)."
    Rationale   = 'Missing security updates are among the most exploited weaknesses; attackers weaponize published patches within days.'
    Remediation = 'Install the missing updates and configure Azure Update Manager maintenance configurations with patch orchestration for regular, automatic patching.'
    References  = @('https://learn.microsoft.com/azure/update-manager/overview')
    Frameworks  = @{ MCSB = 'PV-6'; WAF = 'SE:08' }
    Defender    = @{ 'e1145ab1-eb4f-43d8-911b-36ddf771d13f' = 'System updates should be installed on your machines (powered by Azure Update Manager)' }
    Policy      = @{ 'f85bf3e0-d513-442e-89c3-1784ad63382b' = 'System updates should be installed on your machines (powered by Update Center)' }
    Requires    = @('defender/assessments')
    Run         = {
        Get-AssessmentFindings -Keys @{ 'e1145ab1-eb4f-43d8-911b-36ddf771d13f' = 'missing system updates' } -HealthyText 'System updates installed' -SubscriptionNotApplicable 'Defender for Cloud reports no system update assessments'
    }
}

Add-AzTest @{
    Id          = 'AZ-DFA-003'
    Title       = 'Vulnerability findings are resolved'
    Category    = 'Posture and vulnerability management'
    Service     = 'Microsoft Defender for Cloud'
    Severity    = 'High'
    Description = 'Reads the Defender for Cloud vulnerability assessments of machines, container images, running containers, AKS, SQL databases and function apps.'
    Rationale   = 'Known vulnerabilities in operating systems, images, packages and databases give attackers ready made exploits.'
    Remediation = 'Remediate the vulnerabilities listed in each Defender for Cloud recommendation (patch, rebuild images on patched base images, upgrade AKS), prioritizing exploitable and Internet exposed resources.'
    References  = @('https://learn.microsoft.com/azure/defender-for-cloud/remediate-vulnerability-findings-vm')
    Frameworks  = @{ MCSB = @('PV-6', 'PV-5'); WAF = 'SE:08' }
    Defender    = @{ '1195afff-c881-495e-9bc5-1486211ae03f' = 'Machines should have vulnerability findings resolved'; '44d12760-2cf2-4e6d-8613-8451c11c1abc' = 'Servers onboarded with MDE should have vulnerability findings resolved'; '33422d8f-ab1e-42be-bc9a-38685bb567b9' = 'Container images in Azure registry should have vulnerability findings resolved'; 'c5045ea3-afc6-4006-ab8f-86c8574dbf3d' = 'Containers running in Azure should have vulnerability findings resolved'; '5409cb02-6884-4de3-870d-c17b98bbe04f' = 'Vulnerable Azure Kubernetes Service should be updated to resolve vulnerability findings'; '82e20e14-edc5-4373-bfc4-f13121257c37' = 'SQL databases should have vulnerability findings resolved'; 'f97aa83c-9b63-4f9a-99f6-b22c4398f936' = 'SQL servers on machines should have vulnerability findings resolved'; 'afd071f0-ebaa-422b-bb2f-8a772a31db75' = 'Function apps should have vulnerability findings resolved' }
    Requires    = @('defender/assessments')
    Run         = {
        Get-AssessmentFindings -Keys @{ '1195afff-c881-495e-9bc5-1486211ae03f' = 'machine vulnerabilities'; '44d12760-2cf2-4e6d-8613-8451c11c1abc' = 'server vulnerabilities (MDE)'; '33422d8f-ab1e-42be-bc9a-38685bb567b9' = 'registry image vulnerabilities'; 'c5045ea3-afc6-4006-ab8f-86c8574dbf3d' = 'running container vulnerabilities'; '5409cb02-6884-4de3-870d-c17b98bbe04f' = 'AKS version vulnerabilities'; '82e20e14-edc5-4373-bfc4-f13121257c37' = 'SQL database vulnerabilities'; 'f97aa83c-9b63-4f9a-99f6-b22c4398f936' = 'SQL server on machine vulnerabilities'; 'afd071f0-ebaa-422b-bb2f-8a772a31db75' = 'function app vulnerabilities' } -HealthyText 'No open vulnerability findings' -SubscriptionNotApplicable 'Defender for Cloud reports no vulnerability assessments'
    }
}

Add-AzTest @{
    Id          = 'AZ-DFA-004'
    Title       = 'Machines meet the Azure compute security baseline'
    Category    = 'Posture and vulnerability management'
    Service     = 'Microsoft Defender for Cloud'
    Severity    = 'Medium'
    Description = 'Reads the Defender for Cloud assessments of operating system security configuration against the Azure compute security baseline (machine configuration).'
    Rationale   = 'Operating system hardening gaps (weak protocols, missing audit policy, unsafe services) make exploitation and lateral movement easier.'
    Remediation = 'Remediate the failed baseline rules on each machine, preferably through machine configuration with auto remediation or your configuration management tooling.'
    References  = @('https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows')
    Frameworks  = @{ MCSB = @('PV-4', 'PV-3'); WAF = 'SE:08'; ALZ = 'Enforce-ACSB' }
    Defender    = @{ '1f655fb7-63ca-4980-91a3-56dbc2b715c6' = 'Vulnerabilities in security configuration on your Linux machines should be remediated (powered by Guest Configuration)'; '8c3d9ad0-3639-4686-9cd2-2b2ab2609bda' = 'Vulnerabilities in security configuration on your Windows machines should be remediated (powered by Guest Configuration)' }
    Requires    = @('defender/assessments')
    Run         = {
        Get-AssessmentFindings -Keys @{ '1f655fb7-63ca-4980-91a3-56dbc2b715c6' = 'Linux baseline deviations'; '8c3d9ad0-3639-4686-9cd2-2b2ab2609bda' = 'Windows baseline deviations' } -HealthyText 'Baseline compliant' -SubscriptionNotApplicable 'Defender for Cloud reports no security baseline assessments (requires the guest configuration extension)'
    }
}
