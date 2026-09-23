#Network security: NSG exposure, segmentation, public addresses, DDoS, WAF, firewall, VPN and DNS

function Get-NsgAssociation {
    param($Nsg)
    return [ordered]@{ subnets = @($Nsg.properties.subnets | Where-Object { $_ }).Count; networkInterfaces = @($Nsg.properties.networkInterfaces | Where-Object { $_ }).Count }
}

function Test-NsgPorts {
    #evaluates a list of TCP ports on an NSG; returns a result with the exposed ports and allowing rules
    param($Record, [int[]]$Ports, [string]$Label)
    $exposed = [ordered]@{}
    foreach ($port in $Ports) {
        $rule = Get-NsgInternetExposure -Nsg $Record.resource -Port $port -Protocol Tcp
        if ($rule) { $exposed["$port"] = $rule.name }
    }
    $evidence = Get-NsgAssociation $Record.resource
    $evidence.exposedPorts = @($exposed.Keys)
    $evidence.allowingRules = @($exposed.Values | Sort-Object -Unique)
    if ($exposed.Count) { return New-Fail "$Label open to the Internet by rule(s) $($evidence.allowingRules -join ', ') (ports $($exposed.Keys -join ', '))" $evidence }
    New-Pass "$Label not open to the Internet" $evidence
}

$managementPortPolicy = @{ '22730e10-96f6-4aac-ad84-9383d35b5917' = 'Management ports should be closed on your virtual machines' }

Add-AzTest @{
    Id            = 'AZ-NET-001'
    Title         = 'RDP (3389) is not open to the Internet'
    Category      = 'Network security'
    Service       = 'Network security groups'
    Severity      = 'High'
    Description   = 'Evaluates the inbound rules of each network security group in priority order for TCP 3389 from any source (*, Internet, 0.0.0.0/0).'
    Rationale     = 'RDP exposed to the Internet is continuously brute forced and has a history of pre-authentication vulnerabilities; it is one of the most common initial access vectors.'
    Remediation   = 'Remove or restrict the rule to known source addresses, and use Azure Bastion or just-in-time VM access for administration.'
    References    = @('https://learn.microsoft.com/azure/bastion/bastion-overview')
    Frameworks    = @{ MCSB = @('NS-1', 'NS-3'); CIS = '7.1'; WAF = 'SE:06'; ALZ = 'Deny-MgmtPorts-Internet' }
    Policy        = $managementPortPolicy
    ResourceTypes = @('Microsoft.Network/networkSecurityGroups')
    Evaluate      = { param($Record) Test-NsgPorts -Record $Record -Ports 3389 -Label 'RDP' }
}

Add-AzTest @{
    Id            = 'AZ-NET-002'
    Title         = 'SSH (22) is not open to the Internet'
    Category      = 'Network security'
    Service       = 'Network security groups'
    Severity      = 'High'
    Description   = 'Evaluates the inbound rules of each network security group in priority order for TCP 22 from any source (*, Internet, 0.0.0.0/0).'
    Rationale     = 'SSH exposed to the Internet is continuously brute forced and exposes the host to SSH vulnerabilities.'
    Remediation   = 'Remove or restrict the rule to known source addresses, and use Azure Bastion or just-in-time VM access for administration.'
    References    = @('https://learn.microsoft.com/azure/bastion/bastion-overview')
    Frameworks    = @{ MCSB = @('NS-1', 'NS-3'); CIS = '7.2'; WAF = 'SE:06'; ALZ = 'Deny-MgmtPorts-Internet' }
    Policy        = $managementPortPolicy
    ResourceTypes = @('Microsoft.Network/networkSecurityGroups')
    Evaluate      = { param($Record) Test-NsgPorts -Record $Record -Ports 22 -Label 'SSH' }
}

Add-AzTest @{
    Id            = 'AZ-NET-003'
    Title         = 'UDP is not open to the Internet'
    Category      = 'Network security'
    Service       = 'Network security groups'
    Severity      = 'Medium'
    Description   = 'Finds inbound allow rules for UDP (or any protocol) from any source that are not overridden by a higher priority deny rule for all ports.'
    Rationale     = 'Internet facing UDP services (DNS, NTP, SNMP, SSDP, CLDAP, memcached) are abused for reflection and amplification DDoS attacks and expose services that are rarely meant to be public.'
    Remediation   = 'Remove the UDP allow rules or restrict them to the required source addresses and ports.'
    Frameworks    = @{ MCSB = @('NS-1', 'NS-8'); CIS = '7.3'; WAF = 'SE:06' }
    ResourceTypes = @('Microsoft.Network/networkSecurityGroups')
    Evaluate      = {
        param($Record)
        $rules = @(@($Record.resource.properties.securityRules) + @($Record.resource.properties.defaultSecurityRules) | Where-Object { $_ -and $_.properties.direction -eq 'Inbound' } | Sort-Object { [int]$_.properties.priority })
        $exposing = [System.Collections.Generic.List[string]]::new()
        $blockedAll = $false
        foreach ($rule in $rules) {
            $p = $rule.properties
            if ($p.protocol -notin '*', 'Udp') { continue }
            $sources = @($p.sourceAddressPrefix) + @($p.sourceAddressPrefixes) | Where-Object { $_ }
            if (-not ($sources | Where-Object { Test-InternetSource $_ })) { continue }
            $ranges = @($p.destinationPortRange) + @($p.destinationPortRanges) | Where-Object { $_ }
            if ($p.access -eq 'Deny' -and $ranges -contains '*') { $blockedAll = $true; break }
            if ($p.access -eq 'Allow') { $exposing.Add("$($rule.name) ($($ranges -join ','))") }
        }
        $evidence = Get-NsgAssociation $Record.resource
        $evidence.allowingRules = @($exposing)
        if ($exposing.Count) { return New-Fail "UDP open to the Internet by $($exposing -join ', ')" $evidence }
        New-Pass 'No UDP open to the Internet' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-NET-004'
    Title         = 'HTTP and HTTPS exposure to the Internet is restricted'
    Category      = 'Network security'
    Service       = 'Network security groups'
    Severity      = 'Low'
    Description   = 'Evaluates the inbound rules of each network security group for TCP 80 and 443 from any source.'
    Rationale     = 'Web ports opened directly on virtual machines bypass a web application firewall and are often opened wider than the application requires. Each exposure should be deliberate.'
    Remediation   = 'Publish web applications through Application Gateway or Front Door with WAF and restrict the NSG to their source addresses, or document and accept the direct exposure.'
    Frameworks    = @{ MCSB = @('NS-1', 'NS-6'); CIS = '7.4'; WAF = 'SE:06' }
    ResourceTypes = @('Microsoft.Network/networkSecurityGroups')
    Evaluate      = { param($Record) Test-NsgPorts -Record $Record -Ports 80, 443 -Label 'HTTP(S)' }
}

Add-AzTest @{
    Id            = 'AZ-NET-005'
    Title         = 'Database, file sharing and remote management ports are not open to the Internet'
    Category      = 'Network security'
    Service       = 'Network security groups'
    Severity      = 'High'
    Description   = 'Evaluates the inbound rules of each network security group for high risk TCP ports from any source: FTP (20, 21), Telnet (23), RPC/NetBIOS/SMB (135, 139, 445), LDAP (389, 636), SQL Server (1433, 1434), Oracle (1521), MySQL (3306), PostgreSQL (5432), WinRM (5985, 5986), Redis (6379), Elasticsearch (9200, 9300), memcached (11211) and MongoDB (27017).'
    Rationale     = 'These services are not designed for Internet exposure; exposed instances are found by scanners within minutes and are a leading cause of data breaches and ransomware.'
    Remediation   = 'Remove the rules or restrict them to specific source addresses; reach these services through private endpoints, VPN or Bastion.'
    Frameworks    = @{ MCSB = @('NS-1', 'NS-8'); WAF = 'SE:06' }
    ResourceTypes = @('Microsoft.Network/networkSecurityGroups')
    Evaluate      = { param($Record) Test-NsgPorts -Record $Record -Ports 20, 21, 23, 135, 139, 389, 445, 636, 1433, 1434, 1521, 3306, 5432, 5985, 5986, 6379, 9200, 9300, 11211, 27017 -Label 'High risk ports' }
}

#subnets that do not support or need an NSG
$nsgExemptSubnets = @('GatewaySubnet', 'AzureFirewallSubnet', 'AzureFirewallManagementSubnet', 'RouteServerSubnet')

Add-AzTest @{
    Id          = 'AZ-NET-006'
    Version     = 2
    Title       = 'Subnets are associated with a network security group'
    Category    = 'Network security'
    Service     = 'Virtual network'
    Severity    = 'Medium'
    Description = 'Checks every subnet (except GatewaySubnet, AzureFirewallSubnet, AzureFirewallManagementSubnet and RouteServerSubnet) for an associated network security group.'
    Rationale   = 'Without an NSG a subnet has no layer 4 filtering: every resource in it can be reached from the whole virtual network (and peered networks), which enables lateral movement.'
    Remediation = 'Associate an NSG with each subnet (az network vnet subnet update --network-security-group <nsg> ...) and deny subnet creation without NSG through Azure Policy.'
    References  = @('https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview')
    Frameworks  = @{ MCSB = 'NS-1'; CIS = '7.11'; WAF = 'SE:04'; ALZ = 'Deny-Subnet-Without-Nsg' }
    Policy      = @{ 'e71308d3-144b-4262-b144-efdc3cc90517' = 'Subnets should be associated with a Network Security Group' }
    Run         = {
        foreach ($vnet in (Get-AzResourceRecords -Type 'Microsoft.Network/virtualNetworks')) {
            foreach ($subnet in @($vnet.resource.properties.subnets | Where-Object { $_ -and $_.name -notin $nsgExemptSubnets })) {
                $nsg = $subnet.properties.networkSecurityGroup.id
                $evidence = [ordered]@{ virtualNetwork = $vnet.resource.name; networkSecurityGroup = $nsg; delegations = @($subnet.properties.delegations | ForEach-Object { $_.properties.serviceName }) }
                $result = if ($nsg) { New-Pass "NSG $(Get-ResourceName $nsg)" $evidence } else { New-Fail 'No network security group' $evidence }
                New-Finding -ResourceId $subnet.id -ResourceType 'Microsoft.Network/virtualNetworks/subnets' -ResourceName "$($vnet.resource.name)/$($subnet.name)" -Result $result
            }
        }
    }
}

Add-AzTest @{
    Id          = 'AZ-NET-007'
    Title       = 'Subnets do not use default outbound access'
    Category    = 'Network security'
    Service     = 'Virtual network'
    Severity    = 'Low'
    Description = 'Checks that subnets are private (defaultOutboundAccess set to false), so virtual machines only reach the Internet through an explicit egress path.'
    Rationale   = 'Default outbound access gives virtual machines an implicit, unmanaged public IP for egress that bypasses egress filtering and logging. Microsoft is retiring it in favor of explicit outbound methods.'
    Remediation = 'Configure an explicit outbound path (Azure Firewall or NAT Gateway) and set defaultOutboundAccess to false on the subnet (az network vnet subnet update --default-outbound-access false ...).'
    References  = @('https://learn.microsoft.com/azure/virtual-network/ip-services/default-outbound-access')
    Frameworks  = @{ MCSB = @('NS-1', 'NS-3'); WAF = 'SE:06'; ALZ = 'Enforce-Subnet-Private' }
    Policy      = @{ '7bca8353-aa3b-429b-904a-9229c4385837' = 'Subnets should be private' }
    Run         = {
        foreach ($vnet in (Get-AzResourceRecords -Type 'Microsoft.Network/virtualNetworks')) {
            foreach ($subnet in @($vnet.resource.properties.subnets | Where-Object { $_ -and $_.name -notin ($nsgExemptSubnets + 'AzureBastionSubnet') })) {
                $evidence = [ordered]@{ virtualNetwork = $vnet.resource.name; defaultOutboundAccess = $subnet.properties.defaultOutboundAccess; natGateway = $subnet.properties.natGateway.id }
                $result = if ($subnet.properties.defaultOutboundAccess -eq $false) { New-Pass 'Private subnet' $evidence } else { New-Fail 'Default outbound access is enabled' $evidence }
                New-Finding -ResourceId $subnet.id -ResourceType 'Microsoft.Network/virtualNetworks/subnets' -ResourceName "$($vnet.resource.name)/$($subnet.name)" -Result $result
            }
        }
    }
}

Add-AzTest @{
    Id            = 'AZ-NET-008'
    Title         = 'Network interfaces do not have public IP addresses'
    Category      = 'Network security'
    Service       = 'Networking'
    Severity      = 'Medium'
    Description   = 'Finds network interfaces with a public IP address in any IP configuration.'
    Rationale     = 'A public IP address on a VM network interface exposes the machine directly to the Internet, where a single NSG mistake is enough for compromise. Ingress should pass through a load balancer, gateway or firewall.'
    Remediation   = 'Remove the public IP address from the network interface and publish services through Application Gateway, Front Door, a load balancer or Azure Firewall; administer through Bastion.'
    Frameworks    = @{ MCSB = @('NS-1', 'NS-2'); WAF = 'SE:06'; ALZ = @('Deny-Public-IP-On-NIC', 'Deny-Public-IP') }
    Policy        = @{ '83a86a26-fd1f-447c-b59d-e51f44264114' = 'Network interfaces should not have public IPs' }
    ResourceTypes = @('Microsoft.Network/networkInterfaces')
    Evaluate      = {
        param($Record)
        $publicIps = @($Record.resource.properties.ipConfigurations | ForEach-Object { $_.properties.publicIPAddress.id } | Where-Object { $_ })
        $evidence = [ordered]@{ publicIpAddresses = $publicIps; virtualMachine = $Record.resource.properties.virtualMachine.id }
        if ($publicIps) { return New-Fail "Public IP $(($publicIps | ForEach-Object { Get-ResourceName $_ }) -join ', ')" $evidence }
        New-Pass 'No public IP address' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-NET-009'
    Title         = 'IP forwarding is disabled on network interfaces'
    Category      = 'Network security'
    Service       = 'Networking'
    Severity      = 'Medium'
    Description   = 'Finds network interfaces with IP forwarding enabled.'
    Rationale     = 'IP forwarding lets a VM route traffic that is not addressed to it, which can bypass network segmentation. Only network virtual appliances need it.'
    Remediation   = 'Disable IP forwarding (az network nic update --ip-forwarding false ...) on all interfaces that are not network virtual appliances.'
    Frameworks    = @{ MCSB = 'NS-3'; ALZ = 'Deny-IP-forwarding' }
    Policy        = @{ 'bd352bd5-2853-4985-bf0d-73806b4a5744' = 'IP Forwarding on your virtual machine should be disabled' }
    ResourceTypes = @('Microsoft.Network/networkInterfaces')
    Evaluate      = {
        param($Record)
        $evidence = [ordered]@{ enableIPForwarding = [bool]$Record.resource.properties.enableIPForwarding }
        if ($Record.resource.properties.enableIPForwarding) { return New-Fail 'IP forwarding is enabled' $evidence }
        New-Pass 'IP forwarding is disabled' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-NET-010'
    Title         = 'Virtual networks are protected by DDoS Network Protection'
    Category      = 'Network security'
    Service       = 'DDoS Protection'
    Severity      = 'Medium'
    Description   = 'Checks virtual networks for DDoS Network Protection (a DDoS protection plan).'
    Rationale     = 'Basic infrastructure protection does not tune mitigation to your applications or provide attack telemetry, cost protection and rapid response support.'
    Remediation   = 'Associate a DDoS protection plan (one plan can protect many virtual networks across subscriptions), or use DDoS IP Protection on individual public IP addresses.'
    References    = @('https://learn.microsoft.com/azure/ddos-protection/ddos-protection-overview')
    Frameworks    = @{ MCSB = 'NS-5'; CIS = '8.5'; ALZ = 'Enable-DDoS-VNET' }
    Policy        = @{ '94de2ad3-e0c1-4caf-ad78-5d47bbc83d3d' = 'Virtual networks should be protected by Azure DDoS Protection'; 'a7aca53f-2ed4-4466-a25e-0b45ade68efd' = 'Azure DDoS Protection should be enabled' }
    ResourceTypes = @('Microsoft.Network/virtualNetworks')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ enableDdosProtection = [bool]$p.enableDdosProtection; ddosProtectionPlan = $p.ddosProtectionPlan.id }
        if ($p.enableDdosProtection -and $p.ddosProtectionPlan) { return New-Pass 'DDoS Network Protection enabled' $evidence }
        New-Fail 'No DDoS Network Protection plan' $evidence
    }
}

Add-AzTest @{
    Id          = 'AZ-NET-011'
    Title       = 'Azure Bastion is available for virtual machine administration'
    Category    = 'Network security'
    Service     = 'Azure Bastion'
    Severity    = 'Low'
    Description = 'Checks that the subscription has an Azure Bastion host when it contains virtual machines.'
    Rationale   = 'Bastion provides RDP and SSH over TLS through the Azure control plane with Entra authentication, removing the need to expose management ports or public IP addresses.'
    Remediation = 'Deploy Azure Bastion (Standard or Premium, or a shared Bastion in a hub network peered with this subscription) and remove direct management access.'
    References  = @('https://learn.microsoft.com/azure/bastion/bastion-overview')
    Frameworks  = @{ MCSB = @('NS-1', 'PA-6'); CIS = '8.4.1' }
    Requires    = @('subscription/resources')
    Run         = {
        $resources = @(Get-IngestData 'subscription/resources' | Where-Object { $_ })
        $vms = @($resources | Where-Object { $_.type -in 'Microsoft.Compute/virtualMachines', 'Microsoft.Compute/virtualMachineScaleSets' })
        $bastions = @($resources | Where-Object { $_.type -eq 'Microsoft.Network/bastionHosts' })
        $evidence = [ordered]@{ virtualMachines = $vms.Count; bastionHosts = @($bastions | ForEach-Object name | Sort-Object) }
        if (-not $vms) { return New-SubscriptionFinding (New-NotApplicable 'No virtual machines' $evidence) }
        if ($bastions) { return New-SubscriptionFinding (New-Pass "Bastion host(s): $($evidence.bastionHosts -join ', ')" $evidence) }
        New-SubscriptionFinding (New-Fail 'Virtual machines exist but no Bastion host in this subscription (a hub Bastion may be used)' $evidence)
    }
}

Add-AzTest @{
    Id            = 'AZ-NET-012'
    Title         = 'Application Gateways use a Web Application Firewall'
    Category      = 'Network security'
    Service       = 'Application Gateway'
    Severity      = 'High'
    Description   = 'Checks Application Gateways for the WAF_v2 tier with an associated WAF policy (or an enabled legacy WAF configuration).'
    Rationale     = 'A WAF blocks common web attacks (OWASP top 10, bots, known CVE exploits) before they reach the application.'
    Remediation   = 'Upgrade to the WAF_v2 SKU and associate a WAF policy in Prevention mode; migrate legacy WAF configurations to WAF policies.'
    References    = @('https://learn.microsoft.com/azure/web-application-firewall/ag/ag-overview')
    Frameworks    = @{ MCSB = 'NS-6'; CIS = '7.10'; WAF = 'SE:06'; ALZ = 'Audit-AppGW-WAF' }
    Policy        = @{ '564feb30-bf6a-4854-b4bb-0d2d2d1e6c66' = 'Web Application Firewall (WAF) should be enabled for Application Gateway' }
    ResourceTypes = @('Microsoft.Network/applicationGateways')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ skuTier = $p.sku.tier; firewallPolicy = $p.firewallPolicy.id; legacyWafEnabled = [bool]$p.webApplicationFirewallConfiguration.enabled }
        if ($p.sku.tier -like 'WAF*' -and ($p.firewallPolicy -or $p.webApplicationFirewallConfiguration.enabled)) { return New-Pass 'WAF enabled' $evidence }
        New-Fail 'No Web Application Firewall' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-NET-013'
    Title         = 'Application Gateways require TLS 1.2 or higher'
    Category      = 'Data protection'
    Service       = 'Application Gateway'
    Severity      = 'Medium'
    Description   = 'Checks the SSL policy of Application Gateways for a minimum protocol version of TLS 1.2.'
    Rationale     = 'TLS 1.0 and 1.1 have known weaknesses and are retired across Azure; the listener policy should not negotiate them.'
    Remediation   = 'Set the SSL policy to AppGwSslPolicy20220101 or AppGwSslPolicy20220101S (or CustomV2 with minimum TLSv1_2).'
    References    = @('https://learn.microsoft.com/azure/application-gateway/application-gateway-ssl-policy-overview')
    Frameworks    = @{ MCSB = @('DP-3', 'NS-8'); CIS = '7.12'; ALZ = 'Enforce-TLS-SSL-Q225' }
    Policy        = @{ '6313cbe8-6fb7-451b-a9e3-3f23b59843ca' = 'Azure Application Gateway should be running TLS version 1.2 or newer' }
    ResourceTypes = @('Microsoft.Network/applicationGateways')
    Evaluate      = {
        param($Record)
        $policy = $Record.resource.properties.sslPolicy
        $evidence = [ordered]@{ policyType = $policy.policyType; policyName = $policy.policyName; minProtocolVersion = $policy.minProtocolVersion }
        $strong = @('AppGwSslPolicy20170401S', 'AppGwSslPolicy20220101', 'AppGwSslPolicy20220101S')
        if ($policy.minProtocolVersion) {
            if (Test-VersionAtLeast $policy.minProtocolVersion '1.2') { return New-Pass "Minimum $($policy.minProtocolVersion)" $evidence }
            return New-Fail "Minimum $($policy.minProtocolVersion)" $evidence
        }
        if ($policy.policyName -in $strong) { return New-Pass "Predefined policy $($policy.policyName)" $evidence }
        if (-not $policy) { return New-Fail 'No SSL policy set; older gateways default to a policy that allows TLS 1.0' $evidence }
        New-Fail "Policy $($policy.policyName) allows TLS versions below 1.2" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-NET-014'
    Title         = 'Application Gateways have HTTP/2 enabled'
    Category      = 'Network security'
    Service       = 'Application Gateway'
    Severity      = 'Informational'
    Description   = 'Checks the enableHttp2 setting of Application Gateways.'
    Rationale     = 'CIS recommends HTTP/2 on Application Gateway for its protocol efficiencies and header handling improvements over HTTP/1.1.'
    Remediation   = 'Enable HTTP/2 on the gateway (az network application-gateway update --http2 Enabled ...).'
    Frameworks    = @{ MCSB = 'NS-8'; CIS = '7.13' }
    ResourceTypes = @('Microsoft.Network/applicationGateways')
    Evaluate      = {
        param($Record)
        $evidence = [ordered]@{ enableHttp2 = [bool]$Record.resource.properties.enableHttp2 }
        if ($Record.resource.properties.enableHttp2) { return New-Pass 'HTTP/2 enabled' $evidence }
        New-Fail 'HTTP/2 disabled' $evidence
    }
}

$wafPolicyTypes = @('Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies', 'Microsoft.Network/frontdoorWebApplicationFirewallPolicies', 'Microsoft.Cdn/cdnWebApplicationFirewallPolicies')

Add-AzTest @{
    Id            = 'AZ-NET-015'
    Title         = 'WAF policies are enabled in Prevention mode'
    Category      = 'Network security'
    Service       = 'Web Application Firewall'
    Severity      = 'High'
    Description   = 'Checks Application Gateway, Front Door and CDN WAF policies for the enabled state and Prevention mode.'
    Rationale     = 'A WAF in Detection mode or disabled only logs attacks; it does not stop them.'
    Remediation   = 'After tuning exclusions in Detection mode, switch the policy to Prevention mode and keep it enabled.'
    References    = @('https://learn.microsoft.com/azure/web-application-firewall/ag/policy-overview')
    Frameworks    = @{ MCSB = 'NS-6'; WAF = 'SE:06' }
    Policy        = @{ '12430be1-6cc8-4527-a9a8-e3d38f250096' = 'Web Application Firewall (WAF) should use the specified mode for Application Gateway'; '425bea59-a659-4cbb-8d31-34499bd030b8' = 'Web Application Firewall (WAF) should use the specified mode for Azure Front Door Service' }
    ResourceTypes = $wafPolicyTypes
    Evaluate      = {
        param($Record)
        $settings = $Record.resource.properties.policySettings
        $enabled = if ($settings.PSObject.Properties.Name -contains 'state') { $settings.state -eq 'Enabled' } else { $settings.enabledState -eq 'Enabled' }
        $evidence = [ordered]@{ mode = $settings.mode; enabled = $enabled }
        if ($enabled -and $settings.mode -eq 'Prevention') { return New-Pass 'Enabled in Prevention mode' $evidence }
        New-Fail "WAF policy is $(if ($enabled) { 'enabled' } else { 'disabled' }) in $($settings.mode) mode" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-NET-016'
    Title         = 'WAF policies inspect request bodies'
    Category      = 'Network security'
    Service       = 'Web Application Firewall'
    Severity      = 'Medium'
    Description   = 'Checks Application Gateway and Front Door WAF policies for request body inspection.'
    Rationale     = 'Without request body inspection, attacks carried in POST bodies (SQL injection, XSS, deserialization payloads) are not evaluated by the WAF.'
    Remediation   = 'Enable request body inspection in the WAF policy settings.'
    Frameworks    = @{ MCSB = 'NS-6'; CIS = '7.14' }
    Policy        = @{ 'ca85ef9a-741d-461d-8b7a-18c2da82c666' = 'Azure Web Application Firewall on Azure Application Gateway should have request body inspection enabled'; '4598f028-de1f-4694-8751-84dceb5f86b9' = 'Azure Web Application Firewall on Azure Front Door should have request body inspection enabled' }
    ResourceTypes = $wafPolicyTypes
    Evaluate      = {
        param($Record)
        $check = $Record.resource.properties.policySettings.requestBodyCheck
        $evidence = [ordered]@{ requestBodyCheck = $check }
        if ($check -eq $true -or $check -eq 'Enabled') { return New-Pass 'Request body inspection enabled' $evidence }
        New-Fail 'Request body inspection disabled' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-NET-017'
    Title         = 'WAF policies have bot protection enabled'
    Category      = 'Network security'
    Service       = 'Web Application Firewall'
    Severity      = 'Low'
    Description   = 'Checks Application Gateway and Front Door WAF policies for the Microsoft bot manager managed rule set.'
    Rationale     = 'The bot manager rule set blocks known malicious bots and scanners based on Microsoft threat intelligence.'
    Remediation   = 'Add the Microsoft_BotManagerRuleSet managed rule set to the WAF policy.'
    Frameworks    = @{ MCSB = 'NS-6'; CIS = '7.15' }
    ResourceTypes = $wafPolicyTypes
    Evaluate      = {
        param($Record)
        $sets = @($Record.resource.properties.managedRules.managedRuleSets | Where-Object { $_ } | ForEach-Object { $_.ruleSetType })
        $evidence = [ordered]@{ managedRuleSets = $sets }
        if ($sets | Where-Object { $_ -match 'BotManager|BotProtection' }) { return New-Pass 'Bot protection enabled' $evidence }
        New-Fail 'No bot protection rule set' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-NET-018'
    Title         = 'Front Door endpoints are protected by a WAF policy'
    Category      = 'Network security'
    Service       = 'Azure Front Door'
    Severity      = 'High'
    Description   = 'Checks Front Door Standard/Premium profiles for a security policy (WAF) and classic Front Door frontend endpoints for a WAF policy link.'
    Rationale     = 'Front Door publishes applications to the Internet; without a WAF policy, web attacks pass straight to the origin.'
    Remediation   = 'Create a WAF policy in Prevention mode and associate it with all Front Door domains through a security policy.'
    References    = @('https://learn.microsoft.com/azure/web-application-firewall/afds/afds-overview')
    Frameworks    = @{ MCSB = 'NS-6'; WAF = 'SE:06' }
    Policy        = @{ '055aa869-bc98-4af8-bafc-23f1ab6ffe2c' = 'Azure Web Application Firewall should be enabled for Azure Front Door entry-points' }
    ResourceTypes = @('Microsoft.Cdn/profiles', 'Microsoft.Network/frontDoors')
    Evaluate      = {
        param($Record)
        if ($Record.type -eq 'Microsoft.Network/frontDoors') {
            $unprotected = @($Record.resource.properties.frontendEndpoints | Where-Object { $_ -and -not $_.properties.webApplicationFirewallPolicyLink } | ForEach-Object name)
            $evidence = [ordered]@{ frontendEndpointsWithoutWaf = $unprotected }
            if ($unprotected) { return New-Fail "Frontend endpoint(s) without WAF: $($unprotected -join ', ')" $evidence }
            return New-Pass 'All frontend endpoints have a WAF policy' $evidence
        }
        if ($Record.resource.sku.name -notmatch 'AzureFrontDoor') { return $null }
        if (-not (Test-ChildCollected $Record 'securityPolicies')) { return New-Unknown 'Security policies could not be read' }
        $policies = @(Get-Child $Record 'securityPolicies' | Where-Object { $_ -and $_.properties.parameters.type -eq 'WebApplicationFirewall' })
        $evidence = [ordered]@{ wafSecurityPolicies = @($policies | ForEach-Object name) }
        if ($policies) { return New-Pass 'WAF security policy associated' $evidence }
        New-Fail 'No WAF security policy on the Front Door profile' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-NET-019'
    Title         = 'Azure Firewall threat intelligence is set to alert and deny'
    Category      = 'Network security'
    Service       = 'Azure Firewall'
    Severity      = 'Medium'
    Description   = 'Checks firewall policies (and firewalls with classic rules) for threat intelligence mode Deny.'
    Rationale     = 'Threat intelligence based filtering blocks traffic to and from known malicious IP addresses and domains, such as command and control servers.'
    Remediation   = "Set the threat intelligence mode to 'Alert and deny' in the firewall policy (az network firewall policy update --threat-intel-mode Deny ...)."
    References    = @('https://learn.microsoft.com/azure/firewall/threat-intel')
    Frameworks    = @{ MCSB = 'NS-3'; WAF = 'SE:06' }
    Policy        = @{ 'da79a7e2-8aa1-45ed-af81-ba050c153564' = 'Azure Firewall Policy should enable Threat Intelligence'; '7c591a93-c34c-464c-94ac-8f9f9a46e3d6' = 'Azure Firewall Standard - Classic Rules should enable Threat Intelligence' }
    ResourceTypes = @('Microsoft.Network/firewallPolicies', 'Microsoft.Network/azureFirewalls')
    Evaluate      = {
        param($Record)
        if ($Record.type -eq 'Microsoft.Network/azureFirewalls' -and $Record.resource.properties.firewallPolicy) { return $null }
        $mode = $Record.resource.properties.threatIntelMode
        $evidence = [ordered]@{ threatIntelMode = $mode }
        if ($mode -eq 'Deny') { return New-Pass 'Threat intelligence alerts and denies' $evidence }
        New-Fail "Threat intelligence mode is $mode" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-NET-020'
    Title         = 'Azure Firewall intrusion detection and prevention (IDPS) is enabled'
    Category      = 'Network security'
    Service       = 'Azure Firewall'
    Severity      = 'Medium'
    Description   = 'Checks firewall policies for the Premium tier with IDPS in Alert or Deny mode.'
    Rationale     = 'Signature based IDPS detects and blocks exploits, malware and command and control traffic, including in TLS inspected flows.'
    Remediation   = 'Upgrade to Azure Firewall Premium and set IDPS to Alert and deny in the firewall policy.'
    References    = @('https://learn.microsoft.com/azure/firewall/premium-features')
    Frameworks    = @{ MCSB = 'NS-4'; WAF = 'SE:06' }
    Policy        = @{ '8c19196d-7fd7-45b2-a9b4-7288f47c769a' = 'Azure Firewall Standard should be upgraded to Premium for next generation protection' }
    ResourceTypes = @('Microsoft.Network/firewallPolicies')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $mode = $p.intrusionDetection.mode
        $evidence = [ordered]@{ tier = $p.sku.tier; idpsMode = $mode }
        if ($p.sku.tier -eq 'Premium' -and $mode -in 'Alert', 'Deny') { return New-Pass "IDPS in $mode mode" $evidence }
        New-Fail $(if ($p.sku.tier -ne 'Premium') { "Firewall policy tier $($p.sku.tier) has no IDPS" } else { 'IDPS is off' }) $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-NET-021'
    Title         = 'Point-to-site VPN uses Microsoft Entra authentication only'
    Category      = 'Identity management'
    Service       = 'VPN Gateway'
    Severity      = 'Medium'
    Description   = 'Checks VPN gateways with point-to-site configuration for Microsoft Entra ID as the only authentication type.'
    Rationale     = 'Entra authentication applies MFA, Conditional Access and central account lifecycle to VPN users; certificate and RADIUS authentication do not.'
    Remediation   = 'Configure point-to-site with Azure Active Directory (Entra ID) authentication only and remove certificate and RADIUS authentication.'
    References    = @('https://learn.microsoft.com/azure/vpn-gateway/openvpn-azure-ad-tenant')
    Frameworks    = @{ MCSB = @('IM-1', 'IM-6'); CIS = '7.9' }
    Policy        = @{ '21a6bc25-125e-4d13-b82d-2e19b7208ab7' = 'VPN gateways should use only Azure Active Directory (Azure AD) authentication for point-to-site users' }
    ResourceTypes = @('Microsoft.Network/virtualNetworkGateways')
    Evaluate      = {
        param($Record)
        $config = $Record.resource.properties.vpnClientConfiguration
        if (-not $config -or -not $config.vpnClientAddressPool) { return $null }
        $types = @($config.vpnAuthenticationTypes)
        $evidence = [ordered]@{ vpnAuthenticationTypes = $types }
        if ($types.Count -eq 1 -and $types[0] -eq 'AAD') { return New-Pass 'Entra ID authentication only' $evidence }
        New-Fail "Authentication types: $($types -join ', ')" $evidence
    }
}

#DNS suffixes of Azure services whose names can be claimed by someone else when released
$claimableSuffixes = @('azurewebsites.net', 'cloudapp.net', 'cloudapp.azure.com', 'trafficmanager.net', 'blob.core.windows.net', 'web.core.windows.net', 'azureedge.net', 'azurefd.net', 'azure-api.net', 'azurecontainer.io', 'azurestaticapps.net', 'azurecontainerapps.io', 'search.windows.net', 'redis.cache.windows.net', 'azurehdinsight.net', 'servicebus.windows.net', 'azureml.ms')

function Get-SubscriptionHostNames {
    #host names of resources in this subscription that DNS records can point to
    $hosts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $add = { param($value) if ($value) { $null = $hosts.Add((([string]$value) -replace '^https?://', '' -replace '[/:].*$', '').TrimEnd('.')) } }
    foreach ($record in (Get-AzResourceRecords)) {
        $p = $record.resource.properties
        foreach ($value in @($p.defaultHostName, $p.defaultHostname, $p.dnsSettings.fqdn, $p.dnsConfig.fqdn, $p.fqdn, $p.hostName, $p.gatewayUrl, $p.configuration.ingress.fqdn) + @($p.hostNames) + @($p.enabledHostNames)) { & $add $value }
        foreach ($endpoint in @($p.primaryEndpoints.PSObject.Properties.Value) + @($p.secondaryEndpoints.PSObject.Properties.Value)) { if ($endpoint -is [string]) { & $add $endpoint } }
        foreach ($child in 'endpoints', 'afdEndpoints') { foreach ($item in @(Get-Child $record $child)) { if ($item) { & $add $item.properties.hostName } } }
    }
    return , $hosts
}

Add-AzTest @{
    Id          = 'AZ-NET-022'
    Version     = 2
    Title       = 'DNS records do not point to missing Azure resources (dangling DNS)'
    Category    = 'Network security'
    Service     = 'Azure DNS'
    Severity    = 'High'
    Description = 'Checks alias records and CNAME records in Azure DNS zones that target Azure service host names (for example *.azurewebsites.net, *.cloudapp.azure.com, *.blob.core.windows.net). An alias record pointing at a deleted resource in this subscription fails. A CNAME whose target is not in this subscription is reported Unknown: the target may well exist in another subscription or tenant, which this ingestion cannot see.'
    Rationale   = 'When an Azure resource is deleted but DNS still points to its name, an attacker can create a resource with the same name and take over the subdomain (phishing, cookie theft, bypassing allow lists).'
    Remediation = 'Delete DNS records that point to removed resources, and remove DNS records before (not after) deprovisioning resources. For each Unknown target, confirm that the name is still owned by your organization. Use alias records where possible, because those can be verified automatically.'
    References  = @('https://learn.microsoft.com/azure/security/fundamentals/subdomain-takeover')
    Frameworks  = @{ MCSB = 'NS-10'; WAF = 'SE:08' }
    Run         = {
        $zones = @(Get-AzResourceRecords -Type 'Microsoft.Network/dnszones')
        if (-not $zones) { return New-SubscriptionFinding (New-NotApplicable 'No public DNS zones') }
        $hosts = Get-SubscriptionHostNames
        foreach ($zone in $zones) {
            if (-not (Test-ChildCollected $zone 'recordsets')) { New-Finding -Record $zone -Result (New-Unknown 'Record sets could not be read'); continue }
            foreach ($recordSet in @(Get-Child $zone 'recordsets' | Where-Object { $_ })) {
                $p = $recordSet.properties
                $target = $p.CNAMERecord.cname
                if ($p.targetResource.id) {
                    $exists = [bool](Get-AzResourceRecord $p.targetResource.id) -or -not ($p.targetResource.id -match "^/subscriptions/$($script:Ingest.SubscriptionId)/")
                    $evidence = [ordered]@{ fqdn = $p.fqdn; aliasTarget = $p.targetResource.id }
                    $result = if ($exists) { New-Pass 'Alias target exists' $evidence } else { New-Fail "Alias record points to missing resource $($p.targetResource.id)" $evidence }
                    New-Finding -ResourceId $recordSet.id -ResourceType $recordSet.type -ResourceName $p.fqdn -Result $result
                    continue
                }
                if (-not $target) { continue }
                $cname = $target.TrimEnd('.')
                $suffix = $claimableSuffixes | Where-Object { $cname -like "*.$_" } | Select-Object -First 1
                if (-not $suffix) { continue }
                $evidence = [ordered]@{ fqdn = $p.fqdn; cname = $cname }
                #a name outside this subscription is not evidence of a dangling record: the resource may exist elsewhere
                $result = if ($hosts.Contains($cname)) { New-Pass 'Target exists in this subscription' $evidence } else { New-Unknown "CNAME points to $cname, which is not a resource in this subscription; verify that the name is still owned by your organization" $evidence }
                New-Finding -ResourceId $recordSet.id -ResourceType $recordSet.type -ResourceName $p.fqdn -Result $result
            }
        }
    }
}

Add-AzTest @{
    Id            = 'AZ-NET-023'
    Title         = 'Virtual machines with management ports open are covered by just-in-time access'
    Category      = 'Network security'
    Service       = 'Microsoft Defender for Cloud'
    Severity      = 'Medium'
    Description   = 'For each virtual machine whose network security groups allow RDP (3389), SSH (22), WinRM (5985, 5986) or the SQL port (1433) from the Internet, checks for a Defender for Cloud just-in-time network access policy covering that machine. Machines without such exposure are not applicable.'
    Rationale     = 'Just-in-time access keeps management ports closed and opens them to a requesting address for a limited time after an authorized, audited request, which removes the permanent exposure that scanners and brute force rely on.'
    Remediation   = "Enable just-in-time VM access in Defender for Cloud (Workload protections > Just-in-time VM access) for these machines, or remove the Internet facing management rule from the network security group."
    References    = @('https://learn.microsoft.com/azure/defender-for-cloud/just-in-time-access-usage')
    Frameworks    = @{ MCSB = @('NS-1', 'PA-6'); WAF = 'SE:06' }
    Policy        = @{ 'b0f33259-77d7-4c9e-aac6-3aabcfae693c' = 'Management ports of virtual machines should be protected with just-in-time network access control' }
    Requires      = @('defender/jitNetworkAccessPolicies')
    ResourceTypes = @('Microsoft.Compute/virtualMachines')
    Evaluate      = {
        param($Record)
        #network interfaces carry the NSG, or the subnet they sit in does
        $nsgIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($reference in @($Record.resource.properties.networkProfile.networkInterfaces | Where-Object { $_.id })) {
            $nic = Get-AzResourceRecord $reference.id
            if (-not $nic) { continue }
            if ($nic.resource.properties.networkSecurityGroup.id) { $null = $nsgIds.Add([string]$nic.resource.properties.networkSecurityGroup.id) }
            foreach ($configuration in @($nic.resource.properties.ipConfigurations | Where-Object { $_.properties.subnet.id })) {
                $subnetId = [string]$configuration.properties.subnet.id
                $vnet = Get-AzResourceRecord ($subnetId -replace '(?i)/subnets/[^/]+$', '')
                $subnet = @($vnet.resource.properties.subnets | Where-Object { $_.id -and $_.id -eq $subnetId }) | Select-Object -First 1
                if ($subnet.properties.networkSecurityGroup.id) { $null = $nsgIds.Add([string]$subnet.properties.networkSecurityGroup.id) }
            }
        }
        $exposed = [ordered]@{}
        foreach ($nsgId in $nsgIds) {
            $nsg = Get-AzResourceRecord $nsgId
            if (-not $nsg) { continue }
            foreach ($port in 22, 1433, 3389, 5985, 5986) {
                $rule = Get-NsgInternetExposure -Nsg $nsg.resource -Port $port -Protocol Tcp
                if ($rule) { $exposed["$port"] = "$($nsg.resource.name)/$($rule.name)" }
            }
        }
        if (-not $exposed.Count) { return New-NotApplicable 'No management port is open to the Internet on this machine' ([ordered]@{ networkSecurityGroups = @($nsgIds) }) }
        $covered = @(Get-IngestData 'defender/jitNetworkAccessPolicies' | Where-Object { $_ } | ForEach-Object { $_.properties.virtualMachines } | Where-Object { $_.id -and $_.id -eq $Record.id })
        $evidence = [ordered]@{ exposedPorts = @($exposed.Keys); allowingRules = @($exposed.Values | Sort-Object -Unique); jitPolicy = [bool]$covered }
        if ($covered) { return New-Pass 'Just-in-time access policy covers this machine' $evidence }
        New-Fail "Management port(s) $($exposed.Keys -join ', ') open to the Internet without a just-in-time policy" $evidence
    }
}
