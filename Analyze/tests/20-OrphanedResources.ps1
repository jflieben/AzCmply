#Orphaned resources: left behind when what used them was deleted. They cost money, keep data, access or attack surface
#outside any lifecycle, and make the environment harder to review. Resources whose lifecycle a service owns (an AKS node
#resource group, a managed application, Databricks) are left to that service.

function Get-ServiceManager {
    #the resource that manages a resource or its resource group, $null when nothing does
    param($Record)
    if ($Record.resource.managedBy) { return [string]$Record.resource.managedBy }
    if (-not $script:Ingest.Cache.ContainsKey('#groupManagers')) {
        $managers = @{}
        foreach ($group in @(Get-IngestData 'subscription/resourceGroups' | Where-Object { $_ -and $_.name })) { if ($group.managedBy) { $managers[([string]$group.name).ToLowerInvariant()] = [string]$group.managedBy } }
        $script:Ingest.Cache['#groupManagers'] = $managers
    }
    $group = Get-ResourceGroupName $Record.id
    if ($group -and $script:Ingest.Cache['#groupManagers'].ContainsKey($group.ToLowerInvariant())) { return $script:Ingest.Cache['#groupManagers'][$group.ToLowerInvariant()] }
    return $null
}

function Test-ResourceListed {
    #true when a resource id of this subscription is in the resource list or was read; ids of other subscriptions count
    #as existing unless their record was read and is gone (they cannot be listed from here)
    param([string]$Id)
    if (-not $Id) { return $false }
    $key = $Id.TrimEnd('/').ToLowerInvariant()
    if (-not $script:Ingest.Cache.ContainsKey('#listedIds')) {
        $listed = @{}
        $indexedTypes = @{}
        foreach ($item in @(Get-IngestData 'subscription/resources' | Where-Object { $_ -and $_.id })) { $listed[([string]$item.id).ToLowerInvariant()] = $true }
        foreach ($group in @(Get-IngestData 'subscription/resourceGroups' | Where-Object { $_ -and $_.id })) { $listed[([string]$group.id).ToLowerInvariant()] = $true }
        foreach ($entry in @($script:Ingest.Index | Where-Object { $_.id -and $_.type -ne 'resourceGroup' })) {
            $listed[([string]$entry.id).ToLowerInvariant()] = $true
            $indexedTypes[([string]$entry.type).ToLowerInvariant()] = $true
        }
        $script:Ingest.Cache['#listedIds'] = [pscustomobject]@{ Ids = $listed; Types = $indexedTypes }
    }
    $scope = (Get-SubscriptionScope).ToLowerInvariant()
    if ($key -eq $scope -or $key -notlike "$scope/*") { return $true }
    $known = $script:Ingest.Cache['#listedIds']
    if ($known.Ids.ContainsKey($key)) { return $true }
    #a child (subnet, blob service) exists with its parent, unless the ingestion reads its type as records (SQL databases)
    if ($key -match '^(/subscriptions/[^/]+/resourcegroups/[^/]+/providers/([^/]+)/([^/]+)/[^/]+)/([^/]+)/') {
        return $known.Ids.ContainsKey($Matches[1]) -and -not $known.Types.ContainsKey("$($Matches[2])/$($Matches[3])/$($Matches[4])")
    }
    return $false
}

function New-OrphanResult {
    #Pass or Fail with the service manager check that every orphan test shares
    param($Record, [bool]$Orphaned, [string]$FailDetail, [string]$PassDetail, $Evidence)
    $manager = Get-ServiceManager $Record
    if ($manager) { $Evidence.managedBy = $manager; return New-NotApplicable "Managed by $(Get-ResourceName $manager), which decides its lifecycle" $Evidence }
    if ($Orphaned) { return New-Fail $FailDetail $Evidence }
    New-Pass $PassDetail $Evidence
}

$orphanRationale = 'Resources that nothing uses any more are outside every lifecycle: nobody patches, reviews or monitors them, they keep data, access or reachable endpoints, and most of them are billed while unused.'

Add-AzTest @{
    Id            = 'AZ-GOV-018'
    Title         = 'No unattached network interfaces'
    Category      = 'Asset management'
    Service       = 'Networking'
    Severity      = 'Low'
    Description   = 'Finds network interfaces that are not attached to a virtual machine, a private endpoint or a private link service, and host no service workload.'
    Rationale     = "$orphanRationale An unattached network interface keeps its private IP address reserved, its public IP address if it has one, and its network security group rules."
    Remediation   = 'Delete network interfaces that are left from deleted virtual machines, after checking they are not about to be reused.'
    References    = @('https://learn.microsoft.com/azure/virtual-network/virtual-network-network-interface')
    ResourceTypes = @('Microsoft.Network/networkInterfaces')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ virtualMachine = $p.virtualMachine.id; privateEndpoint = $p.privateEndpoint.id; privateLinkService = $p.privateLinkService.id; hostedWorkloads = @($p.hostedWorkloads | Where-Object { $_ }).Count }
        $used = $p.virtualMachine.id -or $p.privateEndpoint.id -or $p.privateLinkService.id -or $evidence.hostedWorkloads
        New-OrphanResult $Record (-not $used) 'Not attached to any virtual machine, private endpoint or private link service' 'Attached' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-019'
    Title         = 'No network security groups without subnets or network interfaces'
    Category      = 'Asset management'
    Service       = 'Network security groups'
    Severity      = 'Low'
    Description   = 'Finds network security groups that are associated with no subnet and no network interface.'
    Rationale     = "$orphanRationale An unassociated group protects nothing but still looks like a control, and an old permissive one is easily associated again."
    Remediation   = 'Delete network security groups that no subnet or network interface uses.'
    References    = @('https://learn.microsoft.com/azure/virtual-network/manage-network-security-group')
    ResourceTypes = @('Microsoft.Network/networkSecurityGroups')
    Evaluate      = {
        param($Record)
        $evidence = Get-NsgAssociation $Record.resource
        New-OrphanResult $Record (-not ($evidence.subnets + $evidence.networkInterfaces)) 'Associated with no subnet and no network interface' 'Associated' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-020'
    Title         = 'No route tables without subnets'
    Category      = 'Asset management'
    Service       = 'Virtual network'
    Severity      = 'Low'
    Description   = 'Finds route tables that are associated with no subnet.'
    Rationale     = "$orphanRationale An unassociated route table suggests a subnet that lost its forced tunnelling to the firewall."
    Remediation   = 'Associate the route table with the subnets that need it, or delete it.'
    References    = @('https://learn.microsoft.com/azure/virtual-network/manage-route-table')
    ResourceTypes = @('Microsoft.Network/routeTables')
    Evaluate      = {
        param($Record)
        $evidence = [ordered]@{ subnets = @($Record.resource.properties.subnets | Where-Object { $_ }).Count; routes = @($Record.resource.properties.routes | Where-Object { $_ }).Count }
        New-OrphanResult $Record (-not $evidence.subnets) 'Associated with no subnet' 'Associated' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-021'
    Title         = 'No paid App Service plans without apps'
    Category      = 'Asset management'
    Service       = 'App Service'
    Severity      = 'Low'
    Description   = 'Finds App Service plans outside the Free tier on which no app runs (numberOfSites 0), as the Azure landing zones audit for unused resources does.'
    Rationale     = "$orphanRationale An App Service plan is billed for its instances whether or not apps run on it."
    Remediation   = 'Delete App Service plans that host no app, or scale them down to the Free tier while they wait for one.'
    References    = @('https://learn.microsoft.com/azure/app-service/overview-hosting-plans')
    ResourceTypes = @('Microsoft.Web/serverfarms')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ tier = $Record.resource.sku.tier; sku = $Record.resource.sku.name; apps = $p.numberOfSites }
        if ($null -eq $p.numberOfSites) { return New-Unknown 'The number of apps was not returned' $evidence }
        if ([string]$Record.resource.sku.tier -eq 'Free') { return New-NotApplicable 'Free plan, not billed' $evidence }
        New-OrphanResult $Record ([int]$p.numberOfSites -eq 0) 'No app runs on the plan, which is billed for its instances' "$($p.numberOfSites) app(s)" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-022'
    Title         = 'No load balancers without backend members'
    Category      = 'Asset management'
    Service       = 'Load Balancer'
    Severity      = 'Low'
    Description   = 'Finds load balancers with no member in any backend pool (network interface, scale set or IP address) and no inbound NAT rule that points to a machine.'
    Rationale     = "$orphanRationale A Standard load balancer is billed for its rules, and its public frontend stays reachable on the Internet."
    Remediation   = 'Delete load balancers left without backends, together with their public IP addresses.'
    References    = @('https://learn.microsoft.com/azure/load-balancer/backend-pool-management')
    ResourceTypes = @('Microsoft.Network/loadBalancers')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $members = @($p.backendAddressPools | Where-Object { $_ } | ForEach-Object { @($_.properties.backendIPConfigurations | Where-Object { $_ }) + @($_.properties.loadBalancerBackendAddresses | Where-Object { $_ }) }).Count
        $nat = @($p.inboundNatRules | Where-Object { $_ -and ($_.properties.backendIPConfiguration -or $_.properties.backendAddressPool) }).Count
        $evidence = [ordered]@{ sku = $Record.resource.sku.name; backendPools = @($p.backendAddressPools | Where-Object { $_ }).Count; backendMembers = $members; inboundNatRulesWithTarget = $nat }
        New-OrphanResult $Record (-not ($members + $nat)) 'No backend member and no NAT rule target' "$members backend member(s)" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-023'
    Title         = 'No Application Gateways without backend targets'
    Category      = 'Asset management'
    Service       = 'Application Gateway'
    Severity      = 'Low'
    Description   = 'Finds Application Gateways whose backend pools hold no address and no network interface.'
    Rationale     = "$orphanRationale An Application Gateway is billed per hour and per capacity unit, and its listeners stay published on the Internet."
    Remediation   = 'Delete Application Gateways that no longer publish anything, or stop them while they wait.'
    References    = @('https://learn.microsoft.com/azure/application-gateway/application-gateway-components#backend-pools')
    ResourceTypes = @('Microsoft.Network/applicationGateways')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $targets = @($p.backendAddressPools | Where-Object { $_ } | ForEach-Object { @($_.properties.backendAddresses | Where-Object { $_ }) + @($_.properties.backendIPConfigurations | Where-Object { $_ }) }).Count
        $evidence = [ordered]@{ backendPools = @($p.backendAddressPools | Where-Object { $_ }).Count; backendTargets = $targets; operationalState = $p.operationalState }
        New-OrphanResult $Record (-not $targets) 'No backend target in any pool' "$targets backend target(s)" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-024'
    Title         = 'No NAT gateways without subnets'
    Category      = 'Asset management'
    Service       = 'NAT Gateway'
    Severity      = 'Low'
    Description   = 'Finds NAT gateways that are associated with no subnet.'
    Rationale     = "$orphanRationale A NAT gateway is billed per hour together with its public IP addresses."
    Remediation   = 'Associate the NAT gateway with the subnets that need outbound access, or delete it and its public IP addresses.'
    References    = @('https://learn.microsoft.com/azure/nat-gateway/nat-overview')
    ResourceTypes = @('Microsoft.Network/natGateways')
    Evaluate      = {
        param($Record)
        $evidence = [ordered]@{ subnets = @($Record.resource.properties.subnets | Where-Object { $_ }).Count; publicIpAddresses = @($Record.resource.properties.publicIpAddresses | Where-Object { $_ }).Count }
        New-OrphanResult $Record (-not $evidence.subnets) 'Associated with no subnet' 'Associated' $evidence
    }
}

function Get-ConnectionReferences {
    #lowercase ids of the gateways and ExpressRoute circuits that connections in the subscription use (gateway connections
    #and Virtual WAN ExpressRoute connections); Unread is true when some of them could not be read
    if (-not $script:Ingest.Cache.ContainsKey('#connectionRefs')) {
        $refs = @{}
        foreach ($connection in (Get-AzResourceRecords -Type 'Microsoft.Network/connections')) {
            $p = $connection.resource.properties
            foreach ($id in @($p.virtualNetworkGateway1.id, $p.virtualNetworkGateway2.id, $p.localNetworkGateway2.id, $p.peer.id)) { if ($id) { $refs[([string]$id).ToLowerInvariant()] = $true } }
        }
        foreach ($gateway in (Get-AzResourceRecords -Type 'Microsoft.Network/expressRouteGateways')) {
            foreach ($erConnection in @($gateway.resource.properties.expressRouteConnections | Where-Object { $_ })) {
                $peering = [string]$erConnection.properties.expressRouteCircuitPeering.id
                if ($peering) { $refs[($peering -replace '(?i)/peerings/[^/]+$', '').ToLowerInvariant()] = $true }
            }
        }
        $script:Ingest.Cache['#connectionRefs'] = [pscustomobject]@{ Ids = $refs; Unread = @(Get-FailedResourceIds -Type 'Microsoft.Network/connections', 'Microsoft.Network/expressRouteGateways').Count -gt 0 }
    }
    return $script:Ingest.Cache['#connectionRefs']
}

Add-AzTest @{
    Id            = 'AZ-GOV-025'
    Title         = 'No VPN or ExpressRoute gateways without connections'
    Category      = 'Asset management'
    Service       = 'VPN Gateway'
    Severity      = 'Low'
    Description   = 'Finds virtual network gateways that no connection in the subscription uses and that offer no point-to-site configuration.'
    Rationale     = "$orphanRationale A gateway is billed per hour, often hundreds of euros a month, and its public endpoint stays reachable."
    Remediation   = 'Delete gateways whose connections were removed, or recreate the connection if it was deleted by mistake.'
    References    = @('https://learn.microsoft.com/azure/vpn-gateway/vpn-gateway-about-vpngateways')
    ResourceTypes = @('Microsoft.Network/virtualNetworkGateways')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $refs = Get-ConnectionReferences
        $pointToSite = @($p.vpnClientConfiguration.vpnClientAddressPool.addressPrefixes | Where-Object { $_ }).Count
        $connected = $refs.Ids.ContainsKey($Record.id.ToLowerInvariant())
        $evidence = [ordered]@{ gatewayType = $p.gatewayType; sku = $p.sku.name; usedByConnection = $connected; pointToSiteAddressPools = $pointToSite }
        if (-not $connected -and -not $pointToSite -and $refs.Unread) { return New-Unknown 'No connection uses the gateway, but some connections could not be read' $evidence }
        New-OrphanResult $Record (-not ($connected -or $pointToSite)) 'No connection uses the gateway and it has no point-to-site configuration' 'In use' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-026'
    Title         = 'No local network gateways without connections'
    Category      = 'Asset management'
    Service       = 'VPN Gateway'
    Severity      = 'Informational'
    Description   = 'Finds local network gateways (the on-premises side of a site-to-site VPN) that no connection in the subscription uses.'
    Rationale     = "$orphanRationale A leftover local network gateway keeps the address and address ranges of a site that may no longer belong to the organization, ready for a new connection."
    Remediation   = 'Delete local network gateways that no connection uses.'
    References    = @('https://learn.microsoft.com/azure/vpn-gateway/vpn-gateway-modify-local-network-gateway-portal')
    ResourceTypes = @('Microsoft.Network/localNetworkGateways')
    Evaluate      = {
        param($Record)
        $refs = Get-ConnectionReferences
        $connected = $refs.Ids.ContainsKey($Record.id.ToLowerInvariant())
        $evidence = [ordered]@{ gatewayIpAddress = $Record.resource.properties.gatewayIpAddress; fqdn = $Record.resource.properties.fqdn; usedByConnection = $connected }
        if (-not $connected -and $refs.Unread) { return New-Unknown 'No connection uses it, but some connections could not be read' $evidence }
        New-OrphanResult $Record (-not $connected) 'No connection uses this local network gateway' 'Used by a connection' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-045'
    Title         = 'No ExpressRoute circuits that nothing uses'
    Category      = 'Asset management'
    Service       = 'ExpressRoute'
    Severity      = 'Low'
    Description   = 'Finds ExpressRoute circuits that no gateway connection or Virtual WAN ExpressRoute gateway in this subscription uses, with no authorization in use by another subscription and no Global Reach connection.'
    Rationale     = "$orphanRationale An ExpressRoute circuit is billed every month for its bandwidth, whether traffic flows or not."
    Remediation   = 'Deprovision the circuit with the connectivity provider, then delete it.'
    References    = @('https://learn.microsoft.com/azure/expressroute/expressroute-howto-circuit-portal-resource-manager')
    ResourceTypes = @('Microsoft.Network/expressRouteCircuits')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $refs = Get-ConnectionReferences
        $connected = $refs.Ids.ContainsKey($Record.id.ToLowerInvariant())
        $authorizations = @($p.authorizations | Where-Object { $_ -and [string]$_.properties.authorizationUseStatus -eq 'InUse' }).Count
        $globalReach = @($p.peerings | Where-Object { $_ } | ForEach-Object { @($_.properties.connections | Where-Object { $_ }) }).Count
        $evidence = [ordered]@{ providerState = $p.serviceProviderProvisioningState; bandwidthMbps = $p.serviceProviderProperties.bandwidthInMbps; usedByConnection = $connected; authorizationsInUse = $authorizations; globalReachConnections = $globalReach }
        $used = $connected -or $authorizations -or $globalReach
        if (-not $used -and $refs.Unread) { return New-Unknown 'No connection uses the circuit, but some connections could not be read' $evidence }
        New-OrphanResult $Record (-not $used) 'No connection, authorization or Global Reach link uses the circuit' 'In use' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-027'
    Title         = 'No DDoS protection plans without virtual networks'
    Category      = 'Asset management'
    Service       = 'DDoS Protection'
    Severity      = 'Low'
    Description   = 'Finds DDoS protection plans that protect no virtual network, in this or any other subscription.'
    Rationale     = "$orphanRationale A DDoS protection plan costs a fixed fee of thousands of euros a month, whether it protects anything or not."
    Remediation   = 'Associate the plan with the virtual networks that need it, or delete it.'
    References    = @('https://learn.microsoft.com/azure/ddos-protection/manage-ddos-protection')
    ResourceTypes = @('Microsoft.Network/ddosProtectionPlans')
    Evaluate      = {
        param($Record)
        $evidence = [ordered]@{ virtualNetworks = @($Record.resource.properties.virtualNetworks | Where-Object { $_ }).Count }
        New-OrphanResult $Record (-not $evidence.virtualNetworks) 'Protects no virtual network, while its monthly fee is charged' "Protects $($evidence.virtualNetworks) virtual network(s)" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-028'
    Title         = 'No public IP prefixes without addresses'
    Category      = 'Asset management'
    Service       = 'Networking'
    Severity      = 'Low'
    Description   = 'Finds public IP prefixes from which no public IP address was created and that no NAT gateway or load balancer frontend uses.'
    Rationale     = "$orphanRationale A prefix is billed for every address in it."
    Remediation   = 'Delete public IP prefixes that nothing uses.'
    References    = @('https://learn.microsoft.com/azure/virtual-network/ip-services/public-ip-address-prefix')
    ResourceTypes = @('Microsoft.Network/publicIPPrefixes')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ prefixLength = $p.prefixLength; publicIpAddresses = @($p.publicIPAddresses | Where-Object { $_ }).Count; natGateway = $p.natGateway.id; loadBalancerFrontend = $p.loadBalancerFrontendIpConfiguration.id }
        New-OrphanResult $Record (-not ($evidence.publicIpAddresses -or $evidence.natGateway -or $evidence.loadBalancerFrontend)) 'No address, NAT gateway or load balancer uses the prefix' 'In use' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-029'
    Title         = 'Private DNS zones are linked to an existing virtual network'
    Category      = 'Asset management'
    Service       = 'Private DNS'
    Severity      = 'Low'
    Description   = 'Finds private DNS zones without a virtual network link to an existing network. Links to networks in other subscriptions count as existing.'
    Rationale     = "$orphanRationale A private link zone without a link resolves for nobody, so clients fall back to the public address of the service; its records outlive the resources they pointed to."
    Remediation   = 'Link the zone to the virtual networks (or the DNS resolver network) that need it, or delete the zone and the links to deleted networks.'
    References    = @('https://learn.microsoft.com/azure/dns/private-dns-virtual-network-links')
    Requires      = @('subscription/resources')
    ResourceTypes = @('Microsoft.Network/privateDnsZones')
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'virtualNetworkLinks')) { return New-Unknown 'The virtual network links could not be read' }
        $links = @(Get-Child $Record 'virtualNetworkLinks' | Where-Object { $_ })
        $dead = @($links | Where-Object { -not (Test-ResourceListed ([string]$_.properties.virtualNetwork.id)) } | ForEach-Object { [string]$_.properties.virtualNetwork.id })
        $evidence = [ordered]@{ links = $links.Count; linksToDeletedNetworks = $dead }
        New-OrphanResult $Record (($links.Count - $dead.Count) -le 0) $(if ($links.Count) { 'Only linked to virtual networks that no longer exist' } else { 'Not linked to any virtual network' }) "$($links.Count - $dead.Count) live link(s)" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-030'
    Title         = 'Private endpoints are connected'
    Category      = 'Asset management'
    Service       = 'Private Link'
    Severity      = 'Low'
    Description   = 'Finds private endpoints whose connection is Disconnected (the target resource was deleted) or Rejected.'
    Rationale     = "$orphanRationale A disconnected endpoint keeps a private IP address and DNS records that now point nowhere, or to whatever is created next under the same name."
    Remediation   = 'Delete private endpoints whose target no longer exists or rejected them, together with their private DNS records.'
    References    = @('https://learn.microsoft.com/azure/private-link/manage-private-endpoint')
    ResourceTypes = @('Microsoft.Network/privateEndpoints')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $connections = @(@($p.privateLinkServiceConnections) + @($p.manualPrivateLinkServiceConnections) | Where-Object { $_ })
        $states = @($connections | ForEach-Object { [string]$_.properties.privateLinkServiceConnectionState.status })
        $evidence = [ordered]@{ targets = @($connections | ForEach-Object { $_.properties.privateLinkServiceId }); states = $states }
        if (-not $connections) { return New-OrphanResult $Record $true 'The private endpoint has no connection' '' $evidence }
        New-OrphanResult $Record (-not @($states | Where-Object { $_ -notin 'Disconnected', 'Rejected' }).Count) "Connection $($states -join ', ')" "Connection $($states -join ', ')" $evidence
    }
}

Add-AzTest @{
    Id          = 'AZ-GOV-031'
    Title       = 'Virtual network peerings are connected'
    Category    = 'Asset management'
    Service     = 'Virtual network'
    Severity    = 'Low'
    Description = 'Finds virtual network peerings in the Disconnected state: the remote network or its side of the peering was deleted.'
    Rationale   = "$orphanRationale A disconnected peering carries no traffic, but it reconnects the moment a network with the same address space is peered back, which may not be the network the rules were written for."
    Remediation = 'Delete disconnected peerings, and recreate both sides if the connection is still needed.'
    References  = @('https://learn.microsoft.com/azure/virtual-network/virtual-network-manage-peering')
    Run         = {
        foreach ($network in @(Get-AzResourceRecords -Type 'Microsoft.Network/virtualNetworks' | Sort-Object id)) {
            foreach ($peering in @($network.resource.properties.virtualNetworkPeerings | Where-Object { $_ } | Sort-Object name)) {
                $state = [string]$peering.properties.peeringState
                $evidence = [ordered]@{ virtualNetwork = $network.resource.name; remoteVirtualNetwork = $peering.properties.remoteVirtualNetwork.id; peeringState = $state }
                $id = if ($peering.id) { [string]$peering.id } else { "$($network.id)/virtualNetworkPeerings/$($peering.name)" }
                $result = if ($state -eq 'Disconnected') { New-Fail 'The peering is disconnected' $evidence } else { New-Pass "Peering $state" $evidence }
                New-Finding -ResourceId $id -ResourceType 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings' -ResourceName "$($network.resource.name)/$($peering.name)" -Result $result
            }
        }
        foreach ($failedId in @(Get-FailedResourceIds -Type 'Microsoft.Network/virtualNetworks' | Sort-Object)) {
            New-Finding -ResourceId $failedId -ResourceType 'Microsoft.Network/virtualNetworks' -ResourceName (Get-ResourceName $failedId) -Result (New-Unknown 'The virtual network could not be read during ingestion')
        }
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-032'
    Title         = 'No empty availability sets'
    Category      = 'Asset management'
    Service       = 'Compute'
    Severity      = 'Informational'
    Description   = 'Finds availability sets that contain no virtual machine.'
    Rationale     = "$orphanRationale Empty availability sets are free, but they are left from deleted workloads and clutter reviews."
    Remediation   = 'Delete availability sets that hold no virtual machine.'
    References    = @('https://learn.microsoft.com/azure/virtual-machines/availability-set-overview')
    ResourceTypes = @('Microsoft.Compute/availabilitySets')
    Evaluate      = {
        param($Record)
        $evidence = [ordered]@{ virtualMachines = @($Record.resource.properties.virtualMachines | Where-Object { $_ }).Count }
        New-OrphanResult $Record (-not $evidence.virtualMachines) 'Contains no virtual machine' "$($evidence.virtualMachines) virtual machine(s)" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-033'
    Title         = 'No snapshots of disks that no longer exist'
    Category      = 'Asset management'
    Service       = 'Compute'
    Severity      = 'Low'
    Description   = 'Finds disk snapshots whose source disk in this subscription no longer exists. Snapshots of disks in other subscriptions and imported snapshots are not evaluated.'
    Rationale     = "$orphanRationale A snapshot of a deleted disk is a full copy of its data, often of a decommissioned machine with its credentials and secrets, billed per GB and outside every retention decision."
    Remediation   = 'Delete snapshots that no retention requirement covers, or move the ones you must keep into a governed backup.'
    References    = @('https://learn.microsoft.com/azure/virtual-machines/snapshot-copy-managed-disk')
    Requires      = @('subscription/resources')
    ResourceTypes = @('Microsoft.Compute/snapshots')
    Evaluate      = {
        param($Record)
        $source = [string]$Record.resource.properties.creationData.sourceResourceId
        $evidence = [ordered]@{ sourceResourceId = $source; timeCreated = $Record.resource.properties.timeCreated; diskSizeGB = $Record.resource.properties.diskSizeGB }
        if (-not $source -or $source -notmatch '(?i)/providers/Microsoft\.Compute/disks/') { return New-NotApplicable 'Not taken from a managed disk' $evidence }
        if ($source.ToLowerInvariant() -notlike "$((Get-SubscriptionScope).ToLowerInvariant())/*") { return New-NotApplicable 'The source disk is in another subscription' $evidence }
        New-OrphanResult $Record (-not (Test-ResourceListed $source)) 'The source disk no longer exists' 'The source disk exists' $evidence
    }
}

Add-AzTest @{
    Id          = 'AZ-GOV-034'
    Title       = 'No empty resource groups'
    Category    = 'Asset management'
    Service     = 'Azure Resource Manager'
    Severity    = 'Informational'
    Description = 'Finds resource groups that contain no resource, other than the ones another resource manages.'
    Rationale   = "$orphanRationale An empty resource group keeps its role assignments, policies and locks, ready to give whoever holds them a place to create resources."
    Remediation = 'Delete empty resource groups, together with their role assignments.'
    References  = @('https://learn.microsoft.com/azure/azure-resource-manager/management/manage-resource-groups-portal')
    Requires    = @('subscription/resources', 'subscription/resourceGroups')
    Run         = {
        $counts = @{}
        foreach ($item in @(Get-IngestData 'subscription/resources' | Where-Object { $_ -and $_.id })) {
            $group = Get-ResourceGroupName ([string]$item.id)
            if ($group) { $key = $group.ToLowerInvariant(); $counts[$key] = 1 + [int]$counts[$key] }
        }
        $assignments = @(Get-ActiveRoleAssignments)
        foreach ($group in @(Get-IngestData 'subscription/resourceGroups' | Where-Object { $_ -and $_.name } | Sort-Object id)) {
            $key = ([string]$group.name).ToLowerInvariant()
            $evidence = [ordered]@{ resources = [int]$counts[$key]; roleAssignments = @($assignments | Where-Object { ([string]$_.properties.scope).ToLowerInvariant() -eq ([string]$group.id).ToLowerInvariant() }).Count }
            if ($group.managedBy) { $evidence.managedBy = $group.managedBy; $result = New-NotApplicable "Managed by $(Get-ResourceName ([string]$group.managedBy))" $evidence }
            elseif ($evidence.resources) { $result = New-Pass "$($evidence.resources) resource(s)" $evidence }
            else { $result = New-Fail "Empty resource group with $($evidence.roleAssignments) role assignment(s)" $evidence }
            New-Finding -ResourceId $group.id -ResourceType 'Microsoft.Resources/resourceGroups' -ResourceName $group.name -Result $result
        }
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-035'
    Title         = 'No unused user-assigned managed identities'
    Category      = 'Asset management'
    Service       = 'Managed identities'
    Severity      = 'Low'
    Description   = 'Finds user-assigned managed identities that no resource or policy assignment in this subscription references, that hold no role assignment visible here and that have no federated credential. An identity used only from other subscriptions shows as unused.'
    Rationale     = "$orphanRationale An unused identity is an account nobody owns: anyone who can attach it, now or after a role is granted to it by mistake, acts as it."
    Remediation   = 'Delete user-assigned identities that nothing uses.'
    References    = @('https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/manage-user-assigned-managed-identities')
    Requires      = @('rbac/roleAssignments')
    ResourceTypes = @('Microsoft.ManagedIdentity/userAssignedIdentities')
    Evaluate      = {
        param($Record)
        #every reference to the identity in other resources (identity blocks, AKS kubelet identity, policy assignments)
        if (-not $script:Ingest.Cache.ContainsKey('#identityText')) {
            $texts = foreach ($other in (Get-AzResourceRecords)) { if ($other.type -ne 'Microsoft.ManagedIdentity/userAssignedIdentities') { ($other.resource | ConvertTo-Json -Depth 30 -Compress).ToLowerInvariant() } }
            $policies = (@(Get-PolicyAssignments) | ConvertTo-Json -Depth 30 -Compress)
            $script:Ingest.Cache['#identityText'] = "$($texts -join "`n")`n$([string]$policies)".ToLowerInvariant()
        }
        $principal = ([string]$Record.resource.properties.principalId).ToLowerInvariant()
        $referenced = $script:Ingest.Cache['#identityText'].Contains($Record.id.ToLowerInvariant())
        $roles = @(Get-ActiveRoleAssignments | Where-Object { $principal -and ([string]$_.properties.principalId).ToLowerInvariant() -eq $principal }).Count
        if (-not (Test-ChildCollected $Record 'federatedIdentityCredentials')) { return New-Unknown 'Federated credentials could not be read' }
        $federated = @(Get-Child $Record 'federatedIdentityCredentials' | Where-Object { $_ }).Count
        $evidence = [ordered]@{ referencedByResources = $referenced; roleAssignments = $roles; federatedCredentials = $federated }
        New-OrphanResult $Record (-not ($referenced -or $roles -or $federated)) 'No resource uses the identity, and it has no role assignment and no federated credential' 'In use' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-036'
    Title         = 'No SQL elastic pools without databases'
    Category      = 'Asset management'
    Service       = 'Azure SQL Database'
    Severity      = 'Low'
    Description   = 'Finds elastic pools of Azure SQL servers that hold no database.'
    Rationale     = "$orphanRationale An elastic pool is billed for its capacity whether databases use it or not."
    Remediation   = 'Move databases into the pool or delete it.'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/elastic-pool-overview')
    ResourceTypes = @('Microsoft.Sql/servers/elasticPools')
    Evaluate      = {
        param($Record)
        $poolId = $Record.id.ToLowerInvariant()
        $server = $poolId -replace '/elasticpools/[^/]+$', ''
        $databases = @(Get-AzResourceRecords -Type 'Microsoft.Sql/servers/databases' | Where-Object { $_.id.ToLowerInvariant().StartsWith("$server/") })
        $inPool = @($databases | Where-Object { ([string]$_.resource.properties.elasticPoolId).ToLowerInvariant() -eq $poolId })
        $evidence = [ordered]@{ sku = $Record.resource.sku.name; databases = @($inPool | ForEach-Object { $_.resource.name } | Sort-Object) }
        $unread = @(Get-FailedResourceIds -Type 'Microsoft.Sql/servers/databases' | Where-Object { ([string]$_).ToLowerInvariant().StartsWith("$server/") })
        if (-not $inPool -and $unread) { return New-Unknown 'No database is in the pool, but some databases of the server could not be read' $evidence }
        New-OrphanResult $Record (-not $inPool) 'No database is in the pool, which is billed for its capacity' "$($inPool.Count) database(s)" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-037'
    Title         = 'No Service Bus or Event Hubs namespaces without entities'
    Category      = 'Asset management'
    Service       = 'Messaging'
    Severity      = 'Low'
    Description   = 'Finds Service Bus namespaces without queues or topics and Event Hubs namespaces without event hubs.'
    Rationale     = "$orphanRationale Standard and Premium namespaces are billed per hour or per unit, and their access keys keep working."
    Remediation   = 'Delete namespaces that hold no entity.'
    References    = @('https://learn.microsoft.com/azure/service-bus-messaging/service-bus-messaging-overview')
    ResourceTypes = @('Microsoft.ServiceBus/namespaces', 'Microsoft.EventHub/namespaces')
    Evaluate      = {
        param($Record)
        $eventHubs = $Record.type -eq 'Microsoft.EventHub/namespaces'
        $children = if ($eventHubs) { @('eventhubs') } else { @('queues', 'topics') }
        $label = if ($eventHubs) { 'event hubs' } else { 'queues or topics' }
        $countLabel = if ($eventHubs) { 'event hub(s)' } else { 'queue(s) and topic(s)' }
        $unread = @($children | Where-Object { -not (Test-ChildCollected $Record $_) })
        if ($unread) { return New-Unknown "Could not list $($unread -join ', ')" }
        $evidence = [ordered]@{ sku = $Record.resource.sku.name }
        foreach ($child in $children) { $evidence[$child] = @(Get-Child $Record $child | Where-Object { $_ }).Count }
        $entities = 0
        foreach ($child in $children) { $entities += $evidence[$child] }
        New-OrphanResult $Record (-not $entities) "The namespace holds no $label" "$entities $countLabel" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-038'
    Title         = 'No Azure Virtual Desktop host pools without session hosts'
    Category      = 'Asset management'
    Service       = 'Azure Virtual Desktop'
    Severity      = 'Informational'
    Description   = 'Finds host pools that have no session host.'
    Rationale     = "$orphanRationale A host pool without session hosts keeps its application groups and assignments, and new hosts that join it get them straight away."
    Remediation   = 'Delete host pools, application groups and workspaces that no longer have session hosts.'
    References    = @('https://learn.microsoft.com/azure/virtual-desktop/terminology')
    ResourceTypes = @('Microsoft.DesktopVirtualization/hostPools')
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'sessionHosts')) { return New-Unknown 'Session hosts could not be listed' }
        $evidence = [ordered]@{ sessionHosts = @(Get-Child $Record 'sessionHosts' | Where-Object { $_ }).Count }
        New-OrphanResult $Record (-not $evidence.sessionHosts) 'No session host' "$($evidence.sessionHosts) session host(s)" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-039'
    Title         = 'No Front Door or CDN profiles without endpoints'
    Category      = 'Asset management'
    Service       = 'Azure Front Door'
    Severity      = 'Low'
    Description   = 'Finds Front Door Standard/Premium and CDN profiles without endpoints.'
    Rationale     = "$orphanRationale Front Door Standard and Premium profiles are billed a monthly base fee, and their WAF policies, certificates and custom domains stay configured."
    Remediation   = 'Delete profiles without endpoints, together with their custom domains and DNS records.'
    References    = @('https://learn.microsoft.com/azure/frontdoor/front-door-overview')
    ResourceTypes = @('Microsoft.Cdn/profiles')
    Evaluate      = {
        param($Record)
        $path = if ([string]$Record.resource.sku.name -match 'AzureFrontDoor') { 'afdEndpoints' } else { 'endpoints' }
        if (-not (Test-ChildCollected $Record $path)) { return New-Unknown 'Endpoints could not be listed' }
        $evidence = [ordered]@{ sku = $Record.resource.sku.name; endpoints = @(Get-Child $Record $path | Where-Object { $_ }).Count }
        New-OrphanResult $Record (-not $evidence.endpoints) 'The profile has no endpoint' "$($evidence.endpoints) endpoint(s)" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-040'
    Title         = 'No Traffic Manager profiles without enabled endpoints'
    Category      = 'Asset management'
    Service       = 'Traffic Manager'
    Severity      = 'Low'
    Description   = 'Finds Traffic Manager profiles that are disabled or have no enabled endpoint.'
    Rationale     = "$orphanRationale A profile whose endpoints are gone keeps its trafficmanager.net name, and CNAME records that point to it are open to takeover once it is deleted carelessly."
    Remediation   = 'Remove the DNS records that point to the profile, then delete it.'
    References    = @('https://learn.microsoft.com/azure/traffic-manager/traffic-manager-overview', 'https://learn.microsoft.com/azure/security/fundamentals/subdomain-takeover')
    ResourceTypes = @('Microsoft.Network/trafficManagerProfiles')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $enabled = @($p.endpoints | Where-Object { $_ -and [string]$_.properties.endpointStatus -ne 'Disabled' }).Count
        $evidence = [ordered]@{ profileStatus = $p.profileStatus; endpoints = @($p.endpoints | Where-Object { $_ }).Count; enabledEndpoints = $enabled; fqdn = $p.dnsConfig.fqdn }
        New-OrphanResult $Record ([string]$p.profileStatus -eq 'Disabled' -or -not $enabled) $(if ([string]$p.profileStatus -eq 'Disabled') { 'The profile is disabled' } else { 'No enabled endpoint' }) "$enabled enabled endpoint(s)" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-041'
    Title         = 'No unused application security groups'
    Category      = 'Asset management'
    Service       = 'Network security groups'
    Severity      = 'Informational'
    Description   = 'Finds application security groups that no network interface is a member of and no network security group rule uses.'
    Rationale     = "$orphanRationale A rule that names an empty group matches nothing, and a network interface added to an old group later inherits whatever the rules for it still allow."
    Remediation   = 'Delete application security groups that no rule and no network interface uses.'
    References    = @('https://learn.microsoft.com/azure/virtual-network/application-security-groups')
    ResourceTypes = @('Microsoft.Network/applicationSecurityGroups')
    Evaluate      = {
        param($Record)
        if (-not $script:Ingest.Cache.ContainsKey('#asgText')) {
            $texts = foreach ($other in (Get-AzResourceRecords -Type 'Microsoft.Network/networkInterfaces', 'Microsoft.Network/networkSecurityGroups')) { ($other.resource | ConvertTo-Json -Depth 30 -Compress).ToLowerInvariant() }
            $script:Ingest.Cache['#asgText'] = ($texts -join "`n")
        }
        $used = $script:Ingest.Cache['#asgText'].Contains($Record.id.ToLowerInvariant())
        $evidence = [ordered]@{ usedByInterfacesOrRules = $used }
        New-OrphanResult $Record (-not $used) 'No network interface or rule uses the group' 'In use' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-042'
    Title         = 'No firewall policies without firewalls'
    Category      = 'Asset management'
    Service       = 'Azure Firewall'
    Severity      = 'Informational'
    Description   = 'Finds Azure Firewall policies that no firewall uses and that are the parent of no other policy.'
    Rationale     = "$orphanRationale A detached policy no longer filters anything, but still reads as the rule base, which misleads reviews."
    Remediation   = 'Delete firewall policies that no firewall and no child policy uses.'
    References    = @('https://learn.microsoft.com/azure/firewall-manager/policy-overview')
    ResourceTypes = @('Microsoft.Network/firewallPolicies')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ firewalls = @($p.firewalls | Where-Object { $_ }).Count; childPolicies = @($p.childPolicies | Where-Object { $_ }).Count }
        New-OrphanResult $Record (-not ($evidence.firewalls + $evidence.childPolicies)) 'No firewall and no child policy uses it' 'In use' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-043'
    Title         = 'WAF policies are associated with a gateway, listener or Front Door'
    Category      = 'Asset management'
    Service       = 'Web Application Firewall'
    Severity      = 'Low'
    Description   = 'Finds Application Gateway, Front Door and CDN WAF policies that are associated with no gateway, listener, path rule, Front Door endpoint, security policy or CDN endpoint.'
    Rationale     = "$orphanRationale A WAF policy that protects nothing still passes the WAF checks, so the application it was meant for may in fact be unprotected."
    Remediation   = 'Associate the policy with the application it was made for, or delete it.'
    References    = @('https://learn.microsoft.com/azure/web-application-firewall/ag/policy-overview')
    ResourceTypes = $wafPolicyTypes
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $links = 0
        foreach ($name in 'applicationGateways', 'httpListeners', 'pathBasedRules', 'frontendEndpointLinks', 'securityPolicyLinks', 'routingRuleLinks', 'endpointLinks') { $links += @($p.$name | Where-Object { $_ }).Count }
        $evidence = [ordered]@{ associations = $links }
        New-OrphanResult $Record (-not $links) 'The policy protects nothing' "$links association(s)" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-GOV-044'
    Title         = 'App Service certificates are bound to an app'
    Category      = 'Asset management'
    Service       = 'App Service'
    Severity      = 'Low'
    Description   = 'Finds App Service certificates (Microsoft.Web/certificates) whose thumbprint no app or slot in the subscription uses in a TLS binding.'
    Rationale     = "$orphanRationale An unused certificate keeps its private key in the platform, and an expired one hides which domains are still served."
    Remediation   = 'Delete certificates that no TLS binding uses.'
    References    = @('https://learn.microsoft.com/azure/app-service/configure-ssl-certificate')
    ResourceTypes = @('Microsoft.Web/certificates')
    Evaluate      = {
        param($Record)
        if (-not $script:Ingest.Cache.ContainsKey('#boundThumbprints')) {
            $bound = @{}
            foreach ($site in (Get-AzResourceRecords -Type 'Microsoft.Web/sites', 'Microsoft.Web/sites/slots')) {
                foreach ($state in @($site.resource.properties.hostNameSslStates | Where-Object { $_ -and $_.thumbprint })) { $bound[([string]$state.thumbprint).ToUpperInvariant()] = $true }
            }
            $script:Ingest.Cache['#boundThumbprints'] = $bound
        }
        $p = $Record.resource.properties
        $thumbprint = ([string]$p.thumbprint).ToUpperInvariant()
        $evidence = [ordered]@{ subjectName = $p.subjectName; thumbprint = $thumbprint; expires = Format-UtcDate (ConvertTo-UtcDate $p.expirationDate) }
        if (-not $thumbprint) { return New-Unknown 'The thumbprint was not returned' $evidence }
        New-OrphanResult $Record (-not $script:Ingest.Cache['#boundThumbprints'].ContainsKey($thumbprint)) 'No app or slot uses the certificate' 'Bound to an app' $evidence
    }
}

function Get-DiagnosticDestinations {
    #destinations of a diagnostic setting as resource ids (event hub and Service Bus rules by their namespace)
    param($Setting)
    $p = $Setting.properties
    @(@($p.workspaceId, $p.storageAccountId, $p.eventHubAuthorizationRuleId, $p.serviceBusRuleId) | Where-Object { $_ } | ForEach-Object { ([string]$_) -replace '(?i)/authorizationrules/[^/]+$', '' })
}

Add-AzTest @{
    Id          = 'AZ-LOG-036'
    Title       = 'Diagnostic settings send to destinations that exist'
    Category    = 'Logging and threat detection'
    Service     = 'Azure Monitor'
    Severity    = 'Medium'
    Description = 'Finds diagnostic settings of resources and of the subscription activity log whose Log Analytics workspace, storage account or event hub namespace in this subscription no longer exists. Destinations in other subscriptions are not evaluated.'
    Rationale   = 'A diagnostic setting whose destination was deleted delivers nothing, while the resource still looks as if its logs are collected. The gap shows only when an investigation needs the logs.'
    Remediation = 'Point the diagnostic setting to an existing destination (the central Log Analytics workspace), or delete it and create a new one.'
    References  = @('https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings')
    Requires    = @('subscription/resources')
    Run         = {
        $sources = [System.Collections.Generic.List[object]]::new()
        foreach ($record in @(Get-AzResourceRecords | Where-Object { $null -ne $_.diagnosticSettings } | Sort-Object id)) { $sources.Add([pscustomobject]@{ Id = $record.id; Type = $record.type; Name = $record.resource.name; Settings = @($record.diagnosticSettings | Where-Object { $_ }) }) }
        if (Test-IngestSection 'subscription/diagnosticSettings') { $sources.Add([pscustomobject]@{ Id = (Get-SubscriptionScope); Type = 'Microsoft.Resources/subscriptions'; Name = 'activity log'; Settings = @(Get-IngestData 'subscription/diagnosticSettings' | Where-Object { $_ }) }) }
        $findings = foreach ($source in $sources) {
            $missing = @(foreach ($setting in $source.Settings) { foreach ($destination in (Get-DiagnosticDestinations $setting)) { if (-not (Test-ResourceListed $destination)) { "$($setting.name) > $destination" } } })
            if (-not $missing) { continue }
            New-Finding -ResourceId $source.Id -ResourceType $source.Type -ResourceName $source.Name -Result (New-Fail "Diagnostic setting(s) send to destinations that no longer exist: $(@($missing | Sort-Object -Unique) -join '; ')" ([ordered]@{ missingDestinations = @($missing | Sort-Object -Unique) }))
        }
        if (-not $findings) { return New-SubscriptionFinding (New-Pass 'Every diagnostic setting sends to an existing destination') }
        $findings
    }
}

Add-AzTest @{
    Id            = 'AZ-LOG-037'
    Title         = 'Alert rules monitor resources that exist'
    Category      = 'Logging and threat detection'
    Service       = 'Azure Monitor'
    Severity      = 'Medium'
    Description   = 'Finds enabled metric, log search and activity log alert rules whose scopes in this subscription (resources or resource groups) no longer exist. Scopes in other subscriptions are not evaluated.'
    Rationale     = 'An alert rule on a deleted resource never fires again, so the monitoring that was set up for a workload, or for its replacement under another name, silently stops.'
    Remediation   = 'Point the alert rule to the resources that replaced the deleted ones, or delete it.'
    References    = @('https://learn.microsoft.com/azure/azure-monitor/alerts/alerts-manage-alert-rules')
    Requires      = @('subscription/resources', 'subscription/resourceGroups')
    ResourceTypes = @('Microsoft.Insights/metricAlerts', 'Microsoft.Insights/scheduledQueryRules', 'Microsoft.Insights/activityLogAlerts')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $scopes = @($p.scopes | Where-Object { $_ })
        $missing = @($scopes | Where-Object { -not (Test-ResourceListed ([string]$_)) })
        $evidence = [ordered]@{ enabled = $(if ($null -ne $p.enabled) { $p.enabled } else { $p.isEnabled }); scopes = $scopes; missingScopes = $missing }
        if ($p.enabled -eq $false -or $p.isEnabled -eq $false) { return New-NotApplicable 'The alert rule is disabled' $evidence }
        if (-not $scopes) { return New-Unknown 'The alert rule reports no scope' $evidence }
        if ($missing.Count -eq $scopes.Count) { return New-Fail "Every scope of the rule no longer exists: $($missing -join ', ')" $evidence }
        if ($missing) { return New-Fail "Some scopes of the rule no longer exist: $($missing -join ', ')" $evidence }
        New-Pass 'All scopes exist' $evidence
    }
}
