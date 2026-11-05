#Databases: Azure SQL, SQL Managed Instance, PostgreSQL and MySQL flexible server, Cosmos DB, Azure Cache for Redis

function Get-ServerParameter {
    #value of a server parameter from the 'configurations' child (PostgreSQL / MySQL); $null when the parameter is not in it
    param($Record, [string]$Name)
    $item = @(Get-Child $Record 'configurations') | Where-Object { $_ -and $_.name -eq $Name } | Select-Object -First 1
    if (-not $item) { return $null }
    return [string]$item.properties.value
}

function Get-ServerParameterResult {
    #Pass when a server parameter has the required value (case-insensitive); Unknown when the parameters or this parameter were not read
    param($Record, [string]$Name, [string]$Required)
    if (-not (Test-ChildCollected $Record 'configurations')) { return New-Unknown 'Server parameters could not be read' }
    $value = Get-ServerParameter $Record $Name
    $evidence = [ordered]@{ $Name = $value }
    if ($null -eq $value) { return New-Unknown "Server parameter $Name was not returned" $evidence }
    if ($value -eq $Required) { return New-Pass "$Name is $value" $evidence }
    New-Fail "$Name is $(if ($value) { $value } else { 'empty' })" $evidence
}

function Test-PrivateEndpointsCollected {
    #true when the private endpoint connections were read, in the resource body or as child
    param($Record)
    $p = $Record.resource.properties
    if ($null -ne $p -and $p.PSObject.Properties.Name -contains 'privateEndpointConnections') { return $true }
    return (Test-ChildCollected $Record 'privateEndpointConnections')
}

function Get-ApprovedPrivateEndpointCount {
    #number of approved private endpoint connections in the resource body and the child
    param($Record)
    $connections = @($Record.resource.properties.privateEndpointConnections) + @(Get-Child $Record 'privateEndpointConnections') | Where-Object { $_ -and $_.properties.privateLinkServiceConnectionState.status -eq 'Approved' }
    return @($connections | ForEach-Object { [string]$_.id } | Sort-Object -Unique).Count
}

function ConvertTo-IPv4Number {
    param([string]$Address)
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$parsed) -or $parsed.AddressFamily -ne 'InterNetwork') { return $null }
    $bytes = $parsed.GetAddressBytes()
    return ([uint64]$bytes[0] -shl 24) + ([uint64]$bytes[1] -shl 16) + ([uint64]$bytes[2] -shl 8) + [uint64]$bytes[3]
}

function Test-DatabaseFirewallCollected {
    #false when the firewall rules of a database service were not read, so "no wide rules" cannot be concluded.
    #Cosmos DB carries its rules on the resource itself, so there is nothing separate to collect.
    param($Record)
    if ($Record.type -eq 'Microsoft.DocumentDB/databaseAccounts') { return $true }
    return (Test-ChildCollected $Record 'firewallRules')
}

function Get-DatabaseFirewallRules {
    #firewall rules of a database service as objects with Name, Start and End (IPv4), or Prefix (IPv6)
    param($Record)
    switch ($Record.type) {
        'Microsoft.Cache/Redis' {
            foreach ($rule in @(Get-Child $Record 'firewallRules' | Where-Object { $_ })) { [pscustomobject]@{ Name = $rule.name; Start = $rule.properties.startIP; End = $rule.properties.endIP; Prefix = $null } }
        }
        'Microsoft.DocumentDB/databaseAccounts' {
            foreach ($rule in @($Record.resource.properties.ipRules | Where-Object { $_ })) {
                $value = [string]$rule.ipAddressOrRange
                if ($value -eq '0.0.0.0') { [pscustomobject]@{ Name = $value; Start = '0.0.0.0'; End = '0.0.0.0'; Prefix = $null }; continue }
                if ($value -match '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') {
                    $start = ConvertTo-IPv4Number $Matches[1]
                    $size = [math]::Pow(2, 32 - [int]$Matches[2])
                    $endNumber = [uint64]($start + $size - 1)
                    $end = '{0}.{1}.{2}.{3}' -f (($endNumber -shr 24) -band 255), (($endNumber -shr 16) -band 255), (($endNumber -shr 8) -band 255), ($endNumber -band 255)
                    [pscustomobject]@{ Name = $value; Start = $Matches[1]; End = $end; Prefix = $null }
                    continue
                }
                [pscustomobject]@{ Name = $value; Start = $value; End = $value; Prefix = $null }
            }
        }
        default {
            foreach ($rule in @(Get-Child $Record 'firewallRules' | Where-Object { $_ })) { [pscustomobject]@{ Name = $rule.name; Start = $rule.properties.startIpAddress; End = $rule.properties.endIpAddress; Prefix = $null } }
            #SQL servers keep IPv6 allow rules in a separate collection; a wide IPv6 rule exposes the endpoint just as much
            foreach ($rule in @(Get-Child $Record 'ipv6FirewallRules' | Where-Object { $_ })) {
                [pscustomobject]@{ Name = $rule.name; Start = $null; End = $null; Prefix = "$($rule.properties.startIPv6Address)-$($rule.properties.endIPv6Address)" }
            }
        }
    }
}

function Test-IPv6RuleWide {
    #true when an IPv6 firewall rule spans the whole address space or an unreasonably large prefix
    param($Rule)
    if (-not $Rule.Prefix) { return $false }
    $start, $end = ($Rule.Prefix -split '-')
    if (-not $start -or -not $end) { return $false }
    $from = $null; $to = $null
    if (-not [System.Net.IPAddress]::TryParse($start, [ref]$from) -or -not [System.Net.IPAddress]::TryParse($end, [ref]$to)) { return $false }
    if ($from.AddressFamily -ne 'InterNetworkV6' -or $to.AddressFamily -ne 'InterNetworkV6') { return $false }
    #compare the first 8 bytes (a /64 or wider range is already far beyond a single client)
    $a = $from.GetAddressBytes(); $b = $to.GetAddressBytes()
    for ($i = 0; $i -lt 8; $i++) { if ($a[$i] -ne $b[$i]) { return $true } }
    return $false
}

function Get-WideFirewallRules {
    #'name (range)' of every rule that covers at least a /8 (IPv6: wider than a /64)
    param($Rules)
    $Rules | Where-Object {
        if ($_.Prefix) { return (Test-IPv6RuleWide $_) }
        $start = ConvertTo-IPv4Number $_.Start
        $end = ConvertTo-IPv4Number $_.End
        $null -ne $start -and $null -ne $end -and ($end - $start + 1) -ge 16777216
    } | ForEach-Object { "$($_.Name) ($(if ($_.Prefix) { $_.Prefix } else { "$($_.Start)-$($_.End)" }))" }
}

function Test-PublicNetworkDisabled {
    param($Record)
    $p = $Record.resource.properties
    return ($p.publicNetworkAccess -eq 'Disabled' -or $p.network.publicNetworkAccess -eq 'Disabled')
}

#SQL servers have their own variants (AZ-SQL-012, AZ-SQL-013)
$firewallTypes = @('Microsoft.Synapse/workspaces', 'Microsoft.DBforPostgreSQL/flexibleServers', 'Microsoft.DBforMySQL/flexibleServers', 'Microsoft.DBforPostgreSQL/servers', 'Microsoft.DBforMySQL/servers', 'Microsoft.Cache/Redis', 'Microsoft.DocumentDB/databaseAccounts')

Add-AzTest @{
    Id            = 'AZ-DB-001'
    Version       = 3
    Title         = 'Database firewalls do not allow access from the entire Internet'
    Category      = 'Network security'
    Service       = 'Databases'
    Severity      = 'Critical'
    Description   = 'Finds IPv4 and IPv6 firewall rules on Synapse workspaces, PostgreSQL and MySQL servers, Redis caches and Cosmos DB accounts that cover 0.0.0.0-255.255.255.255 or at least a /8 range (IPv6: wider than a /64), while public network access is enabled. SQL servers: AZ-SQL-012.'
    Rationale     = 'Such rules expose the database endpoint to every attacker on the Internet, leaving authentication as the only control against brute force and credential stuffing.'
    Remediation   = 'Delete the rule and allow only specific client addresses, or better, disable public network access and use private endpoints.'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/firewall-configure')
    ResourceTypes = $firewallTypes
    Evaluate      = {
        param($Record)
        if (Test-PublicNetworkDisabled $Record) { return New-Pass 'Public network access disabled, firewall rules do not apply' }
        if (-not (Test-DatabaseFirewallCollected $Record)) { return New-Unknown 'Firewall rules could not be read' }
        $rules = @(Get-DatabaseFirewallRules $Record)
        $wide = @(Get-WideFirewallRules $rules)
        $evidence = [ordered]@{ firewallRules = $rules.Count; wideRules = $wide }
        if ($wide) { return New-Fail "Internet wide rule(s): $($wide -join ', ')" $evidence }
        New-Pass 'No Internet wide firewall rules' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-DB-002'
    Version       = 3
    Title         = "Database firewalls do not allow all Azure services"
    Category      = 'Network security'
    Service       = 'Databases'
    Severity      = 'Medium'
    Description   = "Finds the 'Allow Azure services and resources to access this server' rule (0.0.0.0) on Synapse workspaces and PostgreSQL and MySQL servers. SQL servers: AZ-SQL-013; Cosmos DB: AZ-COS-005."
    Rationale     = 'The rule admits connections from any Azure resource of any customer, not just your own, so anyone can host a client in Azure and reach the database endpoint.'
    Remediation   = 'Remove the rule and use private endpoints, virtual network rules or managed identity based access for your Azure workloads.'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/firewall-configure')
    ResourceTypes = $firewallTypes
    Filter        = { param($Record) $Record.type -notin 'Microsoft.Cache/Redis', 'Microsoft.DocumentDB/databaseAccounts' }
    Evaluate      = {
        param($Record)
        if (Test-PublicNetworkDisabled $Record) { return New-Pass 'Public network access disabled, firewall rules do not apply' }
        if (-not (Test-DatabaseFirewallCollected $Record)) { return New-Unknown 'Firewall rules could not be read' }
        $azure = @(Get-DatabaseFirewallRules $Record | Where-Object { $_.Start -eq '0.0.0.0' -and $_.End -eq '0.0.0.0' } | ForEach-Object Name)
        $evidence = [ordered]@{ allowAzureRules = $azure }
        if ($azure) { return New-Fail "All Azure services allowed ($($azure -join ', '))" $evidence }
        New-Pass 'Azure services are not allowed wholesale' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-SQL-001'
    Title         = 'Auditing is enabled on SQL servers'
    Category      = 'Logging and threat detection'
    Service       = 'Azure SQL'
    Severity      = 'High'
    Description   = 'Checks that server level auditing is enabled on Azure SQL logical servers.'
    Rationale     = 'SQL auditing records logins, queries and permission changes. Without it, data theft and misuse of database access cannot be detected or investigated.'
    Remediation   = 'Enable server auditing to a Log Analytics workspace (az sql server audit-policy update --state Enabled --lats Enabled --lawri <workspace id> ...).'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/auditing-overview')
    Policy        = @{ 'a6fb4358-5bf4-4ad7-ba82-2cd2f41ce5e9' = 'Auditing on SQL server should be enabled' }
    ResourceTypes = @('Microsoft.Sql/servers')
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'auditingSettings')) { return New-Unknown 'Auditing settings could not be read' }
        $settings = @(Get-Child $Record 'auditingSettings') + @(Get-Child $Record 'extendedAuditingSettings') | Where-Object { $_ }
        $enabled = @($settings | Where-Object { $_.properties.state -eq 'Enabled' })
        $evidence = [ordered]@{ state = @($settings | ForEach-Object { $_.properties.state } | Sort-Object -Unique); logAnalytics = [bool]($enabled | Where-Object { $_.properties.isAzureMonitorTargetEnabled }); storage = [bool]($enabled | Where-Object { $_.properties.storageEndpoint }) }
        if ($enabled) { return New-Pass 'Server auditing enabled' $evidence }
        New-Fail 'Server auditing disabled' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-SQL-002'
    Version       = 2
    Title         = 'SQL auditing to storage retains logs for at least 90 days'
    Category      = 'Logging and threat detection'
    Service       = 'Azure SQL'
    Severity      = 'Low'
    Description   = 'Checks the retention of server auditing that writes to a storage account (0 means unlimited).'
    Rationale     = 'Database access logs are needed for investigations that start long after the activity.'
    Remediation   = 'Set the audit retention to 90 days or more, or 0 for unlimited (az sql server audit-policy update --retention-days 90 ...).'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/auditing-overview')
    Policy        = @{ '89099bee-89e0-4b26-a5f4-165451757743' = 'SQL servers with auditing to storage account destination should be configured with 90 days retention or higher' }
    ResourceTypes = @('Microsoft.Sql/servers')
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'auditingSettings')) { return New-Unknown 'Auditing settings could not be read' }
        $storage = @(Get-Child $Record 'auditingSettings') | Where-Object { $_ -and $_.properties.state -eq 'Enabled' -and $_.properties.storageEndpoint } | Select-Object -First 1
        if (-not $storage) { return New-NotApplicable 'No auditing to a storage account' }
        $days = [int]$storage.properties.retentionDays
        $evidence = [ordered]@{ retentionDays = $days }
        if ($days -eq 0 -or $days -ge 90) { return New-Pass $(if ($days -eq 0) { 'Unlimited retention' } else { "$days days retention" }) $evidence }
        New-Fail "$days days retention" $evidence
    }
}

function Get-SqlEntraAdmin {
    #Entra administrator of a SQL server, managed instance or Synapse workspace; $false when not collected
    param($Record)
    switch ($Record.type) {
        'Microsoft.Synapse/workspaces' {
            if (-not (Test-ChildCollected $Record 'sqlAdministrators/activeDirectory') -and -not (Test-ChildCollected $Record 'administrators/activeDirectory')) { return $false }
            $admin = Get-Child $Record 'sqlAdministrators/activeDirectory'
            if (-not $admin) { $admin = Get-Child $Record 'administrators/activeDirectory' }
            return $admin.properties.login
        }
        default {
            if (-not (Test-ChildCollected $Record 'administrators')) { return $false }
            return (@(Get-Child $Record 'administrators') | Where-Object { $_ } | Select-Object -First 1).properties.login
        }
    }
}

$sqlEntraAdminCheck = {
    param($Record)
    $admin = Get-SqlEntraAdmin $Record
    if ($admin -eq $false) { return New-Unknown 'Administrators could not be read' }
    $evidence = [ordered]@{ entraAdministrator = $admin }
    if ($admin) { return New-Pass "Entra administrator $admin" $evidence }
    New-Fail 'No Entra administrator' $evidence
}

Add-AzTest @{
    Id            = 'AZ-SQL-003'
    Version       = 2
    Title         = 'A Microsoft Entra administrator is configured for SQL servers'
    Category      = 'Identity management'
    Service       = 'Azure SQL'
    Severity      = 'Medium'
    Description   = 'Checks SQL logical servers for a Microsoft Entra administrator. Managed instances and Synapse workspaces: AZ-SQL-014.'
    Rationale     = 'Entra authentication enables MFA, Conditional Access, managed identities and central account lifecycle for database access; it requires an Entra administrator.'
    Remediation   = 'Set an Entra group as administrator (az sql server ad-admin create --display-name <group> --object-id <id> ...).'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/authentication-aad-configure')
    Policy        = @{ '1f314764-cb73-4fc9-b863-8eca98ac36e9' = 'An Azure Active Directory administrator should be provisioned for SQL servers' }
    ResourceTypes = @('Microsoft.Sql/servers')
    Evaluate      = $sqlEntraAdminCheck
}

Add-AzTest @{
    Id            = 'AZ-SQL-014'
    Title         = 'A Microsoft Entra administrator is configured for SQL managed instances and Synapse workspaces'
    Category      = 'Identity management'
    Service       = 'Azure SQL'
    Severity      = 'Medium'
    Description   = 'Checks SQL managed instances and Synapse workspaces for a Microsoft Entra administrator.'
    Rationale     = 'Entra authentication enables MFA, Conditional Access, managed identities and central account lifecycle for database access; it requires an Entra administrator.'
    Remediation   = 'Set an Entra group as administrator (az sql mi ad-admin create ..., az synapse sql ad-admin create ...).'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/authentication-aad-configure')
    ResourceTypes = @('Microsoft.Sql/managedInstances', 'Microsoft.Synapse/workspaces')
    Evaluate      = $sqlEntraAdminCheck
}

Add-AzTest @{
    Id            = 'AZ-SQL-004'
    Title         = 'SQL uses Microsoft Entra-only authentication'
    Category      = 'Identity management'
    Service       = 'Azure SQL'
    Severity      = 'Medium'
    Description   = 'Checks that SQL authentication is disabled (Entra-only authentication) on SQL logical servers, managed instances and Synapse workspaces.'
    Rationale     = 'SQL logins are passwords without MFA, lockout policies or central lifecycle management and are a common brute force target, including the server administrator login.'
    Remediation   = 'Move applications to Entra authentication (managed identities), then enable Entra-only authentication (az sql server ad-only-auth enable ...).'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/authentication-azure-ad-only-authentication')
    Policy        = @{ 'abda6d70-9778-44e7-84a8-06713e6db027' = 'Azure SQL logical servers should have Microsoft Entra-only authentication enabled during creation'; '78215662-041e-49ed-a9dd-5385911b3a1f' = 'Azure SQL Managed Instances should have Microsoft Entra-only authentication enabled during creation' }
    ResourceTypes = @('Microsoft.Sql/servers', 'Microsoft.Sql/managedInstances', 'Microsoft.Synapse/workspaces')
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'azureADOnlyAuthentications')) { return New-Unknown 'Entra-only authentication setting could not be read' }
        $setting = @(Get-Child $Record 'azureADOnlyAuthentications') | Where-Object { $_ } | Select-Object -First 1
        $evidence = [ordered]@{ azureADOnlyAuthentication = $setting.properties.azureADOnlyAuthentication }
        if ($setting.properties.azureADOnlyAuthentication -eq $true) { return New-Pass 'Entra-only authentication enabled' $evidence }
        New-Fail 'SQL authentication is allowed' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-SQL-005'
    Version       = 2
    Title         = 'SQL servers disable public network access'
    Category      = 'Network security'
    Service       = 'Azure SQL'
    Severity      = 'Medium'
    Description   = 'Checks that public network access of SQL logical servers is Disabled. Managed instances: AZ-SQL-011.'
    Rationale     = 'A public endpoint depends solely on firewall rules and authentication; private endpoints remove Internet exposure entirely.'
    Remediation   = 'Create private endpoints and set public network access to Disabled (az sql server update --enable-public-network false ...).'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/connectivity-settings')
    Policy        = @{ '1b8ca024-1d5c-4dec-8995-b1a932b41780' = 'Public network access on Azure SQL Database should be disabled' }
    ResourceTypes = @('Microsoft.Sql/servers')
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.publicNetworkAccess
        $evidence = [ordered]@{ publicNetworkAccess = $value }
        if ($value -eq 'Disabled') { return New-Pass 'Public network access disabled' $evidence }
        New-Fail "Public network access $(if ($value) { $value } else { 'not set' })" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-SQL-011'
    Title         = 'SQL managed instances disable the public data endpoint'
    Category      = 'Network security'
    Service       = 'Azure SQL'
    Severity      = 'Medium'
    Description   = 'Checks the public data endpoint of SQL managed instances.'
    Rationale     = 'The public data endpoint exposes the instance to the Internet, protected only by network security group rules and authentication.'
    Remediation   = 'Disable the public data endpoint (az sql mi update --public-data-endpoint-enabled false ...) and connect through the virtual network or private endpoints.'
    References    = @('https://learn.microsoft.com/azure/azure-sql/managed-instance/public-endpoint-overview')
    Policy        = @{ '9dfea752-dd46-4766-aed1-c355fa93fb91' = 'Azure SQL Managed Instances should disable public network access' }
    ResourceTypes = @('Microsoft.Sql/managedInstances')
    Evaluate      = {
        param($Record)
        $evidence = [ordered]@{ publicDataEndpointEnabled = [bool]$Record.resource.properties.publicDataEndpointEnabled }
        if ($Record.resource.properties.publicDataEndpointEnabled) { return New-Fail 'Public data endpoint enabled' $evidence }
        New-Pass 'Public data endpoint disabled' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-SQL-012'
    Title         = 'SQL server firewalls do not allow access from the entire Internet'
    Category      = 'Network security'
    Service       = 'Azure SQL'
    Severity      = 'Critical'
    Description   = 'Finds IPv4 and IPv6 firewall rules on SQL logical servers that cover 0.0.0.0-255.255.255.255 or at least a /8 range (IPv6: wider than a /64), while public network access is enabled. Database level rules (T-SQL only) are not read.'
    Rationale     = 'Such rules expose the database endpoint to every attacker on the Internet, leaving authentication as the only control against brute force and credential stuffing.'
    Remediation   = 'Delete the rule and allow only specific client addresses, or better, disable public network access and use private endpoints.'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/firewall-configure')
    ResourceTypes = @('Microsoft.Sql/servers')
    Evaluate      = {
        param($Record)
        if (Test-PublicNetworkDisabled $Record) { return New-Pass 'Public network access disabled, firewall rules do not apply' }
        if (-not (Test-ChildCollected $Record 'firewallRules')) { return New-Unknown 'Firewall rules could not be read' }
        $rules = @(Get-DatabaseFirewallRules $Record)
        $wide = @(Get-WideFirewallRules $rules)
        $evidence = [ordered]@{ firewallRules = $rules.Count; wideRules = $wide }
        if ($wide) { return New-Fail "Internet wide rule(s): $($wide -join ', ')" $evidence }
        New-Pass 'No Internet wide firewall rules' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-SQL-013'
    Title         = 'SQL server firewalls have no rules starting at 0.0.0.0'
    Category      = 'Network security'
    Service       = 'Azure SQL'
    Severity      = 'Medium'
    Description   = "Finds firewall rules on SQL logical servers whose start address is 0.0.0.0, including the 'Allow Azure services and resources to access this server' rule (0.0.0.0-0.0.0.0), while public network access is enabled."
    Rationale     = 'The 0.0.0.0 rule admits connections from any Azure resource of any customer, and a range starting at 0.0.0.0 admits a large part of the Internet.'
    Remediation   = 'Remove the rule and use private endpoints, virtual network rules or specific client addresses.'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/firewall-configure')
    ResourceTypes = @('Microsoft.Sql/servers')
    Evaluate      = {
        param($Record)
        if (Test-PublicNetworkDisabled $Record) { return New-Pass 'Public network access disabled, firewall rules do not apply' }
        if (-not (Test-ChildCollected $Record 'firewallRules')) { return New-Unknown 'Firewall rules could not be read' }
        $zero = @(Get-DatabaseFirewallRules $Record | Where-Object { $_.Start -eq '0.0.0.0' } | ForEach-Object { "$($_.Name) ($($_.Start)-$($_.End))" })
        $evidence = [ordered]@{ rulesFrom0000 = $zero }
        if ($zero) { return New-Fail "Rule(s) starting at 0.0.0.0: $($zero -join ', ')" $evidence }
        New-Pass 'No rule starts at 0.0.0.0' $evidence
    }
}

$sqlTlsCheck = {
    param($Record)
    $value = $Record.resource.properties.minimalTlsVersion
    $evidence = [ordered]@{ minimalTlsVersion = $value }
    if (Test-VersionAtLeast $value '1.2') { return New-Pass "Minimal TLS $value" $evidence }
    New-Fail "Minimal TLS $(if ($value) { $value } else { 'not set' })" $evidence
}

Add-AzTest @{
    Id            = 'AZ-SQL-006'
    Version       = 2
    Title         = 'SQL servers require TLS 1.2 or higher'
    Category      = 'Data protection'
    Service       = 'Azure SQL'
    Severity      = 'Medium'
    Description   = 'Checks the minimal TLS version of SQL logical servers. Managed instances: AZ-SQL-016.'
    Rationale     = 'Older TLS versions have known weaknesses. From 31 July 2026 Azure SQL requires TLS 1.2 for all connections; the setting should state it explicitly.'
    Remediation   = 'Set the minimal TLS version to 1.2 (az sql server update --minimal-tls-version 1.2 ...).'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/connectivity-settings')
    Policy        = @{ '32e6bbec-16b6-44c2-be37-c5b672d103cf' = 'Azure SQL Database should be running TLS version 1.2 or newer' }
    ResourceTypes = @('Microsoft.Sql/servers')
    Evaluate      = $sqlTlsCheck
}

Add-AzTest @{
    Id            = 'AZ-SQL-016'
    Title         = 'SQL managed instances require TLS 1.2 or higher'
    Category      = 'Data protection'
    Service       = 'Azure SQL'
    Severity      = 'Medium'
    Description   = 'Checks the minimal TLS version of SQL managed instances.'
    Rationale     = 'Older TLS versions have known weaknesses; the minimal version should be set to 1.2 or higher.'
    Remediation   = 'Set the minimal TLS version to 1.2 (az sql mi update --minimal-tls-version 1.2 ...).'
    References    = @('https://learn.microsoft.com/azure/azure-sql/managed-instance/minimal-tls-version-configure')
    Policy        = @{ 'a8793640-60f7-487c-b5c3-1d37215905c4' = 'SQL Managed Instance should have the minimal TLS version of 1.2' }
    ResourceTypes = @('Microsoft.Sql/managedInstances')
    Evaluate      = $sqlTlsCheck
}

$sqlTdeCheck = {
    param($Record)
    if (-not (Test-ChildCollected $Record 'transparentDataEncryption')) { return New-Unknown 'TDE state could not be read' }
    $state = (@(Get-Child $Record 'transparentDataEncryption') | Where-Object { $_ } | Select-Object -First 1).properties.state
    $evidence = [ordered]@{ state = $state }
    if ($state -eq 'Enabled') { return New-Pass 'TDE enabled' $evidence }
    New-Fail 'TDE disabled' $evidence
}

Add-AzTest @{
    Id            = 'AZ-SQL-007'
    Version       = 2
    Title         = 'Transparent data encryption is enabled on SQL databases'
    Category      = 'Data protection'
    Service       = 'Azure SQL'
    Severity      = 'High'
    Description   = 'Checks the transparent data encryption state of user databases on SQL logical servers. Managed instance databases: AZ-SQL-015.'
    Rationale     = 'TDE encrypts database files, backups and logs at rest, protecting data against theft of storage media and backup copies.'
    Remediation   = 'Enable TDE (az sql db tde set --status Enabled ...).'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/transparent-data-encryption-tde-overview')
    Policy        = @{ '17k78e20-9358-41c9-923c-fb736d382a12' = 'Transparent Data Encryption on SQL databases should be enabled' }
    ResourceTypes = @('Microsoft.Sql/servers/databases')
    Filter        = { param($Record) $Record.resource.name -ne 'master' -and [string]$Record.resource.kind -notmatch 'system' }
    Evaluate      = $sqlTdeCheck
}

Add-AzTest @{
    Id            = 'AZ-SQL-015'
    Title         = 'Transparent data encryption is enabled on SQL managed instance databases'
    Category      = 'Data protection'
    Service       = 'Azure SQL'
    Severity      = 'High'
    Description   = 'Checks the transparent data encryption state of user databases on SQL managed instances.'
    Rationale     = 'TDE encrypts database files, backups and logs at rest, protecting data against theft of storage media and backup copies.'
    Remediation   = "Enable TDE on the database (ALTER DATABASE <name> SET ENCRYPTION ON)."
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/transparent-data-encryption-tde-overview')
    ResourceTypes = @('Microsoft.Sql/managedInstances/databases')
    Filter        = { param($Record) $Record.resource.name -notin 'master', 'model', 'msdb', 'tempdb' -and [string]$Record.resource.kind -notmatch 'system' }
    Evaluate      = $sqlTdeCheck
}

Add-AzTest @{
    Id            = 'AZ-SQL-008'
    Title         = 'SQL TDE uses a customer-managed key (when required)'
    Category      = 'Data protection'
    Service       = 'Azure SQL'
    Severity      = 'Informational'
    Description   = 'Checks whether the TDE protector of SQL servers and managed instances is a customer-managed key in Key Vault.'
    Rationale     = 'A customer-managed TDE protector gives control over key rotation and revocation; only required where data classification or regulation demands it.'
    Remediation   = 'Configure a Key Vault key as TDE protector with auto-rotation (az sql server tde-key set --server-key-type AzureKeyVault ...).'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/transparent-data-encryption-byok-overview')
    Policy        = @{ '0a370ff3-6cab-4e85-8995-295fd854c5b8' = 'SQL servers should use customer-managed keys to encrypt data at rest'; 'ac01ad65-10e5-46df-bdd9-6b0cad13e1d2' = 'SQL managed instances should use customer-managed keys to encrypt data at rest' }
    ResourceTypes = @('Microsoft.Sql/servers', 'Microsoft.Sql/managedInstances')
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'encryptionProtector')) { return New-Unknown 'Encryption protector could not be read' }
        $protector = @(Get-Child $Record 'encryptionProtector') | Where-Object { $_ } | Select-Object -First 1
        $evidence = [ordered]@{ serverKeyType = $protector.properties.serverKeyType; autoRotationEnabled = $protector.properties.autoRotationEnabled }
        if ($protector.properties.serverKeyType -eq 'AzureKeyVault') { return New-Pass 'Customer-managed TDE protector' $evidence }
        New-Fail 'Service-managed TDE protector' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-SQL-009'
    Title         = 'Vulnerability assessment is enabled on SQL servers'
    Category      = 'Posture and vulnerability management'
    Service       = 'Azure SQL'
    Severity      = 'Medium'
    Description   = 'Checks SQL logical servers and managed instances for SQL vulnerability assessment (express or classic with recurring scans).'
    Rationale     = 'Vulnerability assessment finds misconfigurations, excessive permissions and unprotected sensitive data in databases, and tracks drift from a baseline.'
    Remediation   = 'Enable Microsoft Defender for SQL, which turns on the express vulnerability assessment configuration.'
    References    = @('https://learn.microsoft.com/azure/defender-for-cloud/sql-azure-vulnerability-assessment-overview')
    Policy        = @{ 'ef2a8f2a-b3d9-49cd-a8a8-9a3aaaf647d9' = 'Vulnerability assessment should be enabled on your SQL servers' }
    ResourceTypes = @('Microsoft.Sql/servers', 'Microsoft.Sql/managedInstances')
    Evaluate      = {
        param($Record)
        $express = @(Get-Child $Record 'sqlVulnerabilityAssessments') | Where-Object { $_ -and $_.properties.state -eq 'Enabled' }
        $classic = @(Get-Child $Record 'vulnerabilityAssessments') | Where-Object { $_ -and $_.properties.recurringScans.isEnabled -and $_.properties.storageContainerPath }
        $evidence = [ordered]@{ express = [bool]$express; classicRecurringScans = [bool]$classic }
        if ($express -or $classic) { return New-Pass 'Vulnerability assessment enabled' $evidence }
        if (-not (Test-ChildCollected $Record 'sqlVulnerabilityAssessments') -and -not (Test-ChildCollected $Record 'vulnerabilityAssessments')) { return New-Unknown 'Vulnerability assessment settings could not be read' }
        New-Fail 'Vulnerability assessment disabled' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-SQL-010'
    Title         = 'Columns classified as sensitive are masked'
    Category      = 'Data protection'
    Service       = 'Azure SQL'
    Severity      = 'Low'
    Description   = 'For SQL databases with data classification, checks that every column labeled with rank Medium or higher (Confidential and up in the default policy) has an enabled dynamic data masking rule. Databases without such columns are not applicable.'
    Rationale     = 'Dynamic data masking hides sensitive values from users and applications that do not need them, without changing the data. The classification already names the columns that hold such data; masking them limits exposure through reporting tools, support staff and compromised low privileged accounts.'
    Remediation   = 'Add masking rules for the classified columns (database > Dynamic Data Masking) and grant the UNMASK permission only to the principals that need the real values. Administrators always see unmasked data.'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/dynamic-data-masking-overview', 'https://learn.microsoft.com/azure/azure-sql/database/data-discovery-and-classification-overview')
    ResourceTypes = @('Microsoft.Sql/servers/databases')
    Filter        = { param($Record) $Record.resource.name -ne 'master' -and [string]$Record.resource.kind -notmatch '(?i)system' }
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'currentSensitivityLabels')) { return New-Unknown 'The data classification could not be read' }
        $classified = @(Get-Child $Record 'currentSensitivityLabels' | Where-Object { $_ -and -not $_.properties.isDisabled -and $_.properties.rank -in 'Medium', 'High', 'Critical' } | ForEach-Object { "$($_.properties.schemaName).$($_.properties.tableName).$($_.properties.columnName)" } | Sort-Object -Unique)
        if (-not $classified) { return New-NotApplicable 'No columns are classified with rank Medium or higher' }
        if (-not (Test-ChildCollected $Record 'dataMaskingPolicies/Default/rules')) { return New-Unknown 'The masking rules could not be read' ([ordered]@{ classifiedColumns = $classified }) }
        $masked = @(Get-Child $Record 'dataMaskingPolicies/Default/rules' | Where-Object { $_ -and $_.properties.ruleState -ne 'Disabled' } | ForEach-Object { "$($_.properties.schemaName).$($_.properties.tableName).$($_.properties.columnName)" })
        $unmasked = @($classified | Where-Object { $_ -notin $masked })
        $evidence = [ordered]@{ classifiedColumns = $classified; unmaskedColumns = $unmasked }
        if ($unmasked) { return New-Fail "$($unmasked.Count) of $($classified.Count) classified column(s) are not masked" $evidence }
        New-Pass "All $($classified.Count) classified column(s) are masked" $evidence
    }
}

$postgresType = @('Microsoft.DBforPostgreSQL/flexibleServers')
$mysqlType = @('Microsoft.DBforMySQL/flexibleServers')

#public network access and private endpoints of PostgreSQL and MySQL flexible servers
$flexiblePublicAccessCheck = {
    param($Record)
    $network = $Record.resource.properties.network
    $value = $network.publicNetworkAccess
    $evidence = [ordered]@{ publicNetworkAccess = $value; virtualNetworkIntegrated = [bool]$network.delegatedSubnetResourceId }
    if ($null -eq $value) { return New-Unknown 'The public network access setting was not returned' $evidence }
    if ($value -eq 'Disabled') { return New-Pass 'Public network access disabled' $evidence }
    New-Fail "Public network access $value" $evidence
}
$flexiblePrivateEndpointCheck = {
    param($Record)
    if (-not (Test-PrivateEndpointsCollected $Record)) { return New-Unknown 'Private endpoint connections could not be read' }
    $count = Get-ApprovedPrivateEndpointCount $Record
    $subnet = $Record.resource.properties.network.delegatedSubnetResourceId
    $evidence = [ordered]@{ approvedPrivateEndpoints = $count; delegatedSubnetResourceId = $subnet }
    if ($count) { return New-Pass "$count approved private endpoint(s)" $evidence }
    if ($subnet) { return New-Fail 'No private endpoint: the server is integrated in a virtual network, which does not support private endpoints' $evidence }
    New-Fail 'No approved private endpoint' $evidence
}
$flexibleCmkCheck = {
    param($Record)
    $encryption = $Record.resource.properties.dataEncryption
    $evidence = [ordered]@{ type = $encryption.type; primaryKeyURI = [bool]$encryption.primaryKeyURI }
    if ($null -eq $encryption) { return New-Unknown 'The data encryption setting was not returned' }
    if ($encryption.type -eq 'AzureKeyVault' -and $encryption.primaryKeyURI) { return New-Pass 'Customer-managed key' $evidence }
    New-Fail 'Service-managed key' $evidence
}

Add-AzTest @{
    Id            = 'AZ-PG-001'
    Version       = 2
    Title         = 'PostgreSQL flexible servers require encrypted connections'
    Category      = 'Data protection'
    Service       = 'Azure Database for PostgreSQL'
    Severity      = 'High'
    Description   = 'Checks that the require_secure_transport server parameter is on. Minimum TLS version: AZ-PG-011.'
    Rationale     = 'Unencrypted database connections expose credentials and data on the network.'
    Remediation   = 'Set require_secure_transport to ON (az postgres flexible-server parameter set --name require_secure_transport --value on ...).'
    References    = @('https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-networking-ssl-tls')
    Policy        = @{ 'c29c38cb-74a7-4505-9a06-e588ab86620a' = 'Enforce SSL connection should be enabled for PostgreSQL flexible servers' }
    ResourceTypes = $postgresType
    Evaluate      = { param($Record) Get-ServerParameterResult $Record 'require_secure_transport' 'on' }
}

Add-AzTest @{
    Id            = 'AZ-PG-011'
    Title         = 'PostgreSQL flexible servers require TLS 1.2 or higher'
    Category      = 'Data protection'
    Service       = 'Azure Database for PostgreSQL'
    Severity      = 'High'
    Description   = 'Checks that the ssl_min_protocol_version server parameter is TLSv1.2 or higher.'
    Rationale     = 'TLS 1.0 and 1.1 have known weaknesses and are no longer considered secure.'
    Remediation   = 'Set ssl_min_protocol_version to TLSv1.2 or TLSv1.3 (az postgres flexible-server parameter set --name ssl_min_protocol_version --value TLSv1.2 ...).'
    References    = @('https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-networking-ssl-tls')
    Policy        = @{ 'a43d5475-c569-45ce-a268-28fa79f4e87a' = 'PostgreSQL flexible servers should be running TLS version 1.2 or newer' }
    ResourceTypes = $postgresType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'configurations')) { return New-Unknown 'Server parameters could not be read' }
        $minimum = Get-ServerParameter $Record 'ssl_min_protocol_version'
        $evidence = [ordered]@{ ssl_min_protocol_version = $minimum }
        if ($null -eq $minimum) { return New-Unknown 'Server parameter ssl_min_protocol_version was not returned' $evidence }
        if (Test-VersionAtLeast ($minimum -replace '(?i)^TLSv', '') '1.2') { return New-Pass "Minimum protocol $minimum" $evidence }
        New-Fail "Minimum protocol $(if ($minimum) { $minimum } else { 'not set' })" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-PG-002'
    Version       = 2
    Title         = 'PostgreSQL flexible servers log connections'
    Category      = 'Logging and threat detection'
    Service       = 'Azure Database for PostgreSQL'
    Severity      = 'Medium'
    Description   = 'Checks that the log_connections server parameter is on. Disconnections: AZ-PG-010; checkpoints: AZ-PG-009.'
    Rationale     = 'Connection logs show who connected from where and when; they are needed to detect brute force and unauthorized access.'
    Remediation   = 'Set log_connections to on and send the PostgreSQL logs to Log Analytics.'
    References    = @('https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-logging')
    Policy        = @{ '086709ac-11b5-478d-a893-9567a16d2ae3' = 'Log connections should be enabled for PostgreSQL flexible servers' }
    ResourceTypes = $postgresType
    Evaluate      = { param($Record) Get-ServerParameterResult $Record 'log_connections' 'on' }
}

Add-AzTest @{
    Id            = 'AZ-PG-010'
    Title         = 'PostgreSQL flexible servers log disconnections'
    Category      = 'Logging and threat detection'
    Service       = 'Azure Database for PostgreSQL'
    Severity      = 'Medium'
    Description   = 'Checks that the log_disconnections server parameter is on.'
    Rationale     = 'Disconnection logs record the end and duration of each session, which completes the connection trail of an investigation.'
    Remediation   = 'Set log_disconnections to on and send the PostgreSQL logs to Log Analytics.'
    References    = @('https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-logging')
    Policy        = @{ '1d14b021-1bae-4f93-b36b-69695e14984a' = 'Disconnections should be logged for PostgreSQL flexible servers' }
    ResourceTypes = $postgresType
    Evaluate      = { param($Record) Get-ServerParameterResult $Record 'log_disconnections' 'on' }
}

Add-AzTest @{
    Id            = 'AZ-PG-009'
    Title         = 'PostgreSQL flexible servers log checkpoints'
    Category      = 'Logging and threat detection'
    Service       = 'Azure Database for PostgreSQL'
    Severity      = 'Low'
    Description   = 'Checks that the log_checkpoints server parameter is on.'
    Rationale     = 'Checkpoint logs help to diagnose performance problems and unexpected restarts of the server.'
    Remediation   = 'Set log_checkpoints to on.'
    References    = @('https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-logging')
    Policy        = @{ '70be9e12-c935-49ac-9bd8-fd64b85c1f87' = 'Log checkpoints should be enabled for PostgreSQL flexible servers' }
    ResourceTypes = $postgresType
    Evaluate      = { param($Record) Get-ServerParameterResult $Record 'log_checkpoints' 'on' }
}

Add-AzTest @{
    Id            = 'AZ-PG-007'
    Title         = 'PostgreSQL flexible servers throttle connections'
    Category      = 'Logging and threat detection'
    Service       = 'Azure Database for PostgreSQL'
    Severity      = 'Low'
    Description   = 'Checks that the connection_throttle.enable server parameter is on. Servers whose version does not offer the parameter are Unknown.'
    Rationale     = 'Connection throttling slows down repeated failed logins from the same address and logs them, which limits brute force and connection exhaustion.'
    Remediation   = 'Set connection_throttle.enable to on (az postgres flexible-server parameter set --name connection_throttle.enable --value on ...).'
    References    = @('https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-server-parameters')
    ResourceTypes = $postgresType
    Evaluate      = { param($Record) Get-ServerParameterResult $Record 'connection_throttle.enable' 'on' }
}

Add-AzTest @{
    Id            = 'AZ-PG-008'
    Title         = 'PostgreSQL flexible servers keep log files for more than 3 days'
    Category      = 'Logging and threat detection'
    Service       = 'Azure Database for PostgreSQL'
    Severity      = 'Low'
    Description   = 'Checks that the logfiles.retention_days server parameter is greater than 3.'
    Rationale     = 'Server logs are needed to investigate errors and suspicious activity; the default of 3 days is often too short to start an investigation.'
    Remediation   = 'Set logfiles.retention_days to a value from 4 to 7, and send the logs to Log Analytics for longer retention.'
    References    = @('https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-server-parameters')
    ResourceTypes = $postgresType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'configurations')) { return New-Unknown 'Server parameters could not be read' }
        $value = Get-ServerParameter $Record 'logfiles.retention_days'
        $evidence = [ordered]@{ 'logfiles.retention_days' = $value }
        if ($null -eq $value) { return New-Unknown 'Server parameter logfiles.retention_days was not returned' $evidence }
        if ($value -notmatch '^\d+$') { return New-Unknown "Unexpected value $value" $evidence }
        if ([int]$value -gt 3) { return New-Pass "$value days" $evidence }
        New-Fail "$value days" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-PG-003'
    Version       = 2
    Title         = 'PostgreSQL flexible servers audit with pgAudit'
    Category      = 'Logging and threat detection'
    Service       = 'Azure Database for PostgreSQL'
    Severity      = 'Low'
    Description   = 'Checks that the pgaudit extension is loaded and pgaudit.log is not none.'
    Rationale     = 'pgAudit records DDL, role changes and data access statements, which standard PostgreSQL logging does not capture reliably.'
    Remediation   = "Add pgaudit to shared_preload_libraries, restart, create the extension and set pgaudit.log (for example 'ddl,role,write')."
    References    = @('https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-audit')
    Policy        = @{ '4eb5e667-e871-4292-9c5d-8bbb94e0c908' = 'Auditing with PgAudit should be enabled for PostgreSQL flexible servers' }
    ResourceTypes = $postgresType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'configurations')) { return New-Unknown 'Server parameters could not be read' }
        $libraries = Get-ServerParameter $Record 'shared_preload_libraries'
        $log = Get-ServerParameter $Record 'pgaudit.log'
        $evidence = [ordered]@{ shared_preload_libraries = $libraries; 'pgaudit.log' = $log }
        if ($null -eq $libraries) { return New-Unknown 'Server parameter shared_preload_libraries was not returned' $evidence }
        if ($libraries -notmatch 'pgaudit') { return New-Fail 'pgAudit is not loaded' $evidence }
        if ($null -eq $log) { return New-Unknown 'Server parameter pgaudit.log was not returned' $evidence }
        if ($log -and $log -ne 'none') { return New-Pass "pgAudit logging $log" $evidence }
        New-Fail 'pgAudit logs nothing' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-PG-004'
    Version       = 3
    Title         = 'PostgreSQL flexible servers use Microsoft Entra authentication only'
    Category      = 'Identity management'
    Service       = 'Azure Database for PostgreSQL'
    Severity      = 'Medium'
    Description   = 'Checks that Entra authentication is enabled and password authentication is disabled.'
    Rationale     = 'Database passwords lack MFA and central lifecycle management and are the main brute force target of Internet reachable servers.'
    Remediation   = 'Add an Entra administrator group, move clients to Entra tokens (managed identities), then set the authentication method to Microsoft Entra authentication only.'
    References    = @('https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-azure-ad-authentication')
    Policy        = @{ 'fa498b91-8a7e-4710-9578-da944c68d1fe' = '[Preview]: Azure PostgreSQL flexible server should have Microsoft Entra Only Authentication enabled' }
    ResourceTypes = $postgresType
    Evaluate      = {
        param($Record)
        $auth = $Record.resource.properties.authConfig
        if ($null -eq $auth) { return New-Unknown 'The authentication settings were not returned' }
        $evidence = [ordered]@{ activeDirectoryAuth = $auth.activeDirectoryAuth; passwordAuth = $auth.passwordAuth }
        if ($auth.activeDirectoryAuth -eq 'Enabled' -and $auth.passwordAuth -eq 'Disabled') { return New-Pass 'Entra-only authentication' $evidence }
        New-Fail $(if ($auth.activeDirectoryAuth -ne 'Enabled') { 'Entra authentication disabled' } else { 'Password authentication enabled' }) $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-PG-005'
    Title         = 'PostgreSQL flexible servers disable public network access'
    Category      = 'Network security'
    Service       = 'Azure Database for PostgreSQL'
    Severity      = 'Medium'
    Description   = 'Checks that public network access of PostgreSQL flexible servers is Disabled (servers integrated in a virtual network report Disabled).'
    Rationale     = 'A public endpoint depends solely on firewall rules and authentication; private endpoints or virtual network integration remove Internet exposure.'
    Remediation   = 'Create a private endpoint, then disable public access on the Networking page of the server.'
    References    = @('https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-networking-private-link')
    Policy        = @{ '5e1de0e3-42cb-4ebc-a86d-61d0c619ca48' = 'Public network access should be disabled for PostgreSQL flexible servers' }
    ResourceTypes = $postgresType
    Evaluate      = $flexiblePublicAccessCheck
}

Add-AzTest @{
    Id            = 'AZ-PG-006'
    Title         = 'PostgreSQL flexible servers are accessed through private endpoints'
    Category      = 'Network security'
    Service       = 'Azure Database for PostgreSQL'
    Severity      = 'Low'
    Description   = 'Checks PostgreSQL flexible servers for an approved private endpoint connection. Servers integrated in a virtual network cannot have private endpoints and fail.'
    Rationale     = 'Private endpoints keep database traffic on private networks and allow public access to be disabled.'
    Remediation   = 'Create a private endpoint for the server; a server integrated in a virtual network has to be redeployed with public access networking first.'
    References    = @('https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-networking-private-link')
    Policy        = @{ '5375a5bb-22c6-46d7-8a43-83417cfb4460' = 'Private endpoint should be enabled for PostgreSQL flexible servers' }
    ResourceTypes = $postgresType
    Evaluate      = $flexiblePrivateEndpointCheck
}

Add-AzTest @{
    Id            = 'AZ-PG-012'
    Title         = 'PostgreSQL flexible servers encrypt data with a customer-managed key (when required)'
    Category      = 'Data protection'
    Service       = 'Azure Database for PostgreSQL'
    Severity      = 'Informational'
    Description   = 'Checks whether the data encryption of PostgreSQL flexible servers uses a customer-managed key in Key Vault.'
    Rationale     = 'A customer-managed key gives control over key rotation and revocation; only required where data classification or regulation demands it.'
    Remediation   = 'Configure data encryption with a Key Vault key and a user-assigned identity (only possible when the server is created).'
    References    = @('https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-data-encryption')
    Policy        = @{ '12c74c95-0efd-48da-b8d9-2a7d68470c92' = 'PostgreSQL flexible servers should use customer-managed keys to encrypt data at rest' }
    ResourceTypes = $postgresType
    Evaluate      = $flexibleCmkCheck
}

Add-AzTest @{
    Id            = 'AZ-MY-001'
    Version       = 2
    Title         = 'MySQL flexible servers require encrypted connections'
    Category      = 'Data protection'
    Service       = 'Azure Database for MySQL'
    Severity      = 'High'
    Description   = 'Checks that the require_secure_transport server parameter is ON. Allowed TLS versions: AZ-MY-007.'
    Rationale     = 'Unencrypted database connections expose credentials and data on the network.'
    Remediation   = 'Set require_secure_transport to ON (az mysql flexible-server parameter set --name require_secure_transport --value ON ...).'
    References    = @('https://learn.microsoft.com/azure/mysql/flexible-server/concepts-networking#tls-and-ssl')
    ResourceTypes = $mysqlType
    Evaluate      = { param($Record) Get-ServerParameterResult $Record 'require_secure_transport' 'ON' }
}

Add-AzTest @{
    Id            = 'AZ-MY-007'
    Title         = 'MySQL flexible servers allow only TLS 1.2 or higher'
    Category      = 'Data protection'
    Service       = 'Azure Database for MySQL'
    Severity      = 'High'
    Description   = 'Checks that the tls_version server parameter contains TLSv1.2 or higher and no older version.'
    Rationale     = 'TLS 1.0 and 1.1 have known weaknesses and are no longer considered secure.'
    Remediation   = 'Set tls_version to TLSv1.2 or TLSv1.2,TLSv1.3 (az mysql flexible-server parameter set --name tls_version --value TLSv1.2 ...).'
    References    = @('https://learn.microsoft.com/azure/mysql/flexible-server/concepts-networking#tls-and-ssl')
    ResourceTypes = $mysqlType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'configurations')) { return New-Unknown 'Server parameters could not be read' }
        $value = Get-ServerParameter $Record 'tls_version'
        if ($null -eq $value) { return New-Unknown 'Server parameter tls_version was not returned' }
        $versions = @($value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $weak = @($versions | Where-Object { -not (Test-VersionAtLeast $_ '1.2') })
        $strong = @($versions | Where-Object { Test-VersionAtLeast $_ '1.2' })
        $evidence = [ordered]@{ tls_version = $versions }
        if ($weak) { return New-Fail "Older TLS versions allowed: $($weak -join ', ')" $evidence }
        if (-not $strong) { return New-Fail 'TLS 1.2 or higher is not allowed' $evidence }
        New-Pass "Allowed: $($strong -join ', ')" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-MY-006'
    Title         = 'MySQL flexible servers have audit logging enabled'
    Category      = 'Logging and threat detection'
    Service       = 'Azure Database for MySQL'
    Severity      = 'Medium'
    Description   = 'Checks that the audit_log_enabled server parameter is ON.'
    Rationale     = 'Audit logs record connections and statements and are needed to detect and investigate unauthorized database access.'
    Remediation   = 'Set audit_log_enabled to ON and send the MySqlAuditLogs category to Log Analytics.'
    References    = @('https://learn.microsoft.com/azure/mysql/flexible-server/concepts-audit-logs')
    ResourceTypes = $mysqlType
    Evaluate      = { param($Record) Get-ServerParameterResult $Record 'audit_log_enabled' 'ON' }
}

Add-AzTest @{
    Id            = 'AZ-MY-002'
    Version       = 2
    Title         = 'MySQL flexible servers audit connection events'
    Category      = 'Logging and threat detection'
    Service       = 'Azure Database for MySQL'
    Severity      = 'Medium'
    Description   = 'Checks that audit_log_enabled is ON and audit_log_events contains CONNECTION.'
    Rationale     = 'Connection events show successful and failed logins, which are needed to detect brute force and unauthorized access.'
    Remediation   = "Set audit_log_enabled to ON, add CONNECTION to audit_log_events, and send the MySqlAuditLogs category to Log Analytics."
    References    = @('https://learn.microsoft.com/azure/mysql/flexible-server/concepts-audit-logs')
    ResourceTypes = $mysqlType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'configurations')) { return New-Unknown 'Server parameters could not be read' }
        $enabled = Get-ServerParameter $Record 'audit_log_enabled'
        $events = Get-ServerParameter $Record 'audit_log_events'
        $evidence = [ordered]@{ audit_log_enabled = $enabled; audit_log_events = $events }
        if ($null -eq $enabled -or $null -eq $events) { return New-Unknown 'Server parameter audit_log_enabled or audit_log_events was not returned' $evidence }
        $tokens = @($events -split ',' | ForEach-Object { $_.Trim() })
        if ($enabled -eq 'ON' -and $tokens -contains 'CONNECTION') { return New-Pass 'Audit logging enabled including connections' $evidence }
        New-Fail $(if ($enabled -ne 'ON') { 'Audit logging disabled' } else { 'Connection events are not audited' }) $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-MY-009'
    Title         = 'MySQL flexible servers write the error log'
    Category      = 'Logging and threat detection'
    Service       = 'Azure Database for MySQL'
    Severity      = 'Low'
    Description   = 'Checks that the error_server_log_file server parameter is ON.'
    Rationale     = 'The error log records startup, shutdown and error events of the server, which are needed to investigate failures and attacks.'
    Remediation   = 'Set error_server_log_file to ON and send the logs to Log Analytics.'
    References    = @('https://learn.microsoft.com/azure/mysql/flexible-server/concepts-error-logs')
    ResourceTypes = $mysqlType
    Evaluate      = { param($Record) Get-ServerParameterResult $Record 'error_server_log_file' 'ON' }
}

Add-AzTest @{
    Id            = 'AZ-MY-003'
    Version       = 3
    Title         = 'MySQL flexible servers use Microsoft Entra authentication only'
    Category      = 'Identity management'
    Service       = 'Azure Database for MySQL'
    Severity      = 'Medium'
    Description   = 'Checks that the aad_auth_only server parameter is ON (Microsoft Entra authentication only).'
    Rationale     = 'Database passwords lack MFA and central lifecycle management and are the main brute force target of Internet reachable servers.'
    Remediation   = 'Configure an Entra administrator with a user-assigned identity, move clients to Entra tokens and set aad_auth_only to ON.'
    References    = @('https://learn.microsoft.com/azure/mysql/flexible-server/concepts-azure-ad-authentication')
    Policy        = @{ '40e85574-ef33-47e8-a854-7a65c7500560' = 'Azure MySQL flexible server should have Microsoft Entra Only Authentication enabled' }
    ResourceTypes = $mysqlType
    Evaluate      = { param($Record) Get-ServerParameterResult $Record 'aad_auth_only' 'ON' }
}

Add-AzTest @{
    Id            = 'AZ-MY-004'
    Title         = 'MySQL flexible servers disable public network access'
    Category      = 'Network security'
    Service       = 'Azure Database for MySQL'
    Severity      = 'Medium'
    Description   = 'Checks that public network access of MySQL flexible servers is Disabled (servers integrated in a virtual network report Disabled).'
    Rationale     = 'A public endpoint depends solely on firewall rules and authentication; private endpoints or virtual network integration remove Internet exposure.'
    Remediation   = 'Create a private endpoint, then disable public access on the Networking page of the server.'
    References    = @('https://learn.microsoft.com/azure/mysql/flexible-server/how-to-networking-private-link-deny-public-access')
    Policy        = @{ 'c9299215-ae47-4f50-9c54-8a392f68a052' = 'Public network access should be disabled for MySQL flexible servers' }
    ResourceTypes = $mysqlType
    Evaluate      = $flexiblePublicAccessCheck
}

Add-AzTest @{
    Id            = 'AZ-MY-005'
    Title         = 'MySQL flexible servers are accessed through private endpoints'
    Category      = 'Network security'
    Service       = 'Azure Database for MySQL'
    Severity      = 'Low'
    Description   = 'Checks MySQL flexible servers for an approved private endpoint connection. Servers integrated in a virtual network cannot have private endpoints and fail.'
    Rationale     = 'Private endpoints keep database traffic on private networks and allow public access to be disabled.'
    Remediation   = 'Create a private endpoint for the server; a server integrated in a virtual network has to be redeployed with public access networking first.'
    References    = @('https://learn.microsoft.com/azure/mysql/flexible-server/concepts-networking-private-link')
    ResourceTypes = $mysqlType
    Evaluate      = $flexiblePrivateEndpointCheck
}

Add-AzTest @{
    Id            = 'AZ-MY-008'
    Title         = 'MySQL flexible servers encrypt data with a customer-managed key (when required)'
    Category      = 'Data protection'
    Service       = 'Azure Database for MySQL'
    Severity      = 'Informational'
    Description   = 'Checks whether the data encryption of MySQL flexible servers uses a customer-managed key in Key Vault.'
    Rationale     = 'A customer-managed key gives control over key rotation and revocation; only required where data classification or regulation demands it.'
    Remediation   = 'Configure data encryption with a Key Vault key and a user-assigned identity on the Data encryption page of the server.'
    References    = @('https://learn.microsoft.com/azure/mysql/flexible-server/concepts-customer-managed-key')
    ResourceTypes = $mysqlType
    Evaluate      = $flexibleCmkCheck
}

$cosmosType = @('Microsoft.DocumentDB/databaseAccounts')

Add-AzTest @{
    Id            = 'AZ-COS-001'
    Title         = 'Cosmos DB accounts disable key based (local) authentication'
    Category      = 'Identity management'
    Service       = 'Cosmos DB'
    Severity      = 'Medium'
    Description   = 'Checks the disableLocalAuth setting of Cosmos DB accounts.'
    Rationale     = 'Account keys give full data access, are shared secrets without identity and bypass data plane RBAC and its audit trail.'
    Remediation   = 'Move clients to Entra ID with Cosmos DB data plane RBAC, then set disableLocalAuth to true.'
    References    = @('https://learn.microsoft.com/azure/cosmos-db/how-to-setup-rbac#disable-local-auth')
    Policy        = @{ '5450f5bd-9c72-4390-a9c4-a7aba4edfdd2' = 'Cosmos DB database accounts should have local authentication methods disabled' }
    ResourceTypes = $cosmosType
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.disableLocalAuth
        if ($value -eq $true) { return New-Pass 'Key based authentication disabled' ([ordered]@{ disableLocalAuth = $true }) }
        New-Fail 'Key based authentication allowed' ([ordered]@{ disableLocalAuth = $value })
    }
}

Add-AzTest @{
    Id            = 'AZ-COS-002'
    Title         = 'Cosmos DB accounts restrict network access'
    Category      = 'Network security'
    Service       = 'Cosmos DB'
    Severity      = 'High'
    Description   = 'Checks that Cosmos DB accounts disable public network access or restrict it with IP or virtual network rules.'
    Rationale     = 'Without network restrictions the account endpoint accepts connections from the whole Internet, leaving keys and tokens as the only control.'
    Remediation   = 'Use private endpoints and disable public network access, or configure IP and virtual network rules.'
    References    = @('https://learn.microsoft.com/azure/cosmos-db/how-to-configure-firewall')
    Policy        = @{ '862e97cf-49fc-4a5c-9de4-40d4e2e7c8eb' = 'Azure Cosmos DB accounts should have firewall rules' }
    ResourceTypes = $cosmosType
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ publicNetworkAccess = $p.publicNetworkAccess; ipRules = @($p.ipRules).Count; virtualNetworkFilter = [bool]$p.isVirtualNetworkFilterEnabled }
        if ($p.publicNetworkAccess -eq 'Disabled') { return New-Pass 'Public network access disabled' $evidence }
        if (@($p.ipRules | Where-Object { $_ }).Count -or $p.isVirtualNetworkFilterEnabled) { return New-Pass 'Public access restricted by firewall rules' $evidence }
        New-Fail 'Open to all networks' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-COS-006'
    Title         = 'Cosmos DB accounts disable public network access'
    Category      = 'Network security'
    Service       = 'Cosmos DB'
    Severity      = 'Medium'
    Description   = 'Checks that public network access of Cosmos DB accounts is Disabled.'
    Rationale     = 'A public endpoint, even behind firewall rules, can be reached from the Internet; private endpoints remove that exposure.'
    Remediation   = 'Create private endpoints, then set public network access to Disabled (az cosmosdb update --public-network-access Disabled ...).'
    References    = @('https://learn.microsoft.com/azure/cosmos-db/how-to-configure-firewall')
    Policy        = @{ '797b37f7-06b8-444c-b1ad-fc62867f335a' = 'Azure Cosmos DB should disable public network access' }
    ResourceTypes = $cosmosType
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.publicNetworkAccess
        $evidence = [ordered]@{ publicNetworkAccess = $value }
        if ($value -eq 'Disabled') { return New-Pass 'Public network access disabled' $evidence }
        New-Fail "Public network access $(if ($value) { $value } else { 'Enabled (default)' })" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-COS-004'
    Title         = 'Cosmos DB accounts are accessed through private endpoints'
    Category      = 'Network security'
    Service       = 'Cosmos DB'
    Severity      = 'Low'
    Description   = 'Checks Cosmos DB accounts for an approved private endpoint connection.'
    Rationale     = 'Private endpoints keep database traffic on private networks and allow public access to be disabled.'
    Remediation   = 'Create a private endpoint for the account (Networking > Private access).'
    References    = @('https://learn.microsoft.com/azure/cosmos-db/how-to-configure-private-endpoints')
    Policy        = @{ '58440f8a-10c5-4151-bdce-dfbaad4a20b7' = 'CosmosDB accounts should use private link' }
    ResourceTypes = $cosmosType
    Evaluate      = {
        param($Record)
        if (-not (Test-PrivateEndpointsCollected $Record)) { return New-Unknown 'Private endpoint connections could not be read' }
        $count = Get-ApprovedPrivateEndpointCount $Record
        $evidence = [ordered]@{ approvedPrivateEndpoints = $count }
        if ($count) { return New-Pass "$count approved private endpoint(s)" $evidence }
        New-Fail 'No approved private endpoint' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-COS-005'
    Title         = 'Cosmos DB firewalls do not accept connections from all Azure datacenters'
    Category      = 'Network security'
    Service       = 'Cosmos DB'
    Severity      = 'Medium'
    Description   = 'Finds the 0.0.0.0 IP rule (accept connections from within public Azure datacenters) on Cosmos DB accounts with public network access enabled.'
    Rationale     = 'The rule admits connections from any Azure resource of any customer, not just your own, so anyone can host a client in Azure and reach the account.'
    Remediation   = 'Remove 0.0.0.0 from the IP rules and use private endpoints or virtual network rules for your Azure workloads.'
    References    = @('https://learn.microsoft.com/azure/cosmos-db/how-to-configure-firewall#allow-requests-from-global-azure-datacenters-or-other-sources-within-azure')
    Policy        = @{ '12339a85-a25c-4f17-9f82-4766f13f5c4c' = 'Azure Cosmos DB accounts should not allow traffic from all Azure data centers' }
    ResourceTypes = $cosmosType
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        if ($p.publicNetworkAccess -eq 'Disabled') { return New-Pass 'Public network access disabled, IP rules do not apply' }
        $rules = @(@($p.ipRules | Where-Object { $_ } | ForEach-Object { [string]$_.ipAddressOrRange }) + @(([string]$p.ipRangeFilter -split ',') | ForEach-Object { $_.Trim() }) | Where-Object { $_ } | Sort-Object -Unique)
        $azure = @($rules | Where-Object { $_ -eq '0.0.0.0' -or $_.StartsWith('0.0.0.0/') })
        $evidence = [ordered]@{ ipRules = $rules.Count; allowAzureRules = $azure }
        if ($azure) { return New-Fail "All Azure datacenters allowed ($($azure -join ', '))" $evidence }
        New-Pass 'Azure datacenters are not allowed wholesale' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-COS-003'
    Title         = 'Cosmos DB accounts disable key based metadata write access'
    Category      = 'Privileged access'
    Service       = 'Cosmos DB'
    Severity      = 'Low'
    Description   = 'Checks disableKeyBasedMetadataWriteAccess, which prevents account keys from changing databases, containers and throughput.'
    Rationale     = 'With the setting enabled, resource changes must go through Azure Resource Manager and are subject to RBAC, locks, policy and the activity log.'
    Remediation   = 'Set disableKeyBasedMetadataWriteAccess to true (az cosmosdb update --disable-key-based-metadata-write-access true ...).'
    References    = @('https://learn.microsoft.com/azure/cosmos-db/audit-control-plane-logs')
    Policy        = @{ '4750c32b-89c0-46af-bfcb-2e4541a818d5' = 'Azure Cosmos DB key based metadata write access should be disabled' }
    ResourceTypes = $cosmosType
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.disableKeyBasedMetadataWriteAccess
        if ($value -eq $true) { return New-Pass 'Metadata writes through keys disabled' ([ordered]@{ disableKeyBasedMetadataWriteAccess = $true }) }
        New-Fail 'Keys can change databases and containers' ([ordered]@{ disableKeyBasedMetadataWriteAccess = $value })
    }
}

Add-AzTest @{
    Id            = 'AZ-COS-007'
    Title         = 'Cosmos DB accounts encrypt data with a customer-managed key (when required)'
    Category      = 'Data protection'
    Service       = 'Cosmos DB'
    Severity      = 'Informational'
    Description   = 'Checks whether Cosmos DB accounts encrypt data with a customer-managed key (keyVaultKeyUri).'
    Rationale     = 'A customer-managed key gives control over key rotation and revocation; only required where data classification or regulation demands it.'
    Remediation   = 'Configure a Key Vault key as the encryption key of the account (Settings > Data Encryption).'
    References    = @('https://learn.microsoft.com/azure/cosmos-db/how-to-setup-customer-managed-keys')
    Policy        = @{ '1f905d99-2ab7-462c-a6b0-f709acca6c8f' = 'Azure Cosmos DB accounts should use customer-managed keys to encrypt data at rest' }
    ResourceTypes = $cosmosType
    Evaluate      = {
        param($Record)
        $uri = $Record.resource.properties.keyVaultKeyUri
        $evidence = [ordered]@{ keyVaultKeyUri = [bool]$uri }
        if ($uri) { return New-Pass 'Customer-managed key' $evidence }
        New-Fail 'Service-managed key' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-COS-008'
    Title         = 'Cosmos DB accounts send all resource logs to a destination'
    Category      = 'Logging and threat detection'
    Service       = 'Cosmos DB'
    Severity      = 'Medium'
    Description   = 'Checks Cosmos DB accounts for a diagnostic setting that sends the allLogs category group to a destination.'
    Rationale     = 'Cosmos DB resource logs record data plane and control plane requests; they are needed to detect and investigate misuse of the account.'
    Remediation   = 'Create a diagnostic setting with the allLogs category group to a Log Analytics workspace.'
    References    = @('https://learn.microsoft.com/azure/cosmos-db/monitor-resource-logs')
    ResourceTypes = $cosmosType
    Evaluate      = {
        param($Record)
        if ($null -eq $Record.diagnosticSettings) { return New-Unknown 'Diagnostic settings could not be read' }
        $complete = @($Record.diagnosticSettings | Where-Object {
                $_ -and ($_.properties.workspaceId -or $_.properties.storageAccountId -or $_.properties.eventHubAuthorizationRuleId -or $_.properties.marketplacePartnerId) -and
                @($_.properties.logs | Where-Object { $_.enabled -and $_.categoryGroup -eq 'allLogs' }).Count
            } | ForEach-Object name | Sort-Object)
        $evidence = [ordered]@{ diagnosticSettings = @($Record.diagnosticSettings | ForEach-Object name | Sort-Object); withAllLogs = $complete }
        if ($complete) { return New-Pass "All logs exported ($($complete -join ', '))" $evidence }
        New-Fail 'No diagnostic setting exports the allLogs category group' $evidence
    }
}

$redisType = @('Microsoft.Cache/Redis')

Add-AzTest @{
    Id            = 'AZ-RED-001'
    Title         = 'Azure Cache for Redis only accepts TLS connections'
    Category      = 'Data protection'
    Service       = 'Azure Cache for Redis'
    Severity      = 'High'
    Description   = 'Checks that the non-TLS port (6379) is disabled.'
    Rationale     = 'The non-TLS port transfers the access key and all cached data in clear text.'
    Remediation   = 'Disable the non-TLS port (az redis update --set enableNonSslPort=false ...).'
    References    = @('https://learn.microsoft.com/azure/azure-cache-for-redis/cache-remove-tls-10-11')
    Policy        = @{ '22bee202-a82f-4305-9a2a-6d7f44d4dedb' = 'Only secure connections to your Azure Cache for Redis should be enabled' }
    ResourceTypes = $redisType
    Evaluate      = {
        param($Record)
        $value = [bool]$Record.resource.properties.enableNonSslPort
        if ($value) { return New-Fail 'Non-TLS port enabled' ([ordered]@{ enableNonSslPort = $true }) }
        New-Pass 'Non-TLS port disabled' ([ordered]@{ enableNonSslPort = $false })
    }
}

Add-AzTest @{
    Id            = 'AZ-RED-004'
    Title         = 'Azure Cache for Redis requires TLS 1.2 or higher'
    Category      = 'Data protection'
    Service       = 'Azure Cache for Redis'
    Severity      = 'Medium'
    Description   = 'Checks the minimum TLS version of Azure Cache for Redis.'
    Rationale     = 'TLS 1.0 and 1.1 have known weaknesses and are no longer considered secure.'
    Remediation   = 'Set the minimum TLS version to 1.2 (az redis update --set minimumTlsVersion=1.2 ...).'
    References    = @('https://learn.microsoft.com/azure/azure-cache-for-redis/cache-remove-tls-10-11')
    Policy        = @{ 'f38646be-b908-491a-bc9b-fd507154f709' = 'Azure Cache for Redis should be running TLS version 1.2 or newer' }
    ResourceTypes = $redisType
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.minimumTlsVersion
        $evidence = [ordered]@{ minimumTlsVersion = $value }
        if (-not $value) { return New-Unknown 'The minimum TLS version was not returned' $evidence }
        if (Test-VersionAtLeast $value '1.2') { return New-Pass "Minimum TLS $value" $evidence }
        New-Fail "Minimum TLS $value" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-RED-002'
    Title         = 'Azure Cache for Redis disables access key authentication'
    Category      = 'Identity management'
    Service       = 'Azure Cache for Redis'
    Severity      = 'Medium'
    Description   = 'Checks disableAccessKeyAuthentication, which enforces Microsoft Entra authentication.'
    Rationale     = 'The access key is a shared secret with full access that is not tied to an identity.'
    Remediation   = 'Enable Microsoft Entra authentication, grant data access policies to identities, then disable access key authentication.'
    References    = @('https://learn.microsoft.com/azure/azure-cache-for-redis/cache-azure-active-directory-for-authentication')
    Policy        = @{ '3827af20-8f80-4b15-8300-6db0873ec901' = 'Azure Cache for Redis should not use access keys for authentication' }
    ResourceTypes = $redisType
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.disableAccessKeyAuthentication
        if ($value -eq $true) { return New-Pass 'Access key authentication disabled' ([ordered]@{ disableAccessKeyAuthentication = $true }) }
        New-Fail 'Access key authentication enabled' ([ordered]@{ disableAccessKeyAuthentication = $value })
    }
}

Add-AzTest @{
    Id            = 'AZ-RED-007'
    Title         = 'Azure Cache for Redis enables Microsoft Entra authentication'
    Category      = 'Identity management'
    Service       = 'Azure Cache for Redis'
    Severity      = 'Medium'
    Description   = 'Checks the aad-enabled setting of the Redis configuration.'
    Rationale     = 'Entra authentication ties cache access to identities with central lifecycle management, instead of a shared access key.'
    Remediation   = 'Enable Microsoft Entra authentication on the Authentication page of the cache.'
    References    = @('https://learn.microsoft.com/azure/azure-cache-for-redis/cache-azure-active-directory-for-authentication')
    ResourceTypes = $redisType
    Evaluate      = {
        param($Record)
        $value = [string](Get-Prop $Record.resource.properties.redisConfiguration 'aad-enabled')
        $evidence = [ordered]@{ 'aad-enabled' = $value }
        if ($value -eq 'true') { return New-Pass 'Entra authentication enabled' $evidence }
        New-Fail 'Entra authentication disabled' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-RED-008'
    Title         = 'Azure Cache for Redis has a system-assigned managed identity'
    Category      = 'Identity management'
    Service       = 'Azure Cache for Redis'
    Severity      = 'Low'
    Description   = 'Checks Azure Cache for Redis for a system-assigned managed identity.'
    Rationale     = 'A managed identity lets the cache reach storage (import, export, persistence) through RBAC instead of stored keys.'
    Remediation   = 'Turn on the system-assigned identity on the Identity page of the cache.'
    References    = @('https://learn.microsoft.com/azure/azure-cache-for-redis/cache-managed-identity')
    ResourceTypes = $redisType
    Evaluate      = {
        param($Record)
        $identity = $Record.resource.identity
        $evidence = [ordered]@{ identityType = $identity.type }
        if ([string]$identity.type -match 'SystemAssigned' -and $identity.principalId) { return New-Pass 'System-assigned identity' $evidence }
        New-Fail 'No system-assigned identity' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-RED-005'
    Title         = 'Azure Cache for Redis disables public network access'
    Category      = 'Network security'
    Service       = 'Azure Cache for Redis'
    Severity      = 'Medium'
    Description   = 'Checks that public network access of Azure Cache for Redis is Disabled. Caches injected in a virtual network, where the setting cannot be changed, are not applicable.'
    Rationale     = 'A public cache endpoint can be reached from the Internet with a stolen key or token; private endpoints remove that exposure.'
    Remediation   = 'Create a private endpoint, then disable public network access on the Private Endpoint page of the cache.'
    References    = @('https://learn.microsoft.com/azure/azure-cache-for-redis/cache-private-link')
    Policy        = @{ '470baccb-7e51-4549-8b1a-3e5be069f663' = 'Azure Cache for Redis should disable public network access' }
    ResourceTypes = $redisType
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        $evidence = [ordered]@{ publicNetworkAccess = $p.publicNetworkAccess; subnetId = $p.subnetId }
        if ($p.subnetId) { return New-NotApplicable 'Injected in a virtual network, public network access cannot be disabled' $evidence }
        if ($p.publicNetworkAccess -eq 'Disabled') { return New-Pass 'Public network access disabled' $evidence }
        New-Fail "Public network access $(if ($p.publicNetworkAccess) { $p.publicNetworkAccess } else { 'Enabled (default)' })" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-RED-006'
    Title         = 'Azure Cache for Redis is accessed through private endpoints'
    Category      = 'Network security'
    Service       = 'Azure Cache for Redis'
    Severity      = 'Low'
    Description   = 'Checks Azure Cache for Redis for an approved private endpoint connection. Caches injected in a virtual network cannot have private endpoints and fail.'
    Rationale     = 'Private endpoints keep cache traffic on private networks and allow public access to be disabled.'
    Remediation   = 'Create a private endpoint for the cache; a cache injected in a virtual network has to be recreated first.'
    References    = @('https://learn.microsoft.com/azure/azure-cache-for-redis/cache-private-link')
    Policy        = @{ '7803067c-7d34-46e3-8c79-0ca68fc4036d' = 'Azure Cache for Redis should use private link' }
    ResourceTypes = $redisType
    Evaluate      = {
        param($Record)
        if (-not (Test-PrivateEndpointsCollected $Record)) { return New-Unknown 'Private endpoint connections could not be read' }
        $count = Get-ApprovedPrivateEndpointCount $Record
        $subnet = $Record.resource.properties.subnetId
        $evidence = [ordered]@{ approvedPrivateEndpoints = $count; subnetId = $subnet }
        if ($count) { return New-Pass "$count approved private endpoint(s)" $evidence }
        if ($subnet) { return New-Fail 'No private endpoint: the cache is injected in a virtual network, which does not support private endpoints' $evidence }
        New-Fail 'No approved private endpoint' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-RED-003'
    Title         = 'Azure Cache for Redis uses the Stable update channel'
    Category      = 'Posture and vulnerability management'
    Service       = 'Azure Cache for Redis'
    Severity      = 'Low'
    Description   = 'Checks the update channel of Azure Cache for Redis.'
    Rationale     = 'The Preview channel installs Redis updates before they are generally released, with a higher risk of defects.'
    Remediation   = 'Set the update channel to Stable (az redis update --set updateChannel=Stable ...).'
    References    = @('https://learn.microsoft.com/azure/azure-cache-for-redis/cache-administration#update-channel-and-schedule-updates')
    ResourceTypes = $redisType
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.updateChannel
        $evidence = [ordered]@{ updateChannel = $value }
        if (-not $value) { return New-Unknown 'The update channel was not returned' $evidence }
        if ($value -eq 'Stable') { return New-Pass 'Stable update channel' $evidence }
        New-Fail "Update channel $value" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-RED-009'
    Title         = 'Azure Cache for Redis Enterprise encrypts disks with a customer-managed key (when required)'
    Category      = 'Data protection'
    Service       = 'Azure Cache for Redis'
    Severity      = 'Informational'
    Description   = 'Checks whether Redis Enterprise clusters encrypt disk data with a customer-managed key.'
    Rationale     = 'A customer-managed key gives control over key rotation and revocation; only required where data classification or regulation demands it.'
    Remediation   = 'Configure a Key Vault key and a user-assigned identity on the Encryption page of the cluster.'
    References    = @('https://learn.microsoft.com/azure/azure-cache-for-redis/cache-how-to-encryption')
    Policy        = @{ '09aa11bb-87ec-409f-bf0b-49b7c1561a87' = 'Azure Cache for Redis Enterprise should use customer-managed keys for encrypting disk data' }
    ResourceTypes = @('Microsoft.Cache/redisEnterprise')
    Evaluate      = {
        param($Record)
        $key = $Record.resource.properties.encryption.customerManagedKeyEncryption.keyEncryptionKeyUrl
        $evidence = [ordered]@{ customerManagedKey = [bool]$key }
        if ($key) { return New-Pass 'Customer-managed key' $evidence }
        New-Fail 'Microsoft-managed key' $evidence
    }
}
