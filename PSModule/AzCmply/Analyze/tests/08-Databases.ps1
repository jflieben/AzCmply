#Databases: Azure SQL, SQL Managed Instance, PostgreSQL and MySQL flexible server, Cosmos DB, Azure Cache for Redis

function Get-ServerParameter {
    #value of a server parameter from the 'configurations' child (PostgreSQL / MySQL)
    param($Record, [string]$Name)
    $item = @(Get-Child $Record 'configurations') | Where-Object { $_ -and $_.name -eq $Name } | Select-Object -First 1
    if (-not $item) { return $null }
    return [string]$item.properties.value
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

function Test-PublicNetworkDisabled {
    param($Record)
    $p = $Record.resource.properties
    return ($p.publicNetworkAccess -eq 'Disabled' -or $p.network.publicNetworkAccess -eq 'Disabled')
}

$firewallTypes = @('Microsoft.Sql/servers', 'Microsoft.Synapse/workspaces', 'Microsoft.DBforPostgreSQL/flexibleServers', 'Microsoft.DBforMySQL/flexibleServers', 'Microsoft.DBforPostgreSQL/servers', 'Microsoft.DBforMySQL/servers', 'Microsoft.Cache/Redis', 'Microsoft.DocumentDB/databaseAccounts')

Add-AzTest @{
    Id            = 'AZ-DB-001'
    Version       = 2
    Title         = 'Database firewalls do not allow access from the entire Internet'
    Category      = 'Network security'
    Service       = 'Databases'
    Severity      = 'Critical'
    Description   = 'Finds IPv4 and IPv6 firewall rules on SQL servers, Synapse workspaces, PostgreSQL and MySQL servers, Redis caches and Cosmos DB accounts that cover 0.0.0.0-255.255.255.255 or at least a /8 range (IPv6: wider than a /64), while public network access is enabled.'
    Rationale     = 'Such rules expose the database endpoint to every attacker on the Internet, leaving authentication as the only control against brute force and credential stuffing.'
    Remediation   = 'Delete the rule and allow only specific client addresses, or better, disable public network access and use private endpoints.'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/firewall-configure')
    ResourceTypes = $firewallTypes
    Evaluate      = {
        param($Record)
        if (Test-PublicNetworkDisabled $Record) { return New-Pass 'Public network access disabled, firewall rules do not apply' }
        if (-not (Test-DatabaseFirewallCollected $Record)) { return New-Unknown 'Firewall rules could not be read' }
        $rules = @(Get-DatabaseFirewallRules $Record)
        $wide = @($rules | Where-Object {
                if ($_.Prefix) { return (Test-IPv6RuleWide $_) }
                $start = ConvertTo-IPv4Number $_.Start
                $end = ConvertTo-IPv4Number $_.End
                $null -ne $start -and $null -ne $end -and ($end - $start + 1) -ge 16777216
            } | ForEach-Object { "$($_.Name) ($(if ($_.Prefix) { $_.Prefix } else { "$($_.Start)-$($_.End)" }))" })
        $evidence = [ordered]@{ firewallRules = $rules.Count; wideRules = $wide }
        if ($wide) { return New-Fail "Internet wide rule(s): $($wide -join ', ')" $evidence }
        New-Pass 'No Internet wide firewall rules' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-DB-002'
    Version       = 2
    Title         = "Database firewalls do not allow all Azure services"
    Category      = 'Network security'
    Service       = 'Databases'
    Severity      = 'Medium'
    Description   = "Finds the 'Allow Azure services and resources to access this server' rule (0.0.0.0) on SQL servers, Synapse workspaces, PostgreSQL and MySQL servers, and the 0.0.0.0 rule on Cosmos DB accounts."
    Rationale     = 'The rule admits connections from any Azure resource of any customer, not just your own, so anyone can host a client in Azure and reach the database endpoint.'
    Remediation   = 'Remove the rule and use private endpoints, virtual network rules or managed identity based access for your Azure workloads.'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/firewall-configure')
    ResourceTypes = $firewallTypes
    Filter        = { param($Record) $Record.type -ne 'Microsoft.Cache/Redis' }
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

Add-AzTest @{
    Id            = 'AZ-SQL-003'
    Title         = 'A Microsoft Entra administrator is configured for SQL'
    Category      = 'Identity management'
    Service       = 'Azure SQL'
    Severity      = 'Medium'
    Description   = 'Checks SQL logical servers, managed instances and Synapse workspaces for a Microsoft Entra administrator.'
    Rationale     = 'Entra authentication enables MFA, Conditional Access, managed identities and central account lifecycle for database access; it requires an Entra administrator.'
    Remediation   = 'Set an Entra group as administrator (az sql server ad-admin create --display-name <group> --object-id <id> ...).'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/authentication-aad-configure')
    Policy        = @{ '1f314764-cb73-4fc9-b863-8eca98ac36e9' = 'An Azure Active Directory administrator should be provisioned for SQL servers' }
    ResourceTypes = @('Microsoft.Sql/servers', 'Microsoft.Sql/managedInstances', 'Microsoft.Synapse/workspaces')
    Evaluate      = {
        param($Record)
        $admin = Get-SqlEntraAdmin $Record
        if ($admin -eq $false) { return New-Unknown 'Administrators could not be read' }
        $evidence = [ordered]@{ entraAdministrator = $admin }
        if ($admin) { return New-Pass "Entra administrator $admin" $evidence }
        New-Fail 'No Entra administrator' $evidence
    }
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
    Title         = 'SQL servers and managed instances disable public network access'
    Category      = 'Network security'
    Service       = 'Azure SQL'
    Severity      = 'Medium'
    Description   = 'Checks public network access on SQL logical servers and the public data endpoint on managed instances.'
    Rationale     = 'A public endpoint depends solely on firewall rules and authentication; private endpoints remove Internet exposure entirely.'
    Remediation   = 'Create private endpoints and set public network access to Disabled (az sql server update --enable-public-network false ...); disable the public data endpoint on managed instances.'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/connectivity-settings')
    Policy        = @{ '1b8ca024-1d5c-4dec-8995-b1a932b41780' = 'Public network access on Azure SQL Database should be disabled'; '9dfea752-dd46-4766-aed1-c355fa93fb91' = 'Azure SQL Managed Instances should disable public network access' }
    ResourceTypes = @('Microsoft.Sql/servers', 'Microsoft.Sql/managedInstances')
    Evaluate      = {
        param($Record)
        $p = $Record.resource.properties
        if ($Record.type -eq 'Microsoft.Sql/managedInstances') {
            $evidence = [ordered]@{ publicDataEndpointEnabled = [bool]$p.publicDataEndpointEnabled }
            if ($p.publicDataEndpointEnabled) { return New-Fail 'Public data endpoint enabled' $evidence }
            return New-Pass 'Public data endpoint disabled' $evidence
        }
        $evidence = [ordered]@{ publicNetworkAccess = $p.publicNetworkAccess }
        if ($p.publicNetworkAccess -eq 'Disabled') { return New-Pass 'Public network access disabled' $evidence }
        New-Fail 'Public network access enabled' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-SQL-006'
    Title         = 'SQL requires TLS 1.2 or higher'
    Category      = 'Data protection'
    Service       = 'Azure SQL'
    Severity      = 'Medium'
    Description   = 'Checks the minimal TLS version of SQL logical servers and managed instances.'
    Rationale     = 'Older TLS versions have known weaknesses. From 31 July 2026 Azure SQL requires TLS 1.2 for all connections; the setting should state it explicitly.'
    Remediation   = 'Set the minimal TLS version to 1.2 (az sql server update --minimal-tls-version 1.2 ...).'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/connectivity-settings')
    Policy        = @{ '32e6bbec-16b6-44c2-be37-c5b672d103cf' = 'Azure SQL Database should be running TLS version 1.2 or newer' }
    ResourceTypes = @('Microsoft.Sql/servers', 'Microsoft.Sql/managedInstances')
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.minimalTlsVersion
        $evidence = [ordered]@{ minimalTlsVersion = $value }
        if (Test-VersionAtLeast $value '1.2') { return New-Pass "Minimal TLS $value" $evidence }
        New-Fail "Minimal TLS $(if ($value) { $value } else { 'not set' })" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-SQL-007'
    Title         = 'Transparent data encryption is enabled on SQL databases'
    Category      = 'Data protection'
    Service       = 'Azure SQL'
    Severity      = 'High'
    Description   = 'Checks the transparent data encryption state of user databases.'
    Rationale     = 'TDE encrypts database files, backups and logs at rest, protecting data against theft of storage media and backup copies.'
    Remediation   = 'Enable TDE (az sql db tde set --status Enabled ...).'
    References    = @('https://learn.microsoft.com/azure/azure-sql/database/transparent-data-encryption-tde-overview')
    Policy        = @{ '17k78e20-9358-41c9-923c-fb736d382a12' = 'Transparent Data Encryption on SQL databases should be enabled' }
    ResourceTypes = @('Microsoft.Sql/servers/databases', 'Microsoft.Sql/managedInstances/databases')
    Filter        = { param($Record) $Record.resource.name -ne 'master' -and [string]$Record.resource.kind -notmatch 'system' }
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'transparentDataEncryption')) { return New-Unknown 'TDE state could not be read' }
        $state = (@(Get-Child $Record 'transparentDataEncryption') | Where-Object { $_ } | Select-Object -First 1).properties.state
        $evidence = [ordered]@{ state = $state }
        if ($state -eq 'Enabled') { return New-Pass 'TDE enabled' $evidence }
        New-Fail 'TDE disabled' $evidence
    }
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
    Policy        = @{ '0a370ff3-6cab-4e85-8995-295fd854c5b8' = 'SQL servers should use customer-managed keys to encrypt data at rest' }
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

Add-AzTest @{
    Id            = 'AZ-PG-001'
    Title         = 'PostgreSQL flexible servers require encrypted connections with TLS 1.2 or higher'
    Category      = 'Data protection'
    Service       = 'Azure Database for PostgreSQL'
    Severity      = 'High'
    Description   = "Checks the require_secure_transport and ssl_min_protocol_version server parameters."
    Rationale     = 'Unencrypted or weakly encrypted database connections expose credentials and data on the network.'
    Remediation   = "Set require_secure_transport to ON and ssl_min_protocol_version to TLSv1.2 or TLSv1.3 (az postgres flexible-server parameter set ...)."
    References    = @('https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-networking-ssl-tls')
    Policy        = @{ 'c29c38cb-74a7-4505-9a06-e588ab86620a' = 'Enforce SSL connection should be enabled for PostgreSQL flexible servers'; 'a43d5475-c569-45ce-a268-28fa79f4e87a' = 'PostgreSQL flexible servers should be running TLS version 1.2 or newer' }
    ResourceTypes = $postgresType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'configurations')) { return New-Unknown 'Server parameters could not be read' }
        $secure = Get-ServerParameter $Record 'require_secure_transport'
        $minimum = Get-ServerParameter $Record 'ssl_min_protocol_version'
        $evidence = [ordered]@{ require_secure_transport = $secure; ssl_min_protocol_version = $minimum }
        $problems = @()
        if ($secure -ne 'on') { $problems += 'unencrypted connections allowed' }
        if (-not (Test-VersionAtLeast ($minimum -replace '^TLSv', '') '1.2')) { $problems += "minimum protocol $minimum" }
        if ($problems) { return New-Fail ($problems -join ', ') $evidence }
        New-Pass "Encrypted connections with $minimum or higher" $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-PG-002'
    Title         = 'PostgreSQL flexible servers log connections and checkpoints'
    Category      = 'Logging and threat detection'
    Service       = 'Azure Database for PostgreSQL'
    Severity      = 'Medium'
    Description   = 'Checks the log_connections, log_disconnections and log_checkpoints server parameters.'
    Rationale     = 'Connection logs show who connected from where and when; they are needed to detect brute force and unauthorized access.'
    Remediation   = 'Set log_connections, log_disconnections and log_checkpoints to on and send PostgreSQL logs to Log Analytics.'
    References    = @('https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-logging')
    ResourceTypes = $postgresType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'configurations')) { return New-Unknown 'Server parameters could not be read' }
        $values = [ordered]@{}
        foreach ($name in 'log_connections', 'log_disconnections', 'log_checkpoints') { $values[$name] = Get-ServerParameter $Record $name }
        $off = @($values.Keys | Where-Object { $values[$_] -ne 'on' })
        if ($off) { return New-Fail "Not enabled: $($off -join ', ')" $values }
        New-Pass 'Connection and checkpoint logging enabled' $values
    }
}

Add-AzTest @{
    Id            = 'AZ-PG-003'
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
        if ($libraries -match 'pgaudit' -and $log -and $log -ne 'none') { return New-Pass "pgAudit logging $log" $evidence }
        New-Fail 'pgAudit is not enabled' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-PG-004'
    Version       = 2
    Title         = 'PostgreSQL flexible servers use Microsoft Entra authentication only'
    Category      = 'Identity management'
    Service       = 'Azure Database for PostgreSQL'
    Severity      = 'Medium'
    Description   = 'Checks that Entra authentication is enabled with at least one Entra administrator and that password authentication is disabled.'
    Rationale     = 'Database passwords lack MFA and central lifecycle management and are the main brute force target of Internet reachable servers.'
    Remediation   = 'Add an Entra administrator group, move clients to Entra tokens (managed identities), then disable password authentication.'
    References    = @('https://learn.microsoft.com/azure/postgresql/flexible-server/concepts-azure-ad-authentication')
    Policy        = @{ 'fa498b91-8a7e-4710-9578-da944c68d1fe' = '[Preview]: Azure PostgreSQL flexible server should have Microsoft Entra Only Authentication enabled'; 'ce39a96d-bf09-4b60-8c32-e85d52abea0f' = 'A Microsoft Entra administrator should be provisioned for PostgreSQL flexible servers' }
    ResourceTypes = $postgresType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'administrators')) { return New-Unknown 'Entra administrators could not be read' }
        $auth = $Record.resource.properties.authConfig
        $admins = @(Get-Child $Record 'administrators' | Where-Object { $_ })
        $evidence = [ordered]@{ activeDirectoryAuth = $auth.activeDirectoryAuth; passwordAuth = $auth.passwordAuth; entraAdministrators = $admins.Count }
        if ($auth.activeDirectoryAuth -eq 'Enabled' -and $auth.passwordAuth -eq 'Disabled' -and $admins) { return New-Pass 'Entra-only authentication' $evidence }
        New-Fail $(if ($auth.activeDirectoryAuth -ne 'Enabled') { 'Entra authentication disabled' } elseif (-not $admins) { 'No Entra administrator' } else { 'Password authentication enabled' }) $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-MY-001'
    Title         = 'MySQL flexible servers require encrypted connections with TLS 1.2 or higher'
    Category      = 'Data protection'
    Service       = 'Azure Database for MySQL'
    Severity      = 'High'
    Description   = 'Checks the require_secure_transport and tls_version server parameters.'
    Rationale     = 'Unencrypted or weakly encrypted database connections expose credentials and data on the network.'
    Remediation   = "Set require_secure_transport to ON and tls_version to TLSv1.2,TLSv1.3 (az mysql flexible-server parameter set ...)."
    References    = @('https://learn.microsoft.com/azure/mysql/flexible-server/concepts-networking#tls-and-ssl')
    ResourceTypes = $mysqlType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'configurations')) { return New-Unknown 'Server parameters could not be read' }
        $secure = Get-ServerParameter $Record 'require_secure_transport'
        $versions = @((Get-ServerParameter $Record 'tls_version') -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $weak = @($versions | Where-Object { $_ -in 'TLSv1', 'TLSv1.1' })
        $evidence = [ordered]@{ require_secure_transport = $secure; tls_version = $versions }
        $problems = @()
        if ($secure -ne 'ON') { $problems += 'unencrypted connections allowed' }
        if ($weak) { $problems += "weak TLS versions allowed: $($weak -join ', ')" }
        if ($problems) { return New-Fail ($problems -join ', ') $evidence }
        New-Pass 'Encrypted connections with TLS 1.2 or higher' $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-MY-002'
    Title         = 'MySQL flexible servers have audit logging enabled'
    Category      = 'Logging and threat detection'
    Service       = 'Azure Database for MySQL'
    Severity      = 'Medium'
    Description   = 'Checks the audit_log_enabled server parameter and that connection events are audited.'
    Rationale     = 'Audit logs record connections and statements and are needed to detect and investigate unauthorized database access.'
    Remediation   = "Set audit_log_enabled to ON with audit_log_events including CONNECTION, and send the MySqlAuditLogs category to Log Analytics."
    References    = @('https://learn.microsoft.com/azure/mysql/flexible-server/concepts-audit-logs')
    ResourceTypes = $mysqlType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'configurations')) { return New-Unknown 'Server parameters could not be read' }
        $enabled = Get-ServerParameter $Record 'audit_log_enabled'
        $events = Get-ServerParameter $Record 'audit_log_events'
        $evidence = [ordered]@{ audit_log_enabled = $enabled; audit_log_events = $events }
        if ($enabled -eq 'ON' -and $events -match 'CONNECTION') { return New-Pass 'Audit logging enabled including connections' $evidence }
        New-Fail $(if ($enabled -ne 'ON') { 'Audit logging disabled' } else { 'Connection events are not audited' }) $evidence
    }
}

Add-AzTest @{
    Id            = 'AZ-MY-003'
    Version       = 2
    Title         = 'MySQL flexible servers use Microsoft Entra authentication only'
    Category      = 'Identity management'
    Service       = 'Azure Database for MySQL'
    Severity      = 'Medium'
    Description   = 'Checks for a Microsoft Entra administrator and the aad_auth_only server parameter.'
    Rationale     = 'Database passwords lack MFA and central lifecycle management and are the main brute force target of Internet reachable servers.'
    Remediation   = 'Configure an Entra administrator with a user-assigned identity, move clients to Entra tokens and set aad_auth_only to ON.'
    References    = @('https://learn.microsoft.com/azure/mysql/flexible-server/concepts-azure-ad-authentication')
    Policy        = @{ '40e85574-ef33-47e8-a854-7a65c7500560' = 'Azure MySQL flexible server should have Microsoft Entra Only Authentication enabled'; '146412e9-005c-472b-9e48-c87b72ac229e' = 'A Microsoft Entra administrator should be provisioned for MySQL servers' }
    ResourceTypes = $mysqlType
    Evaluate      = {
        param($Record)
        if (-not (Test-ChildCollected $Record 'administrators')) { return New-Unknown 'Entra administrators could not be read' }
        $admins = @(Get-Child $Record 'administrators' | Where-Object { $_ })
        $only = Get-ServerParameter $Record 'aad_auth_only'
        $evidence = [ordered]@{ entraAdministrators = $admins.Count; aad_auth_only = $only }
        if ($admins -and $only -eq 'ON') { return New-Pass 'Entra-only authentication' $evidence }
        New-Fail $(if (-not $admins) { 'No Entra administrator' } else { 'Password authentication allowed' }) $evidence
    }
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
    Policy        = @{ '862e97cf-49fc-4a5c-9de4-40d4e2e7c8eb' = 'Azure Cosmos DB accounts should have firewall rules'; '797b37f7-06b8-444c-b1ad-fc62867f335a' = 'Azure Cosmos DB should disable public network access' }
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
    ResourceTypes = @('Microsoft.Cache/Redis')
    Evaluate      = {
        param($Record)
        $value = [bool]$Record.resource.properties.enableNonSslPort
        if ($value) { return New-Fail 'Non-TLS port enabled' ([ordered]@{ enableNonSslPort = $true }) }
        New-Pass 'Non-TLS port disabled' ([ordered]@{ enableNonSslPort = $false })
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
    ResourceTypes = @('Microsoft.Cache/Redis')
    Evaluate      = {
        param($Record)
        $value = $Record.resource.properties.disableAccessKeyAuthentication
        if ($value -eq $true) { return New-Pass 'Access key authentication disabled' ([ordered]@{ disableAccessKeyAuthentication = $true }) }
        New-Fail 'Access key authentication enabled' ([ordered]@{ disableAccessKeyAuthentication = $value })
    }
}
