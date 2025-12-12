New-Module -Name Az.CSPM -ScriptBlock {

    ######################
    ## Helper Functions ##
    ######################

    function Invoke-AzureRestMethod {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$Uri,
            [Parameter()][ValidateSet("GET", "POST", "PUT", "DELETE", "PATCH")][string]$Method = "GET",
            [Parameter()][hashtable]$Headers = (Get-AuthHeader),
            [Parameter()][object]$Body,
            [Parameter()][string]$ContentType, #= 'application/json',
            [Parameter()][bool]$Paginate = $true,
            [Parameter()][switch]$UseBasicParsing,
            [Parameter()][switch]$UseDefaultCredentials,
            [Parameter()][int]$TimeoutSec = 100,
            [Parameter()][string]$StatusCodeVariable = 'statusCode',
            [Parameter()][string]$ResponseHeadersVariable = 'responseHeader'
        )

        try {
            $results = @()

            # Build the options for Invoke-RestMethod
            $options = @{
                Uri         = $Uri
                Method      = $Method
                Headers     = $Headers
                TimeoutSec  = $TimeoutSec
                ErrorAction = 'Stop'
            }


            if ($Body)         { $options.Body = $Body }
            if ($ContentType)  { $options.ContentType = $ContentType }
            if ($UseBasicParsing) { $options.UseBasicParsing = $true }
            if ($StatusCodeVariable) { $options.StatusCodeVariable = $StatusCodeVariable }
            if ($ResponseHeadersVariable) { $options.ResponseHeadersVariable = $ResponseHeadersVariable }
            
             # Handle pagination
            if ($Paginate -and $Method -eq "GET") {
                $nextLink = $Uri
                while ($nextLink) {
                    $options.Uri = $nextLink
                    $response = Invoke-RestMethod @options
                    if ($response.value) {
                        $results += $response.value
                    }

                    $nextLink = $response.'nextLink'
                }

                return $results
            } else {
                $response = Invoke-RestMethod @options
                $response | Add-Member -MemberType NoteProperty -Name 'statusCode' -Value $statusCode
                $response | Add-Member -MemberType NoteProperty -Name 'headers' -Value $responseHeader
                return $response
            }
        }
        catch {
            throw "Invoke-AzureRestMethod failed: $($_.Exception.Message)"
        }
    }


    function Get-AuthHeader {
        param (
            [string]$ResourceUrl = "https://management.azure.com"
        )

        $secureToken = (Get-AzAccessToken -ResourceUrl $ResourceUrl -AsSecureString).Token

        $token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
        )

        return @{
            Authorization = "Bearer $token"
            ConsistencyLevel = "Eventual"
        }
    }

    function ConvertTo-Guid {
        param (
            [Parameter(Mandatory)]
            [string]$InputString
        )

        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        $hashBytes = $sha1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($InputString))
        $guidBytes = $hashBytes[0..15]
        return [System.Guid]::New([byte[]]$guidBytes)
    }

    function Resolve-CspmScope {
        param (
            [Parameter(Mandatory=$true)]
            [string]$Identifier
        )

        # Ensure Azure context
        if (-not (Get-AzContext)) {
            throw "No Azure context found. Please login using Connect-AzAccount."
        }

        # Try resolving as subscription name
        $sub = Get-AzSubscription | Where-Object { $_.Name -eq $Identifier -or $_.Id -eq $Identifier }
        if ($sub) {
            return "/subscriptions/$($sub.Id)"
        }

        # Try resolving as connector name
        $query = @"
            Resources 
            | where type == "microsoft.security/securityconnectors" 
            | where name =~ '$Identifier'
            | project id
"@

        $match = Search-AzGraph -Query $query

        #$connectors = Get-AzResource -ResourceType "Microsoft.Security/securityConnectors" -ExpandProperties
        #$match = $connectors | Where-Object { $_.Name -eq $Identifier }

        if ($match.Count -eq 1) {
            return $match[0].id
            #return $match.ResourceId
        }

        throw "Could not resolve identifier '$Identifier' as either a subscription or connector name."
    }

    function New-AzRBACAssignment {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)][string]$Scope,
            [Parameter(Mandatory)][string]$MemberName,
            [Parameter(Mandatory)][string]$RoleDefinition,

            [Parameter()][ValidateSet("Active", "Eligible")]
            [string]$AssignmentType = "Active",

            [Parameter()][datetime]$StartDateTime,

            [Parameter()][datetime]$EndDateTime,

            [Parameter()][string]$Justification = "Creating role assignment from RBAC Extension",

            # Force only allows RBAC -> PIM conversion. It WILL remove permanent RBAC if present.
            [Parameter()][switch]$Force
        )

        try {
            # # Resolve resource
            # $resource = Get-AzResource -Name $ResourceName -ErrorAction Stop
            # if (-not $resource -or $resource.Count -eq 0) { throw "Resource '$ResourceName' not found in the current subscription context." }
            # if ($resource.Count -gt 1) {
            #     Write-Error "Multiple resources found with name '$ResourceName'. Specify ResourceId or ResourceGroupName/ResourceType."
            #     $resource | Select-Object Name, ResourceType, ResourceGroupName, ResourceId
            #     return
            # }
            # $scope = $resource[0].ResourceId

            # -------- Resolve Scope --------
            if ($Scope) {
                $scope = $Scope.TrimEnd('/')
                if ($scope -notmatch '^/subscriptions/|^/providers/Microsoft.Management/managementGroups/|^/$'){
                    throw "Invalid scope format. Must be tenant '/', management group, subscription, resource group, or resource."
                }
            }elseif($ResourceName){
                $resource = Get-AzResource -Name $ResourceName -ErrorAction Stop
                if (-not $resource -or $resource.Count -eq 0) {
                    throw "Resource '$ResourceName' not found in the current subscription context."
                }
                if ($resource.Count -gt 1) {
                    throw "Multiple resources found with name '$ResourceName'. Use -Scope with the full resourceId instead."
                }
                $scope = $resource[0].ResourceId
            }else{
                throw "You must specify either -Scope or -ResourceName."
            }

            # Resolve principal
            $entra = Get-AzAdObject -Identity $MemberName
            if (-not $entra) { throw "Principal '$MemberName' not found." }
            $principalId = $entra.Id

            # Resolve role definition
            $role = Get-AzRoleDefinition -Name $RoleDefinition -ErrorAction SilentlyContinue
            if (-not $role) { $role = Get-AzRoleDefinition -Id $RoleDefinition -ErrorAction SilentlyContinue }
            if (-not $role) { throw "Role definition '$RoleDefinition' not found." }
            $roleDefinitionId = $role.Id

            # If EndDateTime not provided => permanent RBAC path
            if (-not $PSBoundParameters.ContainsKey('EndDateTime')) {
                Write-Warning "Permanent RBAC mode detected (no EndDateTime provided)."

                $existing = Get-AzRoleAssignment -ObjectId $principalId -RoleDefinitionId $roleDefinitionId -Scope $scope -ErrorAction SilentlyContinue

                if ($existing) {
                    Write-Warning "An existing permanent RBAC assignment already exists."
                    return $existing
                }

                # Create permanent RBAC
                return New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionId $roleDefinitionId -Scope $scope
            }

            # ---------- PIM mode ----------
            Write-Verbose "PIM mode ($AssignmentType)"

            # Normalize Start/End
            if (-not $StartDateTime) { $StartDateTime = Get-Date }

            # If user supplied a date-only value it will have TimeOfDay == 00:00:00.
            # Treat that as "end of that day local" for EndDateTime.
            if ($EndDateTime.TimeOfDay.TotalSeconds -eq 0) {
                $EndDateTime = $EndDateTime.Date.AddDays(1).AddSeconds(-1)
            }

            $startUtc = $StartDateTime.ToUniversalTime().ToString("o")
            $endUtc   = $EndDateTime.ToUniversalTime().ToString("o")

            # Detect permanent RBAC existence
            $rbac = Get-AzRoleAssignment -ObjectId $principalId -RoleDefinitionId $roleDefinitionId -Scope $scope -ErrorAction SilentlyContinue

            if ($rbac -and -not $Force) {
                throw "Permanent RBAC assignment exists at scope $scope for principal $MemberName and role $RoleDefinition. Rerun with -Force to convert RBAC -> PIM."
            }

            if ($rbac -and $Force) {
                Write-Warning "Force specified — converting permanent RBAC to PIM by removing existing RBAC assignment(s)."
                foreach ($r in $rbac) {
                    # Use Remove-AzRoleAssignment to stay in Az module
                    Remove-AzRoleAssignment -ObjectId $principalId -RoleDefinitionId $roleDefinitionId -Scope $scope -ErrorAction Stop
                }
            }

            # Find existing PIM assignments (schedules)
            Write-Verbose "Finding Existing PIM assignments"
            $pimUri = "https://management.azure.com/$($scope)/providers/Microsoft.Authorization/roleAssignmentSchedules?api-version=2020-10-01"
            $pimAssignments = Invoke-AzureRestMethod -Uri $pimUri -Method GET -ErrorAction SilentlyContinue

            # If Invoke-AzureRestMethod paginates, it will return array. If single response, handle that.
            $pimAssignments = @($pimAssignments) | Where-Object { $_ -ne $null }

            $typeFilter = if ($AssignmentType -eq "Eligible") { "Eligible" } else { "Active" }

            $existingPim = $pimAssignments | Where-Object {
                ($_.principalId -eq $principalId) -and
                ($_.roleDefinitionId -eq $roleDefinitionId) -and
                ($_.scope -eq $scope) -and
                ($_.assignmentType -eq $typeFilter)
            }

            # If PIM exists -> Auto-extend
            if ($existingPim -and $existingPim.Count -gt 0) {
                if ($existingPim.Count -gt 1) {
                    throw "Multiple PIM assignments found for principal/role/scope — manual intervention required."
                }

                Write-Verbose "Existing PIM found — submitting extend request."

                $extendUri = "https://management.azure.com/$($scope)/providers/Microsoft.Authorization/roleAssignmentScheduleRequests?api-version=2020-10-01"
                $extendBody = @{
                    properties = @{
                        requestType = "AdminExtend"
                        principalId = $principalId
                        roleDefinitionId = "/providers/Microsoft.Authorization/roleDefinitions/$($roleDefinitionId)"
                        scope = $scope
                        justification = $Justification
                        scheduleInfo = @{
                            expiration = @{
                                type = "AfterDateTime"
                                endDateTime = $endUtc
                            }
                        }
                    }
                } | ConvertTo-Json -Depth 10

                $extendResp = Invoke-AzureRestMethod -Method POST -Uri $extendUri -Body $extendBody -ContentType "application/json"

                if ($extendResp -and $extendResp.properties -and $extendResp.properties.status -eq "PendingApproval") {
                    Write-Warning "PIM extend request submitted and is pending approval."
                }

                return $extendResp
            }

            # Create new PIM assignment
            Write-Warning "Creating new PIM assignment"
            $requestType = if ($AssignmentType -eq "Eligible") { "AdminAssignEligible" } else { "AdminAssign" }
            $guid = (New-Guid).Guid
            $createUri = "https://management.azure.com/$($scope)/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/$($guid)?api-version=2020-10-01"
            $createBody = @{
                properties = @{
                    condition = $null
                    conditionVersion = $null
                    requestType = $requestType
                    principalId = $principalId
                    roleDefinitionId = "/providers/Microsoft.Authorization/roleDefinitions/$($roleDefinitionId)"
                    justification = $Justification
                    scheduleInfo = @{
                        startDateTime = "2025-12-02T01:14:46.139Z" #$startUtc
                        expiration = @{
                            type = "AfterDateTime"
                            endDateTime = $endUtc
                        }
                    }
                }
            } | ConvertTo-Json -Depth 10
            $response = Invoke-AzureRestMethod -Method PUT -Uri $createUri -Body $createBody -ContentType "application/json"
            #Invoke-RestMethod -Method PUT -Uri $createUri -Body $createBody -Headers $header -ContentType "application/json" 

            if ($response -and $response.properties -and $response.properties.status -eq "PendingApproval") {
                Write-Warning "PIM create request submitted but is pending approval."
            }

            return $response
        }
        catch {
            throw "New-AzRBACAssignment failed: $($_.Exception.Message)"
        }
    }

    # function Invoke-CspmAzGraphQuery {
    #     [CmdletBinding()]
    #     param (
    #         [Parameter(Mandatory = $true)]
    #         [string]$Query
    #     )
    #
    #     # Build ARG request body
    #     $body = @{ query = $Query } | ConvertTo-Json -Depth 5
    #
    #     # ARG REST endpoint
    #     $uri = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources`?api-version=2022-10-01"
    #
    #     try {
    #         Write-Verbose "Invoking Azure Resource Graph query..."
    #         $response = Invoke-AzureRestMethod `
    #             -Method POST `
    #             -Uri $uri `
    #             -Body $body `
    #             -Headers (Get-AuthHeader) `
    #             -ContentType 'application/json'
    #
    #         if (-not $response.data) {
    #             Write-Warning "Query returned no results."
    #             return $response
    #         }
    #
    #         # Return raw data array
    #         return $response.data
    #     }
    #     catch {
    #         throw "Failed to execute Resource Graph query: $_"
    #     }
    # }
    
    ######################
    ## Custom Standards ##
    ######################

    function Get-CspmCustomStandard {
        param(
            [string]$DisplayName,
            [string]$Id,
            [string]$Scope = (Get-AzContext).Subscription.Id
        )

        $scope = Resolve-CspmScope -Identifier $Scope
        if ($DisplayName) {
            $Id = (ConvertTo-Guid $DisplayName).Guid
        }

        if ($Id) {
            $uri = "https://management.azure.com/$Scope/providers/Microsoft.Security/securityStandards/$Id?api-version=2024-08-01"
        } else {
            $uri = "https://management.azure.com/$Scope/providers/Microsoft.Security/securityStandards?api-version=2024-08-01"
        }

        $response = Invoke-AzureRestMethod -Uri $uri -Method GET -Headers (Get-AuthHeader)
        return $response
    }

    function New-CspmCustomStandard {
        param(
            [Parameter(Mandatory)] [string]$DisplayName,
            [Parameter(Mandatory)] [string]$Description,
            [Parameter(Mandatory)] [string[]]$Assessments,
            [Parameter(Mandatory)] [string]$CloudProvider,
            [string]$Scope = (Get-AzContext).Subscription.Id
        )

        $scope = Resolve-CspmScope -Identifier $Scope
        $id = (ConvertTo-Guid $DisplayName).Guid
        $uri = "https://management.azure.com/$Scope/providers/Microsoft.Security/securityStandards/$id?api-version=2024-08-01"

        $body = @{ 
            properties = @{
                displayName    = $DisplayName
                description    = $Description
                standardType   = "Custom"
                assessments    = $Assessments
                cloudProviders = @($CloudProvider)
            }
        } | ConvertTo-Json -Depth 10

        Invoke-AzureRestMethod -Uri $uri -Method PUT -Headers (Get-AuthHeader) -Body $body -ContentType 'application/json'
    }

    function Remove-CspmCustomStandard {
        param(
            [string]$DisplayName,
            [string]$Id,
            [string]$Scope = (Get-AzContext).Subscription.Id
        )

        $scope = Resolve-CspmScope -Identifier $Scope
        if ($DisplayName) {
            $Id = (ConvertTo-Guid $DisplayName).Guid
        }

        if (-not $Id) {
            throw "Either DisplayName or Id must be provided."
        }

        $uri = "https://management.azure.com/$Scope/providers/Microsoft.Security/securityStandards/$Id?api-version=2024-08-01"
        $response = Invoke-AzureRestMethod -Uri $uri -Method DELETE -Headers (Get-AuthHeader)
        if($response.statusCode -eq '202'){
            Write-Host "$($response.statusCode): Successfully Deleted $($DisplayName)" -ForegroundColor Green
        }else{
            Write-Error "$($response.statusCode): $($Error[0])"
        }

    }

    function Update-CspmCustomStandard {
        param (
            [Parameter(Mandatory)][string]$Scope,
            [Parameter(Mandatory)][string]$DisplayName,
            [Parameter(Mandatory)][string[]]$Assessments,
            [Parameter()][string]$Description = $DisplayName,
            [Parameter()][string]$CloudProvider = "AWS"
        )

        $scope = Resolve-CspmScope -Identifier $Scope
        $standardId = (ConvertTo-Guid $DisplayName).Guid

        $body = @{
            properties = @{
                displayName    = $DisplayName
                description    = $Description
                standardType   = "Custom"
                assessments    = @($Assessments)
                cloudProviders = @($CloudProvider)
            }
        } | ConvertTo-Json -Depth 10

        $uri = "https://management.azure.com/$Scope/providers/Microsoft.Security/securityStandards/$standardId?api-version=2024-08-01"

        Invoke-AzureRestMethod -Method PUT -Uri $uri -Headers $script:CspmAuthHeader -Body $body -ContentType 'application/json'
    }

    #####################
    ## Governance Rule ##
    #####################

    function New-CspmGovernanceRule {
        param (
            [Parameter(Mandatory = $false)][string]$Scope,
            [Parameter(Mandatory)][string]$DisplayName,
            [Parameter(Mandatory)][string]$Description = $DisplayName,
            [Parameter(Mandatory)][string[]]$ConditionList,
            [Parameter(Mandatory)][string]$Owner,
            [Parameter(Mandatory)][string]$Priority,
            [boolean]$includeMember = $true,
            [string]$remediationTimeframe = "365.00:00:00",
            [switch]$Severity,
            [switch]$Category,
            [switch]$Risk,
            [switch]$Assessment,
            [switch]$TenantRoot
        )

        # Validate mutually exclusive switches
        $enabledSwitches = @(
            if ($Severity)  { 'Severity' }
            if ($Risk)      { 'Risk' }
            if ($Assessment){ 'Assessment' }
        )

        if ($enabledSwitches.Count -gt 1) {
            throw "Only one specified at a time: Severity, Risk, Assessment. Provided: $($enabledSwitches -join ', ')"
        }
        
        # Determime Scope
        if($TenantRoot){
        # Resolve tenant root MG scope using tenant ID
            $tenantId = (Get-AzContext).Tenant.Id
            $resolvedScope = "/providers/Microsoft.Management/managementGroups/$tenantId"
        }elseif($scope){
            $resolvedScope = Resolve-CspmScope -Identifier $Scope
        }else{
            throw "Either -Scope or -TenantRoot must be specified."
        }


        if($Severity){
            $Condition = "properties.metadata.severity"
        }elseif($Risk){ 
            $Condition = "properties.metadata.risk"
        }elseif($Category){
            $Condition = "properties.metadata.recommendationCategory"
        }elseif($Assessment){
            $Condition = "name"
        }else{
            throw "You must specify one condition to determine the governance rule condition: -Severity, -Risk, -Category or -Assessment."
        }

        # Generate Deterministic GUID
        $ruleId = (ConvertTo-Guid $DisplayName).Guid

        $body = @{
            properties = @{
                displayName    = $DisplayName
                description    = $Description
                remediationTimeframe = $remediationTimeframe
                includeMemberScopes = $includeMember
                isGracePeriod = $true
                rulePriority = $priority
                isDisabled = $false
                ruleType = "Integrated"
                sourceResourceType = "Assessments"
                conditionSets = @(@{
                    conditions = @(@{
                        property = $Condition
                        value    = ConvertTo-Json -InputObject $ConditionList -compress
                        operator = "In"
                    })
                })
                ownerSource = @{
                    ownerType = "Group"
                    type      = "Manually"
                    value     = $Owner
                }
                governanceEmailNotification = @{
                    disableManagerEmailNotification = $true
                    disableOwnerEmailNotification = $false
                }
                excludedScopes = @()
            }
        } | ConvertTo-Json -Depth 10
        Write-Host $body
        $uri = "https://management.azure.com/$resolvedScope/providers/Microsoft.Security/governanceRules/$ruleId`?api-version=2022-01-01-preview"
        Write-Host $uri
        Invoke-AzureRestMethod -Method PUT -Uri $uri -Headers (Get-AuthHeader) -Body $body -ContentType 'application/json'
    }

    function Get-CspmGovernanceRule {
        param (
            [Parameter(Mandatory = $false)][string]$Scope,
            [Parameter(Mandatory = $false)][string]$DisplayName,
            [switch]$TenantRoot
        )

        # Resolve Scope
        if($TenantRoot){
            $tenantId = (Get-AzContext).Tenant.Id
            $resolvedScope = "/providers/Microsoft.Management/managementGroups/$tenantId"
        }elseif($scope){
            $resolvedScope = Resolve-CspmScope -Identifier $Scope
        }else{
            throw "Either -Scope or -TenantRoot must be specified."
        }
    
        # Optional filter by DisplayName (deterministic GUID)
        if ($DisplayName) {
            $ruleId = (ConvertTo-Guid $DisplayName).Guid
            $uri = "https://management.azure.com/$resolvedScope/providers/Microsoft.Security/governanceRules/$ruleId?api-version=2022-01-01-preview"
        } else {
            $uri = "https://management.azure.com/$resolvedScope/providers/Microsoft.Security/governanceRules?api-version=2022-01-01-preview"
        }

        try{
            $response = Invoke-AzureRestMethod -Method GET -Uri $uri -Headers (Get-AuthHeader)
            return $response
        } catch {
            throw "Failed to GET governance rules for $($Scope) $($DisplayName): $_"
        }
    }
    
    # function Get-CspmGovernanceRule {
    #     [CmdletBinding()]
    #     param (
    #         [Parameter(Mandatory = $false)][string]$Scope,
    #         [Parameter(Mandatory = $false)][string]$DisplayName,
    #         [switch]$TenantRoot
    #     )
    #
    #     # Resolve Scope
    #     if ($TenantRoot) {
    #         $tenantId = (Get-AzContext).Tenant.Id
    #         $resolvedScope = "/providers/Microsoft.Management/managementGroups/$tenantId"
    #     } elseif ($Scope) {
    #         $resolvedScope = Resolve-CspmScope -Identifier $Scope
    #     } else {
    #         throw "Either -Scope or -TenantRoot must be specified."
    #     }
    #
    #     # Build base KQL query
    #     $query = "securityresources | where type == 'microsoft.security/governancerules' | extend scopeId = tostring(split(tolower(id), '/providers/microsoft.security/governancerules/')[0]) | where scopeId == tolower('$resolvedScope')"
    #
    #     # Optional filter by DisplayName (deterministic GUID)
    #     if ($DisplayName) {
    #         $ruleId = (ConvertTo-Guid $DisplayName).Guid
    #         $query += "`n| where id endswith '$ruleId'"
    #     }
    #
    #     # Build ARG request body
    #     $body = @{ query = $query } | ConvertTo-Json -Depth 5
    #
    #     # ARG REST endpoint
    #     $uri = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources`?api-version=2022-10-01"
    #
    #     try {
    #         Write-Verbose "Querying ARG for governance rules..."
    #         $response = Invoke-AzureRestMethod -Method POST -Uri $uri -Body $body -Headers (Get-AuthHeader) -ContentType 'application/json'
    #
    #         if (-not $response.data) {
    #             Write-Warning "No governance rules found for scope: $resolvedScope"
    #             return $response
    #         }
    #
    #         # Return clean JSON
    #         return ($response.data ) #| ConvertTo-Json -Depth 10)
    #     } catch {
    #         throw "Failed to query ARG for governance rules: $_"
    #     }
    # }


    function Update-CspmGovernanceRule {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)][string]$Scope,
            [Parameter(Mandatory)][string]$DisplayName,
            #[Parameter(Mandatory)][string[]]$AssessmentGuids,
            [Parameter(Mandatory)][string]$OwnerGroup
        )

        $scope = Resolve-CspmScope -Identifier $Scope
        #New-CspmGovernanceRule -Scope $Scope -DisplayName $DisplayName -AssessmentGuids $AssessmentGuids -OwnerGroup $OwnerGroup
    }

    function Remove-CspmGovernanceRule {
        param (
            [Parameter(Mandatory)][string]$Scope,
            [Parameter(Mandatory)][string]$DisplayName
        )

        $scope = Resolve-CspmScope -Identifier $Scope
        $ruleId = (ConvertTo-Guid $DisplayName).Guid
        $uri = "https://management.azure.com/$Scope/providers/Microsoft.Security/governanceRules/$ruleId?api-version=2022-01-01-preview"

        $response = Invoke-AzureRestMethod -Method DELETE -Uri $uri -Headers (Get-AuthHeader)
        if($statusCode -eq '202'){
            Write-Host "$($statusCode): Successfully Deleted $($DisplayName)" -ForegroundColor Green
        }else{
            Write-Error "$($statusCode): $($Error[0])"
        }
    }

    function Execute-CspmGovernanceRule {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $false)]
            [string]$Scope,
            [string]$DisplayName,
            [Parameter(ValueFromPipeline)]
            [string]$Id,
            [switch]$TenantRoot,
            [switch]$Override,
            [int]$TimeoutSeconds = 1800 #900  # 15 min hard stop
        )

        # -----------------------------
        # Resolve Scope
        # -----------------------------
        if ($TenantRoot){
            $tenantId = (Get-AzContext).Tenant.Id
            $resolvedScope = "/providers/microsoft.management/managementgroups/$tenantId"
        }elseif($Scope){
            $resolvedScope = Resolve-CspmScope -Identifier $Scope
        }else{
            throw "Either -Scope or -TenantRoot must be specified."
        }

        # -----------------------------
        # Resolve Rule ID
        # -----------------------------
        $ruleId = if($Id){
            $Id
        }else{
            (ConvertTo-Guid $DisplayName).Guid
        }

        # -----------------------------
        # Build URI + Body
        # -----------------------------
        $uri = "https://management.azure.com/$resolvedScope/providers/Microsoft.Security/governanceRules/$ruleId/execute?api-version=2022-01-01-preview"

        $body = if($Override){
            @{Override = $true } | ConvertTo-Json
        }else{
            $null
        }

        Write-Host "Executing governance rule $ruleId" -ForegroundColor Magenta

        # -----------------------------
        # Fire Initial Execute
        # -----------------------------
        $response = Invoke-AzureRestMethod -Method POST -Uri $uri -ContentType 'application/json' -Headers (Get-AuthHeader) -Body $body
        
        if ($response.StatusCode -ne 202) {
            throw "Execution failed immediately. StatusCode: $($response.StatusCode)"
        }

        # -----------------------------
        # Extract Polling Headers
        # -----------------------------
        $locationUrl = $response.Headers['Location'] | Select-Object -First 1
        if (-not $locationUrl) {
            throw "No Location header returned from execution. Cannot poll."
        }

        $retryAfter = 60
        #$retryHeader = $response.Headers['Retry-After'] | Select-Object -First 1
        #if ($retryHeader -and [int]::TryParse($retryHeader, [ref]$retryAfter)) { }

        Write-Host "Execution accepted (202). Polling..." -ForegroundColor Cyan
        Write-Host "Poll URL: $locationUrl" -ForegroundColor DarkGray
        Write-Host "Initial Retry-After: $retryAfter sec" -ForegroundColor DarkGray

        # -----------------------------
        # Poll Loop
        # -----------------------------
        $startTime   = Get-Date
        $isComplete  = $false
        $lastStatus  = $null

        while (-not $isComplete) {

            Start-Sleep -Seconds $retryAfter

            # Timeout Guard
            if ((Get-Date) -gt $startTime.AddSeconds($TimeoutSeconds)) {
                throw "Polling timed out after $TimeoutSeconds seconds."
            }

            try {
                $pollResponse = Invoke-AzureRestMethod -Method GET -Uri $locationUrl -Headers (Get-AuthHeader) -Paginate $false
                $pollResponse
                Write-Host "test $($pollResponse.StatusCode)"
                $statusCode = $pollResponse.StatusCode
                $headers    = $pollResponse.Headers

                # Update Retry-After if present
                #$retryHeader = $headers['Retry-After'] | Select-Object -First 1
                #if ($retryHeader -and [int]::TryParse($retryHeader, [ref]$retryAfter)) { }

                # Terminal response often comes back as 200 with body
                if ($statusCode -eq 200) {
                    $bodyJson = $pollResponse.Content | ConvertFrom-Json
                    $lastStatus = $bodyJson.status

                    Write-Host "Final Status: $lastStatus" -ForegroundColor Green
                    return $bodyJson
                }

                # Still running → 202
                if ($statusCode -eq 202) {
                    $locationUrl = $headers['Location'] | Select-Object -First 1
                    Write-Host "Still running... next check in $retryAfter sec" -ForegroundColor Yellow
                    continue
                }

                # Unexpected but non-terminal
                Write-Warning "Unexpected poll status: $statusCode"
            }catch{
                Write-Warning "Polling error: $($_.Exception.Message). Retrying in 60 sec."
                $retryAfter = 60
            }
        }
    }

    #########################
    ## Assessment Metadata ##
    #########################

    function Get-CspmAssessmentMetadata {
        param(
            [string]$Scope # = (Get-AzContext).Subscription.Id
        )

        try {
            if($scope){
                $resolvedScope = Resolve-CspmScope -Identifier $Scope
            }
            $uri = "https://management.azure.com/$resolvedScope/providers/Microsoft.Security/assessmentMetadata?api-version=2020-01-01"

            $response = Invoke-AzureRestMethod -Method GET -Uri $uri -Headers (Get-AuthHeader) -ErrorAction Stop

            if ($response) {
                return $response
            } else {
                Write-Warning "No assessment metadata returned from $resolvedScope"
                return @()
            }
        }
        catch {
            Write-Error "Failed to retrieve assessment metadata: $($_.Exception.Message)"
        }
    }
} | Import-Module
