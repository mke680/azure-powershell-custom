New-Module -Name Az.Entra -ScriptBlock {

    function Get-AzAdObject {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [string]$Identity
        )

        # Try user
        $user = Get-AzADUser -Filter "userPrincipalName eq '$Identity' or displayName eq '$Identity'" -ErrorAction SilentlyContinue
        if ($user) { return $user }

        # Try group
        $group = Get-AzADGroup -Filter "displayName eq '$Identity'" -ErrorAction SilentlyContinue
        if ($group) { return $group }

        # Try service principal
        $sp = Get-AzADServicePrincipal -Filter "displayName eq '$Identity'" -ErrorAction SilentlyContinue
        if ($sp) { return $sp }

        throw "Object '$Identity' not found as User, Group, or Service Principal."
    }

    function Set-MgAppPermissionAssignment {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
            [ValidateSet("Delegated", "Application")]
            [string]$Type,

            [Parameter(Mandatory)]
            [string[]]$Permissions,

            [Parameter(Mandatory)]
            [string[]]$Principals,

            [Parameter(Mandatory)]
            [string]$ResourceDisplayName,

            [Parameter]
            [string]$ClientDisplayName
        )

        $results = @()

        Write-Verbose "Retrieving Azure context and authenticating to Microsoft Graph..."
        $context = Get-AzContext
        $graphToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
            $context.Account,
            $context.Environment,
            $context.Tenant.Id.ToString(),
            $null,
            [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never,
            $null,
            "https://graph.microsoft.com"
        ).AccessToken

        $secureToken = ConvertTo-SecureString $graphToken -AsPlainText -Force
        Connect-MgGraph -AccessToken $secureToken -NoWelcome | Out-Null

        # Retrieve Resource SP
        $resource = Get-MgServicePrincipal -Filter "displayName eq '$ResourceDisplayName'" -Property Id, DisplayName, AppId, AppRoles, Oauth2PermissionScopes
        Write-Verbose ("Connected to Resource: {0} (AppId: {1})" -f $resource.DisplayName, $resource.AppId)

        foreach ($principal in $Principals) {
            Write-Verbose "Processing principal: $principal"

            if ($Type -eq "Application") {
                $sp = Get-MgServicePrincipal -Filter "displayName eq '$principal'"

                foreach ($permission in $Permissions) {
                    $appRole = $resource.AppRoles | Where-Object { $_.Value -eq $permission }

                    if ($null -eq $appRole) {
                        Write-Warning "AppRole '$permission' not found."
                        $results += [pscustomobject]@{
                            Principal     = $principal
                            Permission    = $permission
                            Type          = "Application"
                            Status        = "Failed"
                            Message       = "Permission not found in app roles."
                        }
                        continue
                    }

                    $params = @{
                        PrincipalId = $sp.Id
                        ResourceId  = $resource.Id
                        AppRoleId   = $appRole.Id
                    }

                    try {
                        $assignment = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -BodyParameter $params -ErrorAction Stop
                        $results += [pscustomobject]@{
                            Principal     = $principal
                            Permission    = $permission
                            Type          = "Application"
                            Status        = "Success"
                            Message       = "Assigned successfully."
                            AssignmentId  = $assignment.Id
                            CreatedDate   = $assignment.CreatedDateTime
                        }
                    } catch {
                        $msg = $_.Exception.Message
                        if ($msg -match "already exists") {
                            $results += [pscustomobject]@{
                                Principal     = $principal
                                Permission    = $permission
                                Type          = "Application"
                                Status        = "Exists"
                                Message       = "Already assigned."
                            }
                        } else {
                            $results += [pscustomobject]@{
                                Principal     = $principal
                                Permission    = $permission
                                Type          = "Application"
                                Status        = "Error"
                                Message       = $msg
                            }
                        }
                    }
                }

            } else {
                # Delegated permissions
                $principalUser = Get-AzADUser -UserPrincipalName $principal
                if($null -eq $ClientDisplayName){
                    throw "ClientDisplayName not provided"
                }
                $client = Get-MgServicePrincipal -Filter "displayName eq '$ClientDisplayName'"
                $filter = "principalId eq '{0}' and clientId eq '{1}'" -f $principalUser.Id, $client.Id
                $existingGrant = Get-MgOauth2PermissionGrant -Filter $filter

                foreach ($permission in $Permissions) {
                    $scopeObj = $resource.Oauth2PermissionScopes | Where-Object { $_.Value -eq $permission }

                    if ($null -eq $scopeObj) {
                        Write-Warning "Scope '$permission' not found."
                        $results += [pscustomobject]@{
                            Principal     = $principal
                            Permission    = $permission
                            Type          = "Delegated"
                            Status        = "Failed"
                            Message       = "Scope not found."
                        }
                        continue
                    }

                    if ($existingGrant -and $existingGrant.Scope -like "*$permission*") {
                        $results += [pscustomobject]@{
                            Principal     = $principal
                            Permission    = $permission
                            Type          = "Delegated"
                            Status        = "Exists"
                            Message       = "Already granted."
                        }
                        continue
                    }

                    try {
                        if ($existingGrant) {
                            $newScope = "$($existingGrant.Scope) $permission"
                            Update-MgOauth2PermissionGrant -OAuth2PermissionGrantId $existingGrant.Id -Scope $newScope | Out-Null
                            $results += [pscustomobject]@{
                                Principal     = $principal
                                Permission    = $permission
                                Type          = "Delegated"
                                Status        = "Updated"
                                Message       = "Added to existing grant."
                            }
                        } else {
                            $params = @{
                                clientId     = $client.Id
                                consentType  = "Principal"
                                principalId  = $principalUser.Id
                                resourceId   = $resource.Id
                                scope        = $scopeObj.Value
                            }
                            $grant = New-MgOauth2PermissionGrant -BodyParameter $params
                            $results += [pscustomobject]@{
                                Principal     = $principal
                                Permission    = $permission
                                Type          = "Delegated"
                                Status        = "Success"
                                Message       = "Created new grant."
                                GrantId       = $grant.Id
                            }
                        }
                    } catch {
                        $results += [pscustomobject]@{
                            Principal     = $principal
                            Permission    = $permission
                            Type          = "Delegated"
                            Status        = "Error"
                            Message       = $_.Exception.Message
                        }
                    }
                }
            }
        }

        return $results
    }
}
