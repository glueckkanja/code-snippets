<#
    MIT License

    Copyright (c) Microsoft Corporation.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE
#>
# glueckkanja AG Thorsten Kunzi 2026
# 
# This script will set AD permissions so exchange cmdlets can still be used after AD split permission model is implemented.
# INFO: Some will require re-adding additional EX RBAC Roles: "Security Group Creation and Membership","Mail Recipient Creation" -> see dedicated GK guidance
# Recommended: Create dedicated permissiongroup and nest Exchange Trusted Subsystem into it. This way the custom modifications are easy to track and have no downside.
# New-ADGroup -Name "AD_Custom Exchange Split permissions replacement" -GroupCategory Security -GroupScope DomainLocal -Path "OU=Rights,OU=Groups,OU=T1,OU=_ADM,$((Get-ADDomain).DistinguishedName)" -Description "replaces the permissions lost by split permissions on relevant OUs"
# Add-ADGroupMember "AD_Custom Exchange Split permissions replacement" -Members "Exchange Trusted Subsystem" # reboot Exchange servers
#
# PermissionTypes:
# GroupManage = Create/Delete Groups, Modify Member -> cmdlets: New-DistributionGroup,Remove-DistributionGroup,Add-DistributionGroupMember,Remove-DistributionGroupMember
# UserSendAs = Modfiy AD Permissions on Users -> cmdlet: Add-ADPermission for sendas
# GroupSendAs = Modfiy AD Permissions on Groups -> cmdlet: Add-ADPermission for sendas
# CreateUserAndContact = create/delete, ResetPassword and WriteAllProperties for Users and Contacts -> cmdlets: New-Mailbox, New-RemoteMailbox, New-MailUser, New-MailContact and the matching Remove-*
#
# Usage:
# Add-ExchangeADSplitPermissionOnOU.ps1 -TargetOU <OUDN> -PermissionType <GroupManage|GroupSendAs|CreateUserAndContact|UserSendAs> -Trustee "AD_Custom Exchange Split permissions replacement"
# e.g. Add-ExchangeADSplitPermissionOnOU.ps1 -TargetOU "OU=Groups,OU=HQ,OU=Alderaan,$((Get-ADDomain).DistinguishedName)" -PermissionType GroupManage -Trustee "AD_Custom Exchange Split permissions replacement"
#      Add-ExchangeADSplitPermissionOnOU.ps1 -TargetOU "OU=Groups,OU=HQ,OU=Alderaan,$((Get-ADDomain).DistinguishedName)" -PermissionType GroupSendAs -Trustee "AD_Custom Exchange Split permissions replacement"
#      Add-ExchangeADSplitPermissionOnOU.ps1 -TargetOU "OU=Users,OU=HQ,OU=Alderaan,$((Get-ADDomain).DistinguishedName)" -PermissionType CreateUserAndContact -Trustee "AD_Custom Exchange Split permissions replacement"
#      Add-ExchangeADSplitPermissionOnOU.ps1 -TargetOU "OU=Users,OU=HQ,OU=Alderaan,$((Get-ADDomain).DistinguishedName)" -PermissionType UserSendAs -Trustee "AD_Custom Exchange Split permissions replacement"
# 
param (
    # Specifies the distinguished name of the organizational unit for which the rights groups should be created
    [Parameter(Mandatory = $true)]
    [ValidateScript({
            try {
                # Check if the OU is present
                $ADObject = [ADSI]"LDAP://$_"
                [void]$ADObject.ToString()
                # Return true if everything is fine
                $True
            } catch {
                # Otherwise throw an error
                throw $($_.Exception.Message)
            }
        })]
    $TargetOU,

    # Specifies the permissions to be delegated
    [Parameter(
        Mandatory = $true,
        ParameterSetName = 'PermissionType'
    )]
    [ValidateSet('GroupManage','UserSendAs','GroupSendAs','CreateUserAndContact')]
    [string]$PermissionType,

    # Specifies the object to receive the permissions
    [Parameter(
        Mandatory = $true
    )]
    [string]$Trustee
)
#------------------------------------
#------------------------------------
function CheckADObjectExists
{
	param ($AdAceExistsObjectDN)
 	trap [Exception] {
		return $false
	}
	$dummy=Get-ADObject $AdAceExistsObjectDN
	return $true
}
#------------------------------------
function GetADObjectSid
{
    # can take DistinguishedName, GUID or sAMAccountName and return the SID
    Param
    (
		[Parameter(Mandatory=$true)][string]$Identity
	)
    # try directly as DistinguishedName or Guid
    #Write-Warning "GetADObjectSid Identity $Identity"
    try
    {
        $GetADObjectSidObject = @(Get-ADObject $Identity -Properties ObjectSid -ErrorAction SilentlyContinue)
    }
    catch
    {
        # -ErrorAction SilentlyContinue seems not to work so in try/catch
    }
    IF (!$GetADObjectSidObject) # try other methods
    {
        #Write-Warning "sam"
        $GetADObjectSidObject = @(Get-ADObject -LDAPFilter "sAMAccountName=$Identity" -Properties ObjectSid -ErrorAction SilentlyContinue)
    }
    IF ($GetADObjectSidObject.count -eq 1)
    {
        $AdAceExistsObjectSid=New-Object System.Security.Principal.SecurityIdentifier $GetADObjectSidObject[0].ObjectSid
        return $AdAceExistsObjectSid
    }
    ELSEIF ($GetADObjectSidObject.count -gt 1)
    {
        Write-Warning "ERROR: More than 1 object found for $Identity!!"
        return $false
    }
    ELSE
    {
        Write-Warning "ERROR: No object found for $Identity!!"
        return $false
    }
}
#------------------------------------
function GetADObject
{
    # can take DistinguishedName, GUID or sAMAccountName and return the SID
    Param
    (
		[Parameter(Mandatory=$true)][string]$Identity
	)
    # try directly as DistinguishedName or Guid
    #Write-Warning "GetADObjectSid Identity $Identity"
    try
    {
        $GetADObjectObject = @(Get-ADObject $Identity -Properties ObjectSid -ErrorAction SilentlyContinue)
    }
    catch
    {
        # -ErrorAction SilentlyContinue seems not to work so in try/catch
    }
    IF (!$GetADObjectObject) # try other methods
    {
        #Write-Warning "Sam search"
        $GetADObjectObject = @(Get-ADObject -LDAPFilter "sAMAccountName=$Identity" -Properties ObjectSid -ErrorAction SilentlyContinue)
    }
    IF ($GetADObjectObject.count -eq 1)
    {
        return $GetADObjectObject
    }
    ELSEIF ($GetADObjectSidObject.count -gt 1)
    {
        Write-Warning "ERROR: More than 1 object found for $Identity!!"
        return $false
    }
    ELSE
    {
        Write-Warning "ERROR: No object found for $Identity!!"
        return $false
    }
}
#------------------------------------
function DnToTargetLdapString
{
    Param
    (
		[Parameter(Mandatory=$true)][string]$DistinguishedName
	)
    IF (CheckADObjectExists $DistinguishedName)
    {
        IF ($DistinguishedName -like "*,DC=*")
        {
            try
            {
                $TargetLDAPString = [ADSI]"LDAP://$DistinguishedName"
                return $TargetLDAPString
            }
            catch
            {
                $ExceptionMessage = $_.Exception.Message.Replace("`r","").Replace("`n","") # remove CR/LF
                Write-Error $ExceptionMessage
                return $false
            }
        }
        ELSE
        {
            Write-Warning "ERROR: DistinguishedName $DistinguishedName seems invalid!!"
            return $false
        }
    }
    ELSE
    {
        Write-Warning "ERROR: DistinguishedName $DistinguishedName does not exist"
        return $false
    }
}
#------------------------------------
function GetADReferenceGuid
{
# searches in:
# -Schema ObjectName
# -ExtendedRights
# -Schema lDAPDisplayName as sometimes the ObjectNames differ slightly from what WindowsUI shows
# returns the apropriate GUID or $false
    Param
    (
		[Parameter(Mandatory=$false)][string]$Reference
	)
    # Read Domain Naming Contexts
    $ADRootDSE = Get-ADRootDSE
    $SchemaNamingContext = $ADRootDSE.SchemaNamingContext
    $ExtendedRightsDN = "CN=Extended-Rights,$($ADRootDSE.ConfigurationNamingContext)"
    # search
    IF ($Reference -eq "")
    { # if undefined set Generic Reference
	    $ReferenceGUID = "00000000-0000-0000-0000-000000000000"
        Write-Verbose "Reference empty = $ReferenceGUID"
        return $ReferenceGUID
    }
    ELSEIF (CheckADObjectExists "CN=$Reference,$SchemaNamingContext")
    { # find Reference in Schema
	    $ReferenceGUID = [System.Guid] (Get-ADObject "CN=$Reference,$SchemaNamingContext" -properties schemaIDGUID).SchemaIDGUID
        Write-Verbose "Reference $Reference in Schema = $ReferenceGUID"
        return $ReferenceGUID
    }
    ELSEIF (CheckADObjectExists "CN=$Reference,$ExtendedRightsDN")
    { # find Reference in extendedRights
	    $ReferenceGUID = [System.Guid] (Get-ADObject "CN=$Reference,$ExtendedRightsDN" -properties rightsGUID).rightsGUID
        Write-Verbose "Reference $Reference in ExtendedRights = $ReferenceGUID"
        return $ReferenceGUID
    }
    ELSE
    {
        # find attribute specified by lDAPDisplayName
        $AttributeReferenceObject = (Get-ADObject -SearchBase $SchemaNamingContext -Filter 'lDAPDisplayName -eq $Reference' -properties schemaIDGUID)
        IF ($AttributeReferenceObject)
        {
            $ReferenceGUID = [System.Guid] ($AttributeReferenceObject).SchemaIDGUID
            Write-Verbose "Reference $Reference in lDAPDisplayName = $ReferenceGUID"
            return $ReferenceGUID
        }
        ELSE
        { # if not found anywhere
            return $false
        }
    }
}
#------------------------------------
function GetADInheritanceGUID
{
# checks only Schema ObjectName for possible matches
# returns the apropriate GUID or $false
    Param
    (
		[Parameter(Mandatory=$false)][string]$InheritTo
	)
    # Read Domain Naming Contexts
    $ADRootDSE = Get-ADRootDSE
    $SchemaNamingContext = $ADRootDSE.SchemaNamingContext
    # search
    IF ($InheritTo -eq "")
    {
        $InheritanceGUID = "00000000-0000-0000-0000-000000000000"
        Write-Verbose "InheritTo empty = $InheritanceGUID"
        return "$InheritanceGUID"
    }
    ELSEIF (CheckADObjectExists "CN=$InheritTo,$SchemaNamingContext")
    {
	    $InheritanceGUID = [System.Guid] (Get-ADObject "CN=$InheritTo,$SchemaNamingContext" -properties schemaIDGUID).SchemaIDGUID
        Write-Verbose "InheritTo $InheritTo in Schema = $InheritanceGUID"
        return $InheritanceGUID
    }
    ELSE
    { # if not found
	    return $false
    }
}
#------------------------------------
function AddADAce
{
    <#
    AccessControlType = Allow; Deny
    ADRight = GenericAll; CreateChild,DeleteChild; ReadProperty; WriteProperty; ExtendedRight
    Reference = User; Computer; Group; Organizational-Unit; GP-Link; <blank>=unscoped e.g. WriteAllProperties
       special attribute : Street-Address or any other attribute -> Combined with ADRight="ReadProperty,WriteProperty" or just "WriteProperty"
       special ExtendedRights: Generate-RSoP-Logging or any other ExtendedRight -> Combined with ADRight=ExtendedRight
    InheritanceType = None; All; Descendents; SelfAndChildren; Children
    InheritTo = <blank>; User; Group; Computer; Organizational-Unit; ...
    Inherit-Combinations:
       a) InheritanceType=All & InheritTo <blank> -> All Descendant objects
       b) InheritanceType=Descendents & InheritTo <non-blank> e.g. Group -> e.g all descening Group Objects

    Examples:
    # FullControl over Computers in OU
    AddADAce -IdentityReference "CN=IMEA-AE-ComputerAdmin,OU=AdminRoles,OU=IMEA,DC=zz,DC=group" -TargetDN "OU=TEST,OU=WEUR,DC=zz,DC=group" -AccessControlType "Allow" -ADRight "GenericAll" -InheritanceType "Descendents" -InheritTo "Computer"
    # Create and Delete Computers in OU
    AddADAce -IdentityReference "CN=IMEA-AE-ComputerAdmin,OU=AdminRoles,OU=IMEA,DC=zz,DC=group" -TargetDN "OU=TEST,OU=WEUR,DC=zz,DC=group" -AccessControlType "Allow" -ADRight "CreateChild,DeleteChild" -InheritanceType "All" -Reference "Computer"
    # Add Read/Write on an attribute e.g. missing non-inheritable CertPublishers on some users
    AddADAce -IdentityReference "CN=Cert Publishers,CN=Users,DC=gkalderaan,DC=local" -TargetDN "CN=Userxy,OU=WEUR,DC=zz,DC=group" -AccessControlType Allow -ADRight "Readproperty,WriteProperty" -Reference UserCertificate -InheritanceType None
    # Add WriteAllProperties for descending Users -> no -Reference
    AddADAce -IdentityReference $IdentityReference.DistinguishedName -TargetDN "OU=Users,OU=Site1,OU=Alderaan,$((Get-ADDomain).DistinguishedName)" -AccessControlType "Allow" -ADRight "WriteProperty" -InheritanceType "Descendents" -InheritTo "User"

    #Read exisitng ACL to identify GUIDs etc
    (Get-Acl "AD:\<DN>").Access|where {$_.IdentityReference -like "*<Name>*"}
    #>
    Param 
    ( 
    [Parameter(Position=1,Mandatory=$true,ValueFromPipeline=$false)][string]$TargetDN,
    [Parameter(Position=2,Mandatory=$true,ValueFromPipeline=$false)][string]$IdentityReference,
    [Parameter(Position=3,Mandatory=$true,ValueFromPipeline=$false)][string]$AccessControlType,
    [Parameter(Position=4,Mandatory=$true,ValueFromPipeline=$false)][string]$ADRight,
    [Parameter(Position=5,Mandatory=$false,ValueFromPipeline=$false)][string]$Reference,
    [Parameter(Position=6,Mandatory=$false,ValueFromPipeline=$false)][string]$InheritanceType,
    [Parameter(Position=7,Mandatory=$false,ValueFromPipeline=$false)][string]$InheritTo
    )

    # get required LDAP:// format
    $TargetLdapString = DnToTargetLdapString -DistinguishedName $TargetDN -Verbose
    Write-Verbose "TargetLdapString $($TargetLdapString.Path)"
    
    # get SID
    $IdentityReferenceSid = GetADObjectSid -Identity $IdentityReference -Verbose
    Write-Verbose "IdentityReferenceSid $IdentityReferenceSid"
    
    # resolve the Reference to the GUID needed for the ACE
    IF ($Reference)
    { # 18.09.2025 $Reference may be empty e.g. for WriteAllProperties
        $ReferenceGUID = GetADReferenceGuid -Reference $Reference
        Write-Verbose "ReferenceGUID $ReferenceGUID"
    }

    # resolve the InhertiTo to the GUID needed for the ACE, empty allowed will be set to 000..
        $InheritanceGUID = GetADInheritanceGUID -InheritTo $InheritTo
        Write-Verbose "InheritanceGUID $InheritanceGUID"
    
    IF ($TargetLdapString -and $IdentityReferenceSid -and $InheritanceGUID) # 18.09.2025 $ReferenceGUID may be empty e.g. for WriteAllProperties
    {
        Write-Verbose "ADRight $ADRight"
        Write-Verbose "AccessControlType $AccessControlType"
        Write-Verbose "InheritanceType $InheritanceType"
        try
        {
            IF ($ReferenceGUID)
            {
                Write-Verbose "ReferenceGUID $ReferenceGUID"
                $ace=New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReferenceSid, $ADRight, $AccessControlType, $ReferenceGUID, $inheritanceType, $InheritanceGUID
            }
            ELSE
            { # 18.09.2025 e.g. for WriteAllProperties without $Reference/$ReferenceGUID
                $ace=New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReferenceSid, $ADRight, $AccessControlType, $inheritanceType, $InheritanceGUID
            }
            "Adding ACE to $($TargetLdapString.Path)"
            $ace
            " "
            $TargetLDAPString.get_ObjectSecurity().AddAccessRule($ace)
            $TargetLDAPString.CommitChanges()
            return $true
        }
        catch
        {
            Write-Warning "Error managing ACE for $TargetLDAPString"
	        $ExceptionMessage = $_.Exception.Message.Replace("`r","").Replace("`n","") # remove CR/LF
            Write-Warning $ExceptionMessage
            return $false
        }
    }
    ELSE
    {
	    Write-Warning "Error in Role Definition - Object, Attribute or extended Right does not exist!"
	    return $false
    }
}
#------------------------------------
function GetADAce
{
    <#
    AccessControlType = Allow, Deny
    ADRight = GenericAll; CreateChild,DeleteChild; ReadProperty; WriteProperty; ExtendedRight
    Reference = User; Computer; Group; Organizational-Unit; GP-Link; <blank>=ThisObjectOnly??
       special attribute : Street-Address or any other attribute -> Combined with ADRight="ReadProperty,WriteProperty" or just "WriteProperty"
       special ExtendedRights: Generate-RSoP-Logging or any other ExtendedRight -> Combined with ADRight=ExtendedRight
    InheritanceType = None; All; Descendents; SelfAndChildren; Children
    InheritTo = <blank>; User; Group; Computer; Organizational-Unit; ...
    Inherit-Combinations:
       a) InheritanceType=All & InheritTo <blank> -> All Descendant objects
       b) InheritanceType=Descendents & InheritTo <non-blank> e.g. Group -> e.g all descening Group Objects
    #>
    Param 
    ( 
    [Parameter(Position=1,Mandatory=$true,ValueFromPipeline=$false)][string]$TargetDN,
    [Parameter(Position=2,Mandatory=$false,ValueFromPipeline=$false)][string]$IdentityReference,
    [Parameter(Position=3,Mandatory=$false,ValueFromPipeline=$false)][string]$AccessControlType,
    [Parameter(Position=4,Mandatory=$false,ValueFromPipeline=$false)][string]$ADRight,
    [Parameter(Position=5,Mandatory=$false,ValueFromPipeline=$false)][string]$Reference,
    [Parameter(Position=6,Mandatory=$false,ValueFromPipeline=$false)][string]$InheritanceType,
    [Parameter(Position=7,Mandatory=$false,ValueFromPipeline=$false)][string]$InheritTo
    )
    $AdAceExistsObject = Get-ADObject $TargetDN
    $AdAceExistsObjectACL = (Get-Acl "AD:\$($AdAceExistsObject.DistinguishedName)") # Complete ACL
    $AdAceExistsObjectACLs = (Get-Acl "AD:\$($AdAceExistsObject.DistinguishedName)").Access # only the Access Rules
    Write-Verbose "All -> $($AdAceExistsObjectACLs.count)"
    IF ($IdentityReference)
    {
        $AdAceExistsObjectACLs = $AdAceExistsObjectACLs| where {$_.IdentityReference.ToString() -like "*$IdentityReference"}
        Write-Verbose "IdentityReference $IdentityReference -> $($AdAceExistsObjectACLs.count)"
    }
    IF ($AccessControlType)
    {
        $AdAceExistsObjectACLs = $AdAceExistsObjectACLs| where {$_.AccessControlType.ToString() -like "$AccessControlType"}
        Write-Verbose "AccessControlType $AccessControlType -> $($AdAceExistsObjectACLs.count)"
    }
    IF ($ADRight)
    {
        $AdAceExistsObjectACLs = $AdAceExistsObjectACLs| where {$_.ActiveDirectoryRights.ToString().Replace(" ","") -like $ADRight.Replace(" ","")} # remove spaces for the compare e.g. "ReadProperty,WriteProperty" still matches "ReadProperty, WriteProperty"
        Write-Verbose "ADRight $ADRight -> $($AdAceExistsObjectACLs.count)"
    }
    IF ($Reference)
    {
        $ReferenceGUID = GetADReferenceGuid -Reference $Reference
        $AdAceExistsObjectACLs = $AdAceExistsObjectACLs| where {$_.ObjectType.ToString() -like "$ReferenceGUID"}
        Write-Verbose "ADRight $ADRight -> $($AdAceExistsObjectACLs.count)"
    }
    IF ($InheritanceType)
    {
        $AdAceExistsObjectACLs = $AdAceExistsObjectACLs| where {$_.InheritanceType.ToString() -like "$InheritanceType"}
        Write-Verbose "Inherited $IsInherited -> $($AdAceExistsObjectACLs.count)"
    }
    IF ($InheritTo)
    {
        $InheritanceGUID = GetADInheritanceGUID -InheritTo $InheritTo
        $AdAceExistsObjectACLs = $AdAceExistsObjectACLs| where {$_.InheritanceObjectType.ToString() -like "$InheritanceGUID"}
        Write-Verbose "ADRight $ADRight -> $($AdAceExistsObjectACLs.count)"
    }
    Write-Verbose "END: $($AdAceExistsObjectACLs.count)"
    IF ($AdAceExistsObjectACLs.count -gt 0)
    {
        return $AdAceExistsObjectACLs
    }
    ELSE
    {
        return $false
    }
}
#####################################
# verbose on-off
# $VerbosePreference = "continue"

# resolve the Parameter even when it's just SamAccountName
$IdentityReference = GetADObject $Trustee

Switch ($PermissionType)
{
    GroupManage
    {
        "`ngranting permission to: Create/Delete Groups:"
        #FYI: Exchange Server will become owner of the created objects and have implicit FullAccess
        AddADAce -TargetDN $TargetOU -IdentityReference $IdentityReference.DistinguishedName -AccessControlType "Allow" -ADRight "CreateChild,DeleteChild" -Reference "Group" -InheritanceType "All"
        "granting permission to: edit Member"
        # Add/Remove has usual issues with RBAC logic T1admin is not owner -> done via dsa.msc anyway?!
        AddADAce -TargetDN $TargetOU -IdentityReference $IdentityReference.DistinguishedName -AccessControlType "Allow" -ADRight "WriteProperty" -Reference "Member" -InheritanceType "Descendents" -InheritTo "Group"
    }
    UserSendAs
    {
        "`ngranting permission to: set SendAs (modify permissions):"
        AddADAce -TargetDN $TargetOU -IdentityReference $IdentityReference.DistinguishedName -AccessControlType "Allow" -ADRight WriteDacl -Reference "User" -InheritanceType "Descendents" -InheritTo "User"
    }
    GroupSendAs
    {
        "`ngranting permission to: set SendAs (modify permissions):"
        AddADAce -TargetDN $TargetOU -IdentityReference $IdentityReference.DistinguishedName -AccessControlType "Allow" -ADRight WriteDacl -Reference "Group" -InheritanceType "Descendents" -InheritTo "Group"
    }
    CreateUserAndContact
    {
        "`ngranting permission to: User Create/Delete, ResetPassword, WriteAllProperties"
        AddADAce -TargetDN $TargetOU -IdentityReference $IdentityReference.DistinguishedName -AccessControlType "Allow" -ADRight "CreateChild,DeleteChild" -InheritanceType "All" -Reference "User"
        AddADAce -TargetDN $TargetOU -IdentityReference $IdentityReference.DistinguishedName -AccessControlType "Allow" -ADRight "ExtendedRight" -InheritanceType "Descendents" -Reference "User-Force-Change-Password" -InheritTo "User"
        # WriteAllProperties vs granular
        AddADAce -TargetDN $TargetOU -IdentityReference $IdentityReference.DistinguishedName -AccessControlType "Allow" -ADRight "WriteProperty,Delete,DeleteTree" -InheritanceType "Descendents" -InheritTo "User"
        # might get more granular than WriteAllProperties but ResetPassword, potentially ModifyPermissions for SendAs and usually Full AD-native permissions of T1 Exchange Admins would not gain real security
        # the following are not sufficent and only a disabled User account gets created:
        # AddADAce -TargetDN $TargetOU -IdentityReference $IdentityReference.DistinguishedName -AccessControlType "Allow" -ADRight "ExtendedRight" -InheritanceType "Descendents" -Reference "Pwd-Last-Set" -InheritTo "User"
        # AddADAce -TargetDN $TargetOU -IdentityReference $IdentityReference.DistinguishedName -AccessControlType "Allow" -ADRight "ExtendedRight" -InheritanceType "Descendents" -Reference "Lockout-Time" -InheritTo "User"

        "`ngranting permission to: Contact Create/Delete","WriteAllProperties"
        AddADAce -TargetDN $TargetOU -IdentityReference $IdentityReference.DistinguishedName -AccessControlType "Allow" -ADRight "CreateChild,DeleteChild" -InheritanceType "All" -Reference "Contact"
        AddADAce -TargetDN $TargetOU -IdentityReference $IdentityReference.DistinguishedName -AccessControlType "Allow" -ADRight "WriteProperty,Delete,DeleteTree" -InheritanceType "Descendents" -InheritTo "Contact"
    }
}

# Changelog
# 19.09.2025 New CreateUserAndContact
# 22.09.2025 fixed bug: -IdentityReference not taken from Trustee parameter
# 18.11.2025 CreateUserAndContact - Delte,DeleteTree needed for Remove-Mailbox, Remove-Mailcontact when they weren't created by Exchange
