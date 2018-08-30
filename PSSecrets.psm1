function Set-FullControl {
<#
.SYNOPSIS

Set-FullControl edits a file's permissions by removing inheritence and setting the current user as the sole principal with full control permissions.

PSSecrets.psm1 Function: Set-FullControl
Authors: Bryon Wolcott (@bryon_)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Set-FullControl edits a file's permissions by setting the current user with explicit full control permissions and removing other "allow" permissions other than administrators and SYSTEM.

.PARAMETER Path

Specifies the path to the file to edit.

.PARAMETER DoAccess

Switch to configure file access permissions

.PARAMETER DoAudit

Switch to configure file auditing settings. This action needs to be ran as admin. If admin is gained by a different user, do not re-run DoAccess, it will grant the admin account full control and possibly remove the non-admin's access.

.EXAMPLE

C:\PS> Set-FullControl -Path .\ADFS.secret -DoAccess

.NOTES

Released as part of PSSecrets PS Module for FireEye Community blog post

#>

    Param
    (
        [Parameter(Mandatory=$false, ValueFromPipeline = $false)]
        [ValidateScript({
            if(-Not ($_ | Test-Path) ){
                throw "File or folder does not exist" 
            }
            if(-Not ($_ | Test-Path -PathType Leaf) ){
                throw "The Path argument must be a file. Folder paths are not allowed."
            }
            return $true
        })]
        [System.IO.FileInfo]$Path,

        [Parameter(Mandatory = $false)]
        [Switch]
        $DoAccess,

        [Parameter(Mandatory=$false, ValueFromPipeline = $false)]
        [ValidateScript({
            if(-Not (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) ){
                throw "Must be admin to run `"DoAudit`" parameter" 
            }
            return $true
        })]
        [Switch]
        $DoAudit

    )

    if ($DoAccess){

        $acl = Get-Acl $Path

        $acl0 = New-Object System.Security.AccessControl.DirectorySecurity

        $currentuser = "$env:USERDOMAIN\$env:USERNAME"

        $rights = [System.Security.AccessControl.FileSystemRights]::FullControl

        $inheritance = [int]([System.Security.AccessControl.InheritanceFlags]::ContainerInherit) + [int]([System.Security.AccessControl.InheritanceFlags]::ObjectInherit)

        $propagation = [System.Security.AccessControl.PropagationFlags]::None

        $accessControl = [System.Security.AccessControl.AccessControlType]::Allow

        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentuser, $rights, $inheritance, $propagation , $accessControl)

        $skip=$null

        foreach ($access in $acl.Access){
            if (
                ($access.AccessControlType.value__ -eq $AccessRule.AccessControlType.value__) -and
                ($access.FileSystemRights.value__ -eq $AccessRule.FileSystemRights.value__) -and
                ($access.IdentityReference.Value -eq $AccessRule.IdentityReference.Value) -and
                ($access.IsInherited -eq $AccessRule.IsInherited) -and
                ($access.PropagationFlags.value__ -eq $AccessRule.PropagationFlags.value__)
            ){
                $skip=$true
            }
        }

        if ($skip){Write-Host -f Cyan "Set-FullControl: Explicit Full Control Already Set, Skipping"}

        else{
            write-host -f Cyan "`nSet-FullControl: Adding Access to: $path"
            write-host -f Cyan "`t FileSystemRights : $($AccessRule.FileSystemRights)"
            write-host -f Cyan "`t AccessControlType: $($AccessRule.AccessControlType)"
            write-host -f Cyan "`t IdentityReference: $($AccessRule.IdentityReference)"
            write-host -f Cyan "`t       IsInherited: $($AccessRule.IsInherited)"
            write-host -f Cyan "`t  InheritanceFlags: $($AccessRule.InheritanceFlags)"
            write-host -f Cyan "`t  PropagationFlags: $($AccessRule.PropagationFlags)`n"

            $Acl0.SetAccessRule($AccessRule)

            Set-Acl $Path $Acl0 -Verbose
        }

        $acl1 = Get-Acl $Path

        foreach ($access in $acl1.Access){
            if (($access.IdentityReference.value -notmatch "(?:$env:USERNAME|administrators|system)`$") -and($access.AccessControlType -eq "allow")){
            write-host -f Cyan "`n Set-FullControl: Removing Access from: $path"
            write-host -f Cyan "`t FileSystemRights : $($access.FileSystemRights)"
            write-host -f Cyan "`t AccessControlType: $($access.AccessControlType)"
            write-host -f Cyan "`t IdentityReference: $($access.IdentityReference)"
            write-host -f Cyan "`t IsInherited      : $($access.IsInherited)"
            write-host -f Cyan "`t InheritanceFlags : $($access.InheritanceFlags)"
            write-host -f Cyan "`t PropagationFlags : $($access.PropagationFlags)`n"
            [void]$acl1.RemoveAccessRule($access)
            $set=$true
            }
        }

        if ($set){set-acl $Path $acl1 -Verbose}
    }

    if ($DoAudit){
        try {$acl2 = Get-Acl $Path -Audit}
        catch {
            Write-Host -f Yellow "Set-FullControl: Need to run as admin if you want to set Audit settings on your new file"
            return
        }
        if ($acl2){
            $AuditUser = "Everyone"
            $AuditRules = "ReadData,AppendData,Delete,ChangePermissions,Takeownership"
            $AuditType = "Success,Failure"
            $AuditAccessRule = New-Object System.Security.AccessControl.FileSystemAuditRule($AuditUser,$AuditRules,$AuditType)

            $acl2.SetAuditRule($AuditAccessRule)
           
            write-host -f Cyan "`n Set-FullControl: Configure Auditing for: $path"
            write-host -f Cyan "`t FileSystemRights : $($AuditAccessRule.FileSystemRights)"
            write-host -f Cyan "`t AuditFlags       : $($AuditAccessRule.AuditFlags)"
            write-host -f Cyan "`t IdentityReference: $($AuditAccessRule.IdentityReference)"

            Set-Acl $Path $acl2 -Verbose

            #Check audit policy settings
            $FS_auditing = ([regex]::Matches(((auditpol.exe /get /subcategory:"File System") | Select-String "File System"),"File System\s+(.+)")).groups[1].value
            $HM_auditing = ([regex]::Matches(((auditpol.exe /get /subcategory:"Handle Manipulation") | Select-String "Handle Manipulation"),"Handle Manipulation\s+(.+)")).groups[1].value
            
            switch -Regex ($FS_auditing){
                "success and failure" {
                    Write-Host -f Cyan "`n Set-FullControl: Current Audit Policy (Object Access/ File System):"$FS_auditing
                }
                "success$|^failure" {
                    Write-Host -f Cyan "`n Set-FullControl: Current Audit Policy (Object Access/ File System):"$FS_auditing
                    Write-Host -f Yellow " [WARNING] Audit Policy (File System) Partially Enabled, should be 'Success and Failure'. Run auditpol.exe snippets below to enable"
                    Write-Host -f Yellow "`t auditpol.exe /set /subcategory:'File System' /success:enable"
                    Write-Host -f Yellow "`t auditpol.exe /set /subcategory:'File System' /failure:enable"
                }
                "auditing" {
                    Write-Host -f Cyan "`n Set-FullControl: Current Audit Policy (Object Access/ File System):"$FS_auditing
                    Write-Host -f Red " [WARNING] Audit Policy (File System) NOT Enabled, should be 'Success and Failure'. Run auditpol.exe snippets below to enable"
                    Write-Host -f Red "`tauditpol.exe /set /subcategory:'File System' /success:enable"
                    Write-Host -f Red "`tauditpol.exe /set /subcategory:'File System' /failure:enable"
                }
            }

            switch -Regex ($HM_auditing){
                "failure" {Write-Host -f Cyan "`n Set-FullControl: Current Audit Policy (Object Access/ Handle Manipulation):"$HM_auditing}
                "success$|auditing" {
                    Write-Host -f Cyan "`n Set-FullControl: Current Audit Policy (Object Access/ Handle Manipulation):"$HM_auditing
                    Write-Host -f Red " [WARNING] Audit Policy (Handle Manipulation - Failure) not enabled. Run auditpol.exe snippet below to enable"
                    Write-Host -f Red "`tauditpol.exe /set /subcategory:'Handle Manipulation' /failure:enable"
                }
            }
        }
    }
}

function Set-Path {
<#
.SYNOPSIS

Set-Path is used to set an output file path. It will assist with creating a new file if needed. 

PSSecrets.psm1 Function: Set-Path
Authors: Bryon Wolcott (@bryon_)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Set-Path is used to set an output file path. It will assist with creating a new file if needed. Set-Path will also verify that the optionally passed $path is indeed a file and not a container

.PARAMETER Path

(Optional) Specifies the path to the file to verify.

.EXAMPLE

C:\PS> Set-Path -Path .\ADFS.secret

.EXAMPLE

C:\PS> $path = Set-Path

.NOTES

Released as part of PSSecrets PS Module for FireEye Community blog post

#>
    param
    (
        [Parameter(Mandatory=$false, ValueFromPipeline = $true)]
        [System.IO.FileInfo]
        $Path
    )

    if (!$path){[System.IO.FileInfo]$Path = Read-Host -Prompt "Path for secret file ouput"}

    if (!(Test-Path $Path)){
        do {$consent0 = Read-Host "The file $path does not exist, create it now? [Y] Yes  [N] No  [Q] quit"}

        until ($consent0 -in @("y","n","q"))

        switch ($consent0){
            "y" {
                New-Item -ItemType File -Path $Path -Verbose -Confirm
                if (!(Test-Path $path)){
                    do {$consent1 = Read-Host "Try again? [Y] Yes  [N] No"}
                    until ($consent1 -in @("y","n"))
                    if ($consent1 -eq "y"){Clear-Variable path; Set-Path}
                    else{return 1}
                }
                else {return 0}
            }
            "n" {
                do {$consent1 = Read-Host "Try again? [Y] Yes  [N] No"}
                until ($consent1 -in @("y","n"))
                if ($consent1 -eq "y"){Set-Path}
                else{return 1}
            }
            "q" {return 1}
        }
    }

    if ($path -and ((get-item $Path).PSIsContainer -eq $true)){
        do {$consent2 = Read-Host "Path is not a file, try again? [Y] Yes  [N] No  [Q] quit"}
        until ($consent2 -in @("y","n","q"))
        switch ($consent2){
            "y" {Set-Path}
            "n" {return 1}
            "q" {quit}
        }
    }
    return Get-Item $Path
}

function Set-Secret {
<#
.SYNOPSIS

Set-Secret assists a user in taking a secret in as a securestring, then stores the secret as a variable or a file. If the output is a file, Set-Secret will call Set-FullControl on the file to lock down its NTFS permissions.

PSSecrets.psm1 Function: Set-Secret
Authors: Bryon Wolcott (@bryon_)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Set-Secret assists a user in taking a secret in as a securestring, then stores the secret as a variable or a file. If the output is a file, Set-Secret will call Set-FullControl on the file to lock down its NTFS permissions after it's been created.

.PARAMETER Type

(Optional) Specifies the output type for your secret, Var or File

.PARAMETER Path

(Optional) Specifies the file path to save your secret to, if output type is "file". Setting $path will override $type, setting it to "file"

.PARAMETER ID

(Optional) A user specified unique identifier if storing multiple Var type secrets, defaults to "default"

.EXAMPLE

C:\PS> Set-Secret -type file -path "c:\users\bob.yurhed\secrets\msol.pw"

.EXAMPLE

C:\PS> Set-Secret -path .\azuread.pw

.NOTES

Released as part of PSSecrets PS Module for FireEye Community blog post
#>
    Param
    (
        [Parameter(Mandatory=$false, ValueFromPipeline = $false,HelpMessage="var or file.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("var", "file")]
        [System.String]
        $type="var",

        [Parameter(Mandatory=$false, ValueFromPipeline = $false)]
        [System.IO.FileInfo]
        $Path,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String]
        $id="default"
    )

    if ($path -and ($type -ne "file")){
        #"Changing type to `"file`" because `$path was defined"
        $type="file"
    }

    New-Variable -Name "securestring$id" -Scope global -value (Read-Host -Prompt "Enter Secret" -AsSecureString) -Force -Verbose

    switch ($type){
        "var" {Write-Verbose "Secret stored as: $((Get-Variable -Name "securestring$id").name)"}

        "file" {

            $out = Set-Path $Path

            if ($out -eq 1){Write-Error "Error with path. Try again";return}

            (Get-Variable -Name "securestring$id").Value|ConvertFrom-SecureString|Out-File $out.FullName -Verbose

            Set-FullControl -Path $out.FullName -DoAccess

            Get-Variable -Name "securestring$id" |Remove-Variable -Scope global -Verbose
        }
    }
}

function Get-Secret {
<#
.SYNOPSIS

Get-Secret will retrieve a secret which was stored using Set-Secret.

PSSecrets.psm1 Function: Set-Secret
Authors: Bryon Wolcott (@bryon_)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Get-Secret defaults to retrieve -type "var", it outputs the cleartext secret. If the -type is "file", provide the path to your stored secret, output will be a PSCredential object.

.PARAMETER Type

(Optional) Specifies the input type for your secret, Var or File

.PARAMETER Path

(Optional) Specifies the file path to retrieve your secret from.

.PARAMETER ID

(Optional) A user specified unique identifier if storing multiple Var type secrets, defaults to "default"

.PARAMETER User

(Optional) The username for the PSCredential object output when using -type "file"

.EXAMPLE

C:\PS> Get-Secret -type file -path "c:\users\bob.yurhed\secrets\msol.pw" -user "bob.yurhed@detection.network"

.EXAMPLE

C:\PS> Get-Secret -id "API"

.NOTES

Released as part of PSSecrets PS Module for FireEye Community blog post
#>
    Param
    (
        [Parameter(Mandatory=$false, ValueFromPipeline = $false,HelpMessage="var or file.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("var", "file")]
        [System.String]
        $type="var",

        [Parameter(Mandatory=$false, ValueFromPipeline = $false)]
        [System.IO.FileInfo]
        $Path,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String]
        $id="default",

        [Parameter(Mandatory=$false, ValueFromPipeline = $false)]
        [string]
        $User
    )

    if ($path -and ($type -ne "file")){
        Write-Host "Changing type to `"file`" because `$path was defined"
        $type="file"
    }

    switch ($type){
        "var" {
            (New-Object PSCredential "blank",(Get-Variable -Name "securestring$id" -Scope global).Value).GetNetworkCredential().Password
        }
        "file" {
            if (!$User){$user=Read-Host -Prompt "Username"}
            New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, (Get-Content $Path | ConvertTo-SecureString )
        }
    }
}