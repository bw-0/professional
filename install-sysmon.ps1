#Set vars
$destination_Folder = "\c$\it\sysmon"
$source_dir = "\\detection.network\IT\warez\"
$config_file = "config.xml"
$config_path = $source_dir+$config_file
$install_path = $source_dir+"sysmon\"
$install_files = Get-ChildItem $install_path -Recurse

#Choose Targets
#$targets = Get-ADDomainController -Filter *
$targets = Get-ADComputer -SearchBase "OU=Servers,DC=Detection,DC=Network"

$targets | ForEach-Object{

    #Use admin share to verify destination folder, create as necesary
    $target_dir = $("\\"+$_.name+$destination_Folder)
    if ((Test-Path $target_dir) -eq $false){
        Invoke-Command -ComputerName $_.name -scriptblock {New-Item -ItemType Directory -Path c:\it\sysmon|Out-Null}
    }
    
    #Check for config file, copy as needed
    if ((Test-Path $target_dir+"\"+$config_file) -eq $false){
        Copy-Item $config_path $target_dir -Force
    }
    
    #Grab and print currently installed Sysmon version
    $sysmon_version = $null
    $sysmon_version = Invoke-Command -ComputerName $_.name -scriptblock {(Get-ItemProperty C:\Windows\Sysmon.exe).VersionInfo.fileversion}
    $sysmon_version
    
    #Add Sysmon version as property to item being processed
    $_ | Add-Member -MemberType NoteProperty -Name Sysmon_version -Value $sysmon_version -Force
    
    #Install or upgrade based on version
    if (($sysmon_version -lt 4.0)-or (!($sysmon_version))){

        #copy install files
        #todo:compare versions so it doesn't reinstall the old version
        if (($install_files | ForEach-Object{Test-Path $($target_dir+"\"+$_.name)}) -eq $false){
            $install_files | ForEach-Object{Copy-Item $_.FullName $target_dir}
        }
        
        #Uninstall
        Invoke-Command -ComputerName $_.name -scriptblock {C:\Windows\Sysmon.exe -u 2>&1 | ForEach-Object{ "$_" }}
        
        #Install
        Invoke-Command -ComputerName $_.name -scriptblock {C:\it\sysmon\sysmon64.exe -accepteula -i c:\it\sysmon\v2.xml 2>&1 | ForEach-Object{ "$_" } }
        
        #Grab and print new version, just to compare during an interactive run of script
        $sysmon_version = $null
        $sysmon_version = Invoke-Command -ComputerName $_.name -scriptblock {(Get-ItemProperty C:\Windows\Sysmon.exe).VersionInfo.fileversion}
        $sysmon_version
    
    }
    
    #If already installed, sync config file
    if ($_.sysmon_version -eq "4.0"){
        Invoke-Command -ComputerName $_.name -scriptblock {C:\Windows\Sysmon.exe -c c:\it\sysmon\v2.xml}
    }
}

$targets | Format-Table name, sysmon_version -AutoSize