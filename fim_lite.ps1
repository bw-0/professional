<#
.Synopsis
   Create WMI Subscription to monitor a file
.DESCRIPTION
   Create WMI Event Filter and WMI Event Consumer to be bound to a single subscription to monitor file modifications. JSON output to Application Event Log for export. Hastily put together for POC
.EXAMPLE
    #Monitor Hosts File
   .\fim_lite.ps1 -name "hosts_file" -pathtoMonitor C:\Windows\system32\drivers\etc\hosts
.EXAMPLE
   #Monitor OWA frontend for webshells
   Get-ChildItem "$env:programfiles\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth" | For-EachObject {.\fim_lite.ps1 -name "OWA_Auth" -pathtoMonitor $_.fullname}
#>
[CmdletBinding()]
Param($pathtomonitor, $name)

function set-fim_lite ($pathToMonitor, $name){

    $name = $name+"_"+((new-guid) -split "-")[0]

    $cmd = "Write-EventLog -LogName Application -Source 'SecurityCenter' -EventID 911 -EntryType 'Warning' -Message ([pscustomobject]@{name='$name';path='$pathToMonitor';action='modified';content=(get-content $pathToMonitor)|out-string}|select name, path, content|ConvertTo-Json -Compress)"

    $query = "Select * from __InstanceModificationEvent WITHIN 10 WHERE TargetInstance ISA 'CIM_DataFile' AND TargetInstance.Name='$($pathToMonitor -replace "\\","\\")'"

    $filter   = Set-WmiInstance -Class __EventFilter             -NameSpace "root\subscription" -Arguments @{Name=$name; EventNameSpace="root\cimv2"; QueryLanguage="WQL"; Query=$query}

    $consumer = Set-WmiInstance -Class CommandLineEventConsumer  -Namespace "root\subscription" -Arguments @{Name=$name; ExecutablePath="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"; CommandLineTemplate="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe $cmd"}

    $result =   Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{Filter=$filter; Consumer=$consumer}
    
    if ($null -ne $result){
        Write-Host "Subscription Created`nName=$name`nPath=$pathToMonitor"
        Write-EventLog -LogName Application -Source 'SecurityCenter' -EventID 900 -EntryType SuccessAudit -Message ([pscustomobject]@{name=$name;path=$pathToMonitor;action='created'}|select name, path, action|ConvertTo-Json -Compress)
    }
}

function remove-fim_lite ($name){

    Get-WmiObject -class __EventFilter -namespace root\subscription -filter "name='$name'" | Remove-WmiObject -Verbose

    Get-WmiObject -class CommandLineEventConsumer -Namespace root\subscription -filter "name='$name'" | Remove-WmiObject -Verbose

    $result = Get-WmiObject -class __FilterToConsumerBinding -Namespace root\subscription -filter "Filter = ""__eventfilter.name='$name'""" | Remove-WmiObject -Verbose

    if ($null -ne $result){
        Write-Host "Subscription Deleted`nName=$name"
        Write-EventLog -LogName Application -Source 'SecurityCenter' -EventID 901 -EntryType SuccessAudit -Message ([pscustomobject]@{name=$name;action='deleted'}|select name, action|ConvertTo-Json -Compress)
    }
}

set-fim_lite -name $name -pathToMonitor $pathtomonitor