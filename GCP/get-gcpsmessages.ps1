#PowerShell module for Google Cloud: https://cloud.google.com/sdk/docs/quickstart-windows
try {import-Module GoogleCloud -Cmdlet Get-GcpsMessage}
catch{
    Write-Host "Please install the GoogleCloud PS Module, then run again"
    Install-Module GoogleCloud
    exit
}

function Send-NetworkData {
#adapted from: https://gist.github.com/jstangroome/9adaa87a845e5be906c8

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Computer,

        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [Int16]
        $Port,

        [Parameter(ValueFromPipeline)]
        [string[]]
        $Data

    ) 

    begin {
        # establish the connection and a stream writer
        $Encoding = [System.Text.Encoding]::ASCII

        $Client = New-Object -TypeName System.Net.Sockets.TcpClient
        $Client.Connect($Computer, $Port)
        $Stream = $Client.GetStream()
        $Writer = New-Object -Type System.IO.StreamWriter -ArgumentList $Stream, $Encoding, $Client.SendBufferSize, $true
    }

    process {
        # send all the input data
        foreach ($Line in $Data) {
            $Writer.WriteLine($Line)
        }
    }

    end {
        # flush and close the connection send
        $Writer.Flush()
        $Writer.Dispose()
        $Client.Client.Shutdown('Send')
        $Stream.Dispose()
        $Client.Dispose()
    }
}

<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
function Get-GcPsMessages
{
    [CmdletBinding()]
    Param
    (
        [Parameter(
            Mandatory=$true, 
            Position=0
            )
        ]
        [ValidateNotNullOrEmpty()]
        [array]$Subscriptions,

        [Parameter(
            Mandatory=$true, 
            Position=1
            )
        ]
        [ValidateNotNullOrEmpty()]
        [string]$Destination,

        [Parameter(
            Mandatory=$true, 
            Position=2
            )
        ]
        [ValidateNotNullOrEmpty()]
        [int]$Port
    )

    #Import-Module GoogleCloud

    while ($true){
        $m=@()
        $j=@()
    
        $Subscriptions | ForEach-Object{
            $s = Get-GcpsMessage -Name $_ -MaxMessages 10000 -AutoAck
            Write-Verbose "$(get-date -Format O) - Got $($s.count) messages"
            $m+=$s
        }

        foreach ($e in $m){
            $properties = @{}
        
            $properties+=@{
                "class"="GCP"
               #"activityid"= $e.ackid
                "mid"=        $e.messageid
                "eventlog"=   $e.Subscription
                "issuetime"=  $e.publishtime.tostring()
            }
        
        
            if ($e.Data -match "^{"){
                $d=$e.Data|ConvertFrom-Json
                $properties += @{
                    "sessionname"= $d.logname
                    "devicetype" = $d.resource.type
                    "severity" =   $d.severity
                    "eventtime" =  $d.timestamp
                }
            }
            
            else {
                $properties += @{"msg"=$e.data}
            }
            
        
            if($d.protoPayload){
            
                #<common fields>                
                $properties +=@{
                    "objecttype"=     $d.protoPayload.'@type'
                    "username"=       $d.protoPayload.authenticationInfo.principalEmail
                    "method"=         $d.protoPayload.methodName
                    "useragent"=      $d.protoPayload.requestMetadata.callerSuppliedUserAgent            
                    "hostname"=       $d.protoPayload.resourceName
                    "service" =       $d.protoPayload.serviceName
                }
        
                switch -Regex ($d.protoPayload.requestMetadata.callerIp){
                    "\."{$properties += @{"srcipv4"=$d.protoPayload.requestMetadata.callerIp}}
                    ":" {$properties += @{"srcipv6"=$d.protoPayload.requestMetadata.callerIp}}
                }
                #</common fields>
            
        
                #<option fields>
                if ($d.protoPayload.authorizationInfo){
                    $properties += @{
                        "authmethod"=     $d.protoPayload.authorizationInfo.permission
                        "auth_success"=   $d.protoPayload.authorizationInfo.granted
                    }
                }
                #if ($d.protoPayload.response){
                #    $properties += @{
                #        "eventtype"=      $d.protoPayload.response.'@type'
                #        "transactionid"=  $d.protoPayload.response.id
                #        "operationid"=    $d.protoPayload.response.operationType
                #        "status"=         $d.protoPayload.response.status
                #        "targethost"=     $d.protoPayload.response.targetId
                #        "from"=           $d.protoPayload.response.user
                #        "zone"=           $d.protoPayload.response.zone
                #    }
                #}
                
                if ($d.protoPayload.serviceData){
                    $properties += @{
                        "action"=         $d.protoPayload.serviceData.policyDelta.bindingDeltas.action
                        "targetusername"= $d.protoPayload.serviceData.policyDelta.bindingDeltas.member
                        "roleid"=         $d.protoPayload.serviceData.policyDelta.bindingDeltas.role
                    }
                }
        
                if ($d.protoPayload.request){
                    switch -Regex ($d.protoPayload.request.'@type'){
                        "compute\.firewalls" {
                            $properties += @{
                                "flagtype" =  $d.protoPayload.request.'@type'
                                "protocol" =  $d.protoPayload.request.alloweds.ipprotocol
                                "dstport" =   $d.protoPayload.request.alloweds.ports -join ","
                                "direction" = $d.protoPayload.request.direction
                                "aclname" =   $d.protoPayload.request.name
                                "network" =   $d.protoPayload.request.network
                                "source" =    $d.protoPayload.request.sourceranges -join ","
                                "operationid"=$d.protoPayload.response.operationType
                            }
                        }
                    }
                }
            }#if-protoPayload
        
        
            if($d.jsonPayload){
                #<common fields>
                $properties += @{
                    "username"=      $d.jsonPayload.actor.user
                    "method"=        $d.jsonPayload.event_subtype
                    #"eventtime"=     $d.jsonPayload.event_timestamp_us
                    "srcusagetype"=  $d.jsonPayload.event_type
                    "transactionid"= $d.jsonPayload.operation.id
                    "objecttype"=    $d.jsonPayload.operation.type
                    "zone"=          $d.jsonPayload.operation.zone
                    "hostname"=      $d.jsonPayload.resource.name
                    "connectionid"=  $d.jsonPayload.trace_id
                    "version"=       $d.jsonPayload.version
                }
                #</common fields>
        
        
                #<option fields>
                if ($d.jsonpayload.ip_address){
                    $properties += @{"srcipv4"=$d.jsonPayload.ip_address}
                }
        
                if ($d.jsonpayload.user_agent){
                    $properties += @{"useragent"=$d.jsonPayload.user_agent}
                }
        
                if ($d.jsonpayload.request){
                    $properties += @{
                        "uri"=$d.jsonPayload.request.url
                        "httpbody" = $d.jsonPayload.request.body
                    }
                }
                #</option fields>
        
            }#if-jsonPayload
        
            #let's build the damn thing
            $j += $properties|ConvertTo-Json -Compress| % { [System.Text.RegularExpressions.Regex]::Unescape($_) }
        }
        Write-Verbose "sending $($j.Count) events"
        Send-NetworkData -Computer $Destination -Port $Port -Data $j
    
        sleep 5
    }
}

Get-GcPsMessages -Subscriptions sub_0 -Destination 10.14.215.224 -Port 514 -Verbose