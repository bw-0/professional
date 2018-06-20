#grab some events off the topic
$m=@()
1..10|ForEach-Object{
$m += Get-GcpsMessage -Name sub_0 -MaxMessages 10000 -AutoAck
$m.Count
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
    $j = $properties|ConvertTo-Json -Compress| ForEach-Object { [System.Text.RegularExpressions.Regex]::Unescape($_) }
    Send-NetworkData -Computer 10.14.215.224 -Port 515 -Data $j
}
