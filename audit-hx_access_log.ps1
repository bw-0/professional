#Path to folder with all the "messages.*" files
$folder = ".\messages_folder"

#region Logon/off audit
$all=@()
$no_match=@()

[regex]$r=@'
User (?:logout|login): username '(?<username>[a-zA-Z0-9_@.-]+)',( local username '(?<local>[\w\d]+)',)?( full name '(?<fullname>[a-zA-Z ]+)',)? role '(?<role>.+)', client '(?<client>.+)', line '(?<line>.+)', remote (?:address|hostname) '(?<source>.+)', auth method '(?<auth>[a-z]+)',( auth submethod '(?<auth_sub>[a-z]+)',)? session ID (?<sessionid>.+)
'@

Get-ChildItem $folder | ForEach-Object{
    Write-Host -ForegroundColor Yellow "Processing $($_.FullName)" 
    Select-String -Path $_.FullName -Pattern "user log*"|%{
        if ($m = [regex]::Match($_,$r)){
            
            #optional fields
            if ($m.Groups["fullname"]) {$fullname=$m.Groups["fullname"].Value}else{$fullname=""}
            if ($m.Groups["local"])    {$local=   $m.Groups["local"].Value}   else{$local=""}
            if ($m.Groups["auth_sub"]) {$auth_sub=$m.Groups["auth_sub"].Value}else{$auth_sub=""}
            
            $all += [pscustomobject]@{
                username = $m.Groups["username"].Value
                fullName = $fullname
                localName = $local
                role = $m.Groups["role"].Value
                client = $m.Groups["client"].Value
                line = $m.Groups["line"].Value
                source = $m.Groups["source"].Value
                auth = $m.Groups["auth"].Value
                auth_sub = $auth_sub
                sessionID = $m.Groups["sessionid"].Value
            }
        }
        
        else {$no_match += $_}
        
        Clear-Variable m, fullname, local, auth_sub
    }
}

$all|Group-Object source, username, fullname, localname, role, client, auth, auth_sub|sort name|ft count,name

#endregion

#region SSH audit
$pam = Get-ChildItem $folder | ForEach-Object{
    Write-Host -ForegroundColor Yellow "Processing $($_.FullName)" 
    Select-String -Path $_.FullName -Pattern "pam_unix" |select line|%{($_ -split "]:")[1]}
}

$pam|group|sort name|ft count, name
#$pam|group|sort count|ft count, name
#endregion
