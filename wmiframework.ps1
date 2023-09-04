m               m                    m               # 
#       mmm   mm#mm   mmm    mmm   mm#mm  m   m   mmm# 
#      "   #    #    #"  #  #"  #    #    #   #  #" "# 
#      m"""#    #    #""""  #""""    #    #   #  #   # 
#mmmmm "mm"#    "mm  "#mm"  "#mm"    "mm  "mm"#  "#m## 

#blue prism asset enumeration tool v1.3.0
#using winrm quickconfig on assets

#michael argo 10/21/2022

#lateetud inc

#description
#takes wmi information from a list of machines and uploads it to sql table 
#sleeps for sleepytime seconds and then runs again in a while true

#bugs / todo

#5985 5986 enable for winrm
#135 enable for winrm
#winrm service has to be running
#net start rpcss & net start Winmgmt
#HKLM:\Software\Microsoft\Ole :: EnableDCOM  (should be "Y")

#prototypes
#credential getcredentialfromcredman
#getdatetimefromserver(hostname)
#bool setcruisecredential(user,pass)
#user readcredentialfileuser()
#readcredentialfilepassword
#startbpservice
#startautomatetask
#testport
#gethostup
#gethostlist
#getconfigfile
#getpercentage
#getinversepercentage
#validatesqlstring
#getcpuaverageload
#getfreespace
#gettotalspace
#getfreememory
#gettotalmemory
#getosversion
#gethostname 
#getsqlreachable
#getbpasportrunning
#getbprrportrunning
#gethostcount
#getnumusers
#getloggedinuser
#getrunningprocesses
#getinstalledsoftware
#getphysicaldrives
#getuseraccounts
#getipaddress
#connectsqlserverdatabase
#readsqldata
#writesqldata
#closesqlconnection
#getvalidhostlist
#getblueprismappservers
#getblueprismruntimeresources
#getblueprisminteractiveclients
#getcurrenttimezone
#readparametersfromwebui

#Requires -version 2
Clear-Host
set-location "~"

$timeout = 2000 #network test timeout in ms
$filepath = '~' #path to conf files
$configfile = $filepath + "\bpframework.conf" 
$hostlist = $filepath + "\hostlist.txt"
$errorlog = $filepath + "\errorlog.txt"
$bannerfile = $filepath + "\lbanner.txt"
$maxiterations = 3 #retries to host
$targettable = "MachineInfo" #table to read and write to
$sleepytime = 30 #time between runs in seconds
$rdpport = 3389 #rdp port
$rrport = 8181 #runtime resource port
$asport = 8199 #application server port
$sqlport = 1433 #sql port
$winrmport = 5985 #winrm port
$BPAppserv = "bpreporting" #application server host or lb
$SQLPassword = 'Gone F!shing' 
$SQLUser = 'ese'
$SQLServer = "10.1.0.4"
$SQLDatabase = "bpreporting"
$CurrentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$color = @('gray', 'red', 'cyan', 'green', 'yellow', 'magenta', 'white', 'blue') #color array for console output
$bpdatabase = 'bpdemo'
$serviceName = 'blue prism server'
#$insertquery = "insert into $targettable (hostname,cpuaverageload,totalmemory,freememory,totalspace,freespace, usedspacep, freespacep, usedmemoryp, freememoryp, osversion, bprunning, automaterunning, bpservicerunning, processesrunning, useraccounts, ipaddress, other, installedsoftware, datestamp) values ('$hostname', '$cpuaverageload', '$totalmemory', '$freememory', '$totalspace', '$freespace', '$usedspacepercentage', '$spacepercentage', '$usedmemorypercentage', '$memorypercentage', '$osversion', '$bprunning', , , '$runningprocesses', '$useraccounts', '$ipaddress', ,'$installedsoftware',$currentdatetime')"




function getcredentialfromcredman #reads credential from credentialmanager and returns a user pass
{

       param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )

#   Install-Module CredentialManager -force


 #  New-StoredCredential -Target $url -Username $ENV:Username -Pass ....


 #  Get-StoredCredential -Target .... 

}

function getdatetimefromserver
{

 param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine
                 
   )

    try
    {
        $date = invoke-command -ComputerName $machine -ScriptBlock {get-date}
    }

    catch
    {

        write-host "unable to get datetime"
        return $false

    }

    return $date

}

function setcruisecredential
{

   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$user,
       [string]$password
              
   )

    try
    {
        $Cred = New-Object System.Management.Automation.PsCredential($User,$Password)
    }

    catch
    {

        write-host "unable to set credential"
        return $false

    }

    return $true

}


function readcredentialfileuser
{

try
    {
        
        $user = get-content "~password.txt" | ConvertTo-SecureString

    }

catch

    {

        write-host "unable to read credential file user"
        return $false

    }

return $user

}

function readcredentialfilepassword
{
    try
    {

        $password = Get-Content "~password.txt" | ConvertTo-SecureString
   
    }

catch

    {

        write-host "unable to read credential file password"
        return $false

    }

return $password

}


function startbpservice #starts blue prism service on remote host
{

    param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$hostname,
       [string]$credential
              
   )

try
    {

         Invoke-Command -ComputerName $hostname -ScriptBlock { Start-Service -Name $using:serviceName } -Credential $credential

    }

catch
    {
        write-host "starting bpservice failed"
        return $false
    }

return $true

}

function startautomatetask #starts automate schtask on remote host
{

    param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$hostname,
       [string]$credential
              
   )

    try
    {

        Invoke-Command -ComputerName $hostname -ScriptBlock {schtasks /run /tn "blueprismtask"} -Credential $credential

    }

    catch
    {

        write-host "starting automate task failed"
        return $false

    }

return $true

}

function testport #prototype, trying to make a faster test-netconnection but isn't working consistently
{
   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$hostname,
       [string]$port,
       [string]$timeout

   )

   $requestcallback = $null
   $state = $null
   $open = $null
   try {
           $client = New-Object System.Net.Sockets.TcpClient

           $client.BeginConnect($hostname,$port,$requestCallback,$state)
   
           Start-Sleep -milli $timeOut

   if ($client.Connected)
   {
        $open = $true 
   } 
   
   else 
   { 
       $open = $false 
   }


      }

   catch {

       write-host "Error connecting to socket!"
       $open = $false
   }
   

   $client.Close()

   return $open

}

function gethostup #working tcp port connect validation of object: takes machine and port
{
   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine,
       [string]$port

   )

   $connection = test-netconnection $machine -port $port -erroraction silentlycontinue -warningaction silentlycontinue #-informationlevel Quiet

   if ($connection.tcptestsucceeded) {

       return $True
   
   }

   else {

       return $False
       
       $host.exit()

   }

}
function gethostlist #gets hostlist from config file we are going to update this to pull from the blue prism database
{

try {
   $machines = get-content $hostlist

}

catch {
       write-host "Error no machine list file!"
       exit
       
}

return $machines

}

function getconfigfile #loads variables from config file, this is being redesigned
{

   try {

          $config = Get-Content $configfile
           
               foreach($n in $config)
               {
                    $var = $_.Split(' = ')

           New-Variable -Name $var[0] -Value $var[1]
               }

           }
       
   catch {

       write-host "Error no config file!"

   }

}
  

function getpercentage #returns a percentage
{

   param
   (
       
       [Parameter(Mandatory = $True)]
       [float]$numerator,
       [float]$denominator

   )

   return ($numerator/$denominator).tostring("P")


}

function getinversepercentage #returns inverse percentage
{

   param
   (
       
       [Parameter(Mandatory = $True)]
       [float]$numerator,
       [float]$denominator

   )

   $newnumerator = [float]$denominator - [float]$numerator
   
   return ($newnumerator/$denominator).tostring("P")

}

function validatesqlstring #will use this for certain wmi queries to make sure we can load the return value into the database
{
   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$sqlstring
     

   )

   if ($sqlstring.length -gt 1023)
   {

       $sqlstring = $sqlstring.substring(0,1023)

   }

   else {

       return $sqlstring

   }

   return $sqlstring.tostring()

}

function getcpuaverageload #returns cpu average load from a machine
{
   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )
   
   try
   {

     $processor = Get-WmiObject -Class Win32_Processor -Credential $Credential -ComputerName $machine
     $processor = $processor | Measure-Object -Property LoadPercentage -Average
     $average_load = $processor.Average
     $average_load = [float]$average_load * .01

     return $average_load.tostring("P")
   
   }

catch

{

write-host "Cpu information cannot be obtained"
   
}

}

function getfreespace #returns a machines free space
{
   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )

   $freespace = (Get-WmiObject -Class Win32_Volume -ComputerName $machine -Filter "DriveLetter = 'C:'" -Credential $Credential  -erroraction silentlycontinue -warningaction silentlycontinue).freespace

   return $freespace

}

function gettotalspace #returns a machines total space
{

   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )

   $totalspace = (Get-WmiObject -Class Win32_Volume -ComputerName $machine -Filter "DriveLetter = 'C:'" -Credential $Credential  -erroraction silentlycontinue -warningaction silentlycontinue).capacity    

   return $totalspace

}

function getfreememory #returns a machines free memory
{

   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )

   $free_memory = (get-wmiobject win32_operatingsystem -computername $machine -Credential $Credential  -erroraction silentlycontinue -warningaction silentlycontinue).freephysicalmemory

   return $free_memory

}

function gettotalmemory #returns a machines total memory
{

   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )


   $total_memory = (get-wmiobject win32_operatingsystem -computername $machine -Credential $Credential  -erroraction silentlycontinue -warningaction silentlycontinue).totalvisiblememorysize
   
   return $total_memory

}

function getosversion #returns a machines os version
{
   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )

   $os_version = (get-wmiobject win32_operatingsystem -computername $machine -Credential $Credential  -erroraction silentlycontinue -warningaction silentlycontinue).version 

   return $os_version

}

function gethostname #returns a machines hostname outside of dns
{
   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )

   $machinename = (Get-WmiObject -computername $machine -Credential $Credential  -Class Win32_computersystem).name

   return $machinename

}

function getsqlreachable #tests sql servers connection prior to attempting to connect
{

   $connectable = gethostup $sqlserver $sqlport #-port $sqlport $timeout

   return $connectable

}

function getbpasportrunning #returns whether a blue prism app server is listening on it's default port, may change this to take port as param
{
   
   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )

   $connectable = gethostup $machine $asport #-port $asport $timeout

   return $connectable


}

function getbprrportrunning  #returns whether a blue prism runtime resource is listening on it's default port, may change this to take port as param
{
   
   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )

   $connectable = gethostup $machine $rrport #$rrport $timeout
   #$connectable | get-member

   return $connectable


}

function gethostcount #returns number of hosts read from list or database
{

   $count = 0
   foreach ($m in $hostlist)
   {
       $count++

   }

   return $count
}


function getnumusers #returns the number of users that have logged into the machine
{
   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )

   $numusers = (get-wmiobject win32_operatingsystem -computername $machine -Credential $Credential  -erroraction silentlycontinue -warningaction silentlycontinue).numberofusers

   return $numusers
}

function getloggedinuser #returns the logged in user (deprecated)
{
   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )

   $loggedinuser = (Get-WmiObject -computername $machine -Class win32_computersystem -Credential $Credential  -ErrorAction silentlycontinue).username

   return $loggedinuser 

}

function getrunningprocesses #returns the number of running processes however it is often too big for the database
{

   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )

   $runningprocesses = Get-WMIObject Win32_Process -Credential $Credential  -computername $machine | ForEach-Object { $_.ProcessName } | Sort-Object | Get-Unique
   
   $runningprocesses = validatesqlstring $runningprocesses.tostring()
             
   return $runningprocesses

}

function getinstalledsoftware #returns the name of installed software, however this is often too big for the database
{

   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )

   $installedsoftware = Get-WMIObject Win32_Product -Credential $Credential  -computername $machine | ForEach-Object { $_.Caption } | Sort-Object | Get-Unique

   $installedsoftware = validatesqlstring $installedsoftware.tostring()
   
   return $installedsoftware

}

function getphysicaldrives #returns the physical drives mounted
{

   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )


   $filter = "DriveType = '4' OR DriveType = '3'"
   $physicaldrives = Get-WmiObject -class win32_logicaldisk -Credential $Credential -ComputerName $machine -Filter $filter

   return $physicaldrives

}

function getuseraccounts #returns user accounts on the machine
{

   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )

   $useraccounts = (get-wmiobject -class win32_useraccount -Credential $Credential  -computername $machine).caption
   if ($freespace.length -gt 1024 )
   {

       $average_load.trim(1024)

   }
   return $useraccounts

}

function getipaddress #returns the ip address of the machine from the machine
{

   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )

   $hostipaddress = (get-wmiobject -Credential $Credential  -computername $machine win32_networkadapterconfiguration).ipaddress | select-object -first 1

   if ($hostipaddress.length -gt 128 )
   {

       $hostipaddress.trim(128)

   }
   return $hostipaddress

}

function connectsqlserverdatabase #connects to sql server database, this is being redesigned to be able to create multiple connections simultaneously
{

#   param
#   (
       
#       [Parameter(Mandatory = $True)]
#       [string]$sqlserver,
#       [string]$sqldatabase,
#       [string]$sqluser,
#       [string]$sqlpassword

#   )

   try{

       $Connection = New-Object System.Data.SQLClient.SQLConnection
       
       $Connection.ConnectionString = "server='$sqlserver';database='$sqldatabase';User ID='$sqluser'; Password='$sqlpassword'"
       
       write-host $connection.ConnectionString "-> connection string"

       $Connection.Open()
       
       $Command = New-Object System.Data.SQLClient.SQLCommand

       $Command.Connection = $Connection
       
           if($connection.State -eq "Open"){

               write-host "sql is connected" -foregroundcolor (get-random $color) 

               return $connection 
           }

    

   }

   catch{

           write-host "sql connection failed"
          

   }



}

function readsqldata #this will be redesigned to take a connection and a query and return an output or error
{   

    #   param
#   (
       
#       [Parameter(Mandatory = $True)]
#       [string]$sqlserver,
#       [string]$sqldatabase,
#       [string]$sqluser,
#       [string]$sqlpassword

#   )

   try {

        $selectquery = "select * from $targettable"

        $connection = connectsqlserverdatabase

        $sqladapter = new-object System.Data.SqlClient.SqlDataAdapter 

        $sqladapter.selectcommand = new-object system.data.sqlclient.sqlcommand ($selectquery, $connection)

        $sqldata = new-object System.Data.DataTable

        $query = [void]$sqladapter.fill($sqldata)

    }

catch {

   write-host "sql read failed"
   return $false

}   
   
    $sqldata
    return $query

}

function writesqldata #writes sql data to a table, this will be redesigned to take a connection and query and write it to a table then return success or failure
{

   $insertquery = "insert into $targettable (hostname,cpuaverageload,totalmemory,freememory,totalspace,freespace, usedspacep, freespacep, usedmemoryp, freememoryp, osversion, bprunning, automaterunning, bpserverservicerunning, processesrunning, useraccounts, ipaddress, other, installedsoftware, datestamp) values ('$hostname', '$cpuaverageload', '$totalmemory', '$freememory', '$totalspace', '$freespace', '$usedspacepercentage', '$spacepercentage', '$usedmemorypercentage', '$memorypercentage', '$osversion', '$bprunning', '', '', '$runningprocesses', '$useraccounts', '$ipaddress', '','$installedsoftware','$currentdatetime')"

    try {

        $CurrentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        $connection = connectsqlserverdatabase

        $sqladapter = new-object System.Data.SqlClient.SqlDataAdapter 
        $sqladapter.selectcommand = new-object system.data.sqlclient.sqlcommand ($insertquery, $connection)
        
        
        $sqldata = new-object System.Data.DataTable

        [void]$sqladapter.fill($sqldata)
        write-host "sql write successful"

    }

    catch {
    
        Write-Host "sql write failed"
        return $false
        
    }
$insertquery    
#$sqldata

return $true
   
}

function closesqlconnection #closes sql connection, this will be redesigned to take a parameter of connection to close and return true or false
{

   if ($connection.open -eq $True)
   {
   
   $connection.close()
   
   }

   Write-host "sql connection closed"

}

function getvalidhostlist #checks to see if hosts are up and returns a list of hosts that are up this will be redesigned to also create a list of hosts that are down and write it to a table
{
   param
   (
       
       [Parameter(Mandatory = $True)]
       $hostlist

   )
   $hostlist
   $validhostlist = $null

foreach ($m in $hostlist)
   {	
            
            $connection = gethostup $m $rdpport -erroraction silentlycontinue -warningaction silentlycontinue #-informationlevel Quiet

            if ($connection.tcptestsucceeded) {

            $validhostlist = $validhostlist.add($m)
   
                }

             else {

            write-host $m "is offline, skipping..."
       
             }
  
   }

   return $validhostlist

}

function getblueprismappservers #returns a list of blue prism app servers from the blue prism database
{
   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )

}

function getblueprismruntimeresources #returns a list of blue prism runtime resources from the blue prism database
{
   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )

}

function getblueprisminteractiveclients #returns a list of blue prism interactive clients from the blue prism database
{

       param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )

}

function getcurrenttimezone #performs a wmi query to get the current timezone from a machine, we will have to update the schema to implement this but very useful
{

   param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )

}

function readparametersfromwebui #reads and updates parameters from the webui from the database and updates variables in the ui, this is not yet designed
{

       param
   (
       
       [Parameter(Mandatory = $True)]
       [string]$machine

   )
   
}




#_       
#_ __  ___   __ _(_)_ __  
#| '_ ` _ \ / _` | | '_ \ 
#| | | | | | (_| | | | | |
#|_| |_| |_|\__,_|_|_| |_|
#    #void main(void) 
#loops through hostlist and runs a set of wmi queries, then waits for $sleepytime seconds and loops again.
#to make this more granular i may be able to split the loop into different object types for the cruise ui
#one problem we'll have to solve is how to load the changes they make in the ui for these settings and reload the script
#working on what parameters are rational to load from a config file
#working on how we want to handle windows auth vs sql auth and change the connection values
#working on using credential manager for this
#working on elegantly handle login failure
#working on network bug with custom tcp connect and how to handle failures at different stages of the loop

#proposed changes
#test connection to blue prism server
#test connection to reporting server
#connect to blue prism server
#connect to reporting server
#get assets from blue prism server and create a list by type using queries
#validate what assets are online
#create a list of hosts online per asset type
#create a list of hosts offline and upload it to a new table in the database
#load the timing parameters from the cruise db
#within the loop enumerate with wmi per asset type $sleepytime seconds
#upload data to reporting server
#loop and every ten iterations scan hosts again for up / down








$banner = get-content $bannerfile
$banner

#$credential = Get-Credential

$hostlist = gethostlist
write-host "hosts in list" $hostlist -foregroundcolor (get-random $color) 

$hostcount = gethostcount
write-host $hostcount "hosts in list"  -foregroundcolor (get-random $color) 


while($True){

$s = getsqlreachable
write-host "sql server service listening is " $s
   
$connection = connectsqlserverdatabase 

$n = $null

#foreach loop

foreach ($n in $hostlist)
{

   $CurrentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

   $hostname = gethostname $n 
   write-host $n " hostname " $hostname -foregroundcolor (get-random $color) 

   $cpuaverageload = getcpuaverageload $n
   write-host $n " cpu average load " $cpuaverageload -foregroundcolor (get-random $color)

   $totalmemory = gettotalmemory $n
   write-host $n " total memory " $totalmemory -foregroundcolor (get-random $color)

   $freememory = getfreememory $n
   write-host $n " free memory " $freememory -foregroundcolor (get-random $color)

   $memorypercentage = getpercentage $freememory $totalmemory
   write-host $n " free memory percentage " $memorypercentage -foregroundcolor (get-random $color)

   $usedmemorypercentage = getinversepercentage $freememory $totalmemory
   write-host $n " used memory percentage " $usedmemorypercentage -foregroundcolor (get-random $color)

   $totalspace = gettotalspace $n
   write-host $n " total space " $totalspace -foregroundcolor (get-random $color)  

   $freespace = getfreespace $n
   write-host $n " free space " $freespace -foregroundcolor (get-random $color) 

   $spacepercentage = getpercentage $freespace $totalspace
   write-host $n " free space percentage " $spacepercentage -foregroundcolor (get-random $color) 

   $usedspacepercentage = getinversepercentage $freespace $totalspace
   write-host $n " used space percentage " $usedspacepercentage -foregroundcolor (get-random $color) 

   $osversion = getosversion $n
   write-host $n " os version " $osversion -foregroundcolor (get-random $color)

   $bprunning = getbprrportrunning $n
   write-host $n " bp running is " $bprunning -foregroundcolor (get-random $color)

   $numusers = getnumusers $n
   write-host $n " has this many users " $numusers -foregroundcolor (get-random $color)

  # $runningprocesses = getrunningprocesses $n
  # write-host $n " has processes running " $runningprocesses -foregroundcolor (get-random $color)

  # $physicaldrives = getphysicaldrives $n
  # write-host $n "has physical drives " $physicaldrives -foregroundcolor (get-random $color)

  # $useraccounts = getuseraccounts $n
  # write-host $n "has user accounts " $useraccounts -foregroundcolor (get-random $color)

   $ipaddress = getipaddress $n
   write-host $n "has ip address " $ipaddress -foregroundcolor (get-random $color)

  # $installedsoftware = getinstalledsoftware $n
  # write-host $n "has installed software " $installedsoftware -foregroundcolor (get-random $color)


writesqldata
#startbpservice '10.1.0.5' $credential

}
closesqlconnection $connection
write-host "Sleeping for " $sleepytime "seconds..."
start-sleep $sleepytime

} #foreach






