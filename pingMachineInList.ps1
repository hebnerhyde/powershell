Param(            
    #[parameter(Mandatory=$true)]            
    #$InputFilePath,
    #[parameter(Mandatory=$true)]
    #$MaxConcurrent,
    #[parameter(Mandatory=$true)]
    #$TimesToPing,
    #$TimeoutInSeconds,
    #$ResolveNames
    $InputFilePath = "C:\Users\hdin\Desktop\list.txt",
    $MaxConcurrent = 100,
    $TimesToPing = 1
    )

$Start = [System.DateTime]::Now
Write-Host "Version 1.0"
Write-Host "InputFilePath:"$InputFilePath
Write-Host "MaxConcurrent:"$MaxConcurrent
Write-Host "TimesToPing:"$TimesToPing
Write-Host "TimeoutInSeconds:"$TimeoutInSeconds
Write-Host "ResolveNames:"$ResolveNames

function GetNamesFromTextFile
{
  param($file)

  $ht = @{}

  try
  {
    foreach ($line in [System.IO.File]::ReadLines($file))
    {
      try { $ht.Add($line.ToString().Trim(), $line.ToString().Trim()) } catch {}
    }
  }
  catch
  {
    Write-Host "Failed to Read File, Exiting:"$ms -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    exit
  }

  return $ht
}

function GetStatusCodeString
{
  param ($code)

  switch ($code)
  {
    $null {$ret = "Ping Command Failed"}
        0 {$ret = "Success"}
    11001 {$ret = "Buffer Too Small"}
    11002 {$ret = "Destination Net Unreachable"}
    11003 {$ret = "Destination Host Unreachable"}
    11004 {$ret = "Destination Protocol Unreachable"}
    11005 {$ret = "Destination Port Unreachable"}
    11006 {$ret = "No Resources"}
    11007 {$ret = "Bad Option"}
    11008 {$ret = "Hardware Error"}
    11009 {$ret = "Packet Too Big"}
    11010 {$ret = "Request Timed Out"}
    11011 {$ret = "Bad Request"}
    11012 {$ret = "Bad Route"}
    11013 {$ret = "TimeToLive Expired Transit"}
    11014 {$ret = "TimeToLive Expired Reassembly"}
    11015 {$ret = "Parameter Problem"}
    11016 {$ret = "Source Quench"}
    11017 {$ret = "Option Too Big"}
    11018 {$ret = "Bad Destination"}
    11032 {$ret = "Negotiating IPSEC"}
    11050 {$ret = "General Error"}
    default {$ret = "Ping Failed"}
  }

  return $ret
}

function GetPingResultsFromHashTable
{
  param($ht, $maxConcurrent, $count, $timeout)

  $bDone = $false
  $i = 0
  $totalMachines = 0
  $htResults = @{}
  $dotTime = [System.DateTime]::Now
  if ($timeout -eq $null) {$timeout = 120}

  Write-Host ("Sending Ping Command to {0} Machines" -f $ht.Count) -NoNewline

  foreach ($name in $ht.GetEnumerator())
  {
    while ((Get-Job -State Running).Count -ge $maxConcurrent)
    {    
      Start-Sleep -Seconds 1
      if ($i -ge 50) { Write-Host "*"; $i = 0 }
      else { Write-Host "*" -NoNewline; $i++ }
    }

    $job = Test-Connection -ComputerName $name.Key.ToString() -Count $count -AsJob
    $job.name = "ping:{0}" -f $name.Key.ToString()

    if ([System.DateTime]::Now -gt $dotTime)
    {
      $dotTime = ([System.DateTime]::Now).AddSeconds(1)
      if ($i -ge 50) { Write-Host "."; $i = 0 }
      else { Write-Host "." -NoNewline; $i++ }
    }
  }

  #Start time now, exit in case of timeout
  $timeout = ([System.DateTime]::Now).AddSeconds($timeout)
  $dotTime = [System.DateTime]::Now
  $i = 0
  Write-Host
  Write-Host "Getting Ping Results" -NoNewline

  while(!($bDone))
  {
    $results = Get-Job -Name 'ping:*'
    $bRunning = $false

    foreach ($result in $results)
    {
      if ($result.State -ne 'Running')
      {
        if ($result.State -eq 'Failed')
        {
          #resubmit job
          if ($i -ge 50) { Write-Host "+"; $i = 0 }
          else { Write-Host "+" -NoNewline; $i++ }
          $job = Test-Connection -ComputerName $result.Name.ToString().Split(":")[1] -Count $count -AsJob
          $job.name = "ping:{0}" -f $result.Name.ToString().Split(":")[1]
        }
        else
        {
          try { $htResults.Add($result.Name.ToString().Split(":")[1], (Receive-Job $result)) } catch {}
          $totalMachines++
        }

        if ([System.DateTime]::Now -gt $dotTime)
        {
          $dotTime = ([System.DateTime]::Now).AddSeconds(1)
          if ($i -ge 50) { Write-Host "."; $i = 0 }
          else { Write-Host "." -NoNewline; $i++ }
        }
        
        try { Remove-Job $result } catch {}
      }
      else
      {
        $bRunning = $true
      }
    }

    #Check for timeout condition, clean up all jobs if true
    if ([System.DateTime]::Now -gt $timeout)
    {
      $bDone = $true
      Write-Host "Timeout reached, removing jobs"
      $results = Get-Job -Name 'ping:*'
      foreach ($result in $results)
      {
        Write-Host "RemoveJob:"$result.Name
        try
        {
          Stop-Job $result
          try { Remove-Job $result -Force } catch {}
        }
        catch {}
      }
    }

    #If the timeout hasn't been reached and jobs are still running, loop again
    if (!($bRunning)) { $bDone = $true }
  }

  Write-Host 
  Write-Host ("Received Ping Results From {0} Machines" -f $totalMachines)
  
  return $htResults
}

function ResolveNamesFromPingResults
{
  param($array, $maxConcurrent, $resolveNames, $timeout)

  try { if ($resolveNames -ne $null) { [bool]$resolveNames = [System.Convert]::ToBoolean($resolveNames) } } catch {}

  $htResults = @{}

  if ($resolveNames)
  {
    $dotTime = ([System.DateTime]::Now)
    if ($timeout -eq $null) {$timeout = 120}
    $i = 0
    $scriptBlock = 
    {
      param($s)
      try { $ret = [System.Net.DNS]::GetHostEntry($s) } catch {}
      return $ret
    }
    Write-Host ("Resolving DNS Names for {0} Machines" -f $array.Count) -NoNewline
    foreach ($name in $array)
    {
      while ((Get-Job -State Running).Count -ge $maxConcurrent)
      {    
        Start-Sleep -Seconds 1
        if ($i -ge 50) { Write-Host "*"; $i = 0 }
        else { Write-Host "*" -NoNewline; $i++ }
      }
      $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $name.NameInList
      $job.name = "resolve:{0}" -f $name.NameInList
      if ([System.DateTime]::Now -gt $dotTime)
      {
        $dotTime = ([System.DateTime]::Now).AddSeconds(1)
        if ($i -ge 50) { Write-Host "."; $i = 0 }
        else { Write-Host "." -NoNewline; $i++ }
      }
    }

    #Start time now, exit in case of timeout
    $timeout = ([System.DateTime]::Now).AddSeconds($timeout)
    $dotTime = ([System.DateTime]::Now)
    $i = 0
    $bDone = $false

    Write-Host
    Write-Host "Getting DNS Results" -NoNewline
    while(!($bDone))
    {
      $results = Get-Job -Name 'resolve:*'
      $bRunning = $false

      foreach ($result in $results)
      {
        if ($result.State -ne 'Running')
        {
          if ($result.State -eq 'Failed')
          {
            #resubmit job
            if ($i -ge 50) { Write-Host "+"; $i = 0 }
            else { Write-Host "+" -NoNewline; $i++ }
            $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $result.Name.ToString().Split(":")[1]
            $job.name = "resolve:{0}" -f $result.Name.ToString().Split(":")[1]
          }
          else
          {
            try { $htResults.Add($result.Name.ToString().Split(":")[1], (Receive-Job $result)) } catch {continue}
          }

          if ([System.DateTime]::Now -gt $dotTime)
          {
            $dotTime = ([System.DateTime]::Now).AddSeconds(1)
            if ($i -ge 50) { Write-Host "."; $i = 0 }
            else { Write-Host "." -NoNewline; $i++ }
          }
        
          try { Remove-Job $result -Force} catch {}
        }
        else
        {
          $bRunning = $true
        }
      }

      #Check for timeout condition, clean up all jobs if true
      if ([System.DateTime]::Now -gt $timeout)
      {
        $bDone = $true
        Write-Host "Timeout reached, removing jobs"
        $results = Get-Job -Name 'resolve:*'
        foreach ($result in $results)
        {
          Write-Host "RemoveJob:"$result.Name
          try
          {
            Stop-Job $result
            try { Remove-Job $result -Force } catch {}
          }
          catch {}
        }
      }

      #If the timeout hasn't been reached and jobs are still running, loop again
      if (!($bRunning)) { $bDone = $true }
    }
    Write-Host 
    Write-Host ("Received DNS Results From {0} Machines" -f $htResults.Count)
  }

  return $htResults
}

function GetFormattedPingResultsFromHashTable
{
  param($ht)

  $fResults = New-Object System.Collections.ArrayList
  $dotTime = ([System.DateTime]::Now)
  $i = 0
  Write-Host "Formatting Ping Results" -NoNewLine

  foreach ($result in $ht.GetEnumerator())
  {
    #There are multiple pings here if we ping more than once per computer
    $originalAddress = $result.Key.ToString()
    $pingCount = 0
    $successCount = 0
    $status = 'Ping Job Failed'
    $pingedFrom = 'Ping Job Failed'
    $successPercentage = 0
    
    try { $pings = $result.Value.Count } catch { $pings = 0 }
    if ($pings -gt 0) 
    {
      $status = GetStatusCodeString -code $result.Value[$pings-1].StatusCode
      $pingedFrom = $result.Value[$pings-1].PSComputerName
    }

    foreach ($ping in $result.Value)
    {
      $pingCount++
      if ($ping.StatusCode -eq 0) { $successCount++ }
      #If you try to get the IPv4Address or IPv6Address it slows down this loop significantly
    }
     
    #Calculate percentage
    if ($pingCount -ne 0) { $successPercentage = ($successCount / $pingCount) * 100 } 
    else { $successPercentage = 0 }

    #Add to array
    $o = New-Object PSObject -Property @{
      NameInList = $originalAddress
      PingedFrom = $pingedFrom
      SuccessPercentage = $successPercentage
      LastPingStatus = $status
    }
   
    [void]$fResults.Add($o)

    if ([System.DateTime]::Now -gt $dotTime)
    {
      $dotTime = ([System.DateTime]::Now).AddSeconds(1)
      if ($i -ge 50) { Write-Host "."; $i = 0 }
      else { Write-Host "." -NoNewline; $i++ }
    }
  }

  Write-Host 
  Write-Host ("Formatted Ping Results for {0} Machines" -f $fResults.Count)

  return $fResults
}

function GetFormattedPingAndDNSResults
{
  param($pingResults, $dnsResults)

  if ($dnsResults.Count -ne 0)
  {
    Write-Host "Formatting DNS Results" -NoNewLine
    $dotTime = ([System.DateTime]::Now)
    $i = 0
    foreach ($ping in $pingResults)
    {
      $dns = $dnsResults.Get_Item($ping.NameInList)
      if ($dns -ne $null)
      {
        $bFirst = $true
        foreach ($ip in $dns.AddressList)
        {
          if ($bFirst){ $ipList = $ip }
          else { $ipList += "|" + $ip }
        }

        $fqdn = $dns.HostName
      }
      else
      {
        $ipList = $null
        $fqdn = 'No DNS Entry Found'
      }

      $ping | Add-Member -MemberType NoteProperty -Name NameFromDNS -value $fqdn -Force
      $ping | Add-Member -MemberType NoteProperty -Name IPAddressListFromDNS -value $ipList -Force

      if ([System.DateTime]::Now -gt $dotTime)
      {
        $dotTime = ([System.DateTime]::Now).AddSeconds(1)
        if ($i -ge 50) { Write-Host "."; $i = 0 }
        else { Write-Host "." -NoNewline; $i++ }
      }
    }
    Write-Host 
    Write-Host ("Formatted DNS Results for {0} Machines" -f $pingResults.Count)
  }

  return $pingResults
}

function GetOutputPath
{
  param($fileName, $dir)
  $outputPath = $dir + "\" + $fileName
  return $outputPath
}

function GetTimeSpanStringInMinutesAndSeconds
{
  param($startTime, $endTime)

  $time = $startTime.Subtract($endTime)
  $minutes = $time.ToString().Split(":")[1]
  $seconds = $time.ToString().Split(":")[2].Split(".")[0]
  $timeSpan = "{0} Minutes and {1} Seconds" -f $minutes, $seconds
  return $timeSpan
}

function GetSuccessPingCount
{
  param($results)

  $successCount = 0
  foreach ($result in $results)
  {
    if ($result.SuccessPercentage -gt 0) { $successCount++ }
  }

  return $successCount
}

function GetDNSNamesResolvedCount
{
  param($results)

  $namesResolved = 0
  foreach ($result in $results)
  {
    if ($result.IPAddressListFromDNS -ne $null) { $namesResolved++ }
  }

  return $namesResolved
}

function GetPercentageAsString
{
  param($n1, $n2)

  if ($n1 -ne 0) { $percentage = ($n1 / $n2) * 100 } 
  else { $percentage = 0 }

  $percentage = ("{0:N0}" -f $percentage) + "%"

  return $percentage
}

#Read in Names from text file
$Names = GetNamesFromTextFile -file $InputFilePath

#Get ping results in a hash table. The key is the name and the value is the returned array of ping objects (one element per ping).
$Results = GetPingResultsFromHashTable -ht $Names -maxConcurrent $MaxConcurrent -count $TimesToPing -timeout $TimeoutInSeconds

#Format ping results into an array of objects
$FormattedPingResults = GetFormattedPingResultsFromHashTable -ht $Results

#Resolve DNS Names if specified
$DNSResults = ResolveNamesFromPingResults -array $FormattedPingResults -maxConcurrent 5 -resolveNames $ResolveNames -timeout $TimeoutInSeconds

#Format DNS results by adding them to the ping results
$FormattedPingResults = GetFormattedPingAndDNSResults -pingResults $FormattedPingResults -dnsResults $DNSResults

#Output to CSV
$OutputPath = GetOutputPath -fileName 'PingResults.csv' -dir ([Environment]::CurrentDirectory=(Get-Location -PSProvider FileSystem).ProviderPath)
try { if ($ResolveNames -ne $null) { [bool]$ResolveNames = [System.Convert]::ToBoolean($ResolveNames) } } catch {}
if ($ResolveNames) { $FormattedPingResults | Sort-Object SuccessPercentage | Select-Object NameInList, NameFromDNS, IPAddressListFromDNS, SuccessPercentage, LastPingStatus, PingedFrom | Export-Csv -Path $OutputPath -NoTypeInformation }
else { $FormattedPingResults | Sort-Object SuccessPercentage | Select-Object NameInList, SuccessPercentage, LastPingStatus, PingedFrom | Export-Csv -Path $OutputPath -NoTypeInformation }

#Output Statistics
$SuccessPingCount = GetSuccessPingCount -results $FormattedPingResults
Write-Host "---Statistics---" -ForegroundColor Green
Write-Host ("Total Time Elapsed: " + (GetTimeSpanStringInMinutesAndSeconds -startTime $Start -endTime ([System.DateTime]::Now))) -ForegroundColor Green
Write-Host "Total Names Pinged:"$FormattedPingResults.Count -ForegroundColor Green
Write-Host ("Hosts that Responded: " + ($SuccessPingCount)) -ForegroundColor Green
Write-Host ("DNS Names Resolved: " + (GetDNSNamesResolvedCount -results $FormattedPingResults)) -ForegroundColor Green
Write-Host ("Percentage of Hosts that Responded at Least Once: " + (GetPercentageAsString -n1 $SuccessPingCount -n2 $FormattedPingResults.Count)) -ForegroundColor Green
Write-Host "CSV Output Location:"$OutputPath -ForegroundColor Yellow