# Feed Windows Security events to LogMind.
#
# Windows records logons as event IDs, not as text LogMind's parser knows, so
# this reshapes 4624 (logon), 4625 (failed logon) and 4720/4732 (account
# created / added to a group) into syslog-shaped lines.
#
#   powershell -File winlogs.ps1 | python watch.py -          # live
#   powershell -File winlogs.ps1 -Once -Max 500 > win.log      # snapshot
#
# Needs an elevated shell: the Security log is not readable otherwise.

param(
  [int]$Max = 200,          # events per poll
  [int]$Every = 10,         # seconds between polls
  [switch]$Once             # print one batch and exit
)

$host_name = $env:COMPUTERNAME
$last = (Get-Date).AddMinutes(-15)

function Emit-Events($since) {
  $filter = @{ LogName = 'Security'; Id = 4624, 4625, 4720, 4732; StartTime = $since }
  $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $Max -ErrorAction SilentlyContinue
  if (-not $events) { return }
  foreach ($e in ($events | Sort-Object TimeCreated)) {
    $x = [xml]$e.ToXml()
    $d = @{}
    foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    $user = $d['TargetUserName']
    $ip = $d['IpAddress']
    if (-not $ip -or $ip -eq '-' -or $ip -eq '::1') { $ip = '127.0.0.1' }
    $ts = $e.TimeCreated.ToString('MMM dd HH:mm:ss')
    switch ($e.Id) {
      4625 { "$ts $host_name sshd[$($e.Id)]: Failed password for $user from $ip port 0 ssh2" }
      4624 { "$ts $host_name sshd[$($e.Id)]: Accepted password for $user from $ip port 0 ssh2" }
      4720 { "$ts $host_name sudo: $($d['SubjectUserName']) : COMMAND=/usr/sbin/useradd $user" }
      4732 { "$ts $host_name sudo: $($d['SubjectUserName']) : COMMAND=/usr/sbin/usermod -aG sudo $user" }
    }
  }
}

Emit-Events $last
if ($Once) { return }
while ($true) {
  Start-Sleep -Seconds $Every
  $now = Get-Date
  Emit-Events $last
  $last = $now
}
