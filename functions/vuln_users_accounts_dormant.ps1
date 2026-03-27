function vuln_users_accounts_dormant{
$limit = (Get-Date).AddYears(-1)

$users = Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate,whenCreated
$computers = Get-ADComputer -Filter {Enabled -eq $true} -Properties LastLogonDate,whenCreated

$all = $users + $computers

$dormant = $all | Where-Object {
    ($_.LastLogonDate -and $_.LastLogonDate -lt $limit) -or
    (-not $_.LastLogonDate -and $_.whenCreated -lt $limit)
}

$percent = [math]::Round(($dormant.Count / $all.Count) * 100, 2)

"$($percent)% de comptes dormants ($($dormant.Count)/$($all.Count))"
}
