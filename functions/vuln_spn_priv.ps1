function vuln_spn_priv {
$Groups = @(
    "Administrateurs",
    "Contrôleurs de domaine",
    "Administrateurs du schéma",
    "Administrateurs de l'entreprise",
    "Administrateurs du domaine",
    "Administrateurs des clés",
    "Opérateurs de compte",
    "Opérateurs de serveur",
    "Opérateurs de sauvegarde",
    "Opérateurs d'impression",
    "Administrators",
    "Domain Controllers",
    "Schema Admins",
    "Enterprise Admins",
    "Domain Admins",
    "Key Admins",
    "Account Operators",
    "Server Operators",
    "Backup Operators",
    "Print Operators"
)

$Users = foreach ($g in $Groups) {
    Get-ADGroupMember $g -Recursive |
    Where-Object objectClass -eq user
}

$Users |
Sort-Object SID -Unique |
Get-ADUser -Properties ServicePrincipalName |
Where-Object { $_.ServicePrincipalName } |
Select SamAccountName, ServicePrincipalName
}
