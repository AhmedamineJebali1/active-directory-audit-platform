"""Module — Tier 1 remediation guidance generation.

Generates Markdown remediation guides (one per attack path) explaining how
to *reduce the risk* introduced by an Active Directory misconfiguration.

DESIGN PRINCIPLE — read this before extending:
    AD attack paths are usually misconfigurations or legitimate-but-too-broad
    delegations, NOT CVE-style vulnerabilities. A naive "Remove-ADGroupMember"
    or "Set-Acl Remove" can break a service account, a help-desk delegation,
    or a tier-0 admin that the platform doesn't know about.

    The deliverable is therefore an EXPLANATORY GUIDE, not a click-to-fix
    script. Each guide structures advice as:
      1. Pourquoi ce chemin est risqué (business language)
      2. Avant d'agir — questions à se poser
      3. Options de mitigation classées par impact (least-invasive first)
      4. Commandes PowerShell de référence (clearly marked "à valider")

    The platform NEVER executes anything on the AD itself.
"""

from __future__ import annotations

import io
import logging
import re
import zipfile
from datetime import UTC, datetime
from typing import Iterable

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Per-edge guidance content (French, business-language for sections 1-3,
# PowerShell only in section 4 marked as "à valider")
# ─────────────────────────────────────────────────────────────────────────────

# Each entry: explanation of WHY the edge is risky + list of mitigation options
# (label, description) ranked from least to most invasive.
_EDGE_GUIDANCE: dict[str, dict] = {
    "WriteOwner": {
        "why": (
            "Le principal **{source_label}** peut redéfinir le propriétaire de l'objet "
            "**{target_label}**. En AD, le propriétaire d'un objet peut s'attribuer toutes "
            "les permissions sur cet objet (équivalent à GenericAll). Ce droit est donc "
            "souvent un raccourci vers un contrôle total, sans laisser de trace évidente "
            "dans les ACL standard."
        ),
        "options": [
            (
                "Surveiller",
                "Activer une règle SIEM / Defender for Identity sur l'événement 5136 "
                "(modification du propriétaire) ciblant **{target_label}**.",
            ),
            (
                "Restreindre",
                "Si le droit est lié à une délégation, vérifier qu'il s'applique uniquement "
                "à une OU précise et non au domaine entier (héritage). Réduire la portée via "
                "« Cette OU et ses descendants » plutôt que « Cet objet et tous ses descendants ».",
            ),
            (
                "Reconfigurer",
                "Si **{source_label}** est un compte humain, le placer dans le groupe "
                "« Protected Users » et migrer les opérations qui dépendent de WriteOwner "
                "vers un compte d'administration tiéré (PAW + JIT/PAM).",
            ),
            (
                "Supprimer",
                "Si aucune dépendance opérationnelle n'est confirmée après revue, retirer "
                "l'ACE WriteOwner. À effectuer **uniquement** après validation par le "
                "propriétaire fonctionnel de l'objet.",
            ),
        ],
        "ps_reference": (
            'Import-Module ActiveDirectory\n'
            '$targetDn = (Get-ADObject -Filter "Name -eq \'{target_label}\'").DistinguishedName\n'
            '$acl = Get-Acl -Path "AD:\\$targetDn"\n'
            '# Lister d\'abord les ACE concernées avant toute action :\n'
            '$acl.Access | Where-Object {{ $_.IdentityReference -like "*{source_label}*" -and $_.ActiveDirectoryRights -match "WriteOwner" }} | Format-List\n'
            '# Si la suppression est validée :\n'
            '# $rules = $acl.Access | Where-Object {{ $_.IdentityReference -like "*{source_label}*" -and $_.ActiveDirectoryRights -match "WriteOwner" }}\n'
            '# $rules | ForEach-Object {{ [void]$acl.RemoveAccessRule($_) }}\n'
            '# Set-Acl -Path "AD:\\$targetDn" -AclObject $acl'
        ),
    },
    "WriteDacl": {
        "why": (
            "**{source_label}** peut modifier les permissions de **{target_label}**. "
            "Il peut donc s'octroyer GenericAll, puis exploiter cet objet à sa guise. "
            "Cette ACE est rarement justifiée pour un compte utilisateur standard."
        ),
        "options": [
            (
                "Surveiller",
                "Auditer les modifications d'ACL via les events 5136/5137 sur **{target_label}** "
                "et corréler avec les autres actions du principal.",
            ),
            (
                "Restreindre",
                "Vérifier que l'ACE WriteDacl n'est pas héritée d'une OU parente. "
                "Si oui, l'éliminer à la racine plutôt qu'au niveau de l'objet.",
            ),
            (
                "Reconfigurer",
                "Replacer **{source_label}** dans un modèle d'administration tiéré "
                "(tier 0 isolé, comptes nominatifs). Documenter la délégation dans "
                "le référentiel d'IAM.",
            ),
            (
                "Supprimer",
                "Retirer l'ACE WriteDacl après validation. Conserver uniquement les "
                "ACE strictement nécessaires (principe du moindre privilège).",
            ),
        ],
        "ps_reference": (
            'Import-Module ActiveDirectory\n'
            '$targetDn = (Get-ADObject -Filter "Name -eq \'{target_label}\'").DistinguishedName\n'
            '$acl = Get-Acl -Path "AD:\\$targetDn"\n'
            '$acl.Access | Where-Object {{ $_.IdentityReference -like "*{source_label}*" -and $_.ActiveDirectoryRights -match "WriteDacl" }} | Format-List\n'
            '# Suppression à valider en recette avant production :\n'
            '# $acl.Access | Where-Object {{ ... }} | ForEach-Object {{ [void]$acl.RemoveAccessRule($_) }}\n'
            '# Set-Acl -Path "AD:\\$targetDn" -AclObject $acl'
        ),
    },
    "GenericAll": {
        "why": (
            "**{source_label}** dispose d'un contrôle total sur **{target_label}** : "
            "lecture, écriture, modification de mot de passe, ajout de membres, etc. "
            "C'est le droit le plus large possible sur un objet AD."
        ),
        "options": [
            (
                "Surveiller",
                "Mettre en place un détecteur d'usage anormal (réinitialisations massives, "
                "modifications d'attributs sensibles).",
            ),
            (
                "Restreindre",
                "Remplacer GenericAll par un droit ciblé : par exemple, uniquement "
                "« Reset Password » et « Enable/Disable account » si le besoin métier est "
                "la gestion de comptes utilisateurs.",
            ),
            (
                "Reconfigurer",
                "Si la délégation est légitime (équipe support), créer un groupe dédié "
                "« Helpdesk-Tier1 » avec uniquement les droits nécessaires, et migrer "
                "**{source_label}** dedans.",
            ),
            (
                "Supprimer",
                "Si aucune justification métier n'est trouvée, retirer GenericAll. "
                "Tracer la décision dans le référentiel.",
            ),
        ],
        "ps_reference": (
            'Import-Module ActiveDirectory\n'
            '$targetDn = (Get-ADObject -Filter "Name -eq \'{target_label}\'").DistinguishedName\n'
            'Get-Acl -Path "AD:\\$targetDn" | Select-Object -ExpandProperty Access | Where-Object {{ $_.IdentityReference -like "*{source_label}*" }} | Format-Table IdentityReference, ActiveDirectoryRights, ObjectType -AutoSize\n'
            '# Restriction recommandée à GenericAll : remplacer par un set précis :\n'
            '# $acl = Get-Acl -Path "AD:\\$targetDn"\n'
            '# $sid = (Get-ADObject -Identity "{source_label}").objectSid\n'
            '# $newRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "ExtendedRight", "Allow", [Guid]"00299570-246d-11d0-a768-00aa006e0529") # ResetPassword uniquement\n'
            '# Voir documentation Microsoft : Delegating Common Tasks'
        ),
    },
    "AddMember": {
        "why": (
            "**{source_label}** peut ajouter n'importe quel principal au groupe "
            "**{target_label}**, y compris lui-même. Si ce groupe est privilégié "
            "(Domain Admins, Enterprise Admins, etc.), l'élévation est immédiate."
        ),
        "options": [
            (
                "Surveiller",
                "Configurer une alerte temps-réel sur l'event 4728 (ajout de membre) "
                "pour le groupe **{target_label}**, avec escalade SOC.",
            ),
            (
                "Restreindre",
                "Si la délégation est nécessaire, la limiter à un sous-groupe non-privilégié "
                "et utiliser le « membership groupe imbriqué » uniquement pour les fonctions "
                "non sensibles.",
            ),
            (
                "Reconfigurer",
                "Implémenter une procédure JIT/PAM (Microsoft Identity Manager, BeyondTrust, "
                "CyberArk) : l'ajout est temporaire, validé, audité, et expire automatiquement.",
            ),
            (
                "Supprimer",
                "Retirer la permission AddMember sur le groupe et reprendre la gestion "
                "manuelle par un administrateur tier-0.",
            ),
        ],
        "ps_reference": (
            'Import-Module ActiveDirectory\n'
            '# Lister les membres actuels et les délégations :\n'
            'Get-ADGroupMember -Identity "{target_label}"\n'
            '$groupDn = (Get-ADGroup -Identity "{target_label}").DistinguishedName\n'
            '(Get-Acl -Path "AD:\\$groupDn").Access | Where-Object {{ $_.IdentityReference -like "*{source_label}*" }} | Format-List\n'
            '# Pour retirer la délégation après validation :\n'
            '# $acl = Get-Acl -Path "AD:\\$groupDn"\n'
            '# $rules = $acl.Access | Where-Object {{ ... }}\n'
            '# Set-Acl -Path "AD:\\$groupDn" -AclObject $acl'
        ),
    },
    "ForceChangePassword": {
        "why": (
            "**{source_label}** peut réinitialiser le mot de passe de **{target_label}** "
            "sans connaître l'ancien. Si **{target_label}** est privilégié, "
            "**{source_label}** peut s'authentifier en tant que cette identité."
        ),
        "options": [
            (
                "Surveiller",
                "Alerter sur les events 4724 (réinitialisation de mot de passe) ciblant "
                "**{target_label}** lorsque l'auteur n'est pas le helpdesk attendu.",
            ),
            (
                "Restreindre",
                "Limiter cette délégation à une OU non-administrative ; les comptes "
                "à privilèges ne doivent jamais avoir leur mot de passe réinitialisable "
                "par un compte de tier supérieur.",
            ),
            (
                "Reconfigurer",
                "Pour un compte de service : utiliser un gMSA (Group Managed Service Account) "
                "dont le mot de passe est géré automatiquement par AD. Pour un humain : "
                "déplacer **{target_label}** dans Protected Users.",
            ),
            (
                "Supprimer",
                "Retirer le droit « Reset Password » de **{source_label}** sur **{target_label}**.",
            ),
        ],
        "ps_reference": (
            'Import-Module ActiveDirectory\n'
            '$targetDn = (Get-ADUser -Identity "{target_label}").DistinguishedName\n'
            '(Get-Acl -Path "AD:\\$targetDn").Access | Where-Object {{ $_.IdentityReference -like "*{source_label}*" -and $_.ObjectType -eq "00299570-246d-11d0-a768-00aa006e0529" }} | Format-List\n'
            '# Vérifier si {target_label} est dans Protected Users :\n'
            'Get-ADGroupMember -Identity "Protected Users" | Where-Object SamAccountName -eq "{target_label}"'
        ),
    },
    "GetChangesAll": {
        "why": (
            "**{source_label}** dispose des droits de réplication AD (DCSync). Il peut "
            "extraire les hash de tous les comptes du domaine, y compris krbtgt. C'est "
            "l'équivalent d'une compromission complète : Pass-the-Hash, Golden Ticket, etc. "
            "Ce droit ne doit appartenir qu'aux contrôleurs de domaine et à un nombre "
            "très restreint de comptes de service de réplication (Azure AD Connect, etc.)."
        ),
        "options": [
            (
                "Surveiller",
                "Alerter immédiatement sur tout DCSync provenant d'un host non-DC (event 4662 "
                "avec GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 ou 1131f6ad). C'est l'un "
                "des indicateurs d'attaque les plus critiques.",
            ),
            (
                "Restreindre",
                "Aucune restriction partielle possible : ce droit est binaire. Soit "
                "**{source_label}** en a besoin, soit non.",
            ),
            (
                "Reconfigurer",
                "Si **{source_label}** est un compte de service (Azure AD Connect, "
                "Sophos, etc.), confirmer que c'est bien la documentation officielle qui "
                "exige ce droit. Sinon, faire valider l'usage par l'éditeur.",
            ),
            (
                "Supprimer",
                "Si **{source_label}** n'est pas un compte de service de réplication "
                "documenté, retirer immédiatement le droit. **Action prioritaire.**",
            ),
        ],
        "ps_reference": (
            '# Lister tous les principaux ayant le droit DCSync :\n'
            '$domainDn = (Get-ADDomain).DistinguishedName\n'
            'dsacls.exe "$domainDn" | Select-String "Replicating Directory Changes"\n'
            '# Pour révoquer (à valider) :\n'
            '# dsacls.exe "$domainDn" /R "{source_label}"\n'
            '# Vérifier que le compte n\'est pas Azure AD Connect / autre service légitime avant action.'
        ),
    },
    "GetChanges": {
        "why": (
            "**{source_label}** peut lire le contenu de la réplication AD (sans les "
            "credentials). Combiné avec d'autres droits, cela peut permettre une élévation. "
            "Sans `GetChangesAll`, ce droit seul ne permet pas DCSync."
        ),
        "options": [
            ("Surveiller", "Auditer l'usage du droit GetChanges sur le domaine."),
            (
                "Restreindre",
                "Limiter aux comptes de service strictement nécessaires.",
            ),
            (
                "Reconfigurer",
                "Confirmer la justification métier auprès de l'équipe IAM.",
            ),
            (
                "Supprimer",
                "Retirer le droit si non justifié.",
            ),
        ],
        "ps_reference": (
            '$domainDn = (Get-ADDomain).DistinguishedName\n'
            'dsacls.exe "$domainDn" | Select-String "{source_label}"\n'
            '# Suppression : dsacls.exe "$domainDn" /R "{source_label}"'
        ),
    },
    "DCSync": {
        "why": (
            "Voir GetChangesAll. **{source_label}** peut effectuer un DCSync, "
            "extraire les hash de tous les comptes (compromission totale du domaine)."
        ),
        "options": [
            (
                "Surveiller",
                "Alerte SIEM critique sur tout DCSync depuis un host non-DC.",
            ),
            ("Restreindre", "Pas de restriction partielle possible."),
            (
                "Reconfigurer",
                "Vérifier s'il s'agit d'un compte de service documenté.",
            ),
            (
                "Supprimer",
                "Retirer le droit immédiatement si non justifié. **Priorité maximale.**",
            ),
        ],
        "ps_reference": (
            '$domainDn = (Get-ADDomain).DistinguishedName\n'
            'dsacls.exe "$domainDn" | Select-String "Replicating Directory Changes"\n'
            '# Révocation : dsacls.exe "$domainDn" /R "{source_label}"'
        ),
    },
    "Owns": {
        "why": (
            "**{source_label}** est propriétaire de **{target_label}**. Le propriétaire "
            "peut toujours modifier les ACL d'un objet, ce qui équivaut à GenericAll "
            "implicite. Le propriétaire d'un objet sensible devrait être un groupe "
            "administratif tier-0, jamais un compte utilisateur ou un compte de service."
        ),
        "options": [
            (
                "Surveiller",
                "Auditer le propriétaire actuel de **{target_label}** et alerter sur tout "
                "changement.",
            ),
            (
                "Restreindre",
                "Réassigner la propriété à « Domain Admins » ou « Enterprise Admins » plutôt "
                "qu'à un compte individuel.",
            ),
            (
                "Reconfigurer",
                "Mettre en place un processus de revue trimestriel des propriétaires "
                "d'objets sensibles (groupes privilégiés, OUs administratives).",
            ),
            (
                "Supprimer",
                "Pas applicable — un objet AD a toujours un propriétaire. La mitigation "
                "consiste à le réassigner correctement.",
            ),
        ],
        "ps_reference": (
            'Import-Module ActiveDirectory\n'
            '$targetDn = (Get-ADObject -Filter "Name -eq \'{target_label}\'").DistinguishedName\n'
            '(Get-Acl -Path "AD:\\$targetDn").Owner\n'
            '# Réassignation à valider :\n'
            '# $acl = Get-Acl -Path "AD:\\$targetDn"\n'
            '# $acl.SetOwner((New-Object System.Security.Principal.NTAccount("Domain Admins")))\n'
            '# Set-Acl -Path "AD:\\$targetDn" -AclObject $acl'
        ),
    },
    "AdminTo": {
        "why": (
            "**{source_label}** est administrateur local sur **{target_label}**. "
            "Il peut donc dump LSASS, voler les tickets Kerberos d'autres sessions actives, "
            "et pivoter latéralement. Si **{target_label}** héberge la session d'un compte "
            "privilégié, l'élévation est complète."
        ),
        "options": [
            (
                "Surveiller",
                "Activer Credential Guard et l'audit de LSASS (event 4688 avec arguments "
                "suspects). Considérer LAPS pour gérer les comptes admin locaux.",
            ),
            (
                "Restreindre",
                "Limiter l'admin local à une fenêtre temporelle (admin JIT). "
                "Empêcher les comptes privilégiés de se connecter sur **{target_label}** "
                "via la stratégie « Deny log on locally » et le tier model.",
            ),
            (
                "Reconfigurer",
                "Modèle Tier 0 / Tier 1 / Tier 2 : un admin de tier inférieur ne peut pas "
                "compromettre une ressource de tier supérieur. Voir documentation Microsoft "
                "« Administrative tier model » (ESAE / Active Directory Tier Model).",
            ),
            (
                "Supprimer",
                "Retirer **{source_label}** du groupe Administrators local de "
                "**{target_label}** (de préférence via GPO Restricted Groups appliquée à l'OU).",
            ),
        ],
        "ps_reference": (
            '# Auditer (depuis la machine cible ou via PSRemoting) :\n'
            'Invoke-Command -ComputerName "{target_label}" -ScriptBlock {{ Get-LocalGroupMember -Group "Administrators" }}\n'
            '# Suppression (à valider) :\n'
            '# Invoke-Command -ComputerName "{target_label}" -ScriptBlock {{ Remove-LocalGroupMember -Group "Administrators" -Member "{source_label}" }}\n'
            '# Préférer une GPO Restricted Groups appliquée à l\'OU.'
        ),
    },
    "HasSession": {
        "why": (
            "**{source_label}** a une session active sur **{target_label}**. Si un attaquant "
            "compromet **{target_label}**, il peut voler le ticket Kerberos ou le hash NTLM "
            "de **{source_label}** (Pass-the-Hash, Pass-the-Ticket). Plus le compte est "
            "privilégié, plus l'impact est élevé."
        ),
        "options": [
            (
                "Surveiller",
                "Auditer les connexions interactives sur les machines non-administratives "
                "via les events 4624/4625.",
            ),
            (
                "Restreindre",
                "Stratégie « Deny log on locally » et « Deny log on as a service » pour "
                "interdire aux comptes privilégiés de se connecter sur des machines de "
                "tier inférieur.",
            ),
            (
                "Reconfigurer",
                "Imposer le modèle PAW (Privileged Access Workstation) : les comptes "
                "tier-0 ne se connectent QUE sur des PAW dédiées. Activer Credential Guard.",
            ),
            (
                "Supprimer",
                "Forcer la déconnexion de la session (logoff) et imposer la rotation du mot "
                "de passe ou du KRBTGT si un compte sensible est concerné.",
            ),
        ],
        "ps_reference": (
            '# Lister les sessions actives :\n'
            'Invoke-Command -ComputerName "{target_label}" -ScriptBlock {{ quser }}\n'
            '# Vérifier si {source_label} est dans Protected Users :\n'
            'Get-ADGroupMember -Identity "Protected Users" | Where-Object SamAccountName -eq "{source_label}"'
        ),
    },
    "AllowedToDelegate": {
        "why": (
            "**{source_label}** peut emprunter l'identité d'un autre utilisateur via la "
            "délégation Kerberos contrainte (S4U2Self + S4U2Proxy) pour accéder à "
            "**{target_label}**. Cette délégation est puissante et fréquemment exploitée."
        ),
        "options": [
            (
                "Surveiller",
                "Auditer les events 4769 avec un nom de service inhabituel ; activer "
                "Microsoft Defender for Identity (alertes de délégation).",
            ),
            (
                "Restreindre",
                "Marquer les comptes sensibles avec l'attribut « Account is sensitive and "
                "cannot be delegated » (UAC flag 0x100000).",
            ),
            (
                "Reconfigurer",
                "Privilégier RBCD (Resource-Based Constrained Delegation) au lieu de la "
                "délégation classique : la décision est prise par la ressource, pas par le "
                "compte source.",
            ),
            (
                "Supprimer",
                "Retirer la liste msDS-AllowedToDelegateTo de **{source_label}** si la "
                "délégation n'est plus nécessaire.",
            ),
        ],
        "ps_reference": (
            'Get-ADUser -Identity "{source_label}" -Properties msDS-AllowedToDelegateTo, TrustedForDelegation, TrustedToAuthForDelegation\n'
            '# Suppression à valider :\n'
            '# Set-ADUser -Identity "{source_label}" -Clear "msDS-AllowedToDelegateTo"'
        ),
    },
    "AllowedToAct": {
        "why": (
            "**{source_label}** est autorisé à agir au nom d'autres comptes vers "
            "**{target_label}** (RBCD). Si **{source_label}** est compromis, l'attaquant "
            "peut s'authentifier sur **{target_label}** en tant que n'importe quel utilisateur, "
            "y compris un admin de domaine."
        ),
        "options": [
            (
                "Surveiller",
                "Auditer les modifications de l'attribut msDS-AllowedToActOnBehalfOfOtherIdentity.",
            ),
            (
                "Restreindre",
                "Vérifier que la liste RBCD ne contient que les principaux strictement "
                "nécessaires. Marquer les comptes sensibles « cannot be delegated ».",
            ),
            (
                "Reconfigurer",
                "Documenter et tracer toutes les délégations RBCD dans le référentiel IAM.",
            ),
            (
                "Supprimer",
                "Retirer l'attribut msDS-AllowedToActOnBehalfOfOtherIdentity de "
                "**{target_label}**.",
            ),
        ],
        "ps_reference": (
            'Get-ADComputer -Identity "{target_label}" -Properties PrincipalsAllowedToDelegateToAccount\n'
            '# Suppression à valider :\n'
            '# Set-ADComputer -Identity "{target_label}" -Clear "msDS-AllowedToActOnBehalfOfOtherIdentity"'
        ),
    },
    "ReadLAPSPassword": {
        "why": (
            "**{source_label}** peut lire le mot de passe administrateur local de "
            "**{target_label}** géré par LAPS. Cela donne un accès admin local immédiat."
        ),
        "options": [
            (
                "Surveiller",
                "Auditer les lectures de l'attribut ms-Mcs-AdmPwd (LAPS legacy) ou "
                "msLAPS-Password (LAPS Windows). Alerter sur les lectures fréquentes.",
            ),
            (
                "Restreindre",
                "Limiter la lecture LAPS à un groupe « Helpdesk-LAPS-Read » strictement "
                "scoped à une OU précise.",
            ),
            (
                "Reconfigurer",
                "Migrer vers Windows LAPS (intégré à Windows Server 2022+) avec chiffrement "
                "des mots de passe et audit natif.",
            ),
            (
                "Supprimer",
                "Retirer **{source_label}** des principaux autorisés à lire l'attribut LAPS.",
            ),
        ],
        "ps_reference": (
            'Import-Module ActiveDirectory\n'
            '$targetDn = (Get-ADComputer -Identity "{target_label}").DistinguishedName\n'
            '(Get-Acl -Path "AD:\\$targetDn").Access | Where-Object {{ $_.IdentityReference -like "*{source_label}*" }} | Format-List'
        ),
    },
    "ReadGMSAPassword": {
        "why": (
            "**{source_label}** peut récupérer le mot de passe du gMSA "
            "**{target_label}**. Si ce gMSA est privilégié, cela revient à compromettre "
            "ce compte de service."
        ),
        "options": [
            (
                "Surveiller",
                "Auditer les lectures de l'attribut msDS-ManagedPassword.",
            ),
            (
                "Restreindre",
                "Limiter PrincipalsAllowedToRetrieveManagedPassword aux seules machines "
                "ou comptes qui exécutent réellement le service.",
            ),
            (
                "Reconfigurer",
                "Documenter chaque gMSA et son usage dans le référentiel des comptes "
                "de service.",
            ),
            (
                "Supprimer",
                "Retirer **{source_label}** de PrincipalsAllowedToRetrieveManagedPassword.",
            ),
        ],
        "ps_reference": (
            'Get-ADServiceAccount -Identity "{target_label}" -Properties PrincipalsAllowedToRetrieveManagedPassword\n'
            '# Mise à jour à valider :\n'
            '# Set-ADServiceAccount -Identity "{target_label}" -PrincipalsAllowedToRetrieveManagedPassword <nouvelle liste>'
        ),
    },
    "MemberOf": {
        "why": (
            "**{source_label}** est membre du groupe **{target_label}**. Si **{target_label}** "
            "est privilégié, **{source_label}** hérite directement de ces privilèges. "
            "**Attention** : cette appartenance peut être tout à fait légitime (administrateur "
            "désigné, compte de service documenté). Ne rien retirer sans confirmation."
        ),
        "options": [
            (
                "Surveiller",
                "Revue trimestrielle des membres des groupes privilégiés. Alerter "
                "automatiquement sur tout ajout (event 4728).",
            ),
            (
                "Restreindre",
                "Si **{source_label}** est un compte humain, vérifier qu'il dispose d'un "
                "compte d'administration dédié (admin-jdoe vs jdoe).",
            ),
            (
                "Reconfigurer",
                "Mettre en place une procédure JIT/PAM pour l'appartenance aux groupes "
                "sensibles (Domain Admins, Enterprise Admins, etc.).",
            ),
            (
                "Supprimer",
                "Si l'appartenance n'est pas justifiée, retirer **{source_label}** du groupe "
                "**{target_label}** après accord du propriétaire fonctionnel.",
            ),
        ],
        "ps_reference": (
            'Get-ADGroupMember -Identity "{target_label}" | Format-Table SamAccountName, ObjectClass\n'
            '# Lister les groupes privilégiés à examiner :\n'
            'Get-ADGroup -Filter "AdminCount -eq 1" | Select-Object Name, DistinguishedName\n'
            '# Suppression à valider :\n'
            '# Remove-ADGroupMember -Identity "{target_label}" -Members "{source_label}" -Confirm:$true'
        ),
    },
    "GPLink": {
        "why": (
            "La GPO **{source_label}** est liée à l'OU **{target_label}** et peut donc "
            "modifier la configuration de tous les objets de cette OU (scripts de démarrage, "
            "ACL, paramètres de sécurité). Une GPO compromise sur une OU sensible permet "
            "d'exécuter du code sur toutes les machines de cette OU."
        ),
        "options": [
            (
                "Surveiller",
                "Auditer les modifications de GPO via la baseline DSC ou Microsoft Sentinel.",
            ),
            (
                "Restreindre",
                "Vérifier que la GPO n'applique que des paramètres pertinents pour cette OU. "
                "Éviter les GPO « fourre-tout » liées à plusieurs OUs.",
            ),
            (
                "Reconfigurer",
                "Limiter les droits d'édition de la GPO aux administrateurs tier-0 uniquement.",
            ),
            (
                "Supprimer",
                "Délier la GPO de l'OU si elle n'est plus pertinente.",
            ),
        ],
        "ps_reference": (
            'Get-GPO -Name "{source_label}" | Get-GPInheritance\n'
            'Get-GPPermissions -Name "{source_label}" -All\n'
            '# Suppression du lien (à valider) :\n'
            '# $ouDn = (Get-ADOrganizationalUnit -Filter "Name -eq \'{target_label}\'").DistinguishedName\n'
            '# Remove-GPLink -Name "{source_label}" -Target $ouDn'
        ),
    },
    "Contains": {
        "why": (
            "**{target_label}** est contenu dans **{source_label}** (relation de hiérarchie "
            "AD : OU → enfant). Cette relation n'est pas une vulnérabilité en soi mais elle "
            "permet aux ACL et GPO de **{source_label}** de s'appliquer à **{target_label}**. "
            "Vérifier que les délégations sur l'OU parente ne donnent pas indirectement accès "
            "aux objets sensibles qu'elle contient."
        ),
        "options": [
            (
                "Surveiller",
                "Audit régulier des ACL et GPO appliquées à l'OU **{source_label}**.",
            ),
            (
                "Restreindre",
                "Désactiver l'héritage des ACL pour les objets sensibles, ou les déplacer "
                "dans une OU dédiée avec un contrôle d'accès strict.",
            ),
            (
                "Reconfigurer",
                "Restructurer l'arborescence pour que les objets tier-0 soient regroupés "
                "dans une OU isolée (« Tier0 / Admin Forest »).",
            ),
            (
                "Supprimer",
                "Pas applicable directement — la relation Contains est structurelle.",
            ),
        ],
        "ps_reference": (
            'Get-ADObject -Filter "DistinguishedName -like \'*{target_label}*\'" -Properties Modified, ProtectedFromAccidentalDeletion\n'
            'Get-GPInheritance -Target (Get-ADOrganizationalUnit -Filter "Name -eq \'{source_label}\'").DistinguishedName'
        ),
    },
    "TrustedBy": {
        "why": (
            "Une relation d'approbation existe entre **{source_label}** et **{target_label}**. "
            "Si l'un des deux domaines est compromis, l'approbation peut être exploitée pour "
            "escalader vers l'autre (notamment via SID History et inter-realm Kerberos)."
        ),
        "options": [
            (
                "Surveiller",
                "Activer le filtrage SID (SID Filter Quarantining) sur les approbations entre "
                "forêts non-administrées.",
            ),
            (
                "Restreindre",
                "Activer l'authentification sélective (Selective Authentication) sur "
                "l'approbation, plutôt que l'authentification large.",
            ),
            (
                "Reconfigurer",
                "Documenter la finalité de chaque trust. Considérer la migration vers "
                "Azure AD B2B pour les collaborations externes.",
            ),
            (
                "Supprimer",
                "Si le trust n'est plus utilisé, le supprimer.",
            ),
        ],
        "ps_reference": (
            'Get-ADTrust -Filter * | Format-Table Source, Target, Direction, ForestTransitive, SIDFilteringQuarantined\n'
            '# Suppression à valider en concertation avec l\'équipe AD distante :\n'
            '# Remove-ADTrust -Identity "{target_label}"'
        ),
    },
}

_RISK_ORDER = {"critique": 0, "eleve": 1, "moyen": 2, "faible": 3}
_RISK_LABEL = {
    "critique": "Critique",
    "eleve": "Élevé",
    "moyen": "Moyen",
    "faible": "Faible",
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _slug(text: str, max_len: int = 40) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", str(text or "")).strip("-").lower()
    return s[:max_len] or "path"


def _format_path_summary(hops: list[dict]) -> str:
    """Render hops as: NODE_A → [Edge] → NODE_B → [Edge] → NODE_C"""
    if not hops:
        return "(chemin vide)"
    parts: list[str] = []
    for i, hop in enumerate(hops):
        src = hop.get("source_label") or hop.get("source") or "?"
        tgt = hop.get("target_label") or hop.get("target") or "?"
        edge = hop.get("edge_type") or "?"
        if i == 0:
            parts.append(str(src))
        parts.append(f"→ [{edge}] →")
        parts.append(str(tgt))
    return " ".join(parts)


def _ctx_for_hop(hop: dict) -> dict:
    return {
        "source": hop.get("source") or "",
        "target": hop.get("target") or "",
        "source_label": hop.get("source_label") or hop.get("source") or "",
        "target_label": hop.get("target_label") or hop.get("target") or "",
    }


def _render_step_section(idx: int, hop: dict) -> str:
    """Render one numbered step (= one hop) in markdown."""
    edge = hop.get("edge_type") or "Unknown"
    ctx = _ctx_for_hop(hop)
    guide = _EDGE_GUIDANCE.get(edge)

    src = ctx["source_label"]
    tgt = ctx["target_label"]
    header = f"### Étape {idx} — `{edge}` : {src} → {tgt}\n"

    if not guide:
        return (
            header
            + f"_Aucune fiche de mitigation automatique pour le type de relation `{edge}`. "
            "Consulter la documentation Microsoft « Active Directory Security Best Practices » "
            "et l'analyse LLM détaillée plus haut._\n"
        )

    why = guide["why"].format(**ctx)
    options_md = ""
    for label, desc in guide["options"]:
        options_md += f"- **{label}** — {desc.format(**ctx)}\n"

    ps_ref = guide["ps_reference"].format(**ctx)

    return (
        header
        + f"\n**Pourquoi c'est risqué :** {why}\n\n"
        + "**Options de mitigation** (de la moins invasive à la plus invasive) :\n\n"
        + options_md
        + "\n**Commandes PowerShell de référence** (à adapter, à tester en recette, à ne pas exécuter à l'aveugle) :\n\n"
        + "```powershell\n"
        + ps_ref
        + "\n```\n"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


def build_guide_for_path(
    path,
    engagement=None,
    *,
    generated_at: datetime | None = None,
) -> str:
    """Generate a complete Markdown remediation guide for one attack path.

    Args:
        path: AttackPath ORM instance with hops, risk_level, recommendation_fr,
              llm_raw_response, mitre_techniques eagerly loaded.
        engagement: optional Engagement instance for header context.
        generated_at: optional override for the timestamp (used in tests).

    Returns:
        Full .md file content as a string.
    """
    ts = generated_at or datetime.now(UTC)
    hops = path.hops or []

    risk = (path.risk_level or "non_evalue").lower()
    risk_label = _RISK_LABEL.get(risk, risk.capitalize())
    score = path.global_score
    score_str = f"{score:.1f}/10" if score is not None else "n/a"

    techniques: list[str] = []
    try:
        for t in (path.mitre_techniques or []):
            techniques.append(f"`{t.technique_id}` — {t.technique_name}")
    except Exception:
        pass
    techniques_str = ", ".join(techniques) if techniques else "_Aucune_"

    summary = _format_path_summary(hops)
    eng_line = (
        f"{engagement.code} — {engagement.client_name}"
        if engagement
        else "_(mission non renseignée)_"
    )

    explanation = (path.explanation_fr or "").strip()
    explanation_section = (
        f"\n## Analyse détaillée\n\n{explanation}\n"
        if explanation
        else ""
    )

    # Per-hop steps
    steps = "\n".join(_render_step_section(i + 1, h) for i, h in enumerate(hops))

    return f"""# Guide de mitigation — Chemin d'attaque

| | |
|---|---|
| **Mission** | {eng_line} |
| **Identifiant du chemin** | `{path.id}` |
| **Niveau de risque** | **{risk_label}** ({score_str}) |
| **Techniques MITRE** | {techniques_str} |
| **Généré le** | {ts.strftime('%Y-%m-%d à %H:%M UTC')} |

## Chemin

```
{summary}
```
{explanation_section}
## ⚠️ Avant d'agir — questions à se poser

En Active Directory, un chemin d'attaque est presque toujours une **mauvaise configuration** ou
une **délégation trop large**, **rarement une vulnérabilité** au sens classique. Avant toute
action, valider chaque point ci-dessous :

1. **Le principal source est-il un compte humain, un compte de service, ou un compte legacy ?**
2. **Le droit accordé est-il documenté dans le référentiel IAM ?** Si non, qui a réalisé la délégation ?
3. **Cette permission est-elle utilisée en production ?** Vérifier les logs des 90 derniers jours.
4. **Existe-t-il une dépendance applicative ?** Une suppression peut casser un service métier.
5. **Le principal cible est-il bien dans le bon tier (0/1/2) ?** Voir le modèle Microsoft.

> **Règle d'or :** ne jamais retirer un droit AD sans avoir confirmé qu'il n'est pas utilisé,
> et toujours tester en environnement de recette avant la production.

## Plan de mitigation par étape

Le chemin se compose de {len(hops)} relation(s). Pour chacune, plusieurs options de mitigation
sont proposées, classées de la **moins invasive** (surveiller) à la **plus invasive** (supprimer).
**Choisir l'option la plus adaptée au contexte métier**, pas systématiquement la suppression.

{steps}

## Validation post-mitigation

Une fois les actions appliquées, relancer un audit AD via la plateforme pour confirmer que
le chemin a disparu. Si le chemin persiste, consulter à nouveau ce guide ou contacter
votre auditeur référent.

---
*Document généré automatiquement par AD Audit AI. La plateforme **n'exécute jamais** de
modifications sur l'Active Directory : toutes les actions doivent être validées et appliquées
manuellement par les équipes habilitées.*
"""


def _bundle_filename(idx: int, path) -> str:
    risk = (path.risk_level or "non_evalue").lower()
    rank = _RISK_ORDER.get(risk, 9)
    src = _slug(getattr(path, "source_node", "src"), 24)
    tgt = _slug(getattr(path, "target_node", "tgt"), 24)
    return f"{rank}{idx:03d}-{risk}-{src}__to__{tgt}.md"


def _build_readme(engagement, paths, generated_at: datetime) -> str:
    paths_list = list(paths)
    counts: dict[str, int] = {}
    for p in paths_list:
        risk = (p.risk_level or "non_evalue").lower()
        counts[risk] = counts.get(risk, 0) + 1

    breakdown_lines = []
    for risk_key in ("critique", "eleve", "moyen", "faible"):
        if counts.get(risk_key):
            breakdown_lines.append(f"- **{_RISK_LABEL[risk_key]}** : {counts[risk_key]} guide(s)")
    if counts.get("non_evalue"):
        breakdown_lines.append(f"- **Non évalué** : {counts['non_evalue']} guide(s)")
    breakdown = "\n".join(breakdown_lines) or "- _(aucun)_"

    eng_line = (
        f"{engagement.code} — {engagement.client_name}" if engagement else "_(non renseignée)_"
    )

    return f"""# Plan de mitigation — Mission {eng_line}

_Généré le {generated_at.strftime('%Y-%m-%d à %H:%M UTC')} par AD Audit AI._

## Avant tout

> **Important.** En Active Directory, les chemins d'attaque sont presque toujours des
> **mauvaises configurations** ou des **délégations trop larges héritées du passé**, et non
> des vulnérabilités exploitables au sens d'un CVE. **Aucune action ne doit être appliquée
> sans validation préalable** : suppression d'un membre de groupe, retrait d'une ACE ou
> changement de propriétaire peuvent **casser un service métier légitime**.

## Contenu de l'archive

Cette archive contient **{len(paths_list)} guide(s)** de mitigation au format Markdown,
un par chemin d'attaque détecté lors de l'audit. Chaque guide est structuré en quatre parties :

1. **Pourquoi le chemin est risqué** (explication métier)
2. **Questions à se poser avant d'agir** (validation préalable)
3. **Options de mitigation** (de la moins invasive — surveiller — à la plus invasive — supprimer)
4. **Commandes PowerShell de référence** (à adapter, à tester, à ne jamais exécuter à l'aveugle)

### Répartition par criticité

{breakdown}

## Ordre de traitement recommandé

Les fichiers sont préfixés pour suivre l'ordre suivant :

1. **`0xxx-critique-…`** — à traiter en priorité absolue.
2. **`1xxx-eleve-…`** — ensuite.
3. **`2xxx-moyen-…`** et **`3xxx-faible-…`** — lors des fenêtres de maintenance suivantes.

## Procédure recommandée par chemin

1. Lire l'intégralité du guide (`.md`).
2. Répondre aux questions de la section *« Avant d'agir »* avec le propriétaire fonctionnel.
3. Choisir **l'option de mitigation la plus adaptée** au contexte métier — pas systématiquement
   la suppression. Surveiller ou restreindre est souvent suffisant et beaucoup moins risqué.
4. Tester l'action choisie en environnement de recette.
5. Appliquer en production avec un plan de rollback.
6. Documenter la décision dans le référentiel.
7. Relancer un audit via la plateforme pour confirmer la disparition du chemin.

## Outils utiles

- **Microsoft Active Directory Security Best Practices** (documentation officielle).
- **Modèle Tier 0 / Tier 1 / Tier 2** (Active Directory Tier Model / ESAE).
- **Protected Users** (groupe AD), **Authentication Policies & Silos**.
- **PAW** (Privileged Access Workstations) pour les comptes tier-0.
- **PAM / JIT** (Microsoft Identity Manager, BeyondTrust, CyberArk).
- **Microsoft Defender for Identity** pour la détection comportementale.

## Précautions

- AD Audit AI **n'exécute jamais** de modifications sur votre Active Directory.
- Vous restez seul(e) responsable des actions appliquées en production.
- En cas de doute, contactez votre auditeur référent avant toute action.

---
*AD Audit AI — Plateforme d'audit Active Directory automatisé*
"""


def build_bundle(engagement, paths: Iterable, *, generated_at: datetime | None = None) -> bytes:
    """Build a ZIP archive containing every per-path Markdown guide + a French README."""
    ts = generated_at or datetime.now(UTC)
    paths_list = list(paths)
    paths_list.sort(
        key=lambda p: (
            _RISK_ORDER.get((p.risk_level or "non_evalue").lower(), 9),
            -(p.global_score or 0.0),
        )
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("LISEZ-MOI.md", _build_readme(engagement, paths_list, ts))
        for idx, path in enumerate(paths_list, start=1):
            try:
                content = build_guide_for_path(path, engagement=engagement, generated_at=ts)
                zf.writestr(_bundle_filename(idx, path), content)
            except Exception as exc:
                logger.exception(
                    "remediation_guide_failed",
                    extra={"path_id": str(path.id), "error": str(exc)},
                )
                zf.writestr(
                    f"ERREUR-{idx:03d}-{path.id}.txt",
                    f"Échec de génération du guide pour le chemin {path.id} : {exc}\n",
                )
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# Backwards-compatible aliases (so the API endpoint still works)
# ─────────────────────────────────────────────────────────────────────────────

# Previous name used by paths.py — keep so we don't break the import.
build_script_for_path = build_guide_for_path
