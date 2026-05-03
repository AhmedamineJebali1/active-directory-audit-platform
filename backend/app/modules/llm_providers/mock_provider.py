"""Mock LLM provider for testing — returns deterministic plausible JSON."""

import json
import logging
import random

from app.modules.llm_providers.base import LLMProvider

logger = logging.getLogger(__name__)


class MockProvider(LLMProvider):
    """Returns deterministic mock responses for CI/testing without calling any LLM."""

    @property
    def provider_name(self) -> str:
        return "mock"

    async def invoke(self, prompt: str, system: str = "") -> str:
        if "executive_summary" in prompt.lower() or "synthèse" in prompt.lower() or "resume_executif" in prompt.lower():
            return json.dumps({
                "verdict_global": "Élevé",
                "resume_executif": "L'environnement Active Directory analysé présente des risques élevés. Plusieurs chemins d'attaque permettent à des utilisateurs non privilégiés d'atteindre les comptes Domain Admins. Les vecteurs principaux incluent des sessions administrateur exposées sur des postes de travail, des délégations Kerberos mal configurées, et des droits ACL excessifs sur des groupes privilégiés.",
                "principaux_risques": [
                    "Sessions administrateur exposées sur des postes de travail non protégés",
                    "Délégations Kerberos non contraintes permettant l'usurpation d'identité",
                    "Droits WriteOwner sur le groupe Domain Admins",
                ],
                "recommandations_prioritaires": [
                    {"priorite": 1, "action": "Supprimer les sessions administrateur actives sur les postes de travail", "urgence": "Immédiate"},
                    {"priorite": 2, "action": "Désactiver les délégations Kerberos non contraintes", "urgence": "Immédiate"},
                    {"priorite": 3, "action": "Auditer et corriger les ACL sur les groupes privilégiés", "urgence": "Court terme"},
                ],
                "feuille_de_route": "Phase 1 (Immédiat) : Corriger les délégations Kerberos et les sessions exposées. Phase 2 (1 mois) : Auditer l'ensemble des ACL et des droits d'administration. Phase 3 (3 mois) : Déployer une solution PAM et mettre en place une surveillance continue des chemins d'attaque."
            })

        scores = {
            "exploitability_score": random.randint(5, 9),
            "stealth_score": random.randint(3, 8),
            "global_score": random.randint(5, 10),
            "risk_level": random.choice(["Élevé", "Critique", "Moyen"]),
            "explanation": (
                "Ce chemin d'attaque exploite une combinaison de relations Active Directory qui permet "
                "à un attaquant de progresser d'un compte utilisateur standard vers des privilèges administrateur "
                "de domaine. Les étapes successives exploitent des sessions actives d'administrateurs sur des "
                "postes non sécurisés, permettant la capture de credentials via des techniques de Pass-the-Hash "
                "ou de Kerberoasting. Ce type d'attaque est particulièrement dangereux car il ne nécessite "
                "aucune exploitation de vulnérabilité logicielle — il exploite uniquement des configurations "
                "Active Directory incorrectes."
            ),
            "recommendation": (
                "1. Mettre en place une politique de Tier Model séparant les comptes d'administration par niveau. "
                "2. Désactiver les sessions RDP directes vers les contrôleurs de domaine depuis des postes utilisateurs. "
                "3. Implémenter Microsoft LAPS pour la gestion des mots de passe locaux. "
                "4. Configurer des alertes SIEM sur les événements d'authentification anormaux. "
                "5. Auditer régulièrement les chemins d'attaque avec BloodHound."
            ),
        }
        return json.dumps(scores)
