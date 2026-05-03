// Path detail page: scores, MITRE techniques, hop visualization, recommendation.
function pathDetailApp() {
  return {
    user: null,
    loading: true,
    error: null,
    path: null,
    analysis: null,
    engagement: null,

    async init() {
      this.user = await auth.requireAuth();
      if (!this.user) return;
      auth.renderNav();
      const params = new URLSearchParams(location.search);
      const analysisId = params.get('analysis_id');
      const pathId = params.get('id');
      if (!analysisId || !pathId) {
        location.href = '/dashboard.html';
        return;
      }
      try {
        this.path = await api.getPath(analysisId, pathId);
        this.analysis = await api.getAnalysis(analysisId);
        this.engagement = await api.getEngagement(this.analysis.engagement_id);
        this.$nextTick(() => this.renderScoreChart());
      } catch (e) {
        this.error = e.message;
      } finally {
        this.loading = false;
      }
    },

    renderScoreChart() {
      const el = document.getElementById('score-chart');
      if (!el || !this.path) return;
      try {
        new Chart(el, {
          type: 'radar',
          data: {
            labels: ['Exploitabilité', 'Furtivité', 'Score global'],
            datasets: [
              {
                label: 'Scores (0-10)',
                data: [
                  this.path.exploitability_score || 0,
                  this.path.stealth_score || 0,
                  this.path.global_score || 0,
                ],
                backgroundColor: 'rgba(134, 188, 37, 0.25)',
                borderColor: '#86BC25',
                borderWidth: 2,
                pointBackgroundColor: '#86BC25',
              },
            ],
          },
          options: {
            responsive: true,
            scales: {
              r: {
                min: 0, max: 10,
                ticks: {
                  stepSize: 2,
                  color: 'rgba(255,255,255,0.4)',
                  backdropColor: 'transparent',
                  font: { size: 11 },
                },
                grid: { color: 'rgba(255,255,255,0.08)' },
                angleLines: { color: 'rgba(255,255,255,0.1)' },
                pointLabels: { color: 'rgba(255,255,255,0.7)', font: { size: 12, weight: '600' } },
              },
            },
            plugins: { legend: { display: false } },
          },
        });
      } catch (e) {
        console.error('chart error', e);
      }
    },

    riskBadgeClass(level) {
      return 'badge badge-' + (level || 'neutral');
    },

    riskLabel(level) {
      return {
        critique: 'Critique',
        eleve: 'Élevé',
        moyen: 'Moyen',
        faible: 'Faible',
      }[level] || level || 'Indéterminé';
    },

    scoreColor(score) {
      if (score == null) return 'rgba(255,255,255,0.5)';
      if (score >= 8) return 'var(--risk-critique)';
      if (score >= 6) return 'var(--risk-eleve)';
      if (score >= 4) return 'var(--risk-moyen)';
      return 'var(--risk-faible)';
    },

    backToEngagement() {
      if (this.engagement) {
        location.href = `/engagement.html?id=${this.engagement.id}`;
      } else {
        history.back();
      }
    },

    formatScore(s) {
      return s == null ? '—' : Number(s).toFixed(1);
    },

    // Tooltip description for each BloodHound edge type
    edgeDescription(edgeType) {
      const map = {
        AdminTo: 'Droits d\'administrateur local sur la machine cible. Permet l\'exécution de code, l\'extraction de credentials (Mimikatz), et le mouvement latéral.',
        MemberOf: 'Appartenance à un groupe. Si le groupe a des droits élevés, le membre en hérite automatiquement.',
        HasSession: 'Une session active existe sur cette machine. Un attaquant peut capturer le token/ticket d\'authentification de l\'utilisateur connecté.',
        DCSync: 'Permission de répliquer les secrets du contrôleur de domaine (hashes NTLM de tous les comptes). Équivaut à compromettre tout le domaine.',
        GenericAll: 'Contrôle total sur l\'objet. Peut modifier n\'importe quel attribut, réinitialiser le mot de passe, ajouter des membres.',
        GenericWrite: 'Écriture sur certains attributs. Permet de modifier des propriétés sensibles (délégation, SPN, scripts de connexion).',
        WriteOwner: 'Peut changer le propriétaire de l\'objet, ce qui donne un contrôle total.',
        WriteDACL: 'Peut modifier les ACL de l\'objet et s\'accorder n\'importe quelle permission.',
        Owns: 'Est propriétaire de l\'objet — équivalent à GenericAll.',
        ForceChangePassword: 'Peut forcer la réinitialisation du mot de passe sans connaître l\'ancien.',
        AllowedToDelegate: 'Délégation Kerberos : peut demander des tickets de service au nom d\'autres utilisateurs vers des machines spécifiques.',
        AllowedToAct: 'Resource-Based Constrained Delegation (RBCD) : permet l\'usurpation d\'identité vers cette ressource.',
        AddMember: 'Peut ajouter des membres à ce groupe (ex: s\'ajouter soi-même à Domain Admins).',
        ReadLAPSPassword: 'Peut lire le mot de passe LAPS (administrateur local rotatif) de la machine cible.',
        ReadGMSAPassword: 'Peut lire le mot de passe du Group Managed Service Account — souvent avec des droits élevés.',
        GPLink: 'Une GPO est liée à cet OU — peut propager des configurations malveillantes à tous les objets de l\'OU.',
        Contains: 'Relation de contenance AD (domaine > OU > objet). Permet d\'identifier la portée des GPO.',
        TrustedBy: 'Relation de confiance entre domaines — un compte du domaine A peut s\'authentifier sur le domaine B.',
        CanRDP: 'Peut se connecter via Remote Desktop Protocol. Permet l\'accès interactif à la machine.',
        CanPSRemote: 'Peut exécuter des commandes via PowerShell Remoting (WinRM).',
        ExecuteDCOM: 'Peut exécuter du code via DCOM — vecteur d\'exécution distante.',
        SQLAdmin: 'Droits administrateur sur l\'instance SQL Server — accès aux données et exécution de commandes OS via xp_cmdshell.',
        AddSelf: 'Peut s\'ajouter lui-même comme membre de ce groupe.',
        HasSIDHistory: 'L\'objet contient un SID d\'un autre domaine dans son historique — peut hériter de droits anciens.',
      };
      return map[edgeType] || `Relation BloodHound de type "${edgeType}" — consultez la documentation BloodHound pour plus de détails.`;
    },

    // Full edge glossary for the collapsible section
    edgeGlossary() {
      return [
        { name: 'AdminTo',            desc: 'Administrateur local de la machine. Permet l\'extraction de credentials et le mouvement latéral.' },
        { name: 'MemberOf',           desc: 'Membre d\'un groupe AD. Les permissions du groupe s\'appliquent au membre.' },
        { name: 'HasSession',         desc: 'Session active sur cette machine. Le token de l\'utilisateur peut être capturé.' },
        { name: 'DCSync',             desc: 'Peut répliquer tous les hashes NTLM du domaine depuis un DC.' },
        { name: 'GenericAll',         desc: 'Contrôle total : réinitialisation de mot de passe, ajout de membres, modification des ACL.' },
        { name: 'GenericWrite',       desc: 'Écriture sur attributs sensibles : délégation Kerberos, SPN, scripts de logon.' },
        { name: 'WriteOwner',         desc: 'Peut changer le propriétaire et obtenir un contrôle total sur l\'objet.' },
        { name: 'WriteDACL',          desc: 'Modifie les ACL pour s\'octroyer n\'importe quelle permission.' },
        { name: 'Owns',               desc: 'Propriétaire de l\'objet — contrôle total équivalent à GenericAll.' },
        { name: 'ForceChangePassword', desc: 'Réinitialise le mot de passe d\'un compte sans connaître l\'actuel.' },
        { name: 'AllowedToDelegate', desc: 'Délégation Kerberos contrainte — usurpation d\'identité vers des services spécifiques.' },
        { name: 'AllowedToAct',      desc: 'RBCD — usurpation d\'identité vers cette ressource via S4U2Proxy.' },
        { name: 'AddMember',         desc: 'Ajoute des membres à ce groupe, y compris soi-même.' },
        { name: 'ReadLAPSPassword',  desc: 'Lit le mot de passe administrateur local rotatif (LAPS).' },
        { name: 'ReadGMSAPassword',  desc: 'Lit le mot de passe du GMSA — souvent compte de service privilégié.' },
        { name: 'GPLink',            desc: 'GPO liée à un OU — propagation de configuration à tous les objets enfants.' },
        { name: 'Contains',          desc: 'Contenance AD : un domaine contient des OU, qui contiennent des objets.' },
        { name: 'TrustedBy',         desc: 'Confiance inter-domaine — authentification croisée possible.' },
        { name: 'CanRDP',            desc: 'Accès Remote Desktop — connexion interactive à la machine.' },
        { name: 'CanPSRemote',       desc: 'Exécution via PowerShell Remoting (port 5985/5986).' },
        { name: 'ExecuteDCOM',       desc: 'Exécution distante via DCOM — mouvement latéral sans RDP.' },
        { name: 'SQLAdmin',          desc: 'Admin SQL Server — accès données + exécution OS via xp_cmdshell.' },
      ];
    },

    // Tactics for the MITRE collapsible section
    mitreTactics() {
      return [
        { id: 'TA0001', name: 'Initial Access',      desc: 'Obtenir un premier accès au réseau (phishing, exploit).' },
        { id: 'TA0002', name: 'Execution',            desc: 'Exécuter du code malveillant sur le système cible.' },
        { id: 'TA0003', name: 'Persistence',          desc: 'Maintenir l\'accès malgré les redémarrages et réinitialisations.' },
        { id: 'TA0004', name: 'Privilege Escalation', desc: 'Obtenir des permissions plus élevées (SYSTEM, Domain Admin).' },
        { id: 'TA0005', name: 'Defense Evasion',      desc: 'Éviter la détection par les outils de sécurité.' },
        { id: 'TA0006', name: 'Credential Access',    desc: 'Voler des mots de passe, hashes NTLM ou tickets Kerberos.' },
        { id: 'TA0007', name: 'Discovery',            desc: 'Explorer l\'environnement : comptes, machines, services.' },
        { id: 'TA0008', name: 'Lateral Movement',     desc: 'Se déplacer vers d\'autres machines du réseau.' },
        { id: 'TA0009', name: 'Collection',           desc: 'Collecter des données sensibles d\'intérêt.' },
        { id: 'TA0011', name: 'Command & Control',    desc: 'Maintenir une communication avec l\'infrastructure attaquante.' },
      ];
    },
  };
}
