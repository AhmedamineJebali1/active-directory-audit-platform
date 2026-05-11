// Path detail page: scores, MITRE techniques, hop visualization, recommendation.
function pathDetailApp() {
  return {
    user: null,
    loading: true,
    error: null,
    path: null,
    analysis: null,
    engagement: null,

    // Sibling navigation
    siblingPaths: [],   // ordered by global_score desc, full list
    siblingIdx: -1,     // index of current path in sibling list
    remediation: null,  // markdown content (string) when loaded
    remediationLoading: false,
    remediationError: null,

    async init() {
      this.user = await auth.requireAuth();
      if (!this.user) return;
      auth.renderNav();
      if (window.statusChips) statusChips.attach({ wsBound: false });
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
        // Load sibling paths in parallel — used for prev/next nav
        this._loadSiblings(analysisId, pathId);
        this.$nextTick(() => {
          this.renderScoreChart();
          this.renderHopChainSvg();
        });
      } catch (e) {
        this.error = e.message;
      } finally {
        this.loading = false;
      }
    },

    async _loadSiblings(analysisId, pathId) {
      try {
        const data = await api.listPaths(analysisId, { limit: 100 });
        const items = (data.items || []).slice().sort((a, b) => {
          const sa = a.global_score == null ? -1 : a.global_score;
          const sb = b.global_score == null ? -1 : b.global_score;
          return sb - sa;
        });
        this.siblingPaths = items;
        this.siblingIdx = items.findIndex(p => p.id === pathId);
      } catch (_) { /* siblings are optional */ }
    },

    hasPrev() { return this.siblingIdx > 0; },
    hasNext() { return this.siblingIdx >= 0 && this.siblingIdx < this.siblingPaths.length - 1; },

    goPrev() {
      if (!this.hasPrev()) return;
      const p = this.siblingPaths[this.siblingIdx - 1];
      location.href = `/path_detail.html?analysis_id=${this.analysis.id}&id=${p.id}`;
    },
    goNext() {
      if (!this.hasNext()) return;
      const p = this.siblingPaths[this.siblingIdx + 1];
      location.href = `/path_detail.html?analysis_id=${this.analysis.id}&id=${p.id}`;
    },

    async loadRemediation() {
      if (this.remediation || this.remediationLoading) return;
      this.remediationLoading = true;
      this.remediationError = null;
      try {
        const url = `/api/v1/analyses/${this.analysis.id}/paths/${this.path.id}/remediation-script`;
        const res = await fetch(url, {
          headers: { 'Authorization': 'Bearer ' + api.getAccessToken() },
        });
        if (!res.ok) throw new Error('Erreur ' + res.status);
        this.remediation = await res.text();
      } catch (e) {
        this.remediationError = e.message;
        if (window.toast) toast.error('Chargement remédiation : ' + e.message);
      } finally {
        this.remediationLoading = false;
      }
    },

    /**
     * Render an SVG mini-graph of the path hops (linear chain with edge labels).
     * Lightweight, no Cytoscape dependency — fits cleanly inline.
     */
    renderHopChainSvg() {
      const host = document.getElementById('hop-chain-svg');
      if (!host || !this.path) return;
      const hops = this.path.hops || [];
      if (!hops.length) { host.innerHTML = ''; return; }

      const colors = {
        User: '#4A9EFF', Computer: '#A78BFA', Group: '#FBBF24',
        Domain: '#F472B6', GPO: '#34D399', OU: '#94A3B8', Container: '#64748B',
      };
      const nodeRadius = 14;
      const yMid = 60;
      const stepX = 230;
      const padX = 24;
      const labelLen = 24;

      // Build node list: [src0, dst0, dst1, ..., dstN-1] (since dst[i]==src[i+1])
      const nodes = [{ id: hops[0].source, label: hops[0].source_label || hops[0].source, type: hops[0].source_type }];
      for (const h of hops) nodes.push({ id: h.target, label: h.target_label || h.target, type: h.target_type });

      const totalW = padX * 2 + (nodes.length - 1) * stepX;
      const h = 130;

      const truncate = (s) => (s || '').length > labelLen ? s.slice(0, labelLen - 1) + '…' : (s || '');

      let svg = `<svg viewBox="0 0 ${totalW} ${h}" width="100%" preserveAspectRatio="xMidYMid meet" class="hop-svg">`;
      // Edges first (so circles overlap)
      for (let i = 0; i < hops.length; i++) {
        const x1 = padX + i * stepX;
        const x2 = padX + (i + 1) * stepX;
        const midX = (x1 + x2) / 2;
        const edgeType = hops[i].edge_type || '';
        const isHighRisk = ['DCSync','GenericAll','WriteDacl','WriteOwner','Owns','ForceChangePassword',
                            'AllowedToDelegate','AllowedToAct','AddMember','AddSelf','AddKeyCredentialLink',
                            'WriteAccountRestrictions'].includes(edgeType);
        const stroke = isHighRisk ? '#EF4444' : 'rgba(148,163,184,0.5)';
        svg += `
          <line x1="${x1 + nodeRadius}" y1="${yMid}" x2="${x2 - nodeRadius}" y2="${yMid}"
                stroke="${stroke}" stroke-width="2" marker-end="url(#arrow-${isHighRisk ? 'red' : 'gray'})"/>
          <rect x="${midX - 50}" y="${yMid - 32}" width="100" height="20"
                rx="10" fill="rgba(10,14,26,0.95)" stroke="${stroke}" stroke-width="1"/>
          <text x="${midX}" y="${yMid - 18}" text-anchor="middle"
                font-family="JetBrains Mono, monospace" font-size="10" font-weight="600"
                fill="${isHighRisk ? '#FCA5A5' : '#CBD5E1'}">${edgeType}</text>
        `;
      }
      // Markers
      svg += `<defs>
        <marker id="arrow-gray" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto">
          <path d="M0,0 L10,5 L0,10 z" fill="rgba(148,163,184,0.7)"/>
        </marker>
        <marker id="arrow-red" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto">
          <path d="M0,0 L10,5 L0,10 z" fill="#EF4444"/>
        </marker>
      </defs>`;
      // Nodes
      nodes.forEach((n, i) => {
        const x = padX + i * stepX;
        const isLast = i === nodes.length - 1;
        const fill = isLast ? '#EF4444' : (colors[n.type] || '#94A3B8');
        const stroke = isLast ? '#FCA5A5' : 'rgba(255,255,255,0.15)';
        svg += `
          <circle cx="${x}" cy="${yMid}" r="${nodeRadius}" fill="${fill}" stroke="${stroke}" stroke-width="${isLast ? 2.5 : 1}"/>
          <text x="${x}" y="${yMid + 4}" text-anchor="middle" font-family="Inter,sans-serif" font-size="9" font-weight="700" fill="#0A0E1A">${(n.type || '?').slice(0,1)}</text>
          <text x="${x}" y="${yMid + 32}" text-anchor="middle" font-family="Inter,sans-serif" font-size="11" font-weight="600" fill="#F9FAFB">${truncate(n.label)}</text>
          <text x="${x}" y="${yMid + 46}" text-anchor="middle" font-family="JetBrains Mono,monospace" font-size="9" fill="#9CA3AF">${(n.type || '').toUpperCase()}</text>
        `;
      });
      svg += '</svg>';
      host.innerHTML = svg;
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

    async downloadRemediationFromHere() {
      try {
        const code = (this.engagement && this.engagement.code) || 'mission';
        const filename = `mitigation-${code}-${this.path.id.slice(0, 8)}.md`
          .replace(/[^A-Za-z0-9._-]+/g, '_');
        await api.downloadRemediationScript(this.analysis.id, this.path.id, filename);
        if (window.toast) toast.success('Plan de remédiation téléchargé');
      } catch (e) {
        if (window.toast) toast.error('Téléchargement échoué : ' + e.message);
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
