'use strict';

(() => {
  const MAX_FINDINGS = 15000;
  const MAX_RAW_PREVIEW = 60000;
  const MAX_STRUCTURED_OUTPUT = 32 * 1024 * 1024;
  const MAX_FABRIC_LIMITATIONS = 8;
  const MAX_RESEARCH_CLAIMS = 50;
  const MAX_RESEARCH_SOURCES = 100;
  const MAX_RESEARCH_GAPS = 100;
  const DIFF_LINE_LIMIT = 500;
  const CURRENT_VERSION = 'Attestor 4.1.4';
  const DEFAULT_VARIANT = 'south-park';
  const VARIANT_MODES = new Set(['attestor41', 'improve', 'cjpcontrol']);
  const VARIANT_LABELS = Object.freeze({
    'cockroach-janta-party': 'Cockroach Janta Party',
    'south-park': 'South Park',
    'gruppe-sechs': 'Gruppe Sechs'
  });
  const SEVERITY_RANK = {CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1};
  const MODE_LABELS = {
    research: 'Deep Public-Web Research',
    computer41: 'Permissioned Pathless Computer Scan',
    cjpcontrol: 'Cockroach Authorized Local File Control',
    escapelab: 'Private Sandbox Escape Lab (Simulation Only)',
    attestor41: 'Attestor 4.1.4 Maximum',
    attestor40: 'Attestor 4.0 Maximum', attestor35: 'Attestor 3.5 Compatibility',
    attestor3: 'Attestor 3.0 Compatibility', improve: 'Verified Improved Result',
    semantic: 'Whole-program Semantics', supplychain: 'Supply-chain Center',
    repositorymemory: 'Repository Memory',
    chat: 'Chat / command', securitymax: 'Security Max', cybermayhem: 'Cybersecurity Mayhem',
    cyber: 'Cyber Sentinel', patchguard: 'Patch Guard', qualitygate: 'Quality Gate',
    rarebugs: 'Rare Bugs', workspace: 'Workspace Scan', mayhem: 'Coding Mayhem',
    attestor2: 'Attestor 2 Max', project: 'Project Brain', grade: 'Python Grade',
    nativegrade: 'Native Grade', polyglot: 'Polyglot Tiny Bugs', codepower: 'Code Power',
    refine: 'Refine', sieve: 'Sieve', codemax: 'Code Max', patch: 'Patch Forge',
    reproduce: 'Bug Reproducer', gauntlet: 'Mutation Gauntlet', factory: 'Code Factory',
    arena: 'Code Arena', darwin: 'Darwin Search', fixmemory: 'Fix Memory'
  };
  const MODE_PLACEHOLDERS = {
    research: 'Ask a non-coding research question. Online search is off until you authorize it...',
    computer41: 'No path is needed. Choose a scope and authorize this single run below.',
    cjpcontrol: 'Path to the strict CJP control request JSON supplied with the authorized local files...',
    escapelab: 'No prompt or path is accepted. Run the compiled in-memory simulation below.',
    attestor41: 'Local project or file for semantic, repair, security, and source-bound evidence...',
    attestor40: 'Local project or file for Engineering Fabric, Security Fabric, and verified evidence...',
    attestor35: 'Local project or file for symbolic, polyglot, Git, dependency, and repair evidence...',
    attestor3: 'Local project or file for Attestor 3.0 compatibility analysis...',
    improve: 'Local Python file or project: find errors and return complete improved source...',
    semantic: 'Local project for call graphs, control flow, and interprocedural data flow...',
    supplychain: 'Local project for dependency risk, SBOM, VEX, and provenance...',
    repositorymemory: 'Local project for a source-free architecture snapshot...',
    chat: 'Ask Attestor, paste a local path, or type a command…',
    securitymax: 'Local file or folder for a complete defensive review…',
    cybermayhem: 'Project folder for maximum defensive security posture…',
    cyber: 'File or folder for secrets, auth, taint, dependencies, and configuration…',
    patchguard: 'target :: candidate-file, or project :: target :: candidate-file…',
    qualitygate: 'Project folder for the release quality gate…', rarebugs: 'Python file or folder…',
    workspace: 'Workspace path for incremental multi-language analysis…',
    mayhem: 'Project folder for the maximum coding gate…', attestor2: 'Project, source file, or coding request…',
    project: 'Folder to map and explain…', grade: 'Python file or folder to grade…',
    nativegrade: 'C/C++/Assembly file or folder to grade…', polyglot: 'Native, Haskell, or Assembly path…',
    codepower: 'File, folder, or coding request…', refine: 'Python file to refine…',
    sieve: 'Coding request or Python path…', codemax: 'Python file, folder, or coding request…',
    patch: 'File path for Patch Forge…', reproduce: 'File path for Bug Reproducer…',
    gauntlet: 'Python file for Mutation Gauntlet…', factory: 'Service count from 1 to 64…',
    arena: 'No target required.', darwin: 'Search bundled payloads: graphql, jwt, xss…',
    fixmemory: 'No target required.'
  };
  const VIEW_COPY = {
    overview: ['ENGINEERING + SECURITY', 'Overview', 'Evidence-bound engineering and security posture from the latest local analysis.'],
    scan: ['ANALYSIS', 'New scan', 'Configure and monitor a bounded Attestor job.'],
    research: ['PUBLIC-WEB EVIDENCE', 'Research', 'Inspect citations, sources, disagreement signals, and coverage gaps.'],
    findings: ['EVIDENCE', 'Findings', 'Search, filter, group, and inspect remediation.'],
    attacks: ['ATTACK GRAPH', 'Attack paths', 'Trace evidence-linked source-to-sink chains.'],
    command: ['SECURITY COMMAND CENTER', 'Security command', 'Inspect evidence states, attack paths, proof gates, regressions, and authorization.'],
    improvements: ['VERIFIED REPAIR', 'Improved results', 'Review complete accepted sources and explicit refusals.'],
    compare: ['CHANGE', 'Compare scans', 'Track new, resolved, and persistent evidence.'],
    history: ['DURABLE EVIDENCE', 'Run history', 'Open or export canonical reports from the bounded local evidence store.'],
    evidence: ['TRUTH GUARD 3', 'Evidence explorer', 'Inspect exact source bindings, coverage, triage, and suppression state.']
  };
  const PROFILES = {
    quick: {limit: 4, timeout: 60}, standard: {limit: 8, timeout: 120}, deep: {limit: 50, timeout: 600}
  };

  const byId = id => document.getElementById(id);
  const elements = {
    sidebar: byId('sidebar'), sidebarBackdrop: byId('sidebarBackdrop'), menuBtn: byId('menuBtn'),
    pageEyebrow: byId('pageEyebrow'), pageTitle: byId('pageTitle'), pageDescription: byId('pageDescription'),
    themeBtn: byId('themeBtn'), serverDot: byId('serverDot'), connectionLabel: byId('connectionLabel'),
    catalogCapacity: byId('catalogCapacity'), installedRules: byId('installedRules'),
    versionSelect: byId('versionSelect'), detectorPath: byId('detectorPath'), modeLabel: byId('modeLabel'),
    resultVariantLabel: byId('resultVariantLabel'),
    scanForm: byId('scanForm'), prompt: byId('prompt'), targetHint: byId('targetHint'), scanMode: byId('scanMode'),
    researchControls: byId('researchControls'), researchOnline: byId('researchOnline'),
    researchFetchPages: byId('researchFetchPages'),
    computerControls: byId('computerControls'), computerAuthorized: byId('computerAuthorized'),
    computerScope: byId('computerScope'), computerMaxProjects: byId('computerMaxProjects'),
    computerImprove: byId('computerImprove'),
    cjpControls: byId('cjpControls'), cjpPermissionConfirmed: byId('cjpPermissionConfirmed'),
    cjpApply: byId('cjpApply'), cjpApplyConfirmed: byId('cjpApplyConfirmed'),
    cjpPreviewEvidence: byId('cjpPreviewEvidence'),
    escapeLabControls: byId('escapeLabControls'),
    blindArenaStatus: byId('blindArenaStatus'), blindArenaObjective: byId('blindArenaObjective'),
    blindArenaEpisodes: byId('blindArenaEpisodes'), blindArenaActions: byId('blindArenaActions'),
    blindArenaFrontier: byId('blindArenaFrontier'), blindArenaReason: byId('blindArenaReason'),
    blindArenaReportProof: byId('blindArenaReportProof'), blindArenaEscapeProof: byId('blindArenaEscapeProof'),
    blindArenaStartBtn: byId('blindArenaStartBtn'), blindArenaStatusBtn: byId('blindArenaStatusBtn'),
    blindArenaCancelBtn: byId('blindArenaCancelBtn'), blindArenaResetBtn: byId('blindArenaResetBtn'),
    variantControls: byId('variantControls'), variantSelect: byId('variantSelect'),
    variantHint: byId('variantHint'), cjpSatire: byId('cjpSatire'),
    requestProfileControls: byId('requestProfileControls'),
    limitField: byId('limitField'), timeoutField: byId('timeoutField'),
    limitInput: byId('limitInput'), timeoutInput: byId('timeoutInput'), responseStyle: byId('responseStyle'),
    sendBtn: byId('sendBtn'), cancelBtn: byId('cancelBtn'), jobState: byId('jobState'),
    jobDetail: byId('jobDetail'), jobProgress: byId('jobProgress'), liveElapsed: byId('liveElapsed'),
    scanError: byId('scanError'), resultSearch: byId('resultSearch'), severityFilter: byId('severityFilter'),
    sortSelect: byId('sortSelect'), groupSelect: byId('groupSelect'), pageSize: byId('pageSize'),
    findingList: byId('findingList'), findingsEmpty: byId('findingsEmpty'), resultCount: byId('resultCount'),
    findingsPagination: byId('findingsPagination'), pageLabel: byId('pageLabel'),
    prevPageBtn: byId('prevPageBtn'), nextPageBtn: byId('nextPageBtn'), navFindingCount: byId('navFindingCount'),
    navAttackCount: byId('navAttackCount'), navImprovementCount: byId('navImprovementCount'),
    attackPathMetric: byId('attackPathMetric'), improvementMetric: byId('improvementMetric'),
    truthGuardMetric: byId('truthGuardMetric'), truthGuardDetail: byId('truthGuardDetail'),
    calibrationMetric: byId('calibrationMetric'), calibrationDetail: byId('calibrationDetail'),
    fabricMetric: byId('fabricMetric'), fabricDetail: byId('fabricDetail'),
    evidenceMetric: byId('evidenceMetric'), evidenceDetail: byId('evidenceDetail'),
    engineeringMetric: byId('engineeringMetric'), engineeringMetricDetail: byId('engineeringMetricDetail'),
    securityFabricMetric: byId('securityFabricMetric'), securityFabricMetricDetail: byId('securityFabricMetricDetail'),
    engineeringSummary: byId('engineeringSummary'), engineeringStatus: byId('engineeringStatus'),
    engineeringEvidenceBadge: byId('engineeringEvidenceBadge'), engineeringCoverageBadge: byId('engineeringCoverageBadge'),
    engineeringVerificationBadge: byId('engineeringVerificationBadge'), engineeringEvidenceCount: byId('engineeringEvidenceCount'),
    engineeringGapCount: byId('engineeringGapCount'), engineeringVerifiedCount: byId('engineeringVerifiedCount'),
    engineeringCapabilities: byId('engineeringCapabilities'), engineeringLimitations: byId('engineeringLimitations'),
    securityFabricSummary: byId('securityFabricSummary'),
    securityFabricStatus: byId('securityFabricStatus'), securityFabricEvidenceBadge: byId('securityFabricEvidenceBadge'),
    securityFabricCoverageBadge: byId('securityFabricCoverageBadge'), securityFabricVerificationBadge: byId('securityFabricVerificationBadge'),
    securityFabricEvidenceCount: byId('securityFabricEvidenceCount'), securityFabricGapCount: byId('securityFabricGapCount'),
    securityFabricVerifiedCount: byId('securityFabricVerifiedCount'), securityFabricCapabilities: byId('securityFabricCapabilities'),
    securityFabricLimitations: byId('securityFabricLimitations'),
    symbolicState: byId('symbolicState'), symbolicDetail: byId('symbolicDetail'),
    polyglotState: byId('polyglotState'), polyglotDetail: byId('polyglotDetail'),
    dependencyState: byId('dependencyState'), dependencyDetail: byId('dependencyDetail'),
    gitState: byId('gitState'), gitDetail: byId('gitDetail'),
    attackPathList: byId('attackPathList'), attackPathEmpty: byId('attackPathEmpty'),
    attackPathCount: byId('attackPathCount'), improvementList: byId('improvementList'),
    commandStatus: byId('commandStatus'), commandCenterGrid: byId('commandCenterGrid'),
    commandMetrics: byId('commandMetrics'), commandClaimStates: byId('commandClaimStates'),
    commandAttackPaths: byId('commandAttackPaths'), commandGaps: byId('commandGaps'),
    commandRepair: byId('commandRepair'), commandRegression: byId('commandRegression'),
    commandApproval: byId('commandApproval'), commandEmpty: byId('commandEmpty'),
    improvementEmpty: byId('improvementEmpty'), verifiedImprovementCount: byId('verifiedImprovementCount'),
    riskScore: byId('riskScore'), riskLabel: byId('riskLabel'), riskRingValue: byId('riskRingValue'),
    totalFindings: byId('totalFindings'), criticalCount: byId('criticalCount'), highCount: byId('highCount'),
    mediumCount: byId('mediumCount'), lowCount: byId('lowCount'), lastScanLabel: byId('lastScanLabel'),
    postureStatus: byId('postureStatus'), overviewEmpty: byId('overviewEmpty'), overviewRecent: byId('overviewRecent'),
    rawOutput: byId('rawOutput'), rawMeta: byId('rawMeta'), historySelect: byId('historySelect'),
    historyList: byId('historyList'), historyEmpty: byId('historyEmpty'), compareA: byId('compareA'),
    compareB: byId('compareB'), compareEmpty: byId('compareEmpty'), compareNotice: byId('compareNotice'), diffPanel: byId('diffPanel'),
    compareSummary: byId('compareSummary'), diffOutput: byId('diffOutput'), drawer: byId('findingDrawer'),
    drawerSeverity: byId('drawerSeverity'), drawerRule: byId('drawerRule'), drawerLocation: byId('drawerLocation'),
    drawerMessage: byId('drawerMessage'), drawerEvidence: byId('drawerEvidence'), drawerFix: byId('drawerFix'),
    toastRegion: byId('toastRegion'), evidenceExplorerStatus: byId('evidenceExplorerStatus'),
    evidenceExplorerSummary: byId('evidenceExplorerSummary'), evidenceExplorerList: byId('evidenceExplorerList'),
    evidenceExplorerEmpty: byId('evidenceExplorerEmpty'), drawerFingerprint: byId('drawerFingerprint'),
    researchStatus: byId('researchStatus'), researchQuestion: byId('researchQuestion'),
    researchSummary: byId('researchSummary'), researchExecution: byId('researchExecution'),
    researchResults: byId('researchResults'), researchClaims: byId('researchClaims'),
    researchSources: byId('researchSources'), researchDisagreements: byId('researchDisagreements'),
    researchCoverage: byId('researchCoverage'), researchEmpty: byId('researchEmpty'),
    triageOwner: byId('triageOwner'), triageState: byId('triageState'), triageReason: byId('triageReason'),
    suppressionExpiry: byId('suppressionExpiry'), annotationStatus: byId('annotationStatus')
  };

  const state = {
    view: 'overview', token: '', versions: {}, variants: {}, detector: '', running: false, jobId: '',
    request: null, record: null, structured: null, research: null, findings: [], attackPaths: [], improvements: [],
    verifiedVariant: null, parseTruncated: false, page: 1,
    history: [], annotations: new Map(), selectedFinding: null, drawerReturnFocus: null,
    blindArenaPollTimer: 0, blindArenaSnapshot: null
  };

  function safeInteger(value, fallback, minimum, maximum) {
    const parsed = Number.parseInt(value, 10);
    return Number.isFinite(parsed) ? Math.max(minimum, Math.min(maximum, parsed)) : fallback;
  }

  function delay(milliseconds) { return new Promise(resolve => setTimeout(resolve, milliseconds)); }

  function toast(message) {
    const item = document.createElement('div');
    item.className = 'toast'; item.textContent = message;
    elements.toastRegion.appendChild(item);
    window.setTimeout(() => item.remove(), 3600);
  }

  function setView(name, focus = false) {
    if (!VIEW_COPY[name]) return;
    state.view = name;
    document.querySelectorAll('[data-view-panel]').forEach(panel => {
      const active = panel.dataset.viewPanel === name;
      panel.hidden = !active; panel.classList.toggle('active', active);
    });
    document.querySelectorAll('.nav-item[data-view]').forEach(button => {
      const active = button.dataset.view === name;
      button.classList.toggle('active', active);
      if (active) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
    });
    const [eyebrow, title, description] = VIEW_COPY[name];
    elements.pageEyebrow.textContent = eyebrow; elements.pageTitle.textContent = title;
    elements.pageDescription.textContent = description;
    closeSidebar();
    if (focus) byId('mainContent').focus();
  }

  function openSidebar() {
    elements.sidebar.classList.add('open'); elements.sidebarBackdrop.hidden = false;
    elements.menuBtn.setAttribute('aria-expanded', 'true');
    const first = elements.sidebar.querySelector('.nav-item'); if (first) first.focus();
  }

  function closeSidebar() {
    elements.sidebar.classList.remove('open'); elements.sidebarBackdrop.hidden = true;
    elements.menuBtn.setAttribute('aria-expanded', 'false');
  }

  function applyTheme(theme) {
    const chosen = theme === 'light' ? 'light' : 'dark';
    document.body.dataset.theme = chosen;
    elements.themeBtn.textContent = 'Theme: ' + chosen;
    elements.themeBtn.setAttribute('aria-label', 'Switch to ' + (chosen === 'dark' ? 'light' : 'dark') + ' theme');
    try { localStorage.setItem('attestor-theme', chosen); } catch (_error) { /* storage is optional */ }
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (state.token) headers.set('X-Attestor-Token', state.token);
    if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    const response = await fetch(path, {...options, headers, credentials: 'same-origin'});
    let data;
    try { data = await response.json(); }
    catch (_error) { throw new Error('The local server returned a non-JSON response (' + response.status + ').'); }
    if (!response.ok) throw new Error(data.output || ('HTTP ' + response.status));
    return data;
  }

  function severityClass(severity) { return (severity || 'INFO').toLowerCase(); }
  function bucketSeverity(severity) { return severity === 'INFO' ? 'LOW' : severity; }

  function findingHeader(line) {
    let match = line.match(/^(.+?):(\d+):\s*\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s+([\w.:-]+)(?:\s*[—-]\s*(.*))?$/);
    if (match) return {path: match[1], line: Number(match[2]), severity: match[3], rule: match[4], message: match[5] || ''};
    match = line.match(/^\s*[-*]?\s*\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s+(.+?):(\d+)\s+([\w.:-]+)(?:\s+\([^)]*\))?(?:\s*[—-]\s*(.*))?$/);
    if (match) return {path: match[2], line: Number(match[3]), severity: match[1], rule: match[4], message: match[5] || ''};
    match = line.match(/^\s*\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s+([\w.:-]+)\s+at\s+(.+?):(\d+)(?:\s*[—-]\s*(.*))?$/i);
    if (match) return {path: match[3], line: Number(match[4]), severity: match[1].toUpperCase(), rule: match[2], message: match[5] || ''};
    return null;
  }

  function safeText(value, fallback = '', limit = 8000) {
    const text = value === null || value === undefined ? String(fallback || '') : String(value);
    const maximum = Number.isSafeInteger(limit) ? Math.max(0, Math.min(1000000, limit)) : 8000;
    let output = '';
    for (const character of text) {
      const code = character.codePointAt(0);
      const bidi = code === 0x061c || code === 0x200e || code === 0x200f ||
        (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069);
      const token = code < 0x20 || (code >= 0x7f && code <= 0x9f) || bidi ?
        '\\u' + code.toString(16).padStart(4, '0') : character;
      if (output.length + token.length > maximum) break;
      output += token;
    }
    return output;
  }

  function isObject(value) { return Boolean(value) && typeof value === 'object' && !Array.isArray(value); }

  function normalizedVariantDescriptor(value, requireCatalogMatch = false) {
    if (!isObject(value)) return null;
    const slug = typeof value.slug === 'string' ? value.slug : '';
    const expectedName = VARIANT_LABELS[slug];
    const language = isObject(value.response_language) ?
      value.response_language : null;
    const c3Expected = slug === 'cockroach-janta-party';
    if (!expectedName || value.display_name !== expectedName ||
        typeof value.profile_sha256 !== 'string' ||
        !/^[0-9a-f]{64}$/.test(value.profile_sha256) || !language ||
        language.schema !== 'attestor-response-language/4.1.4' ||
        language.tier !== (c3Expected ? 'C3' : 'existing') ||
        language.label !== (c3Expected ?
          'C3 (Attestor-specific; not CEFR)' : 'Existing response behavior') ||
        language.attestor_specific_tier !== c3Expected ||
        language.official_cefr_claim !== false ||
        language.renderer !== (c3Expected ?
          'c3-evidence-locked/4.1.4' : 'response41-existing/4.1.3') ||
        language.request_override_allowed !== false) return null;
    const timeout = safeInteger(value.timeout_seconds, 0, 1, 600);
    const workerTimeout = safeInteger(
      value.worker_timeout_seconds, 0, 1, 180);
    const outputBytes = safeInteger(
      value.max_output_bytes, 0, 1024 * 1024, MAX_STRUCTURED_OUTPUT);
    if (!timeout || !workerTimeout || workerTimeout > timeout || !outputBytes) return null;
    const catalog = state.variants[slug];
    if (requireCatalogMatch && (!catalog ||
        catalog.profile_sha256 !== value.profile_sha256)) return null;
    return {slug, displayName: expectedName, mode: safeText(value.mode, '', 40),
      responseLanguage: {
        tier: language.tier, label: language.label,
        attestorSpecificTier: language.attestor_specific_tier,
        officialCefrClaim: language.official_cefr_claim,
        renderer: language.renderer
      },
      profile_sha256: value.profile_sha256, timeoutSeconds: timeout,
      workerTimeoutSeconds: workerTimeout,
      maxOutputBytes: outputBytes};
  }

  function installVariantCatalog(values, defaultSlug) {
    const accepted = {};
    (Array.isArray(values) ? values : []).forEach(value => {
      const profile = normalizedVariantDescriptor(value);
      if (profile) accepted[profile.slug] = profile;
    });
    state.variants = accepted;
    elements.variantSelect.replaceChildren();
    Object.keys(VARIANT_LABELS).forEach(slug => {
      const profile = accepted[slug];
      if (!profile) return;
      const tier = profile.mode ? ' · ' + profile.mode : '';
      const language = profile.responseLanguage.tier === 'C3' ?
        ' · C3' : '';
      elements.variantSelect.appendChild(
        new Option(profile.displayName + tier + language, slug));
    });
    const selectedDefault = defaultSlug === DEFAULT_VARIANT &&
      accepted[defaultSlug] ? defaultSlug : DEFAULT_VARIANT;
    elements.variantSelect.value = accepted[selectedDefault] ?
      selectedDefault : Object.keys(accepted)[0] || '';
    updateVariantHint();
  }

  function verifiedResultVariant(value) {
    return normalizedVariantDescriptor(value, true);
  }

  function verifiedVariantLabel(profile) {
    if (!profile) return '';
    const language = profile.responseLanguage &&
      profile.responseLanguage.tier === 'C3' ?
      ' · ' + profile.responseLanguage.label : '';
    return profile.displayName + language;
  }

  function firstDefined(values, fallback) {
    const value = values.find(item => item !== undefined && item !== null && item !== '');
    return value === undefined ? fallback : value;
  }

  function boundedCollectionSize(value) {
    if (Array.isArray(value)) return Math.min(value.length, 1000000);
    if (isObject(value)) return Math.min(Object.keys(value).length, 1000000);
    return 0;
  }

  function fabricCapabilities(raw) {
    let source = firstDefined([
      raw.capabilities, raw.components, raw.stages, raw.checks, raw.controls, raw.security_controls
    ], []);
    if ((Array.isArray(source) && !source.length) || (!Array.isArray(source) && !isObject(source))) {
      const sections = [
        ['Engineering checks', raw.engineering_checks], ['Architecture map', raw.architecture],
        ['Impact analysis', raw.impact], ['Test plan', raw.test_plan],
        ['Refactor plan', raw.refactor_plan], ['Debug plan', raw.debug_plan],
        ['Patch workflow', raw.patch_workflow], ['Threat model', raw.threat_model],
        ['Supply chain', raw.supply_chain], ['Remediation plan', raw.remediation_plan]
      ];
      source = sections.filter(([_label, value]) => Array.isArray(value) || isObject(value)).map(([label, value]) => ({
        name: label, status: isObject(value) ? firstDefined([value.status, value.state], '') : value.length + ' item(s)'
      }));
    }
    const rows = Array.isArray(source) ? source : isObject(source) ? Object.keys(source).map(key => {
      const value = source[key];
      return isObject(value) ? {...value, name: value.name || key} : {name: key, status: value};
    }) : [];
    return rows.slice(0, 8).map(value => {
      if (typeof value === 'string' || typeof value === 'number') return safeText(value, '', 160);
      if (!isObject(value)) return '';
      const name = safeText(firstDefined([value.name, value.title, value.id, value.kind, value.rule, value.control], 'Observed capability'), '', 120);
      const status = safeText(firstDefined([value.status, value.state, value.outcome], ''), '', 40);
      return name + (status ? ' · ' + status : '');
    }).filter(Boolean);
  }

  function fabricLimitations(raw, coverageObject) {
    const rows = [];
    let omitted = 0;
    const seen = new Set();
    const add = value => {
      let label = '';
      if (typeof value === 'string' || typeof value === 'number') label = safeText(value, '', 500).trim();
      else if (isObject(value)) {
        const message = safeText(firstDefined([
          value.message, value.detail, value.reason, value.description, value.kind
        ], 'Reported structured coverage limitation'), '', 420).trim();
        const path = safeText(value.path, '', 160).trim();
        label = message + (path ? ' (' + path + ')' : '');
      }
      if (!label || seen.has(label)) return;
      seen.add(label);
      if (rows.length < MAX_FABRIC_LIMITATIONS) rows.push(label);
      else omitted += 1;
    };
    [coverageObject.gaps, coverageObject.limitations, raw.limitations,
      raw.assurance_notes, Array.isArray(raw.assurance) ? raw.assurance : []].forEach(source => {
      const sourceRows = Array.isArray(source) ? source : [];
      sourceRows.slice(0, 1000).forEach(add);
      if (sourceRows.length > 1000) omitted += sourceRows.length - 1000;
    });
    if (omitted > 0) {
      const replaced = rows.length === MAX_FABRIC_LIMITATIONS ? 1 : 0;
      const notice = (omitted + replaced) + ' additional reported limitation(s) omitted by the UI boundary.';
      if (replaced) rows[MAX_FABRIC_LIMITATIONS - 1] = notice;
      else rows.push(notice);
    }
    return rows;
  }

  function normalizedFabric(raw, name) {
    if (!isObject(raw)) return null;
    const summaryObject = isObject(raw.summary) ? raw.summary : {};
    const engineeringChecks = isObject(raw.engineering_checks) ? raw.engineering_checks : {};
    const engineeringCheckSummary = isObject(engineeringChecks.summary) ? engineeringChecks.summary : {};
    const coverageObject = isObject(raw.coverage) ? raw.coverage : {};
    const executionObject = isObject(raw.execution) ? raw.execution : {};
    const verificationObject = isObject(raw.verification) ? raw.verification :
      isObject(raw.verification_summary) ? raw.verification_summary :
      isObject(executionObject.verification) ? executionObject.verification : executionObject;
    const evidenceObject = isObject(raw.evidence) ? raw.evidence : {};
    const status = safeText(firstDefined([
      raw.status, raw.state, raw.outcome, summaryObject.status, summaryObject.state
    ], 'reported'), 'reported', 60);
    const summaryValue = typeof raw.summary === 'string' ? raw.summary : firstDefined([
      raw.description, raw.message, summaryObject.description, summaryObject.message, summaryObject.text
    ], name + ' report loaded; inspect its evidence states below.');
    const evidenceDerived = Math.max(
      boundedCollectionSize(raw.evidence), boundedCollectionSize(raw.evidence_catalog),
      boundedCollectionSize(raw.evidence_entries), boundedCollectionSize(evidenceObject.entries),
      boundedCollectionSize(raw.findings), boundedCollectionSize(engineeringChecks.issues)
    );
    const hasEvidenceSurface = Array.isArray(raw.findings) || Array.isArray(engineeringChecks.issues) ||
      Array.isArray(raw.evidence) || Array.isArray(raw.evidence_catalog) || isObject(raw.evidence);
    const evidenceCount = safeInteger(firstDefined([
      raw.evidence_count, raw.evidence_catalog_size, summaryObject.evidence_count,
      summaryObject.evidence, summaryObject.findings, summaryObject.engineering_findings,
      summaryObject.security_fabric_findings, engineeringCheckSummary.total,
      evidenceObject.count, evidenceObject.total
    ], evidenceDerived), evidenceDerived, 0, 1000000);
    const evidenceStatus = safeText(firstDefined([
      raw.evidence_status, evidenceObject.status, evidenceObject.state
    ], evidenceCount || hasEvidenceSurface ? 'present' : 'unavailable'),
    evidenceCount || hasEvidenceSurface ? 'present' : 'unavailable', 60);
    const gaps = firstDefined([coverageObject.gaps, raw.coverage_gaps, raw.gaps], []);
    const gapDerived = boundedCollectionSize(gaps);
    const gapCount = safeInteger(firstDefined([
      raw.gap_count, raw.coverage_gap_count, coverageObject.gap_count,
      coverageObject.gaps_count, coverageObject.missing
    ], gapDerived), gapDerived, 0, 1000000);
    let coverageStatus = firstDefined([
      raw.coverage_status, coverageObject.status, coverageObject.state,
      typeof raw.coverage === 'string' ? raw.coverage : undefined
    ], 'unknown');
    if (coverageObject.complete === true) coverageStatus = 'complete';
    else if (coverageObject.complete === false && coverageStatus === 'unknown') coverageStatus = 'partial';
    if (coverageObject.percentage !== undefined && coverageStatus === 'unknown') {
      coverageStatus = safeInteger(coverageObject.percentage, 0, 0, 100) + '% reported';
    }
    const verificationRows = firstDefined([
      verificationObject.gates, verificationObject.checks, raw.verification_gates, raw.verified_gates
    ], []);
    const verifiedDerived = Array.isArray(verificationRows) ? verificationRows.slice(0, 1000000).filter(row => {
      if (row === true) return true;
      if (!isObject(row)) return false;
      const rowStatus = safeText(firstDefined([row.status, row.state, row.outcome], ''), '', 30).toLowerCase();
      return row.verified === true || row.passed === true || ['verified', 'passed', 'complete'].includes(rowStatus);
    }).length : 0;
    const verifiedCount = safeInteger(firstDefined([
      raw.verified_count, raw.verified_gates_count, verificationObject.verified_count,
      verificationObject.passed, verificationObject.passed_count, executionObject.verified_count
    ], verifiedDerived), verifiedDerived, 0, 1000000);
    let verificationStatus = firstDefined([
      raw.verification_status, verificationObject.status, verificationObject.state,
      typeof raw.verification === 'string' ? raw.verification : undefined
    ], 'unknown');
    if (verificationObject.verified === true || raw.verified === true) verificationStatus = 'verified';
    else if ((verificationObject.verified === false || raw.verified === false) && verificationStatus === 'unknown') verificationStatus = 'not verified';
    return {
      status, summary: safeText(summaryValue, name + ' report loaded.', 700),
      evidenceCount, evidenceStatus, coverageStatus: safeText(coverageStatus, 'unknown', 60), gapCount,
      verificationStatus: safeText(verificationStatus, 'unknown', 60), verifiedCount,
      capabilities: fabricCapabilities(raw), limitations: fabricLimitations(raw, coverageObject)
    };
  }

  function normalizedFinding(raw, index, defaultSource = 'Attestor') {
    if (!raw || typeof raw !== 'object') return null;
    const rule = safeText(raw.rule || raw.rule_id || raw.ruleId, 'finding', 300);
    const severityValue = safeText(raw.severity, 'MEDIUM', 20).toUpperCase();
    const severity = Object.prototype.hasOwnProperty.call(SEVERITY_RANK, severityValue) ? severityValue : 'MEDIUM';
    const line = safeInteger(raw.line, 1, 1, 1000000000);
    const path = safeText(raw.path || raw.relative_path, 'workspace', 4000);
    const projectRoot = safeText(raw.project_root, '', 4000);
    const sourceEvidence = isObject(raw.source_evidence) ? raw.source_evidence : {};
    const evidence = typeof raw.evidence === 'string' ? raw.evidence :
      raw.evidence === undefined ? (Object.keys(sourceEvidence).length ? JSON.stringify(sourceEvidence, null, 2) : '') :
        JSON.stringify(raw.evidence, null, 2);
    const finding = {
      rule, severity, line, path, projectRoot,
      message: safeText(raw.message || raw.detail, 'Review the reported evidence at this location.'),
      evidence: safeText(evidence, rule + ' at ' + path + ':' + line, 32000),
      fix: safeText(raw.fix || raw.remediation, 'Review the finding and apply the narrowest verified remediation.'),
      confidence: raw.confidence,
      source: safeText(raw.source, defaultSource, 200), sourceEvidence,
      evidenceState: safeText(sourceEvidence.state, Object.keys(sourceEvidence).length ? 'unknown' : 'unavailable', 40)
    };
    finding.id = safeText(raw.fingerprint, '', 200) || safeText(sourceEvidence.evidence_sha256, '', 128) ||
      rule + '|' + projectRoot + '|' + path + '|' + line + '|' + index;
    return finding;
  }

  function normalizedImprovement(value, index) {
    const raw = isObject(value) ? value : {};
    const paths = (Array.isArray(raw.paths) ? raw.paths : []).slice(0, 64)
      .map(item => safeText(item, '', 4000)).filter(Boolean);
    const projectRoot = safeText(raw.project_root, '', 4000);
    const hasAcceptance = Object.prototype.hasOwnProperty.call(raw, 'accepted');
    const reviewOnly = raw.review_only === true || (!hasAcceptance && Boolean(projectRoot)) ||
      (!hasAcceptance && safeText(raw.status, '', 80).toLowerCase() === 'review-only');
    const accepted = !reviewOnly && raw.accepted === true;
    return {id: safeText(raw.id || raw.target, 'result-' + index, 4000) + '|' + projectRoot + '|' + index,
      target: safeText(raw.target || paths[0] || raw.rule || raw.id, 'workspace', 4000),
      accepted, reviewOnly, projectRoot, paths,
      summary: safeText(raw.summary || raw.message || raw.fix, '', 4000),
      rule: safeText(raw.rule, '', 300), digest: safeText(raw.digest || raw.candidate_sha256, '', 128),
      status: safeText(raw.status, reviewOnly ? 'review-only' : accepted ? 'verified' : 'refused', 80),
      complete: raw.complete === true,
      reasons: (Array.isArray(raw.reasons) ? raw.reasons : []).slice(0, 50)
        .map(item => safeText(item, '', 4000)).filter(Boolean),
      diff: safeText(raw.diff, '', 2000000),
      improvedSource: accepted ? safeText(raw.improved_source, '', 3000000) : '',
      withheld: raw.improved_source_withheld === true,
      withheldReason: safeText(raw.withheld_reason, '', 4000),
      resolved: safeInteger(raw.resolved_count, 0, 0, 1000000),
      remaining: safeInteger(raw.remaining_count, 0, 0, 1000000)};
  }

  function triState(value) {
    return value === true ? true : value === false ? false : null;
  }

  function normalizedHistoryVerification(value) {
    if (!isObject(value)) return null;
    return {applicable: value.applicable === true, verified: value.verified === true,
      fresh: triState(value.fresh), status: safeText(value.status, 'unknown', 80).toLowerCase()};
  }

  function historicalTruthPresentation(truth) {
    const history = truth && truth.historyVerification;
    if (!history || !history.applicable || (history.verified && history.fresh === true)) return null;
    const stale = history.status === 'stale';
    return {label: stale ? 'Stale historical evidence' : 'Unverified historical evidence',
      detail: stale ? 'Stored evidence is historical and no longer matches current source. Re-run analysis.' :
        'Stored evidence could not be freshly verified. Re-run analysis.'};
  }

  function normalizedResearch(document) {
    if (!isObject(document) || document.schema !== 'attestor-research/4.1') return null;
    const answer = isObject(document.answer) ? document.answer : {};
    const summary = isObject(document.summary) ? document.summary : {};
    const coverageRaw = isObject(document.coverage) ? document.coverage : {};
    const executionRaw = isObject(document.execution) ? document.execution : {};
    const sources = (Array.isArray(document.sources) ? document.sources : []).slice(0, MAX_RESEARCH_SOURCES).map((value, index) => {
      const raw = isObject(value) ? value : {};
      const fetch = isObject(raw.fetch) ? raw.fetch : {};
      return {
        id: safeText(raw.source_id, 'S' + (index + 1), 80),
        url: safeText(raw.url, '', 4000), title: safeText(raw.title, 'Untitled public source', 1000),
        description: safeText(raw.description, '', 4000), published: safeText(raw.published, '', 120),
        sourceKind: safeText(raw.source_kind, 'public web', 80),
        fetchStatus: safeText(fetch.status, 'not-requested', 80)
      };
    });
    const claims = (Array.isArray(answer.claims) ? answer.claims : []).slice(0, MAX_RESEARCH_CLAIMS).map(value => {
      const raw = isObject(value) ? value : {};
      return {
        text: safeText(raw.text, '', 5000), support: safeText(raw.support, 'reported evidence', 100),
        state: safeText(raw.state, 'evidence state unavailable', 160),
        citations: (Array.isArray(raw.citations) ? raw.citations : []).slice(0, 20).map(item => safeText(item, '', 80)).filter(Boolean),
        evidenceIds: (Array.isArray(raw.evidence_ids) ? raw.evidence_ids : []).slice(0, 20).map(item => safeText(item, '', 120)).filter(Boolean)
      };
    }).filter(row => row.text);
    const disagreements = (Array.isArray(document.disagreements) ? document.disagreements : []).slice(0, 20).map(value => {
      const raw = isObject(value) ? value : {};
      return {
        id: safeText(raw.id, 'possible-disagreement', 120), kind: safeText(raw.kind, 'unspecified', 80),
        state: safeText(raw.state, 'possible-disagreement-not-adjudicated', 160),
        left: safeText(raw.left_evidence_id, '', 120), right: safeText(raw.right_evidence_id, '', 120),
        sharedTerms: (Array.isArray(raw.shared_terms) ? raw.shared_terms : []).slice(0, 20).map(item => safeText(item, '', 80)).filter(Boolean)
      };
    });
    const gapRows = [
      ...(Array.isArray(coverageRaw.gaps) ? coverageRaw.gaps : []),
      ...(Array.isArray(answer.gaps) ? answer.gaps : [])
    ].map(item => safeText(item, '', 1000).trim()).filter(Boolean);
    const gaps = [...new Set(gapRows)].slice(0, MAX_RESEARCH_GAPS);
    const limitations = (Array.isArray(answer.limitations) ? answer.limitations : []).slice(0, 20)
      .map(item => safeText(item, '', 1000).trim()).filter(Boolean);
    return {
      status: safeText(document.status, 'unknown', 100), question: safeText(document.question, '', 16000),
      claims, sources, disagreements, gaps, limitations, abstained: answer.abstained === true,
      coverage: {complete: coverageRaw.complete === true && gaps.length === 0,
        provider: safeText(coverageRaw.provider, '', 120),
        pageFetchEnabled: triState(coverageRaw.page_fetch_enabled),
        robotsRespected: triState(coverageRaw.robots_respected)},
      execution: {networkAccessed: triState(executionRaw.network_accessed),
        privateNetworkAccessed: triState(executionRaw.private_network_accessed),
        credentialsBypassed: triState(executionRaw.credentials_bypassed),
        formsSubmitted: triState(executionRaw.forms_submitted), darkWebAccessed: triState(executionRaw.dark_web_accessed),
        providerKeyReported: triState(executionRaw.provider_key_reported)},
      summary: {queries: safeInteger(summary.queries, 0, 0, 1000),
        sources: safeInteger(summary.sources, sources.length, 0, 1000000),
        pagesFetched: safeInteger(summary.pages_fetched, 0, 0, 1000000),
        claims: safeInteger(summary.claims, claims.length, 0, 1000000),
        disagreements: safeInteger(summary.possible_disagreements, disagreements.length, 0, 1000000)}
    };
  }

  function normalizedCommandCenter(documentValue) {
    const raw = isObject(documentValue.security_command_center_413) ?
      documentValue.security_command_center_413 :
      isObject(documentValue.security_validation_413) &&
      isObject(documentValue.security_validation_413.command_center) ?
        documentValue.security_validation_413.command_center : null;
    if (!raw) return null;
    if (raw.schema !== 'attestor-security-command-center/4.1' ||
        !['4.1.3', '4.1.4'].includes(raw.version) ||
        typeof raw.report_sha256 !== 'string' ||
        !/^[0-9a-f]{64}$/.test(raw.report_sha256)) return null;
    const metricsRaw = isObject(raw.metrics) ? raw.metrics : {};
    const severityRaw = isObject(metricsRaw.severity) ? metricsRaw.severity : {};
    const claimsRaw = isObject(metricsRaw.claim_states) ? metricsRaw.claim_states : {};
    const claims = {};
    ['proven', 'inferred', 'unverified', 'unavailable'].forEach(name => {
      claims[name] = safeInteger(claimsRaw[name], 0, 0, 1000000);
    });
    const attackPaths = (Array.isArray(raw.attack_paths) ? raw.attack_paths : []).slice(0, 100)
      .filter(isObject).map((row, index) => ({
        id: safeText(row.id || row.path_id, 'path-' + index, 160),
        title: safeText(row.title || row.summary, 'Evidence-linked attack path', 1000),
        exploitability: safeText(row.exploitability || row.confidence, 'unverified', 120),
        evidenceState: ['proven', 'inferred', 'unverified', 'unavailable'].includes(row.evidence_state) ?
          row.evidence_state : 'unverified',
        reportedEvidenceState: ['proven', 'inferred', 'unverified', 'unavailable'].includes(row.evidence_state) ?
          row.evidence_state : 'unverified'
      }));
    return {
      status: safeText(raw.status, 'unavailable', 80),
      findings: safeInteger(metricsRaw.findings, 0, 0, 1000000),
      attackPathCount: safeInteger(metricsRaw.attack_paths, attackPaths.length, 0, 1000000),
      gapCount: safeInteger(metricsRaw.coverage_gaps, 0, 0, 1000000),
      severity: {
        critical: safeInteger(severityRaw.CRITICAL, 0, 0, 1000000),
        high: safeInteger(severityRaw.HIGH, 0, 0, 1000000),
        medium: safeInteger(severityRaw.MEDIUM, 0, 0, 1000000),
        low: safeInteger(severityRaw.LOW, 0, 0, 1000000),
        info: safeInteger(severityRaw.INFO, 0, 0, 1000000)
      },
      claims: {...claims}, reportedClaims: {...claims}, attackPaths,
      gaps: (Array.isArray(raw.coverage_gaps) ? raw.coverage_gaps : []).slice(0, 100)
        .map(value => safeText(isObject(value) ? value.message || value.reason : value, '', 1000))
        .filter(Boolean),
      repairStatus: safeText(raw.repair_status, 'not-started', 120),
      repairProofState: safeText(raw.repair_proof_state, 'unavailable', 80),
      regressionStatus: safeText(raw.regression_status, 'not-compared', 120),
      sourceReports: isObject(raw.source_reports) ? {
        repair: raw.source_reports.repair_pipeline_integrity_verified === true,
        regression: raw.source_reports.regression_integrity_verified === true,
        ledger: raw.source_reports.claim_ledger_integrity_verified === true
      } : {repair: false, regression: false, ledger: false},
      automaticApply: triState(raw.automatic_apply),
      permissionRetained: triState(raw.permission_retained),
      rawSecretsPresent: triState(raw.raw_secret_values_present),
      integrityVerified: false,
      reportDigest: raw.report_sha256
    };
  }

  function bindCommandCenterIntegrity(center, historyVerification) {
    if (!center) return;
    center.integrityVerified = Boolean(
      historyVerification && historyVerification.applicable &&
      historyVerification.verified && historyVerification.fresh === true);
    center.claims = {...center.reportedClaims};
    center.attackPaths.forEach(pathValue => {
      pathValue.evidenceState = pathValue.reportedEvidenceState;
    });
    if (!center.integrityVerified) {
      center.claims.unverified += center.claims.proven;
      center.claims.proven = 0;
      center.attackPaths.forEach(pathValue => {
        if (pathValue.evidenceState === 'proven') pathValue.evidenceState = 'unverified';
      });
    }
  }

  function parseStructuredOutput(output) {
    const text = String(output || '').trim();
    if (!text.startsWith('{') || text.length > MAX_STRUCTURED_OUTPUT) return null;
    let document;
    try { document = JSON.parse(text); }
    catch (_error) { return null; }
    if (!document || typeof document !== 'object' || Array.isArray(document)) return null;
    const research = normalizedResearch(document);
    const declaredVersion = safeText(firstDefined([
      document.version, document.attestor_version, document.product_version, document.release
    ], ''), '', 40);
    const reportSource = /4\.1\.4/.test(declaredVersion) ? 'Attestor 4.1.4' : /4\.1\.3/.test(declaredVersion) ? 'Attestor 4.1.3' : /4\.1\.2/.test(declaredVersion) ? 'Attestor 4.1.2' : /4\.1/.test(declaredVersion) ? 'Attestor 4.1' : /4\.0/.test(declaredVersion) ? 'Attestor 4.0' :
      /3\.5/.test(declaredVersion) ? 'Attestor 3.5' : /3\.0/.test(declaredVersion) ? 'Attestor 3.0' : 'Attestor';
    let findingRows = Array.isArray(document.findings) ? document.findings : [];
    if (!findingRows.length && Array.isArray(document.risk_findings)) findingRows = document.risk_findings;
    const findings = findingRows.slice(0, MAX_FINDINGS).map((row, index) => normalizedFinding(row, index, reportSource)).filter(Boolean);
    const attackPaths = (Array.isArray(document.attack_paths) ? document.attack_paths : []).slice(0, 100).map((pathValue, index) => {
      const raw = pathValue && typeof pathValue === 'object' ? pathValue : {};
      const nodes = (Array.isArray(raw.nodes) ? raw.nodes : []).slice(0, 100).map(nodeValue => {
        const node = nodeValue && typeof nodeValue === 'object' ? nodeValue : {};
        return {kind: safeText(node.kind || node.type, 'step', 80), label: safeText(node.label || node.detail, 'Evidence step', 1000),
          path: safeText(node.path, '', 4000), line: safeInteger(node.line, 0, 0, 1000000000)};
      });
      return {id: safeText(raw.id, 'path-' + index, 160), title: safeText(raw.title, 'Evidence-linked attack path', 1000),
        severity: safeText(raw.severity, 'HIGH', 20).toUpperCase(), rule: safeText(raw.rule, 'attack-path', 300),
        confidence: raw.confidence, source: safeText(raw.source, reportSource, 200), nodes};
    });
    const improvements = (Array.isArray(document.improvements) ? document.improvements : [])
      .slice(0, 20).map(normalizedImprovement);
    const truthRaw = document.truth_guard3 && typeof document.truth_guard3 === 'object' ? document.truth_guard3 :
      document.truth_guard2 && typeof document.truth_guard2 === 'object' ? document.truth_guard2 :
      document.truth_guard_runtime && typeof document.truth_guard_runtime === 'object' ?
      document.truth_guard_runtime : document.truth_guard && typeof document.truth_guard === 'object' ? document.truth_guard : null;
    const truthSummary = truthRaw && truthRaw.summary && typeof truthRaw.summary === 'object' ? truthRaw.summary : {};
    const truthSignature = truthRaw && truthRaw.signature && typeof truthRaw.signature === 'object' ? truthRaw.signature : {};
    const evidenceRows = truthRaw && Array.isArray(truthRaw.finding_evidence) ? truthRaw.finding_evidence : [];
    const truthGuard = truthRaw ? {status: safeText(truthRaw.status, 'unknown', 40),
      contradictions: safeInteger(truthSummary.contradictions, 0, 0, 1000000),
      observed: safeInteger(truthSummary.observed, 0, 0, 1000000),
      derived: safeInteger(truthSummary.derived, 0, 0, 1000000),
      grounded: safeInteger(firstDefined([truthSummary.grounded, truthSummary.bound],
        safeInteger(truthSummary.observed, 0, 0, 1000000) + safeInteger(truthSummary.derived, 0, 0, 1000000)), 0, 0, 1000000),
      evidence: safeInteger(firstDefined([truthRaw.evidence_catalog_size, evidenceRows.length], 0), 0, 0, 1000000),
      truncated: truthRaw.evidence_truncated === true || truthRaw.finding_evidence_truncated === true,
      ledger: evidenceRows.slice(0, MAX_FINDINGS), gaps: Array.isArray(truthRaw.gaps) ? truthRaw.gaps.slice(0, 200) : [],
      authentication: truthSignature.algorithm === 'hmac-sha256' && ['signed', 'authenticated-shared-key'].includes(truthSignature.state) ?
        'authenticated' : 'integrity-only'} : null;
    const calibrationRaw = document.confidence_calibration_35 && typeof document.confidence_calibration_35 === 'object' ? document.confidence_calibration_35 : {};
    const fabricRaw = document.execution_fabric_35 && typeof document.execution_fabric_35 === 'object' ? document.execution_fabric_35 : {};
    const symbolicRaw = document.symbolic_35 && typeof document.symbolic_35 === 'object' ? document.symbolic_35 : {};
    const polyglotRaw = document.polyglot_ir_35 && typeof document.polyglot_ir_35 === 'object' ? document.polyglot_ir_35 : {};
    const dependencyRaw = document.supply_chain_graph_35 && typeof document.supply_chain_graph_35 === 'object' ? document.supply_chain_graph_35 : {};
    const gitRaw = document.git_intelligence_35 && typeof document.git_intelligence_35 === 'object' ? document.git_intelligence_35 : {};
    const assurance = {
      calibration: {status: safeText(calibrationRaw.status, 'not-run', 60),
        calibrated: safeInteger(calibrationRaw.calibrated_findings, 0, 0, 1000000),
        uncalibrated: safeInteger(calibrationRaw.uncalibrated_findings, 0, 0, 1000000)},
      fabric: {status: safeText(fabricRaw.status, 'not-run', 60),
        eligible: Array.isArray(fabricRaw.eligible_runtimes) ? fabricRaw.eligible_runtimes.slice(0, 20).map(value => safeText(value, '', 80)) : []},
      symbolic: {status: safeText(symbolicRaw.status, 'not-run', 60),
        findings: safeInteger(symbolicRaw.metrics && symbolicRaw.metrics.findings, 0, 0, 1000000),
        reasons: Array.isArray(symbolicRaw.partial_reasons) ? symbolicRaw.partial_reasons.slice(0, 20).map(value => safeText(value, '', 100)) : []},
      polyglot: {status: polyglotRaw.coverage && polyglotRaw.coverage.complete === true ? 'complete' : safeText(polyglotRaw.status, 'partial', 60),
        files: safeInteger(polyglotRaw.coverage && polyglotRaw.coverage.source_files_parsed, 0, 0, 1000000),
        truncated: Boolean(polyglotRaw.coverage && polyglotRaw.coverage.public_report_truncated)},
      dependency: {status: safeText(dependencyRaw.status, 'not-run', 60),
        nodes: Array.isArray(dependencyRaw.nodes) ? dependencyRaw.nodes.length : 0,
        edges: Array.isArray(dependencyRaw.edges) ? dependencyRaw.edges.length : 0},
      git: {status: safeText(gitRaw.status, 'not-run', 60),
        impact: safeText(gitRaw.impact && gitRaw.impact.status, 'not-requested', 60)}
    };
    const engineering = normalizedFabric(document.engineering, 'Engineering Fabric');
    const securityFabric = normalizedFabric(document.security_fabric, 'Security Fabric');
    const commandCenter = normalizedCommandCenter(document);
    const coverageRecords = [document.coverage, document.engineering && document.engineering.coverage,
      document.security_fabric && document.security_fabric.coverage].filter(isObject);
    const gapCount = coverageRecords.reduce((total, value) => total +
      (Array.isArray(value.gaps) ? value.gaps.length : 0) + (Array.isArray(value.limitations) ? value.limitations.length : 0), 0);
    const coverage = {known: coverageRecords.length > 0,
      complete: coverageRecords.length > 0 && coverageRecords.every(value => value.complete === true) && gapCount === 0,
      partial: gapCount > 0 || coverageRecords.some(value => value.complete === false || value.truncated === true), gapCount};
    return {document, research, findings, attackPaths, improvements, truthGuard, assurance, engineering, securityFabric, commandCenter, coverage,
      truncated: findingRows.length > MAX_FINDINGS};
  }

  function parseFindings(output) {
    const structured = parseStructuredOutput(output);
    if (structured) return {findings: structured.findings, truncated: structured.truncated};
    const findings = [];
    const lines = String(output || '').split(/\r?\n/);
    let current = null;
    const finish = () => {
      if (!current || findings.length >= MAX_FINDINGS) { current = null; return; }
      current.message = current.message.trim() || 'Review the reported evidence at this location.';
      current.evidence = current.evidence.trim() || current.header;
      current.fix = current.fix.trim() || 'Review the finding and apply the narrowest verified remediation.';
      current.id = current.rule + '|' + current.path + '|' + current.line + '|' + findings.length;
      findings.push(current); current = null;
    };
    for (const raw of lines) {
      const header = findingHeader(raw.trimEnd());
      if (header) {
        finish();
        if (findings.length >= MAX_FINDINGS) break;
        current = {...header, header: raw.trim(), message: header.message, evidence: '', fix: ''};
        continue;
      }
      if (!current) continue;
      const text = raw.trim();
      if (!text) { finish(); continue; }
      if (/^fix\s*:/i.test(text)) current.fix += (current.fix ? '\n' : '') + text.replace(/^fix\s*:\s*/i, '');
      else if (/^(?:>|evidence\s*:|snippet\s*:)/i.test(text)) current.evidence += (current.evidence ? '\n' : '') + text.replace(/^(?:>|evidence\s*:|snippet\s*:)\s*/i, '');
      else if (!/^(?:confidence|exploitability|safe-autofix)\s*:/i.test(text)) {
        current.message += (current.message ? ' ' : '') + text.replace(/^(?:why|message|detail)\s*:\s*/i, '');
      }
    }
    finish();
    return {findings, truncated: findings.length >= MAX_FINDINGS};
  }

  function findingStats(findings) {
    const counts = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0};
    findings.forEach(finding => { counts[bucketSeverity(finding.severity)] += 1; });
    return {...counts, total: findings.length};
  }

  function postureAssessment(stats, failed, coverage) {
    if (failed) return {score: 0, state: 'At risk', label: 'Analysis failed', tone: 'bad'};
    if (!coverage || !coverage.known) return {score: null, state: 'Unrated', label: 'Coverage unavailable', tone: 'neutral'};
    const score = Math.max(0, 100 - Math.min(100,
      stats.CRITICAL * 30 + stats.HIGH * 12 + stats.MEDIUM * 4 + stats.LOW));
    if (!coverage.complete) return {score, state: 'Partial', label: 'Partial coverage · not a posture verdict', tone: 'warn'};
    return {score, state: score >= 90 ? 'Healthy' : score >= 70 ? 'Needs review' : 'At risk',
      label: score >= 90 ? 'Strong bounded posture' : score >= 70 ? 'Review recommended' : 'Action required',
      tone: score >= 90 ? 'good' : score >= 70 ? 'warn' : 'bad'};
  }

  function activeStats() {
    if (state.record && state.record.result && state.record.result.persisted_truncated && state.record.finding_summary) {
      return state.record.finding_summary;
    }
    return findingStats(state.findings);
  }

  function publicSourceUrl(value) {
    try {
      const parsed = new URL(safeText(value, '', 4000));
      if (parsed.protocol !== 'https:' || parsed.username || parsed.password) return '';
      const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
      if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) return '';
      const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
      if (ipv4) {
        const octets = ipv4.slice(1).map(Number);
        if (octets.some(valuePart => valuePart > 255) || octets[0] === 0 || octets[0] === 10 || octets[0] === 127 ||
            octets[0] >= 224 || (octets[0] === 169 && octets[1] === 254) ||
            (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
            (octets[0] === 192 && octets[1] === 168) || (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127)) return '';
      }
      if (host === '::1' || host === '::' || /^(?:fc|fd|fe[89ab])/i.test(host)) return '';
      return parsed.href;
    } catch (_error) { return ''; }
  }

  function researchRow(titleText, bodyText = '') {
    const row = document.createElement('article'); row.className = 'research-row'; row.setAttribute('role', 'listitem');
    const title = document.createElement('strong'); title.textContent = titleText; row.appendChild(title);
    if (bodyText) { const body = document.createElement('p'); body.textContent = bodyText; row.appendChild(body); }
    return row;
  }

  function researchBoundaryBadge(label, value, expectedFalse = false) {
    const badge = document.createElement('span');
    const displayed = value === null ? 'unknown' : value ? 'yes' : 'no';
    const safe = value !== null && (expectedFalse ? value === false : true);
    badge.className = 'research-boundary-badge ' + (safe ? 'good' : 'warn');
    badge.textContent = label + ': ' + displayed; return badge;
  }

  function renderResearch() {
    elements.researchClaims.replaceChildren(); elements.researchSources.replaceChildren();
    elements.researchDisagreements.replaceChildren(); elements.researchCoverage.replaceChildren();
    elements.researchExecution.replaceChildren();
    const research = state.research;
    if (!research) {
      elements.researchStatus.className = 'status-pill neutral'; elements.researchStatus.textContent = 'No report';
      elements.researchQuestion.textContent = 'No research question loaded.';
      elements.researchSummary.textContent = 'Select Deep public-web research. Online search remains off until explicitly enabled for that run.';
      elements.researchResults.hidden = true; elements.researchEmpty.hidden = false; return;
    }
    const statusTone = research.status === 'evidence-collected' ? 'good' :
      research.status === 'evidence-collected-with-gaps' || research.status === 'network-authorization-required' ? 'warn' : 'neutral';
    elements.researchStatus.className = 'status-pill ' + statusTone;
    elements.researchStatus.textContent = capitalize(research.status);
    elements.researchQuestion.textContent = research.question || 'Question was not reported.';
    elements.researchSummary.textContent = research.summary.claims + ' claim(s) from ' + research.summary.sources +
      ' source(s) across ' + research.summary.queries + ' completed query result set(s); ' +
      research.summary.pagesFetched + ' public page(s) fetched.';
    elements.researchExecution.append(
      researchBoundaryBadge('Network accessed', research.execution.networkAccessed),
      researchBoundaryBadge('Page retrieval enabled', research.coverage.pageFetchEnabled),
      researchBoundaryBadge('Robots policy respected', research.coverage.robotsRespected),
      researchBoundaryBadge('Private network accessed', research.execution.privateNetworkAccessed, true),
      researchBoundaryBadge('Credentials bypassed', research.execution.credentialsBypassed, true),
      researchBoundaryBadge('Forms submitted', research.execution.formsSubmitted, true),
      researchBoundaryBadge('Dark web accessed', research.execution.darkWebAccessed, true),
      researchBoundaryBadge('Provider credential exposed', research.execution.providerKeyReported, true)
    );
    const sourceById = new Map(research.sources.map(source => [source.id, source]));
    research.claims.forEach((claim, index) => {
      const row = researchRow('Claim ' + (index + 1), claim.text);
      const evidenceState = document.createElement('code');
      evidenceState.textContent = claim.support + ' | ' + claim.state +
        (claim.evidenceIds.length ? ' | evidence ' + claim.evidenceIds.join(', ') : ''); row.appendChild(evidenceState);
      const citations = document.createElement('div'); citations.className = 'research-citations';
      claim.citations.forEach(sourceId => {
        const source = sourceById.get(sourceId); const href = source ? publicSourceUrl(source.url) : '';
        const citation = document.createElement(href ? 'a' : 'span');
        citation.textContent = sourceId + (source ? ' - ' + source.title : ' - unresolved source ID');
        if (href) { citation.href = href; citation.target = '_blank'; citation.rel = 'noopener noreferrer'; }
        citations.appendChild(citation);
      });
      if (!claim.citations.length) { const missing = document.createElement('span'); missing.textContent = 'No source citation reported'; citations.appendChild(missing); }
      row.appendChild(citations); elements.researchClaims.appendChild(row);
    });
    if (!research.claims.length) elements.researchClaims.appendChild(researchRow(
      research.abstained ? 'Attestor abstained' : 'No bounded claim reported',
      'No evidence passage supported an answer. Inspect coverage gaps before drawing a conclusion.'));
    research.sources.forEach(source => {
      const row = researchRow(source.id + ' - ' + source.title, source.description || 'No provider description was reported.');
      const href = publicSourceUrl(source.url);
      if (href) {
        const link = document.createElement('a'); link.className = 'research-source-link'; link.href = href;
        link.target = '_blank'; link.rel = 'noopener noreferrer'; link.textContent = href; row.appendChild(link);
      } else { const unavailable = document.createElement('code'); unavailable.textContent = 'Source URL withheld: not a validated public HTTPS URL'; row.appendChild(unavailable); }
      const meta = document.createElement('div'); meta.className = 'research-source-meta';
      [source.sourceKind, 'page fetch: ' + source.fetchStatus, source.published ? 'published: ' + source.published : ''].filter(Boolean).forEach(value => {
        const item = document.createElement('span'); item.textContent = value; meta.appendChild(item);
      }); row.appendChild(meta); elements.researchSources.appendChild(row);
    });
    if (!research.sources.length) elements.researchSources.appendChild(researchRow('No public sources returned', 'The provider was not called or returned no bounded result.'));
    research.disagreements.forEach(disagreement => {
      const row = researchRow(disagreement.id + ' - ' + disagreement.kind, disagreement.state + '. Human adjudication is required.');
      const binding = document.createElement('code'); binding.textContent = 'evidence ' +
        [disagreement.left, disagreement.right].filter(Boolean).join(' vs ') +
        (disagreement.sharedTerms.length ? ' | shared terms: ' + disagreement.sharedTerms.join(', ') : '');
      row.appendChild(binding); elements.researchDisagreements.appendChild(row);
    });
    if (!research.disagreements.length) elements.researchDisagreements.appendChild(researchRow(
      'No lexical disagreement signal reported', 'Absence of a signal is not proof that sources agree.'));
    elements.researchCoverage.appendChild(researchRow(
      research.coverage.complete ? 'Complete for the bounded requested plan' : 'Incomplete coverage',
      research.coverage.complete ? 'No coverage gap was reported for the bounded plan; this is not coverage of the entire web.' :
        'The report is partial or abstained. Listed gaps and limitations remain material.'));
    research.gaps.forEach((gap, index) => elements.researchCoverage.appendChild(researchRow('Gap ' + (index + 1), gap)));
    research.limitations.forEach((limitation, index) => elements.researchCoverage.appendChild(researchRow('Limitation ' + (index + 1), limitation)));
    if (research.coverage.provider) elements.researchCoverage.appendChild(researchRow('Search provider', research.coverage.provider));
    elements.researchResults.hidden = false; elements.researchEmpty.hidden = true;
  }

  function setRecord(record, options = {}) {
    if (!record) return;
    state.record = record;
    state.verifiedVariant = verifiedResultVariant(
      record.result && record.result.verified_variant);
    state.structured = parseStructuredOutput(record.result && record.result.output);
    const historyVerification = normalizedHistoryVerification(record.historyVerification);
    if (state.structured && state.structured.truthGuard) {
      state.structured.truthGuard.historyVerification = historyVerification;
    }
    if (state.structured && state.structured.commandCenter) {
      bindCommandCenterIntegrity(
        state.structured.commandCenter, historyVerification);
    }
    state.research = state.structured ? state.structured.research : null;
    const parsed = state.structured || parseFindings(record.result && record.result.output);
    state.findings = parsed.findings; state.parseTruncated = parsed.truncated; state.page = 1;
    hydrateAnnotations();
    state.attackPaths = state.structured ? state.structured.attackPaths : [];
    state.improvements = state.structured ? state.structured.improvements : [];
    renderOverview(); renderFindings(); renderAttackPaths(); renderCommandCenter(); renderImprovements(); renderEvidenceExplorer(); renderResearch();
    renderHistory(); renderCompareOptions();
    if (options.navigate) {
      const destination = state.research ? 'research' :
        state.structured && state.structured.commandCenter ? 'command' :
          state.improvements.length ? 'improvements' :
            state.findings.length ? 'findings' : state.attackPaths.length ? 'attacks' : 'overview';
      setView(destination, true);
    }
  }

  function hydrateAnnotations() {
    state.findings.forEach(finding => {
      const match = [...state.annotations.values()].find(row => row.rule_id === finding.rule &&
        row.path.replace(/\\/g, '/') === finding.path.replace(/\\/g, '/') && Number(row.line) === finding.line);
      if (match) { finding.id = match.fingerprint; finding.annotation = match; }
    });
  }

  function renderEvidenceExplorer() {
    elements.evidenceExplorerList.replaceChildren();
    const truth = state.structured && state.structured.truthGuard;
    const coverage = state.structured && state.structured.coverage;
    if (!truth) {
      elements.evidenceExplorerStatus.className = 'status-pill neutral';
      elements.evidenceExplorerStatus.textContent = 'Unavailable';
      elements.evidenceExplorerSummary.textContent = 'This report has no Truth Guard evidence ledger. No source binding is inferred.';
      elements.evidenceExplorerEmpty.hidden = false;
      return;
    }
    elements.evidenceExplorerStatus.className = 'status-pill ' + fabricTone(truth.status, true);
    elements.evidenceExplorerStatus.textContent = capitalize(truth.status);
    elements.evidenceExplorerSummary.textContent = truth.evidence + ' ledger entries · ' + truth.grounded +
      ' source-bound · coverage ' + (!coverage || !coverage.known ? 'unrated' : coverage.complete ? 'complete' : 'partial') +
      (coverage && coverage.gapCount ? ' · ' + coverage.gapCount + ' gap(s)' : '');
    const historicalTruth = historicalTruthPresentation(truth);
    if (historicalTruth) {
      elements.evidenceExplorerStatus.className = 'status-pill warn';
      elements.evidenceExplorerStatus.textContent = historicalTruth.label;
      elements.evidenceExplorerSummary.textContent = historicalTruth.detail +
        ' Stored ledger: ' + truth.evidence + ' entries.';
    }
    const fragment = document.createDocumentFragment();
    state.findings.slice(0, 500).forEach(finding => {
      const source = finding.sourceEvidence || {};
      const row = document.createElement('article'); row.className = 'evidence-row'; row.setAttribute('role', 'listitem');
      const heading = document.createElement('div');
      const title = document.createElement('strong'); title.textContent = finding.rule + ' · ' + finding.evidenceState;
      const location = document.createElement('span'); location.textContent =
        (finding.projectRoot ? finding.projectRoot + ' :: ' : '') + finding.path + ':' + finding.line;
      heading.append(title, location);
      const hashes = document.createElement('code');
      hashes.textContent = 'bytes ' + safeInteger(source.byte_start, 0, 0, Number.MAX_SAFE_INTEGER) + '..' +
        safeInteger(source.byte_end, 0, 0, Number.MAX_SAFE_INTEGER) + ' · file ' + safeText(source.file_sha256, 'unavailable', 64) +
        ' · snippet ' + safeText(source.snippet_sha256, 'unavailable', 64) + ' · rule ' + safeText(source.rule_sha256, 'unavailable', 64);
      const action = document.createElement('button'); action.className = 'button secondary'; action.textContent = 'Inspect';
      action.addEventListener('click', () => openFinding(finding, action));
      row.append(heading, hashes, action); fragment.appendChild(row);
    });
    elements.evidenceExplorerList.appendChild(fragment);
    elements.evidenceExplorerEmpty.hidden = state.findings.length > 0;
  }

  function setCount(id, value) { byId(id).textContent = String(value); }

  function fabricTone(status, present = true) {
    if (!present) return 'neutral';
    const value = safeText(status, '', 80).toLowerCase();
    if (/no-static-issues-from-bounded-checks|no-findings-from-enabled-checks/.test(value)) return 'good';
    if (/failed|failure|error|refused|refuted|blocked|inconsistent|not verified/.test(value)) return 'bad';
    if (/partial|warning|warn|gap|missing|degraded|unknown|not[- ]run|unavailable|issues-observed|action-required|findings/.test(value)) return 'warn';
    if (/verified|complete|passed|healthy|ready|present|success|clean/.test(value)) return 'good';
    return 'neutral';
  }

  function setProofBadge(element, label, status, present) {
    const displayStatus = present ? capitalize(safeText(status, 'unknown', 60)) : 'Unavailable';
    element.className = 'proof-badge ' + fabricTone(status, present);
    element.textContent = label + ': ' + displayStatus;
  }

  function renderFabricPanel(kind, fabric) {
    const isEngineering = kind === 'engineering';
    const name = isEngineering ? 'Engineering Fabric' : 'Security Fabric';
    const summary = isEngineering ? elements.engineeringSummary : elements.securityFabricSummary;
    const status = isEngineering ? elements.engineeringStatus : elements.securityFabricStatus;
    const evidenceBadge = isEngineering ? elements.engineeringEvidenceBadge : elements.securityFabricEvidenceBadge;
    const coverageBadge = isEngineering ? elements.engineeringCoverageBadge : elements.securityFabricCoverageBadge;
    const verificationBadge = isEngineering ? elements.engineeringVerificationBadge : elements.securityFabricVerificationBadge;
    const evidenceCount = isEngineering ? elements.engineeringEvidenceCount : elements.securityFabricEvidenceCount;
    const gapCount = isEngineering ? elements.engineeringGapCount : elements.securityFabricGapCount;
    const verifiedCount = isEngineering ? elements.engineeringVerifiedCount : elements.securityFabricVerifiedCount;
    const capabilityList = isEngineering ? elements.engineeringCapabilities : elements.securityFabricCapabilities;
    const limitationList = isEngineering ? elements.engineeringLimitations : elements.securityFabricLimitations;
    const metric = isEngineering ? elements.engineeringMetric : elements.securityFabricMetric;
    const metricDetail = isEngineering ? elements.engineeringMetricDetail : elements.securityFabricMetricDetail;
    const present = Boolean(fabric);
    const reportedStatus = present ? fabric.status : 'unavailable';
    summary.textContent = present ? fabric.summary : 'No top-level ' + (isEngineering ? 'engineering' : 'security_fabric') + ' result is loaded.';
    status.textContent = present ? capitalize(reportedStatus) : 'Unavailable';
    status.className = 'status-pill ' + fabricTone(reportedStatus, present);
    setProofBadge(evidenceBadge, 'Evidence', present ? fabric.evidenceStatus : 'unavailable', present);
    setProofBadge(coverageBadge, 'Coverage', present ? fabric.coverageStatus : 'unknown', present);
    setProofBadge(verificationBadge, 'Verification', present ? fabric.verificationStatus : 'unknown', present);
    evidenceCount.textContent = String(present ? fabric.evidenceCount : 0);
    gapCount.textContent = String(present ? fabric.gapCount : 0);
    verifiedCount.textContent = String(present ? fabric.verifiedCount : 0);
    metric.textContent = present ? capitalize(reportedStatus) : '—';
    metricDetail.textContent = present ? fabric.evidenceCount + ' evidence · ' + fabric.gapCount + ' gap(s)' :
      'Awaiting a 4.0 ' + (isEngineering ? 'engineering' : 'security') + ' result';
    capabilityList.replaceChildren();
    const capabilities = present ? fabric.capabilities : [];
    (capabilities.length ? capabilities : ['Awaiting a bounded ' + name + ' report.']).forEach(label => {
      const item = document.createElement('li'); item.textContent = label; capabilityList.appendChild(item);
    });
    limitationList.replaceChildren();
    const limitations = present ? fabric.limitations : [];
    (limitations.length ? limitations : [present ?
      'No limitation entries were present in this report; that is not proof of complete coverage.' :
      'Awaiting reported coverage gaps and assurance limitations.']).forEach(label => {
      const item = document.createElement('li'); item.textContent = label; limitationList.appendChild(item);
    });
  }

  function renderFabricDashboards() {
    renderFabricPanel('engineering', state.structured && state.structured.engineering);
    renderFabricPanel('security', state.structured && state.structured.securityFabric);
  }

  function renderOverview() {
    const stats = activeStats();
    const failed = Boolean(state.record && state.record.result && !state.record.result.ok);
    const assessment = state.record ? postureAssessment(stats, failed, state.structured && state.structured.coverage) :
      {score: null, state: 'Unrated', label: 'Awaiting evidence', tone: 'neutral'};
    const score = assessment.score;
    elements.riskScore.textContent = score === null ? '—' : String(score) + (assessment.state === 'Partial' ? '*' : '');
    elements.riskRingValue.setAttribute('stroke-dasharray', (score === null ? 0 : score) + ' 100');
    elements.riskLabel.textContent = assessment.label;
    elements.totalFindings.textContent = String(stats.total); elements.criticalCount.textContent = String(stats.CRITICAL);
    elements.highCount.textContent = String(stats.HIGH); elements.mediumCount.textContent = String(stats.MEDIUM);
    elements.lowCount.textContent = String(stats.LOW); elements.navFindingCount.textContent = stats.total > 999 ? '999+' : String(stats.total);
    const verified = state.improvements.filter(item => item.accepted && item.improvedSource).length;
    elements.attackPathMetric.textContent = String(state.attackPaths.length);
    elements.improvementMetric.textContent = String(verified);
    const truth = state.structured && state.structured.truthGuard;
    elements.truthGuardMetric.textContent = truth ?
      (truth.authentication === 'authenticated' ? 'Authenticated' : capitalize(truth.status) + ' integrity') : '—';
    elements.truthGuardDetail.textContent = truth ?
      truth.grounded + ' grounded · ' + truth.contradictions + ' contradictions · ' +
        (truth.authentication === 'authenticated' ? 'HMAC verified' : 'local integrity only') :
      'Awaiting evidence';
    const historicalTruth = truth ? historicalTruthPresentation(truth) : null;
    if (historicalTruth) {
      elements.truthGuardMetric.textContent = historicalTruth.label;
      elements.truthGuardDetail.textContent = historicalTruth.detail;
    }
    const assurance = state.structured && state.structured.assurance;
    const calibration = assurance && assurance.calibration;
    elements.calibrationMetric.textContent = calibration ? capitalize(calibration.status) : '—';
    elements.calibrationDetail.textContent = calibration ? calibration.calibrated + ' empirical · ' +
      calibration.uncalibrated + ' detector-only' : 'Verified labels not loaded';
    const fabric = assurance && assurance.fabric;
    elements.fabricMetric.textContent = fabric ? capitalize(fabric.status) : '—';
    elements.fabricDetail.textContent = fabric ? (fabric.eligible.length ? fabric.eligible.join(', ') : 'No host fallback') :
      'Fail-closed capability unknown';
    elements.evidenceMetric.textContent = truth ? String(truth.evidence) : '0';
    elements.evidenceDetail.textContent = truth ? (truth.truncated ? 'Ledger bounded; partial evidence catalog' : 'Content-addressed evidence entries') : 'No ledger loaded';
    renderFabricDashboards();
    const symbolic = assurance && assurance.symbolic;
    elements.symbolicState.textContent = symbolic ? capitalize(symbolic.status) : 'Not run';
    elements.symbolicDetail.textContent = symbolic ? symbolic.findings + ' witness-backed finding(s)' +
      (symbolic.reasons.length ? ' · ' + symbolic.reasons.join(', ') : '') : 'Python path and field evidence';
    const polyglot = assurance && assurance.polyglot;
    elements.polyglotState.textContent = polyglot ? capitalize(polyglot.status) : 'Not run';
    elements.polyglotDetail.textContent = polyglot ? polyglot.files + ' source file(s)' +
      (polyglot.truncated ? ' · public view bounded' : '') : 'Bounded lexical coverage';
    const dependency = assurance && assurance.dependency;
    elements.dependencyState.textContent = dependency ? capitalize(dependency.status) : 'Not run';
    elements.dependencyDetail.textContent = dependency ? dependency.nodes + ' nodes · ' + dependency.edges + ' exact edges' : 'Exact lockfile edges';
    const git = assurance && assurance.git;
    elements.gitState.textContent = git ? capitalize(git.status) : 'Not run';
    elements.gitDetail.textContent = git ? 'Impact: ' + git.impact : 'Read-only change impact';
    elements.navAttackCount.textContent = String(state.attackPaths.length);
    elements.navImprovementCount.textContent = String(state.improvements.length);
    const maximum = Math.max(1, stats.CRITICAL, stats.HIGH, stats.MEDIUM, stats.LOW);
    for (const severity of ['critical', 'high', 'medium', 'low']) {
      const value = stats[severity.toUpperCase()];
      byId(severity + 'Bar').max = maximum; byId(severity + 'Bar').value = value;
      setCount(severity + 'BarCount', value);
    }
    elements.postureStatus.className = 'status-pill ' + assessment.tone;
    elements.postureStatus.textContent = assessment.state;
    elements.lastScanLabel.textContent = state.record ? formatDate(state.record.timestamp) + ' · ' + (MODE_LABELS[state.record.mode] || state.record.mode) +
      (state.verifiedVariant ? ' · ' + verifiedVariantLabel(state.verifiedVariant) + ' verified' : '') +
      (state.record.result.persisted_truncated ? ' · saved preview' : '') : 'No scan yet';
    elements.resultVariantLabel.textContent = state.verifiedVariant ?
      verifiedVariantLabel(state.verifiedVariant) + ' · verified' :
      (state.record ? 'Not verified or not applicable' : 'No verified result');
    elements.overviewRecent.replaceChildren();
    const priorities = [...state.findings].sort(compareRisk).slice(0, 5);
    elements.overviewEmpty.hidden = priorities.length > 0;
    priorities.forEach(finding => elements.overviewRecent.appendChild(recentFinding(finding)));
    const output = state.record && state.record.result ? String(state.record.result.output || '') : '';
    const diagnostics = state.record && state.record.result ?
      String(state.record.result.diagnostics || '') : '';
    const preview = output.slice(0, MAX_RAW_PREVIEW);
    elements.rawOutput.textContent = preview || 'Run a scan to inspect the bounded raw report preview.';
    elements.rawMeta.textContent = output ? formatBytes(output.length) +
      (state.verifiedVariant ? ' · variant ' + verifiedVariantLabel(state.verifiedVariant) + ' verified' : '') +
      (state.record.result.persisted_truncated ? ' · persisted preview only; original totals retained' : output.length > MAX_RAW_PREVIEW ? ' · preview truncated in the UI' : '') : 'No output available.';
    if (diagnostics) elements.rawMeta.textContent +=
      ' | ' + formatBytes(diagnostics.length) + ' separate diagnostics';
  }

  function recentFinding(finding) {
    const item = document.createElement('div'); item.setAttribute('role', 'listitem');
    const button = document.createElement('button'); button.className = 'recent-row'; button.type = 'button';
    const severity = document.createElement('span'); severity.className = 'severity-badge ' + severityClass(finding.severity); severity.textContent = finding.severity;
    const rule = document.createElement('code'); rule.textContent = finding.rule;
    const message = document.createElement('span'); message.textContent = finding.message;
    const location = document.createElement('span'); location.textContent =
      (finding.projectRoot ? shortPath(finding.projectRoot) + ' :: ' : '') + shortPath(finding.path) + ':' + finding.line;
    button.append(severity, rule, message, location); button.addEventListener('click', () => openFinding(finding, button));
    item.appendChild(button); return item;
  }

  function compareRisk(a, b) {
    return (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0) ||
      a.path.localeCompare(b.path) || a.line - b.line || a.rule.localeCompare(b.rule);
  }

  function filteredFindings() {
    const query = elements.resultSearch.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
    const severity = elements.severityFilter.value;
    const rows = state.findings.filter(finding => {
      if (severity !== 'ALL' && bucketSeverity(finding.severity) !== severity) return false;
      const haystack = [finding.rule, finding.projectRoot, finding.path, finding.message,
        finding.evidence, finding.fix].join(' ').toLowerCase();
      return query.every(token => haystack.includes(token));
    });
    const sort = elements.sortSelect.value;
    rows.sort(sort === 'risk' ? compareRisk : sort === 'rule' ?
      (a, b) => a.rule.localeCompare(b.rule) || compareRisk(a, b) : sort === 'line' ?
      (a, b) => a.line - b.line || a.path.localeCompare(b.path) :
      (a, b) => a.path.localeCompare(b.path) || a.line - b.line);
    return rows;
  }

  function groupKey(finding) {
    const group = elements.groupSelect.value;
    if (group === 'severity') return finding.severity;
    if (group === 'file') return finding.path;
    if (group === 'rule') return finding.rule;
    return '';
  }

  function renderFindings() {
    const rows = filteredFindings();
    const pageSize = safeInteger(elements.pageSize.value, 100, 50, 200);
    const pages = Math.max(1, Math.ceil(rows.length / pageSize));
    state.page = Math.max(1, Math.min(pages, state.page));
    const start = (state.page - 1) * pageSize;
    const pageRows = rows.slice(start, start + pageSize);
    const groupCounts = new Map();
    if (elements.groupSelect.value !== 'none') rows.forEach(row => {
      const key = groupKey(row); groupCounts.set(key, (groupCounts.get(key) || 0) + 1);
    });
    elements.findingList.replaceChildren();
    const fragment = document.createDocumentFragment(); let previousGroup = null;
    pageRows.forEach(finding => {
      const group = groupKey(finding);
      if (group && group !== previousGroup) {
        const heading = document.createElement('div'); heading.className = 'group-heading';
        const label = document.createElement('span'); label.textContent = group;
        const count = document.createElement('span'); count.textContent = (groupCounts.get(group) || 0) + ' findings';
        heading.append(label, count); heading.setAttribute('role', 'presentation'); fragment.appendChild(heading); previousGroup = group;
      }
      fragment.appendChild(findingCard(finding));
    });
    elements.findingList.appendChild(fragment);
    elements.findingsEmpty.hidden = pageRows.length > 0;
    elements.findingsPagination.hidden = pages <= 1;
    elements.prevPageBtn.disabled = state.page <= 1; elements.nextPageBtn.disabled = state.page >= pages;
    elements.pageLabel.textContent = 'Page ' + state.page + ' of ' + pages;
    const persistedPreview = Boolean(state.record && state.record.result && state.record.result.persisted_truncated);
    elements.resultCount.textContent = persistedPreview ? rows.length + ' matching saved preview · ' + activeStats().total + ' total in original scan' :
      rows.length + ' of ' + state.findings.length + ' findings' + (state.parseTruncated ? ' · parser limit reached' : '');
  }

  function renderAttackPaths() {
    elements.attackPathList.replaceChildren();
    const fragment = document.createDocumentFragment();
    state.attackPaths.forEach(pathValue => {
      const card = document.createElement('article'); card.className = 'attack-path-card'; card.setAttribute('role', 'listitem');
      const header = document.createElement('div'); header.className = 'attack-path-header';
      const copy = document.createElement('div');
      const title = document.createElement('h3'); title.textContent = pathValue.title;
      const meta = document.createElement('p');
      meta.textContent = pathValue.rule + ' | ' + pathValue.source + ' | ' + pathValue.nodes.length + ' evidence steps';
      copy.append(title, meta);
      const severity = document.createElement('span'); severity.className = 'severity-badge ' + severityClass(pathValue.severity);
      severity.textContent = pathValue.severity; header.append(copy, severity);
      const flow = document.createElement('div'); flow.className = 'attack-flow';
      pathValue.nodes.forEach(nodeValue => {
        const node = document.createElement('div'); node.className = 'attack-node';
        const kind = document.createElement('strong'); kind.textContent = nodeValue.kind;
        const label = document.createElement('span'); label.textContent = nodeValue.label;
        node.append(kind, label);
        if (nodeValue.path) {
          const location = document.createElement('code');
          location.textContent = nodeValue.path + (nodeValue.line ? ':' + nodeValue.line : '');
          node.appendChild(location);
        }
        flow.appendChild(node);
      });
      card.append(header, flow); fragment.appendChild(card);
    });
    elements.attackPathList.appendChild(fragment);
    elements.attackPathEmpty.hidden = state.attackPaths.length > 0;
    elements.attackPathCount.textContent = state.attackPaths.length + (state.attackPaths.length === 1 ? ' path' : ' paths');
  }

  function renderCommandCenter() {
    const center = state.structured && state.structured.commandCenter;
    elements.commandMetrics.replaceChildren();
    elements.commandClaimStates.replaceChildren();
    elements.commandAttackPaths.replaceChildren();
    elements.commandGaps.replaceChildren();
    if (!center) {
      elements.commandStatus.className = 'status-pill neutral';
      elements.commandStatus.textContent = 'Unavailable';
      elements.commandCenterGrid.hidden = true;
      elements.commandEmpty.hidden = false;
      elements.commandRepair.textContent = 'Not started';
      elements.commandRegression.textContent = 'Not compared';
      elements.commandApproval.textContent = 'Unavailable';
      return;
    }
    elements.commandCenterGrid.hidden = false;
    elements.commandEmpty.hidden = true;
    const unsafeBoundary = center.rawSecretsPresent === true ||
      center.permissionRetained === true || center.automaticApply === true;
    const unknownBoundary = !center.integrityVerified ||
      center.rawSecretsPresent === null || center.permissionRetained === null ||
      center.automaticApply === null;
    elements.commandStatus.className = 'status-pill ' +
      (unsafeBoundary ? 'bad' : unknownBoundary || center.findings ? 'warn' : 'ok');
    elements.commandStatus.textContent = unsafeBoundary ? 'Unsafe report boundary' :
      !center.integrityVerified ? 'Unverified command-center data' :
        center.rawSecretsPresent === null ? 'Secret privacy not assessed' :
          capitalize(center.status);
    const metric = (label, value) => {
      const wrapper = document.createElement('div');
      const term = document.createElement('dt'); term.textContent = label;
      const detail = document.createElement('dd'); detail.textContent = String(value);
      wrapper.append(term, detail); return wrapper;
    };
    elements.commandMetrics.append(
      metric(center.integrityVerified ? 'Findings' : 'Reported findings', center.findings),
      metric(center.integrityVerified ? 'Attack paths' : 'Reported attack paths', center.attackPathCount),
      metric(center.integrityVerified ? 'Coverage gaps' : 'Reported coverage gaps', center.gapCount),
      metric('Critical / high', center.severity.critical + ' / ' + center.severity.high)
    );
    for (const name of ['proven', 'inferred', 'unverified', 'unavailable']) {
      elements.commandClaimStates.appendChild(metric(capitalize(name), center.claims[name]));
    }
    if (!center.attackPaths.length) {
      const row = document.createElement('p');
      row.textContent = 'No bounded attack-path summary is present; successful exploitation is not inferred.';
      elements.commandAttackPaths.appendChild(row);
    }
    center.attackPaths.forEach(pathValue => {
      const row = document.createElement('article'); row.className = 'command-row'; row.setAttribute('role', 'listitem');
      const copy = document.createElement('div');
      const title = document.createElement('strong'); title.textContent = pathValue.title;
      const detail = document.createElement('p');
      detail.textContent = 'Exploitability: ' + pathValue.exploitability + ' · ID ' + pathValue.id;
      copy.append(title, detail);
      const badge = document.createElement('span');
      badge.className = 'command-state-badge state-' + pathValue.evidenceState;
      badge.textContent = pathValue.evidenceState;
      row.append(copy, badge); elements.commandAttackPaths.appendChild(row);
    });
    const boundaryGaps = [];
    if (!center.integrityVerified) {
      boundaryGaps.push('The loaded command-center digest was not freshly verified by durable history; proof labels were downgraded.');
    }
    if (center.rawSecretsPresent === null) {
      boundaryGaps.push('Raw-secret privacy was not assessed by the report; absence of a warning is not proof.');
    }
    const reportedGaps = center.gaps.length ? center.gaps :
      ['No top-level gap details were supplied; that is not proof of complete coverage.'];
    const gaps = [...boundaryGaps, ...reportedGaps];
    gaps.slice(0, 20).forEach(value => {
      const row = document.createElement('li'); row.textContent = value;
      elements.commandGaps.appendChild(row);
    });
    if (gaps.length > 20) {
      const row = document.createElement('li');
      row.textContent = (gaps.length - 20) + ' additional gap(s) omitted by the UI boundary.';
      elements.commandGaps.appendChild(row);
    }
    elements.commandRepair.textContent = capitalize(center.repairStatus) +
      ' · proof ' + center.repairProofState;
    elements.commandRegression.textContent = capitalize(center.regressionStatus);
    elements.commandApproval.textContent = center.automaticApply === true ?
      'Reported enabled — treat as unsafe' : center.permissionRetained === true ?
        'Permission retained — treat as unsafe' :
        center.automaticApply === null || center.permissionRetained === null ?
          'Authorization state unavailable — do not apply' :
          !center.integrityVerified ? 'Unverified; no authorization inferred' :
            'Denied; one-use approval required';
  }

  function codeDisclosure(label, content, open = false) {
    const details = document.createElement('details'); details.className = 'improvement-code'; details.open = open;
    const summary = document.createElement('summary'); summary.textContent = label;
    const pre = document.createElement('pre'); pre.tabIndex = 0; pre.textContent = content;
    details.append(summary, pre); return details;
  }

  function renderImprovements() {
    elements.improvementList.replaceChildren();
    const fragment = document.createDocumentFragment();
    const verified = state.improvements.filter(item => item.accepted && item.improvedSource).length;
    state.improvements.forEach((item, index) => {
      const card = document.createElement('article');
      const resultKind = item.reviewOnly ? 'review' : item.accepted ? 'accepted' : 'refused';
      card.className = 'improvement-card ' + resultKind;
      card.setAttribute('role', 'listitem');
      const header = document.createElement('div'); header.className = 'improvement-header';
      const copy = document.createElement('div');
      const title = document.createElement('h3'); title.textContent = item.projectRoot ?
        shortPath(item.projectRoot) + ' :: ' + item.target : item.target;
      const meta = document.createElement('p');
      meta.textContent = item.reviewOnly ? (item.summary || 'Review-only candidate; no change was applied.') :
        item.accepted ? item.resolved + ' finding(s) resolved; ' + item.remaining + ' remain after verification' :
        'No result was labeled improved; Attestor refused an unproven transformation.';
      copy.append(title, meta);
      const status = document.createElement('span'); status.className = 'result-status ' + resultKind;
      status.textContent = item.reviewOnly ? 'Review only' : item.accepted ? 'Verified' : 'Refused';
      header.append(copy, status); card.appendChild(header);
      const context = [item.projectRoot ? 'Project root: ' + item.projectRoot : '',
        ...item.paths.map(path => 'Candidate path: ' + path), item.rule ? 'Rule: ' + item.rule : '',
        item.digest ? 'Digest: ' + item.digest : ''].filter(Boolean);
      const reasons = item.reasons.length ? item.reasons : item.reviewOnly && context.length ? context : [item.withheldReason ||
        (item.accepted ? 'All configured verification gates accepted this candidate.' : 'No safe deterministic change was proven.')];
      const list = document.createElement('ul'); list.className = 'improvement-reasons';
      reasons.forEach(reason => { const row = document.createElement('li'); row.textContent = reason; list.appendChild(row); });
      card.appendChild(list);
      if (item.accepted && item.improvedSource) {
        card.appendChild(codeDisclosure('Complete improved source', item.improvedSource, verified === 1 && index === 0));
        if (item.diff) card.appendChild(codeDisclosure('Verified unified diff', item.diff));
        const actions = document.createElement('div'); actions.className = 'improvement-actions';
        const copySource = document.createElement('button'); copySource.type = 'button'; copySource.className = 'button secondary';
        copySource.textContent = 'Copy complete source';
        copySource.addEventListener('click', () => copyText(item.improvedSource, 'Complete improved source copied.'));
        actions.appendChild(copySource);
        if (item.diff) {
          const copyDiff = document.createElement('button'); copyDiff.type = 'button'; copyDiff.className = 'button tertiary';
          copyDiff.textContent = 'Copy diff'; copyDiff.addEventListener('click', () => copyText(item.diff, 'Verified diff copied.'));
          actions.appendChild(copyDiff);
        }
        card.appendChild(actions);
      }
      fragment.appendChild(card);
    });
    elements.improvementList.appendChild(fragment);
    elements.improvementEmpty.hidden = state.improvements.length > 0;
    elements.verifiedImprovementCount.textContent = verified + ' verified';
  }

  function findingCard(finding) {
    const item = document.createElement('article'); item.setAttribute('role', 'listitem');
    const button = document.createElement('button'); button.type = 'button'; button.className = 'finding-card';
    const severity = document.createElement('span'); severity.className = 'severity-badge ' + severityClass(finding.severity); severity.textContent = finding.severity;
    const rule = document.createElement('code'); rule.className = 'finding-rule'; rule.textContent = finding.rule;
    const main = document.createElement('span'); main.className = 'finding-main';
    const title = document.createElement('strong'); title.textContent = finding.message;
    const evidence = document.createElement('span'); evidence.textContent = finding.evidence;
    main.append(title, evidence);
    const location = document.createElement('span'); location.className = 'finding-location';
    const path = document.createElement('span'); path.textContent =
      (finding.projectRoot ? shortPath(finding.projectRoot) + ' :: ' : '') + shortPath(finding.path);
    const line = document.createElement('span'); line.textContent = 'line ' + finding.line; location.append(path, line);
    const arrow = document.createElement('span'); arrow.textContent = '›'; arrow.setAttribute('aria-hidden', 'true');
    button.append(severity, rule, main, location, arrow);
    button.setAttribute('aria-label', finding.severity + ' ' + finding.rule + ' at ' +
      (finding.projectRoot ? finding.projectRoot + ' :: ' : '') + finding.path + ' line ' + finding.line);
    button.addEventListener('click', () => openFinding(finding, button)); item.appendChild(button); return item;
  }

  function openFinding(finding, returnFocus) {
    state.selectedFinding = finding; state.drawerReturnFocus = returnFocus || document.activeElement;
    elements.drawerSeverity.textContent = finding.severity;
    elements.drawerSeverity.className = 'severity-badge ' + severityClass(finding.severity);
    elements.drawerRule.textContent = finding.rule;
    elements.drawerLocation.textContent = (finding.projectRoot ? finding.projectRoot + ' :: ' : '') +
      finding.path + ':' + finding.line;
    elements.drawerFingerprint.textContent = finding.id;
    elements.drawerMessage.textContent = finding.message;
    elements.drawerEvidence.textContent = finding.evidence;
    elements.drawerFix.textContent = finding.fix;
    const annotation = finding.annotation || {};
    elements.triageOwner.value = annotation.triage_owner || annotation.suppression_owner || '';
    elements.triageState.value = annotation.state || 'open';
    elements.triageReason.value = annotation.triage_reason || annotation.suppression_reason || '';
    elements.suppressionExpiry.value = annotation.expires_at ? annotation.expires_at.slice(0, 16) : '';
    elements.annotationStatus.textContent = annotation.expires_at ? 'Suppressed until ' + annotation.expires_at :
      annotation.state ? 'Triage: ' + annotation.state : 'Owner and reason are mandatory. Suppressions always expire.';
    elements.drawer.hidden = false; document.body.classList.add('drawer-open'); byId('drawerClose').focus();
  }

  function closeFinding() {
    if (elements.drawer.hidden) return;
    elements.drawer.hidden = true; document.body.classList.remove('drawer-open');
    const target = state.drawerReturnFocus; state.drawerReturnFocus = null;
    if (target && document.contains(target)) target.focus();
  }

  async function saveTriage() {
    const finding = state.selectedFinding;
    if (!finding || !state.token) return;
    const owner = elements.triageOwner.value.trim(); const reason = elements.triageReason.value.trim();
    if (!owner || !reason) { elements.annotationStatus.textContent = 'Owner and reason are required.'; return; }
    try {
      const data = await api('/api/triage', {method: 'POST', body: JSON.stringify({
        fingerprint: finding.id, state: elements.triageState.value, owner, reason})});
      elements.annotationStatus.textContent = 'Triage saved at ' + data.triage.updated_at;
      if (state.record && state.record.run_id) await loadAnnotations(state.record.run_id);
    } catch (error) { elements.annotationStatus.textContent = error.message; }
  }

  async function suppressFinding() {
    const finding = state.selectedFinding;
    if (!finding || !state.token) return;
    const owner = elements.triageOwner.value.trim(); const reason = elements.triageReason.value.trim();
    const expires = elements.suppressionExpiry.value;
    if (!owner || !reason || !expires) { elements.annotationStatus.textContent = 'Owner, reason, and future expiry are required.'; return; }
    try {
      const expiresAt = new Date(expires).toISOString();
      const data = await api('/api/suppressions', {method: 'POST', body: JSON.stringify({
        fingerprint: finding.id, owner, reason, expires_at: expiresAt})});
      elements.annotationStatus.textContent = 'Suppressed until ' + data.suppression.expires_at;
      if (state.record && state.record.run_id) await loadAnnotations(state.record.run_id);
    } catch (error) { elements.annotationStatus.textContent = error.message; }
  }

  async function loadAnnotations(runId) {
    const data = await api('/api/history/' + encodeURIComponent(runId));
    state.annotations = new Map((data.annotations || []).map(row => [row.fingerprint, row]));
    const historyVerification = normalizedHistoryVerification(data.verification);
    if (state.structured && state.structured.truthGuard) {
      state.structured.truthGuard.historyVerification = historyVerification;
    }
    if (state.structured && state.structured.commandCenter) {
      bindCommandCenterIntegrity(
        state.structured.commandCenter, historyVerification);
    }
    hydrateAnnotations(); renderOverview(); renderFindings();
    renderCommandCenter(); renderEvidenceExplorer();
  }

  function requiredPrompt(mode) {
    return !['arena', 'fixmemory', 'grade', 'securitymax', 'rarebugs', 'nativegrade', 'factory',
      'project', 'workspace', 'computer41', 'escapelab', 'attestor40', 'attestor35', 'attestor3', 'improve', 'semantic', 'supplychain', 'repositorymemory',
      'mayhem', 'cybermayhem', 'qualitygate'].includes(mode);
  }

  function resetResearchAuthorization() {
    elements.researchOnline.checked = false; elements.researchFetchPages.checked = false;
    elements.researchFetchPages.disabled = true;
  }

  function resetComputerAuthorization() {
    elements.computerAuthorized.checked = false;
  }

  function resetCjpAuthorization() {
    elements.cjpPermissionConfirmed.checked = false;
    elements.cjpApply.checked = false;
    elements.cjpApplyConfirmed.checked = false;
    elements.cjpPreviewEvidence.value = '';
    elements.cjpPreviewEvidence.disabled = true;
    elements.cjpApplyConfirmed.disabled = true;
  }

  function setMode(mode) {
    if (!MODE_LABELS[mode]) mode = 'chat';
    const option = elements.scanMode.querySelector('option[value="' + mode + '"]');
    if (option && option.disabled) { toast('That engine version does not support ' + MODE_LABELS[mode] + '.'); return; }
    elements.scanMode.value = mode; elements.modeLabel.textContent = MODE_LABELS[mode];
    elements.prompt.placeholder = MODE_PLACEHOLDERS[mode] || MODE_PLACEHOLDERS.chat;
    const isResearch = mode === 'research';
    const isComputer = mode === 'computer41';
    const isCjpControl = mode === 'cjpcontrol';
    const isEscapeLab = mode === 'escapelab';
    elements.researchControls.hidden = !isResearch;
    elements.computerControls.hidden = !isComputer;
    elements.cjpControls.hidden = !isCjpControl;
    elements.escapeLabControls.hidden = !isEscapeLab;
    if (isCjpControl) elements.variantSelect.value = 'cockroach-janta-party';
    elements.targetHint.textContent = isResearch ?
      'Ask a non-coding question. The question reaches a search provider only when online access is checked for this run.' :
      (isComputer ?
        'No path is accepted in this mode. Select a bounded scope and explicitly authorize this run.' :
        (isCjpControl ?
          'Supply only the local request JSON path. Permission and apply confirmations are one-run and reset after submission.' :
          (isEscapeLab ?
            'Simulation only: Attestor solves a compiled in-memory policy graph. No real host, container, or kernel escape is attempted.' :
            'Use a local file/folder path for analysis modes. Ctrl/Command + Enter starts the scan.')));
    elements.sendBtn.textContent = isResearch ? 'Start research' :
      (isComputer ? 'Discover and scan' :
        (isCjpControl ? 'Run authorized control' :
          (isEscapeLab ? 'Run simulated escape' : 'Start analysis')));
    elements.prompt.disabled = state.running || isComputer || isEscapeLab;
    if (isComputer || isEscapeLab) elements.prompt.value = '';
    if (!isResearch) {
      resetResearchAuthorization();
    } else {
      elements.researchFetchPages.disabled = state.running || !elements.researchOnline.checked;
    }
    if (!isComputer) resetComputerAuthorization();
    if (!isCjpControl) resetCjpAuthorization();
    syncVariantControls();
  }

  function variantSelectionApplies() {
    return elements.versionSelect.value === CURRENT_VERSION &&
      VARIANT_MODES.has(elements.scanMode.value);
  }

  function updateVariantHint() {
    const profile = state.variants[elements.variantSelect.value];
    const responseLanguage = profile &&
      profile.responseLanguage.tier === 'C3' ?
      ' Response language: ' + profile.responseLanguage.label +
        '; this is Attestor-specific and grants no authority.' : '';
    elements.variantHint.textContent = profile ?
      profile.displayName + ' is enforced by the server: ' +
        profile.workerTimeoutSeconds + 's per-worker timeout · ' +
        profile.timeoutSeconds + 's outer process timeout · ' +
        formatBytes(profile.maxOutputBytes) + ' stdout boundary. Snapshot file/byte ' +
        'and graph-node ceilings apply to coding-static; inherited analyzers ' +
        'report separate caps and coverage gaps.' + responseLanguage :
      'No verified Attestor 4.1.4 variant catalog is available.';
    elements.cjpSatire.hidden = !profile ||
      profile.slug !== 'cockroach-janta-party' || !variantSelectionApplies();
  }

  function syncVariantControls() {
    const active = variantSelectionApplies();
    const standalone = elements.scanMode.value === 'escapelab';
    elements.variantControls.hidden = !active;
    elements.requestProfileControls.hidden = active || standalone;
    elements.limitField.hidden = active || standalone;
    elements.timeoutField.hidden = active || standalone;
    elements.variantSelect.disabled = state.running || !active ||
      elements.scanMode.value === 'cjpcontrol' ||
      !state.variants[elements.variantSelect.value];
    updateVariantHint();
  }

  function setProfile(name) {
    const profile = PROFILES[name] || PROFILES.standard;
    elements.limitInput.value = profile.limit; elements.timeoutInput.value = profile.timeout;
    document.querySelectorAll('[data-profile]').forEach(button => {
      const active = button.dataset.profile === name;
      button.classList.toggle('active', active); button.setAttribute('aria-pressed', String(active));
    });
  }

  function setRunning(running, label) {
    state.running = running; elements.sendBtn.disabled = running || !state.token;
    elements.cancelBtn.disabled = !running; elements.prompt.disabled = running ||
      ['computer41', 'escapelab'].includes(elements.scanMode.value); elements.scanMode.disabled = running;
    elements.researchOnline.disabled = running;
    elements.researchFetchPages.disabled = running || elements.scanMode.value !== 'research' || !elements.researchOnline.checked;
    elements.computerAuthorized.disabled = running;
    elements.computerScope.disabled = running;
    elements.computerMaxProjects.disabled = running;
    elements.computerImprove.disabled = running;
    elements.cjpPermissionConfirmed.disabled = running;
    elements.cjpApply.disabled = running;
    elements.cjpPreviewEvidence.disabled = running ||
      !elements.cjpApply.checked;
    elements.cjpApplyConfirmed.disabled = running ||
      !elements.cjpApply.checked;
    syncVariantControls();
    elements.jobState.textContent = label || (running ? 'Running' : 'Idle');
    if (!running && elements.jobProgress.value < 100) elements.jobProgress.value = 0;
  }

  function setStages(status) {
    const order = ['stageQueue', 'stageExecute', 'stageParse', 'stageRender'];
    let current = status === 'queued' ? 0 : status === 'running' ? 1 : status === 'parsing' ? 2 : status === 'rendering' ? 3 : status === 'done' ? 4 : -1;
    order.forEach((id, index) => {
      const item = byId(id); item.classList.toggle('complete', current === 4 || index < current);
      item.classList.toggle('current', index === current);
      item.querySelector('span').textContent = current === 4 || index < current ? '✓' : String(index + 1);
    });
  }

  function updateProgress(status, elapsed, timeout) {
    const seconds = elapsed / 1000; elements.liveElapsed.textContent = seconds.toFixed(1) + 's';
    if (status === 'queued') elements.jobProgress.value = 8;
    else if (status === 'running') elements.jobProgress.value = Math.min(90, 18 + (seconds / Math.max(1, timeout)) * 70);
    elements.jobProgress.setAttribute('aria-valuetext', status + ', ' + seconds.toFixed(1) + ' seconds elapsed');
  }

  async function submitScan(event) {
    if (event) event.preventDefault();
    if (state.running) return;
    if (!state.token) { showScanError('The secured local session is not connected.'); return; }
    let prompt = elements.prompt.value.trim(); const mode = elements.scanMode.value;
    if (mode === 'escapelab') prompt = '';
    if (!prompt && requiredPrompt(mode)) {
      showScanError(mode === 'research' ? 'Research needs a non-coding question.' : 'This mode needs a local path or request.');
      elements.prompt.focus(); return;
    }
    if (mode === 'research' && elements.researchFetchPages.checked && !elements.researchOnline.checked) {
      showScanError('Fetching public pages requires explicit online search authorization.'); return;
    }
    if (mode === 'computer41' && elements.computerAuthorized.checked !== true) {
      showScanError('Computer discovery needs explicit permission for this run. Check the authorization box to continue.'); return;
    }
    if (mode === 'cjpcontrol' &&
        elements.cjpPermissionConfirmed.checked !== true) {
      showScanError('Cockroach local control needs explicit owner/custodian permission confirmation for this run.'); return;
    }
    if (mode === 'cjpcontrol' && elements.cjpApply.checked === true &&
        elements.cjpApplyConfirmed.checked !== true) {
      showScanError('Applying a candidate needs the separate exact-apply confirmation.'); return;
    }
    if (mode === 'cjpcontrol' && elements.cjpApply.checked === true &&
        !/^[0-9a-f]{64}$/.test(elements.cjpPreviewEvidence.value.trim())) {
      showScanError('Paste the exact preview evidence SHA-256 from a prior preview-only run before applying.'); return;
    }
    if (mode === 'factory') {
      const count = safeInteger(prompt || '20', -1, 1, 64);
      if (count < 1) { showScanError('Code Factory accepts a service count from 1 to 64.'); return; }
      prompt = String(count);
    }
    const request = {
      mode, prompt, version: elements.versionSelect.value,
      limit: safeInteger(elements.limitInput.value, 8, 1, 100),
      response_style: elements.responseStyle.value,
      research_online: mode === 'research' && elements.researchOnline.checked === true,
      research_fetch_pages: mode === 'research' && elements.researchFetchPages.checked === true,
      computer_authorized: mode === 'computer41' && elements.computerAuthorized.checked === true,
      computer_scope: mode === 'computer41' ? elements.computerScope.value : 'home',
      computer_max_projects: mode === 'computer41' ? safeInteger(elements.computerMaxProjects.value, 3, 1, 12) : 3,
      computer_improve: mode === 'computer41' && elements.computerImprove.checked === true,
      cjp_permission_confirmed: mode === 'cjpcontrol' &&
        elements.cjpPermissionConfirmed.checked === true,
      cjp_apply: mode === 'cjpcontrol' && elements.cjpApply.checked === true,
      cjp_apply_confirmed: mode === 'cjpcontrol' &&
        elements.cjpApplyConfirmed.checked === true,
      cjp_preview_evidence_sha256: mode === 'cjpcontrol' &&
        elements.cjpApply.checked === true ?
        elements.cjpPreviewEvidence.value.trim() : ''
    };
    if (variantSelectionApplies()) {
      if (!state.variants[elements.variantSelect.value]) {
        showScanError('Choose one verified Attestor 4.1.4 variant.'); return;
      }
      request.variant = elements.variantSelect.value;
    } else {
      request.timeout = safeInteger(
        elements.timeoutInput.value, 120, 1, 600);
    }
    if (mode === 'computer41') resetComputerAuthorization();
    if (mode === 'cjpcontrol') resetCjpAuthorization();
    state.request = request; elements.scanError.hidden = true; setView('scan');
    setRunning(true, 'Submitting'); setStages('queued'); elements.jobProgress.value = 4;
    elements.jobDetail.textContent = 'Submitting ' + MODE_LABELS[mode] + ' to the bounded local queue.';
    try {
      const submitted = await api('/api/jobs', {method: 'POST', body: JSON.stringify(request)});
      state.jobId = submitted.id; await pollJob(submitted.id, request);
    } catch (error) {
      finishFailed(error);
    } finally {
      state.jobId = '';
    }
  }

  async function pollJob(jobId, request) {
    while (state.running && state.jobId === jobId) {
      const job = await api('/api/jobs/' + encodeURIComponent(jobId));
      elements.jobState.textContent = capitalize(job.status);
      elements.jobDetail.textContent = MODE_LABELS[request.mode] + ' · ' + job.status + ' · bounded local process';
      const selectedProfile = request.variant && state.variants[request.variant];
      const progressTimeout = selectedProfile ?
        selectedProfile.timeoutSeconds : request.timeout;
      setStages(job.status);
      updateProgress(job.status, job.elapsed_ms || 0, progressTimeout);
      if (['done', 'failed', 'cancelled'].includes(job.status)) {
        const result = job.result || {ok: false, code: 130, output: 'Job cancelled.', elapsed_ms: job.elapsed_ms || 0};
        setStages('parsing'); elements.jobProgress.value = 94; elements.jobState.textContent = 'Structuring';
        await delay(30);
        const record = {id: jobId, run_id: result.history && result.history.run_id,
          timestamp: (result.history && result.history.created_at) || new Date().toISOString(), mode: request.mode,
          prompt: request.prompt, version: request.version, request, result};
        setStages('rendering'); elements.jobProgress.value = 98;
        state.annotations = new Map(); setRecord(record);
        if (record.run_id) {
          try { await refreshHistory(); await loadAnnotations(record.run_id); }
          catch (_error) { toast('Analysis completed, but durable history could not be refreshed.'); }
        }
        setStages('done'); elements.jobProgress.value = 100; elements.liveElapsed.textContent = ((result.elapsed_ms || 0) / 1000).toFixed(1) + 's';
        setRunning(false, job.status === 'done' ? 'Complete' : capitalize(job.status));
        if (request.mode === 'research') resetResearchAuthorization();
        elements.jobDetail.textContent = job.status === 'done' ? (state.research ?
          state.research.summary.claims + ' research claim(s) and ' + state.research.summary.sources + ' source(s) structured.' :
          state.findings.length + ' findings structured.') : (result.output || job.status);
        if (job.status === 'done') {
          if (state.research) {
            toast('Research complete: ' + state.research.summary.claims + ' claims, ' +
              state.research.summary.sources + ' sources, ' + state.research.gaps.length + ' coverage gaps.');
            setView('research', true);
          } else {
            toast('Analysis complete: ' + state.findings.length + ' findings, ' +
              state.attackPaths.length + ' attack paths, ' + state.improvements.length + ' improvement results.');
            setView(state.improvements.length ? 'improvements' : state.findings.length ? 'findings' :
              state.attackPaths.length ? 'attacks' : 'overview', true);
          }
        } else showScanError(result.output || ('Job ' + job.status + '.'));
        return;
      }
      await delay(350);
    }
  }

  function finishFailed(error) {
    setRunning(false, 'Failed'); setStages('failed'); elements.jobProgress.value = 0;
    if (state.request && state.request.mode === 'research') resetResearchAuthorization();
    showScanError(error instanceof Error ? error.message : String(error));
  }

  function showScanError(message) {
    elements.scanError.hidden = false; elements.scanError.querySelector('p').textContent = message;
    elements.jobDetail.textContent = message; toast(message);
  }

  async function cancelJob() {
    if (!state.running || !state.jobId) return;
    elements.cancelBtn.disabled = true; elements.jobState.textContent = 'Cancelling';
    try { await api('/api/jobs/' + encodeURIComponent(state.jobId), {method: 'DELETE'}); }
    catch (error) { elements.cancelBtn.disabled = false; showScanError('Cancel failed: ' + error.message); }
  }

  async function refreshHistory() {
    if (!state.token) return;
    const data = await api('/api/history?limit=100');
    state.history = Array.isArray(data.runs) ? data.runs : [];
    renderHistory(); renderCompareOptions();
  }

  function renderHistory() {
    elements.historyList.replaceChildren();
    elements.historySelect.replaceChildren(new Option('Select history', ''));
    state.history.forEach((record, index) => {
      const title = formatDate(record.created_at) + ' · ' + (record.schema_name || 'Attestor report');
      elements.historySelect.appendChild(new Option(title, record.run_id));
      elements.historyList.appendChild(historyRow(record, index));
    });
    elements.historyEmpty.hidden = state.history.length > 0;
  }

  function historyRow(record, index) {
    const row = document.createElement('article'); row.className = 'history-row'; row.setAttribute('role', 'listitem');
    const identity = document.createElement('div');
    const name = document.createElement('strong'); name.textContent = record.schema_name || 'Attestor report';
    const target = document.createElement('span'); target.textContent = record.status || 'unknown'; identity.append(name, target);
    const time = document.createElement('time'); time.dateTime = record.created_at; time.textContent = formatDate(record.created_at);
    const targetCell = document.createElement('span'); targetCell.className = 'history-target'; targetCell.textContent = record.semantic_digest.slice(0, 12);
    const findingsCell = document.createElement('span'); findingsCell.className = 'history-findings';
    findingsCell.textContent = record.findings + ' findings';
    const open = document.createElement('button'); open.className = 'button secondary'; open.textContent = 'Open';
    open.addEventListener('click', () => openHistory(index));
    row.append(identity, time, targetCell, findingsCell, open); return row;
  }

  async function openHistory(indexOrId) {
    const record = typeof indexOrId === 'number' ? state.history[indexOrId] :
      state.history.find(item => item.run_id === indexOrId);
    if (!record) return;
    try {
      const data = await api('/api/history/' + encodeURIComponent(record.run_id));
      state.annotations = new Map((data.annotations || []).map(row => [row.fingerprint, row]));
      const opened = {id: record.run_id, run_id: record.run_id, timestamp: record.created_at,
        historyVerification: data.verification,
        mode: data.report && data.report.schema === 'attestor-research/4.1' ? 'research' :
          (data.report && data.report.schema === 'attestor-computer-scan/4.1' ? 'computer41' : 'attestor41'),
        prompt: '', version: CURRENT_VERSION, result: {ok: true,
          output: JSON.stringify(data.report),
          verified_variant: data.verified_variant}};
      setRecord(opened, {navigate: true}); elements.historySelect.value = record.run_id;
      toast('Opened canonical report ' + record.run_id + '.');
    } catch (error) { toast(error.message); }
  }

  async function clearHistory() {
    if (!state.token) return;
    try {
      await api('/api/history', {method: 'DELETE'});
      state.history = []; state.record = null; state.structured = null; state.research = null; state.findings = [];
      state.attackPaths = []; state.improvements = []; state.verifiedVariant = null;
      state.annotations = new Map(); state.page = 1;
      renderHistory(); renderCompareOptions(); renderOverview(); renderFindings();
      renderAttackPaths(); renderCommandCenter(); renderImprovements(); renderEvidenceExplorer(); renderResearch();
      elements.diffPanel.hidden = true; elements.compareNotice.hidden = true; elements.compareEmpty.hidden = false;
      toast('Durable history cleared.');
    } catch (error) { toast(error.message); }
  }

  function renderCompareOptions() {
    const fill = select => {
      const previous = select.value; select.replaceChildren(new Option('Select a scan', ''));
      state.history.forEach(record => select.appendChild(new Option(formatDate(record.created_at) + ' · ' +
        (record.schema_name || 'Attestor report'), record.run_id)));
      if (previous && state.history.some(record => record.run_id === previous)) select.value = previous;
    };
    fill(elements.compareA); fill(elements.compareB);
    if (state.history.length >= 2 && !elements.compareA.value && !elements.compareB.value) {
      elements.compareA.value = state.history[1].run_id; elements.compareB.value = state.history[0].run_id;
    }
    elements.compareEmpty.hidden = state.history.length >= 2;
  }

  async function compareScans() {
    if (elements.compareA.value === '' || elements.compareB.value === '') { toast('Choose a baseline and current scan.'); return; }
    if (elements.compareA.value === elements.compareB.value) { toast('Choose two different scans.'); return; }
    try {
      const data = await api('/api/history/compare?baseline=' + encodeURIComponent(elements.compareA.value) +
        '&current=' + encodeURIComponent(elements.compareB.value));
      const delta = data.delta; elements.compareSummary.replaceChildren();
      [['New', delta.new.length], ['Resolved', delta.resolved.length], ['Persistent', delta.persistent.length]].forEach(([label, value]) => {
        const card = document.createElement('article'); card.className = 'delta-card';
        const strong = document.createElement('strong'); strong.textContent = String(value);
        const span = document.createElement('span'); span.textContent = label; card.append(strong, span); elements.compareSummary.appendChild(card);
      });
      const lines = ['delta ' + delta.delta_sha256, '', 'NEW', ...delta.new.map(value => '+ ' + value), '',
        'RESOLVED', ...delta.resolved.map(value => '- ' + value), '', 'PERSISTENT', ...delta.persistent.map(value => '= ' + value)];
      elements.diffOutput.replaceChildren(); elements.diffOutput.textContent = lines.slice(0, DIFF_LINE_LIMIT).join('\n');
      elements.compareNotice.hidden = false;
      elements.compareNotice.textContent = 'Authoritative semantic delta from server-side content-addressed finding identities; line movement alone does not create a new finding.';
      elements.compareEmpty.hidden = true; elements.diffPanel.hidden = false;
      toast(delta.new.length + ' new · ' + delta.resolved.length + ' resolved · ' + delta.persistent.length + ' persistent');
    } catch (error) { toast(error.message); }
  }

  function lineDiff(before, after) {
    const a = before.split(/\r?\n/).slice(0, DIFF_LINE_LIMIT);
    const b = after.split(/\r?\n/).slice(0, DIFF_LINE_LIMIT);
    const table = Array.from({length: a.length + 1}, () => new Uint16Array(b.length + 1));
    for (let i = a.length - 1; i >= 0; i -= 1) {
      for (let j = b.length - 1; j >= 0; j -= 1) table[i][j] = a[i] === b[j] ? table[i + 1][j + 1] + 1 : Math.max(table[i + 1][j], table[i][j + 1]);
    }
    const rows = []; let i = 0; let j = 0;
    while (i < a.length && j < b.length) {
      if (a[i] === b[j]) { rows.push(['same', '  ' + a[i]]); i += 1; j += 1; }
      else if (table[i + 1][j] >= table[i][j + 1]) { rows.push(['del', '- ' + a[i]]); i += 1; }
      else { rows.push(['add', '+ ' + b[j]]); j += 1; }
    }
    while (i < a.length) { rows.push(['del', '- ' + a[i]]); i += 1; }
    while (j < b.length) { rows.push(['add', '+ ' + b[j]]); j += 1; }
    return rows;
  }

  function renderLineDiff(before, after) {
    elements.diffOutput.replaceChildren(); const fragment = document.createDocumentFragment();
    lineDiff(before, after).forEach(([kind, text]) => {
      const line = document.createElement('span'); line.className = 'diff-line ' + kind; line.textContent = text; fragment.appendChild(line);
    }); elements.diffOutput.appendChild(fragment);
  }

  function activeRecord() {
    if (!state.record) toast('Open or complete a scan before exporting.');
    return state.record;
  }

  function declaredReportIdentity(record) {
    const output = record && record.result ? record.result.output : '';
    if (typeof output !== 'string' || output.length > MAX_STRUCTURED_OUTPUT || !output.trim().startsWith('{')) return '';
    let report;
    try { report = JSON.parse(output); }
    catch (_error) { return ''; }
    if (!isObject(report)) return '';
    const schema = safeText(report.schema, '', 80);
    const declared = safeText(firstDefined([
      report.version, report.attestor_version, report.product_version, report.release
    ], ''), '', 40).replace(/^Attestor\s+/i, '');
    if (schema === 'attestor-maximum/4.1.4') {
      return declared === '4.1.4' ? 'Attestor 4.1.4' : '';
    }
    if (schema === 'attestor-maximum/4.1') {
      if (/^4\.1\.3$/.test(declared)) return 'Attestor 4.1.3';
      if (/^4\.1\.2$/.test(declared)) return 'Attestor 4.1.2';
      return 'Attestor 4.1';
    }
    if (schema === 'attestor-maximum/4.0') return 'Attestor 4.0';
    if (schema === 'attestor-maximum/3.5') return 'Attestor 3.5';
    if (schema === 'attestor-maximum/3.0') return 'Attestor 3.0';
    // A generic version field in arbitrary JSON is not an Attestor identity.
    if (!/^attestor(?:[./-])/.test(schema)) return '';
    if (/^4\.1\.4$/.test(declared)) return 'Attestor 4.1.4';
    if (/^4\.1\.3$/.test(declared)) return 'Attestor 4.1.3';
    if (/^4\.1\.2$/.test(declared)) return 'Attestor 4.1.2';
    if (/^4\.1(?:\.0)?$/.test(declared)) return 'Attestor 4.1';
    if (/^4\.0(?:\.0)?$/.test(declared)) return 'Attestor 4.0';
    if (/^3\.5(?:\.0)?$/.test(declared)) return 'Attestor 3.5';
    if (/^3\.0(?:\.0)?$/.test(declared)) return 'Attestor 3.0';
    return '';
  }

  function recordIdentity(record) {
    const reportIdentity = declaredReportIdentity(record);
    if (reportIdentity) return reportIdentity;
    if (record && record.mode === 'attestor41') {
      const releaseVersion = safeText(record['version'], '', 40);
      if (/^Attestor (?:4\.1\.4|4\.1\.3|4\.1\.2|4\.1)$/.test(releaseVersion)) return releaseVersion;
      return CURRENT_VERSION;
    }
    if (record && record.mode === 'attestor35') return 'Attestor 3.5';
    if (record && record.mode === 'attestor3') return 'Attestor 3.0';
    if (record && record.mode === 'attestor40') return 'Attestor 4.0';
    const version = safeText(record && record.version, '', 40);
    if (/^Attestor (?:4\.1\.4|4\.1\.3|4\.1\.2|4\.1|4\.0|3\.5|3\.0)$/.test(version)) return version;
    return CURRENT_VERSION;
  }

  async function canonicalExport(format) {
    const record = activeRecord(); if (!record) return;
    if (!record.run_id) { toast('This result has no durable canonical run.'); return; }
    try {
      const response = await fetch('/api/history/' + encodeURIComponent(record.run_id) + '/export/' + format,
        {headers: {'X-Attestor-Token': state.token}, credentials: 'same-origin'});
      if (!response.ok) {
        let message = 'Canonical export refused (HTTP ' + response.status + ').';
        try { const error = await response.json(); message = error.output || message; } catch (_ignored) { /* bounded status */ }
        throw new Error(message);
      }
      const blob = await response.blob(); const url = URL.createObjectURL(blob);
      const link = document.createElement('a'); link.href = url;
      link.download = record.run_id + (format === 'sarif' ? '.sarif.json' : '.json');
      document.body.appendChild(link); link.click(); link.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast('Downloaded server-verified ' + format.toUpperCase() + '.');
    } catch (error) { toast(error.message); }
  }

  function exportJson() { return canonicalExport('json'); }
  function exportSarif() { return canonicalExport('sarif'); }

  async function copyText(text, success) {
    try { await navigator.clipboard.writeText(text); toast(success); }
    catch (_error) { toast('Clipboard access was unavailable.'); }
  }

  function formatDate(value) {
    try { return new Intl.DateTimeFormat(undefined, {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'}).format(new Date(value)); }
    catch (_error) { return String(value || ''); }
  }
  function formatBytes(length) { return length > 1048576 ? (length / 1048576).toFixed(1) + ' MB' : length > 1024 ? (length / 1024).toFixed(1) + ' KB' : length + ' bytes'; }
  function shortPath(path) { const parts = String(path || '').split(/[\\/]/); return parts.slice(-2).join('/'); }
  function capitalize(text) {
    const value = safeText(text, '', 80).replace(/[-_]+/g, ' ');
    return value ? value[0].toUpperCase() + value.slice(1) : '';
  }

  function blindArenaUnavailable(message) {
    state.blindArenaSnapshot = null;
    elements.blindArenaStatus.className = 'status-pill bad';
    elements.blindArenaStatus.textContent = 'Unavailable';
    elements.blindArenaObjective.textContent = 'Escape';
    elements.blindArenaEpisodes.textContent = '0';
    elements.blindArenaActions.textContent = '0';
    elements.blindArenaFrontier.textContent = 'Unavailable';
    elements.blindArenaReason.textContent = safeText(
      message, 'Blind arena status is unavailable.', 500);
    elements.blindArenaReportProof.className = 'proof-badge neutral';
    elements.blindArenaReportProof.textContent = 'No verified episode report';
    elements.blindArenaEscapeProof.className = 'proof-badge neutral';
    elements.blindArenaEscapeProof.textContent = 'Escape token and trace not verified';
    elements.blindArenaStartBtn.disabled = true;
    elements.blindArenaStatusBtn.disabled = !state.token;
    elements.blindArenaCancelBtn.disabled = true;
    elements.blindArenaResetBtn.disabled = !state.token;
  }

  function renderBlindArena(snapshot) {
    if (!isObject(snapshot) || snapshot.objective !== 'Escape') {
      blindArenaUnavailable('The server returned an invalid fixed-objective arena status.');
      return;
    }
    state.blindArenaSnapshot = snapshot;
    const status = safeText(snapshot.status, 'incomplete', 80);
    const episodes = safeInteger(snapshot.episode_count, 0, 0, 1000000000);
    const actions = safeInteger(snapshot.total_steps, 0, 0, 1000000000);
    const frontier = isObject(snapshot.frontier) ? snapshot.frontier : {};
    const observationsKnown = safeInteger(frontier.observations_known, 0, 0, 1000000000);
    const actionsKnown = safeInteger(frontier.actions_known, 0, 0, 1000000000);
    const frontierState = capitalize(safeText(frontier.state, 'unavailable', 80));
    const verification = isObject(snapshot.verification) ? snapshot.verification : {};
    // A raw status string can never produce the success label.  The server's
    // independent report, hidden-token, and exact-trace gates must all agree.
    const escaped = snapshot.verified_escape === true &&
      verification.report === true && verification.hidden_token === true &&
      verification.trace === true && snapshot.terminal === true;
    const terminal = snapshot.terminal === true;
    const running = snapshot.running === true;
    const cancelRequested = snapshot.cancel_requested === true;
    let label = capitalize(status) || 'Incomplete';
    let tone = 'neutral';
    if (escaped) { label = 'Escaped · verified'; tone = 'good'; }
    else if (status === 'escaped' || status === 'verification-failed' ||
             status === 'checkpoint-error' || status === 'incomplete') {
      label = status === 'checkpoint-error' ? 'Checkpoint failed closed' : 'Incomplete · unverified';
      tone = 'bad';
    } else if (status === 'contained') { label = 'Contained · verified'; tone = 'good'; }
    else if (['cancelled', 'cancelling', 'episode-exhausted', 'explorer-refused'].includes(status)) {
      tone = 'warn';
    }
    elements.blindArenaStatus.className = 'status-pill ' + tone;
    elements.blindArenaStatus.textContent = label;
    elements.blindArenaObjective.textContent = 'Escape';
    elements.blindArenaEpisodes.textContent = episodes.toLocaleString();
    elements.blindArenaActions.textContent = actions.toLocaleString();
    elements.blindArenaFrontier.textContent = observationsKnown.toLocaleString() +
      ' observations · ' + actionsKnown.toLocaleString() + ' learned actions · ' + frontierState;
    elements.blindArenaReason.textContent = safeText(
      snapshot.reason, 'No verified reason is available.', 1000);
    elements.blindArenaReportProof.className = 'proof-badge ' +
      (verification.report === true ? 'good' : 'neutral');
    elements.blindArenaReportProof.textContent = verification.report === true ?
      'Episode report replay verified' : 'No verified episode report';
    elements.blindArenaEscapeProof.className = 'proof-badge ' + (escaped ? 'good' : 'neutral');
    elements.blindArenaEscapeProof.textContent = escaped ?
      'Hidden token and exact trace verified' : 'Escape token and trace not verified';
    const failedCheckpoint = ['checkpoint-error', 'verification-failed', 'incomplete'].includes(status);
    elements.blindArenaStartBtn.disabled = !state.token || running || terminal || failedCheckpoint;
    elements.blindArenaStartBtn.textContent = episodes > 0 ? 'Resume' : 'Start';
    elements.blindArenaStatusBtn.disabled = !state.token;
    elements.blindArenaCancelBtn.disabled = !state.token || !running || cancelRequested;
    elements.blindArenaResetBtn.disabled = !state.token || running;
  }

  function stopBlindArenaPolling() {
    if (state.blindArenaPollTimer) {
      window.clearTimeout(state.blindArenaPollTimer);
      state.blindArenaPollTimer = 0;
    }
  }

  function scheduleBlindArenaPoll() {
    if (state.blindArenaPollTimer || !state.token) return;
    state.blindArenaPollTimer = window.setTimeout(async () => {
      state.blindArenaPollTimer = 0;
      await refreshBlindArenaStatus(false);
    }, 750);
  }

  async function refreshBlindArenaStatus(announceFailure = true) {
    if (!state.token) {
      blindArenaUnavailable('The secured local session is not connected.');
      return;
    }
    try {
      const snapshot = await api('/api/blind-arena/status');
      renderBlindArena(snapshot);
      if (snapshot.running === true) scheduleBlindArenaPoll();
      else stopBlindArenaPolling();
    } catch (error) {
      stopBlindArenaPolling();
      blindArenaUnavailable(error.message);
      if (announceFailure) toast(error.message);
    }
  }

  async function startBlindArena() {
    if (!state.token) return;
    elements.blindArenaStartBtn.disabled = true;
    try {
      const snapshot = await api('/api/blind-arena/start', {
        method: 'POST', body: '{}'
      });
      renderBlindArena(snapshot);
      scheduleBlindArenaPoll();
    } catch (error) {
      toast(error.message);
      await refreshBlindArenaStatus(false);
    }
  }

  async function cancelBlindArena() {
    if (!state.token) return;
    elements.blindArenaCancelBtn.disabled = true;
    try {
      await api('/api/blind-arena', {method: 'DELETE'});
      await refreshBlindArenaStatus(false);
      scheduleBlindArenaPoll();
    } catch (error) {
      toast(error.message);
      await refreshBlindArenaStatus(false);
    }
  }

  async function resetBlindArena() {
    if (!state.token) return;
    const confirmed = window.confirm(
      'Reset/new will permanently replace Attestor\'s fixed blind-arena checkpoint. Continue?');
    if (!confirmed) return;
    elements.blindArenaResetBtn.disabled = true;
    try {
      const snapshot = await api('/api/blind-arena/reset', {
        method: 'POST', body: JSON.stringify({confirmed: true})
      });
      stopBlindArenaPolling();
      renderBlindArena(snapshot);
      toast('A new fixed-objective arena checkpoint is ready.');
    } catch (error) {
      toast(error.message);
      await refreshBlindArenaStatus(false);
    }
  }

  function applyVersionCapabilities() {
    const info = state.versions[elements.versionSelect.value];
    state.detector = info && info.detector ? info.detector : '';
    elements.detectorPath.textContent = state.detector ? shortPath(state.detector) : 'Not extracted';
    const supported = new Set((info && info.modes) || ['chat']);
    elements.scanMode.querySelectorAll('option').forEach(option => { option.disabled = !supported.has(option.value); });
    document.querySelectorAll('[data-quick-mode]').forEach(button => { button.disabled = !supported.has(button.dataset.quickMode); });
    const selected = elements.scanMode.selectedOptions[0];
    if (!selected || selected.disabled) setMode('chat'); else setMode(elements.scanMode.value);
  }

  async function initialize() {
    renderHistory(); renderCompareOptions(); renderOverview(); renderFindings();
    renderAttackPaths(); renderCommandCenter(); renderImprovements(); renderEvidenceExplorer(); renderResearch(); setProfile('standard');
    const preferredTheme = (() => { try { return localStorage.getItem('attestor-theme'); } catch (_error) { return null; } })();
    applyTheme(preferredTheme || (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'));
    setRunning(false, 'Connecting');
    try {
      const response = await fetch('/health', {credentials: 'same-origin'}); const data = await response.json();
      if (!response.ok || !data.ok || !data.token) throw new Error('Health check failed.');
      state.token = data.token; state.versions = data.versions || {};
      installVariantCatalog(data.variants, data.default_variant);
      const precisionRules = safeInteger(data.precision_rules, 15000, 0, 1000000);
      elements.catalogCapacity.textContent = precisionRules.toLocaleString() + ' rules';
      elements.installedRules.textContent = precisionRules.toLocaleString();
      elements.serverDot.className = 'status-dot ok'; elements.connectionLabel.textContent = 'Connected';
      Array.from(elements.versionSelect.options).forEach(option => {
        const info = state.versions[option.value]; option.disabled = !info || !info.available;
        option.textContent = option.value + (option.disabled ? ' · unavailable' : '');
      });
      let saved = ''; try { saved = localStorage.getItem('attestor-version') || ''; } catch (_error) { /* optional */ }
      elements.versionSelect.value = saved && state.versions[saved] && state.versions[saved].available ? saved : (data.version || CURRENT_VERSION);
      let style = ''; try { style = localStorage.getItem('attestor-response-style') || ''; } catch (_error) { /* optional */ }
      if (style && Array.from(elements.responseStyle.options).some(option => option.value === style)) elements.responseStyle.value = style;
      applyVersionCapabilities(); await refreshHistory();
      await refreshBlindArenaStatus(false); setRunning(false, 'Idle');
    } catch (error) {
      state.token = ''; elements.serverDot.className = 'status-dot bad'; elements.connectionLabel.textContent = 'Offline';
      elements.detectorPath.textContent = 'Unavailable'; setRunning(false, 'Offline');
      blindArenaUnavailable('The secured local session is offline.'); showScanError(error.message);
    }
  }

  document.querySelectorAll('.nav-item[data-view]').forEach(button => button.addEventListener('click', () => {
    setView(button.dataset.view, true);
  }));
  document.querySelectorAll('[data-view-link]').forEach(button => button.addEventListener('click', () => setView(button.dataset.viewLink, true)));
  document.querySelectorAll('[data-profile]').forEach(button => button.addEventListener('click', () => setProfile(button.dataset.profile)));
  document.querySelectorAll('[data-quick-mode]').forEach(button => button.addEventListener('click', () => {
    setMode(button.dataset.quickMode);
    elements.prompt.value = ['research', 'computer41'].includes(button.dataset.quickMode) ? '' : state.detector || '.';
    setView('scan', true); if (button.dataset.quickMode !== 'computer41') elements.prompt.focus();
  }));
  byId('newScanBtn').addEventListener('click', () => { setView('scan', true); elements.prompt.focus(); });
  elements.menuBtn.addEventListener('click', openSidebar); byId('sidebarClose').addEventListener('click', closeSidebar); elements.sidebarBackdrop.addEventListener('click', closeSidebar);
  elements.themeBtn.addEventListener('click', () => applyTheme(document.body.dataset.theme === 'dark' ? 'light' : 'dark'));
  elements.scanForm.addEventListener('submit', submitScan); elements.cancelBtn.addEventListener('click', cancelJob);
  elements.blindArenaStartBtn.addEventListener('click', startBlindArena);
  elements.blindArenaStatusBtn.addEventListener('click', () => refreshBlindArenaStatus(true));
  elements.blindArenaCancelBtn.addEventListener('click', cancelBlindArena);
  elements.blindArenaResetBtn.addEventListener('click', resetBlindArena);
  elements.scanMode.addEventListener('change', () => setMode(elements.scanMode.value));
  elements.variantSelect.addEventListener('change', updateVariantHint);
  elements.researchOnline.addEventListener('change', () => {
    if (!elements.researchOnline.checked) elements.researchFetchPages.checked = false;
    elements.researchFetchPages.disabled = state.running || !elements.researchOnline.checked;
  });
  elements.cjpApply.addEventListener('change', () => {
    if (!elements.cjpApply.checked) {
      elements.cjpApplyConfirmed.checked = false;
      elements.cjpPreviewEvidence.value = '';
    }
    elements.cjpPreviewEvidence.disabled = state.running ||
      !elements.cjpApply.checked;
    elements.cjpApplyConfirmed.disabled = state.running ||
      !elements.cjpApply.checked;
  });
  elements.versionSelect.addEventListener('change', () => { try { localStorage.setItem('attestor-version', elements.versionSelect.value); } catch (_error) { /* optional */ } applyVersionCapabilities(); });
  elements.responseStyle.addEventListener('change', () => { try { localStorage.setItem('attestor-response-style', elements.responseStyle.value); } catch (_error) { /* optional */ } });
  [elements.resultSearch, elements.severityFilter, elements.sortSelect, elements.groupSelect, elements.pageSize].forEach(control => {
    control.addEventListener(control === elements.resultSearch ? 'input' : 'change', () => { state.page = 1; renderFindings(); });
  });
  byId('clearFiltersBtn').addEventListener('click', () => {
    elements.resultSearch.value = ''; elements.severityFilter.value = 'ALL'; elements.sortSelect.value = 'risk'; elements.groupSelect.value = 'none'; state.page = 1; renderFindings();
  });
  elements.prevPageBtn.addEventListener('click', () => { state.page -= 1; renderFindings(); byId('findingsTitle').focus?.(); });
  elements.nextPageBtn.addEventListener('click', () => { state.page += 1; renderFindings(); byId('findingsTitle').focus?.(); });
  byId('drawerClose').addEventListener('click', closeFinding);
  byId('saveTriageBtn').addEventListener('click', saveTriage);
  byId('suppressFindingBtn').addEventListener('click', suppressFinding);
  byId('copyFindingBtn').addEventListener('click', () => { if (state.selectedFinding) copyText(JSON.stringify(state.selectedFinding, null, 2), 'Finding copied.'); });
  byId('copyRawBtn').addEventListener('click', () => { if (state.record) copyText(state.record.result.output || '', 'Raw report copied.'); else toast('No report is open.'); });
  byId('openHistoryBtn').addEventListener('click', () => { if (elements.historySelect.value !== '') openHistory(elements.historySelect.value); });
  elements.historySelect.addEventListener('change', () => { if (elements.historySelect.value !== '') openHistory(elements.historySelect.value); });
  byId('clearBtn').addEventListener('click', clearHistory); byId('compareBtn').addEventListener('click', compareScans);
  byId('exportJsonBtn').addEventListener('click', exportJson);
  byId('exportSarifBtn').addEventListener('click', exportSarif);
  document.addEventListener('keydown', event => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement && document.activeElement.tagName);
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') { event.preventDefault(); submitScan(); return; }
    if (event.key === '/' && !typing && state.view === 'findings') { event.preventDefault(); elements.resultSearch.focus(); return; }
    if (event.altKey && ['1', '2', '3', '4', '5', '6', '7'].includes(event.key)) {
      event.preventDefault(); setView(['overview', 'scan', 'findings', 'attacks', 'improvements', 'compare', 'history'][Number(event.key) - 1], true); return;
    }
    if (event.key === 'Escape') { if (!elements.drawer.hidden) closeFinding(); else closeSidebar(); }
    if (!elements.drawer.hidden && event.key === 'Tab') {
      const focusable = [...elements.drawer.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])')].filter(item => !item.disabled);
      if (focusable.length) {
        const first = focusable[0]; const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
    }
  });

  initialize();
})();
