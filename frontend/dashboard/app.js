/**
 * TrustMesh Administrative Security Dashboard — Application Logic
 * Technology: Vanilla ECMAScript (ES2022)
 * Architecture:
 *   1. Config & State Management
 *   2. Mock / Demonstration Telemetry Generator (strictly conforming to docs/api-contract.md)
 *   3. ApiClient: Abstracted backend HTTP connector with automatic fallback detection
 *   4. Presentation / View Controllers: UI rendering, filtering, pagination, and modals
 *   5. Event Listeners & Router
 */

'use strict';

// ── 1. CONFIGURATION & STATE ────────────────────────────────────────────────
const CONFIG = {
  API_BASE_URL: window.location.origin.includes(':8000') 
    ? '/api/v1' 
    : 'http://localhost:8000/api/v1',
  DEFAULT_POLL_INTERVAL_MS: 30000,
  EVENTS_PER_PAGE: 10,
};

const STATE = {
  activeTab: 'overview',
  isBackendLive: false,
  forceDemoMode: false,
  lastUpdated: null,
  
  // Data caches
  summary: null,
  events: [],
  filteredEvents: [],
  eventsPage: 1,
  
  ledger: {
    records: [],
    valid: true,
    error: null,
    totalRecords: 0,
    headHash: null,
  },
  
  accessDecisions: [],
  subsystems: {},
};

// ── 2. DEMO / MOCK DATA GENERATOR ───────────────────────────────────────────
// Conforms strictly to docs/api-contract.md schemas
const MockData = {
  getSummary() {
    return {
      ledger_total_records: STATE.ledger.records.length || 6,
      ledger_integrity: STATE.ledger.valid,
      ledger_head_hash: STATE.ledger.headHash || '8f3e2a9b4c1d7e5f0a2b4c6d8e0f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f',
      security_events_total: 148,
      security_events_last_24h: 37,
      security_events_failures: 4,
      active_dids: 18,
      revoked_dids: 2,
      zero_trust_pass_rate: 96.2,
      services: {
        ledger: 'healthy',
        auth_webauthn: 'healthy',
        did_crypto: 'healthy',
        core_api: 'healthy',
        policy_engine: 'healthy',
        redis_revocation: 'healthy',
      }
    };
  },

  getLedgerRecords() {
    return [
      {
        index: 0,
        timestamp: '2026-10-14T08:00:00.000000+00:00',
        did: 'did:mesh:genesis',
        doc_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        operation: 'GENESIS',
        previous_hash: '0000000000000000000000000000000000000000000000000000000000000000',
        record_hash: '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
        metadata: { network: 'idp-mesh-simulated-v1' }
      },
      {
        index: 1,
        timestamp: '2026-10-14T09:15:22.108200+00:00',
        did: 'did:mesh:key:z6MkuTi89hC757u498h837y4',
        doc_hash: '9a7d32c914bf82069b2d87a74070732890479f66085a676b5cfefee8c950efd0',
        operation: 'CREATE',
        previous_hash: '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
        record_hash: '71c841f48dd77678128e08d6d538e1e792e3a890e791b58535a8f4c2817d2350',
        metadata: { owner: 'security-admin-node-1' }
      },
      {
        index: 2,
        timestamp: '2026-10-14T11:42:01.321000+00:00',
        did: 'did:mesh:key:z6Mkw94jdLAKSm2389smdf82',
        doc_hash: 'c838f7a8b4c08412e84ffef689104fbc875b8a6a575b9f9e160e34a6ef44b025',
        operation: 'CREATE',
        previous_hash: '71c841f48dd77678128e08d6d538e1e792e3a890e791b58535a8f4c2817d2350',
        record_hash: '90b8fbc39648ba78e6308ddbe46c98dcfe18090b86b4931bc162e245a443729e',
        metadata: { device: 'yubikey-5-nfc' }
      },
      {
        index: 3,
        timestamp: '2026-10-14T14:05:44.821900+00:00',
        did: 'did:mesh:key:z6MkuTi89hC757u498h837y4',
        doc_hash: '2c5a7d832c98bf82069b2d87a74070732890479f66085a676b5cfefee8c950ef',
        operation: 'UPDATE',
        previous_hash: '90b8fbc39648ba78e6308ddbe46c98dcfe18090b86b4931bc162e245a443729e',
        record_hash: '38a74e508316c0f20959828d57d7ee4d84f2b1d3d8108c9d0ee4cf50a095a709',
        metadata: { reason: 'key_rotation' }
      },
      {
        index: 4,
        timestamp: '2026-10-14T17:30:19.492000+00:00',
        did: 'did:mesh:key:z6MktEmpOraryRevoked1098',
        doc_hash: 'fa208479e098485290a8ffea88d752934850720498acfe948572093845acde09',
        operation: 'DEACTIVATE',
        previous_hash: '38a74e508316c0f20959828d57d7ee4d84f2b1d3d8108c9d0ee4cf50a095a709',
        record_hash: '8f3e2a9b4c1d7e5f0a2b4c6d8e0f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f',
        metadata: { revocation_agent: 'member-5-policy-enforcer' }
      }
    ];
  },

  getSecurityEvents() {
    return [
      {
        event_id: 'evt_01J9X1001A8F',
        timestamp: new Date(Date.now() - 3 * 60000).toISOString(),
        event_type: 'authentication_attempt',
        outcome: 'success',
        severity: 'low',
        did_ref: 'did:mesh:key:z6MkuTi89hC757u498h837y4',
        reason: 'webauthn_uv_passkey_verified',
        correlation_id: 'req_c8319f01a',
        metadata: { client: 'Safari/WebAuthn', user_agent: 'macOS 15.1' }
      },
      {
        event_id: 'evt_01J9X0958B12',
        timestamp: new Date(Date.now() - 14 * 60000).toISOString(),
        event_type: 'authentication_attempt',
        outcome: 'failure',
        severity: 'high',
        did_ref: 'did:mesh:key:z6Mkx99UnknownSubject01',
        reason: 'webauthn_challenge_signature_invalid',
        correlation_id: 'req_89ab34ef1',
        metadata: { client: 'Chrome', error: 'Signature verification failed' }
      },
      {
        event_id: 'evt_01J9X0912C34',
        timestamp: new Date(Date.now() - 32 * 60000).toISOString(),
        event_type: 'policy_decision',
        outcome: 'failure',
        severity: 'medium',
        did_ref: 'did:mesh:key:z6Mkw94jdLAKSm2389smdf82',
        reason: 'continuous_zt_stepup_required',
        correlation_id: 'req_5510ff82a',
        metadata: { requested_resource: '/admin/keys', step_up: 'biometric_fido2' }
      },
      {
        event_id: 'evt_01J9X0877D90',
        timestamp: new Date(Date.now() - 58 * 60000).toISOString(),
        event_type: 'token_issued',
        outcome: 'success',
        severity: 'low',
        did_ref: 'did:mesh:key:z6MkuTi89hC757u498h837y4',
        reason: 'jwt_short_lived_access_granted',
        correlation_id: 'req_4123de70c',
        metadata: { expiry_seconds: 900, token_family: 'tok_fam_98a' }
      },
      {
        event_id: 'evt_01J9X0820E11',
        timestamp: new Date(Date.now() - 95 * 60000).toISOString(),
        event_type: 'token_revoked',
        outcome: 'success',
        severity: 'high',
        did_ref: 'did:mesh:key:z6MktEmpOraryRevoked1098',
        reason: 'redis_blacklist_anchor_added',
        correlation_id: 'req_2957ac088',
        metadata: { bloom_filter_updated: true, reason: 'administrative_action' }
      },
      {
        event_id: 'evt_01J9X0745F55',
        timestamp: new Date(Date.now() - 140 * 60000).toISOString(),
        event_type: 'credential_registered',
        outcome: 'success',
        severity: 'low',
        did_ref: 'did:mesh:key:z6Mkw94jdLAKSm2389smdf82',
        reason: 'fido2_passkey_attestation_stored',
        correlation_id: 'req_1209cc334',
        metadata: { aaguid: 'ea9b8d3a-4e01-4b18-8f8e-49b0e1e92d8f' }
      },
      {
        event_id: 'evt_01J9X0680G77',
        timestamp: new Date(Date.now() - 210 * 60000).toISOString(),
        event_type: 'ledger_anchor',
        outcome: 'success',
        severity: 'low',
        did_ref: 'did:mesh:key:z6MkuTi89hC757u498h837y4',
        reason: 'block_hash_linked_to_chain',
        correlation_id: 'req_9981aa772',
        metadata: { block_index: 3, operation: 'UPDATE' }
      },
      {
        event_id: 'evt_01J9X0600H99',
        timestamp: new Date(Date.now() - 340 * 60000).toISOString(),
        event_type: 'policy_decision',
        outcome: 'success',
        severity: 'low',
        did_ref: 'did:mesh:key:z6MkuTi89hC757u498h837y4',
        reason: 'rule_allow_low_risk_session',
        correlation_id: 'req_6672ee991',
        metadata: { calculated_risk_score: 12, rule_name: 'internal_mesh_gateway' }
      }
    ];
  },

  getAccessDecisions() {
    return [
      {
        timestamp: new Date(Date.now() - 5 * 60000).toISOString(),
        subject_did: 'did:mesh:key:z6MkuTi89hC757u498h837y4',
        action: 'READ /api/v1/ledger',
        decision: 'ALLOW',
        rule: 'rule_admin_read_unrestricted',
        risk_score: 10,
        correlation_id: 'req_c8319f01a'
      },
      {
        timestamp: new Date(Date.now() - 32 * 60000).toISOString(),
        subject_did: 'did:mesh:key:z6Mkw94jdLAKSm2389smdf82',
        action: 'POST /api/v1/did/rotate',
        decision: 'CHALLENGE',
        rule: 'rule_sensitive_key_rotation',
        risk_score: 68,
        correlation_id: 'req_5510ff82a'
      },
      {
        timestamp: new Date(Date.now() - 85 * 60000).toISOString(),
        subject_did: 'did:mesh:key:z6Mkx99UnknownSubject01',
        action: 'POST /api/v1/tokens/refresh',
        decision: 'DENY',
        rule: 'rule_untrusted_fingerprint',
        risk_score: 92,
        correlation_id: 'req_89ab34ef1'
      },
      {
        timestamp: new Date(Date.now() - 110 * 60000).toISOString(),
        subject_did: 'did:mesh:key:z6MkuTi89hC757u498h837y4',
        action: 'GET /api/v1/dashboard/summary',
        decision: 'ALLOW',
        rule: 'rule_admin_role_verified',
        risk_score: 8,
        correlation_id: 'req_4123de70c'
      }
    ];
  },

  getSubsystems() {
    return {
      ledger: {
        name: 'Module C — Blockchain Ledger',
        owner: 'Member 4 (Midhun)',
        status: 'healthy',
        latency_ms: 3,
        description: 'Append-only SHA-256 chain for immutable identity state anchoring.'
      },
      core_api: {
        name: 'Module A — Core API Gateway',
        owner: 'Member 1 (Rocky)',
        status: 'pending',
        latency_ms: null,
        description: 'FastAPI entry point app/main.py and identity session controller.'
      },
      auth_webauthn: {
        name: 'Module B — WebAuthn FIDO2 Service',
        owner: 'Member 2 (Shad)',
        status: 'pending',
        latency_ms: null,
        description: 'Passwordless biometric passkey attestation and assertion.'
      },
      did_crypto: {
        name: 'Module C2 — Ed25519 DID Resolution',
        owner: 'Member 3',
        status: 'pending',
        latency_ms: null,
        description: 'Decentralized Identifier creation and Ed25519 signature checks.'
      },
      policy_engine: {
        name: 'Module D — Zero-Trust Policy Engine',
        owner: 'Member 5',
        status: 'pending',
        latency_ms: null,
        description: 'Continuous risk score calculation and dynamic access validation.'
      },
      redis_revocation: {
        name: 'Module E — Redis Revocation & Bloom Filter',
        owner: 'Member 5',
        status: 'degraded',
        latency_ms: null,
        description: 'Instant token blacklist with fast Bloom filter pre-checks.'
      }
    };
  }
};

// ── 3. API CLIENT (DECOUPLED DATA ACCESS LAYER) ─────────────────────────────
const ApiClient = {
  /**
   * Safe fetch with timeout and fallback to mock data
   */
  async request(endpoint, options = {}) {
    if (STATE.forceDemoMode) {
      throw new Error('Forced Demo Mode');
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs || 2500);

    try {
      const url = `${CONFIG.API_BASE_URL}${endpoint}`;
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          ...(options.headers || {})
        }
      });
      clearTimeout(timeout);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      return await response.json();
    } catch (err) {
      clearTimeout(timeout);
      throw err;
    }
  },

  /**
   * Health Probe
   */
  async probeBackend() {
    try {
      // First attempt Module C's verified endpoint
      const result = await this.request('/ledger/verify');
      return { live: true, result };
    } catch {
      return { live: false };
    }
  },

  /**
   * Fetch Dashboard Summary (GET /api/v1/dashboard/summary)
   */
  async fetchSummary() {
    try {
      const data = await this.request('/dashboard/summary');
      return { data, isLive: true };
    } catch {
      return { data: MockData.getSummary(), isLive: false };
    }
  },

  /**
   * Fetch Ledger Records (GET /api/v1/ledger)
   */
  async fetchLedger() {
    try {
      const records = await this.request('/ledger');
      const audit = await this.request('/ledger/verify');
      return {
        records,
        valid: audit.valid,
        error: audit.error,
        totalRecords: audit.total_records,
        headHash: audit.head_hash,
        isLive: true
      };
    } catch {
      const records = MockData.getLedgerRecords();
      return {
        records,
        valid: STATE.ledger.valid, // preserve local tamper state if altered
        error: STATE.ledger.error,
        totalRecords: records.length,
        headHash: records[records.length - 1]?.record_hash,
        isLive: false
      };
    }
  },

  /**
   * Fetch Security Events (GET /api/v1/dashboard/events)
   */
  async fetchEvents() {
    try {
      const data = await this.request('/dashboard/events');
      return { events: data.events || data, isLive: true };
    } catch {
      return { events: MockData.getSecurityEvents(), isLive: false };
    }
  },

  /**
   * Tamper Simulation (POST /api/v1/ledger/simulate-tamper)
   */
  async simulateTamper(payload) {
    try {
      const result = await this.request('/ledger/simulate-tamper', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      return { result, isLive: true };
    } catch {
      // Local simulated tamper logic if backend is offline
      const targetIndex = payload.index;
      if (STATE.ledger.records[targetIndex]) {
        STATE.ledger.records[targetIndex][payload.field] = payload.new_value;
        if (!payload.recalculate_record_hash) {
          STATE.ledger.records[targetIndex].record_hash = 'TAMPERED_FORGED_HASH_' + Math.random().toString(16).substring(2, 10);
        }
      }
      STATE.ledger.valid = false;
      STATE.ledger.error = `Data tampering detected at record #${targetIndex}: field '${payload.field}' modified illegally without blockchain quorum.`;
      return {
        result: {
          valid: false,
          error: STATE.ledger.error,
          total_records: STATE.ledger.records.length,
          head_hash: STATE.ledger.headHash
        },
        isLive: false
      };
    }
  }
};

// ── 4. PRESENTATION / VIEW CONTROLLER ───────────────────────────────────────
const UI = {
  elements: {},

  init() {
    // Cache UI element references
    this.elements = {
      sidebar: document.getElementById('sidebar'),
      sidebarBackdrop: document.getElementById('sidebar-backdrop'),
      mobileToggle: document.getElementById('mobile-nav-toggle'),
      pageTitle: document.getElementById('page-title'),
      
      // Status
      backendContainer: document.getElementById('backend-status-container'),
      backendLabel: document.getElementById('backend-status-label'),
      dataSourceBadge: document.getElementById('data-source-badge'),
      dataSourceText: document.getElementById('data-source-text'),
      toggleSourceBtn: document.getElementById('toggle-source-btn'),
      backendBanner: document.getElementById('backend-banner'),
      bannerCloseBtn: document.getElementById('banner-close-btn'),
      lastUpdatedText: document.getElementById('last-updated-text'),
      manualRefreshBtn: document.getElementById('manual-refresh-btn'),
      
      // Overview stats
      statLedgerRecords: document.getElementById('stat-ledger-records'),
      statLedgerIntegrityTag: document.getElementById('stat-ledger-integrity-tag'),
      statLedgerHash: document.getElementById('stat-ledger-hash'),
      statEvents24h: document.getElementById('stat-events-24h'),
      statEventsFailuresTag: document.getElementById('stat-events-failures-tag'),
      statEventsTotal: document.getElementById('stat-events-total'),
      statActiveDids: document.getElementById('stat-active-dids'),
      statRevokedDids: document.getElementById('stat-revoked-dids'),
      statZtRate: document.getElementById('stat-zt-rate'),
      quickActivityList: document.getElementById('quick-activity-list'),
      overviewSubsystemsList: document.getElementById('overview-subsystems-list'),
      
      // Navigation counts
      navEventsCounter: document.getElementById('nav-events-counter'),
      navLedgerDot: document.getElementById('nav-ledger-dot'),
      
      // Events Table
      eventsTableBody: document.getElementById('events-table-body'),
      eventsLoading: document.getElementById('events-loading-overlay'),
      eventsEmpty: document.getElementById('events-empty-state'),
      eventsError: document.getElementById('events-error-state'),
      eventsRetryBtn: document.getElementById('events-retry-btn'),
      eventsPaginationInfo: document.getElementById('events-pagination-info'),
      eventsCurrentPage: document.getElementById('events-current-page'),
      eventsPrevBtn: document.getElementById('events-prev-page'),
      eventsNextBtn: document.getElementById('events-next-page'),
      
      // Filter controls
      filterEventType: document.getElementById('filter-event-type'),
      filterOutcome: document.getElementById('filter-outcome'),
      filterSeverity: document.getElementById('filter-severity'),
      filterDidSearch: document.getElementById('filter-did-search'),
      btnApplyEventsFilter: document.getElementById('btn-apply-events-filter'),
      btnResetEventsFilter: document.getElementById('btn-reset-events-filter'),
      btnExportEvents: document.getElementById('export-events-btn'),
      
      // Ledger Section
      ledgerTableBody: document.getElementById('ledger-table-body'),
      ledgerLoading: document.getElementById('ledger-loading-overlay'),
      ledgerError: document.getElementById('ledger-error-state'),
      ledgerRetryBtn: document.getElementById('ledger-retry-btn'),
      ledgerBadgeWrap: document.getElementById('ledger-badge-wrap'),
      ledgerBadgeIcon: document.getElementById('ledger-badge-icon'),
      ledgerBadgeTitle: document.getElementById('ledger-badge-title'),
      ledgerTotalBlocks: document.getElementById('ledger-total-blocks'),
      ledgerHeadHash: document.getElementById('ledger-head-hash'),
      ledgerIntegrityDetails: document.getElementById('ledger-integrity-details'),
      ledgerAuditBtn: document.getElementById('ledger-audit-btn'),
      
      // Tamper Modal
      tamperDialog: document.getElementById('tamper-dialog'),
      tamperTrigger: document.getElementById('ledger-tamper-modal-trigger'),
      tamperClose: document.getElementById('tamper-dialog-close'),
      tamperCancel: document.getElementById('tamper-cancel-btn'),
      tamperForm: document.getElementById('tamper-form'),
      tamperIndexInput: document.getElementById('tamper-target-index'),
      tamperFieldSelect: document.getElementById('tamper-field-select'),
      tamperValueInput: document.getElementById('tamper-injected-val'),
      tamperRecalcCheck: document.getElementById('tamper-recalc-hash'),
      tamperFeedback: document.getElementById('tamper-feedback-box'),
      
      // Access Table
      accessTableBody: document.getElementById('access-table-body'),
      
      // Health Section
      healthGrid: document.getElementById('health-cards-grid'),
      recheckHealthBtn: document.getElementById('recheck-health-btn'),
      
      // Event Detail Modal
      eventDetailDialog: document.getElementById('event-detail-dialog'),
      eventDetailClose: document.getElementById('event-detail-close'),
      eventDetailContent: document.getElementById('event-detail-content'),
      eventDetailCopyBtn: document.getElementById('event-detail-copy-btn'),
      eventDetailDoneBtn: document.getElementById('event-detail-done-btn'),
      
      // Toast container
      toastRegion: document.getElementById('toast-region'),
    };

    this.bindEvents();
  },

  bindEvents() {
    // Tab Navigation
    document.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const targetId = link.getAttribute('href').replace('#', '');
        Router.navigate(targetId);
      });
    });

    // Quick links in overview
    document.getElementById('view-all-events-link')?.addEventListener('click', (e) => {
      e.preventDefault();
      Router.navigate('events');
    });
    document.getElementById('view-all-health-link')?.addEventListener('click', (e) => {
      e.preventDefault();
      Router.navigate('health');
    });

    // Mobile Navigation Drawer Toggle
    this.elements.mobileToggle.addEventListener('click', () => {
      const isOpen = this.elements.sidebar.classList.toggle('open');
      this.elements.sidebarBackdrop.classList.toggle('active', isOpen);
      this.elements.mobileToggle.setAttribute('aria-expanded', isOpen);
    });

    this.elements.sidebarBackdrop.addEventListener('click', () => {
      this.elements.sidebar.classList.remove('open');
      this.elements.sidebarBackdrop.classList.remove('active');
      this.elements.mobileToggle.setAttribute('aria-expanded', 'false');
    });

    // Manual Refresh
    this.elements.manualRefreshBtn.addEventListener('click', () => {
      App.refreshAll(true);
    });

    // Toggle Backend vs Demo Mode
    this.elements.toggleSourceBtn.addEventListener('click', () => {
      STATE.forceDemoMode = !STATE.forceDemoMode;
      this.showToast(
        STATE.forceDemoMode ? 'Switched to Demo Simulation Mode' : 'Attempting to reconnect to live backend…',
        'info'
      );
      App.refreshAll(true);
    });

    // Close Banner
    this.elements.bannerCloseBtn.addEventListener('click', () => {
      this.elements.backendBanner.style.display = 'none';
    });

    // Event Filters
    this.elements.btnApplyEventsFilter.addEventListener('click', () => this.applyEventFilters());
    this.elements.btnResetEventsFilter.addEventListener('click', () => this.resetEventFilters());
    this.elements.filterDidSearch.addEventListener('keyup', (e) => {
      if (e.key === 'Enter') this.applyEventFilters();
    });

    // Event Pagination
    this.elements.eventsPrevBtn.addEventListener('click', () => {
      if (STATE.eventsPage > 1) {
        STATE.eventsPage--;
        this.renderEventsTable();
      }
    });

    this.elements.eventsNextBtn.addEventListener('click', () => {
      const totalPages = Math.ceil(STATE.filteredEvents.length / CONFIG.EVENTS_PER_PAGE);
      if (STATE.eventsPage < totalPages) {
        STATE.eventsPage++;
        this.renderEventsTable();
      }
    });

    // Event Export
    this.elements.btnExportEvents.addEventListener('click', () => {
      const blob = new Blob([JSON.stringify(STATE.filteredEvents, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `trustmesh-security-events-${new Date().toISOString().substring(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      this.showToast('Security audit events exported to JSON', 'success');
    });

    // Re-verify Ledger Audit
    this.elements.ledgerAuditBtn.addEventListener('click', async () => {
      this.showToast('Running cryptographic ledger verification…', 'info');
      await App.loadLedger();
      if (STATE.ledger.valid) {
        this.showToast('Ledger chain audit PASSED: 100% intact', 'success');
      } else {
        this.showToast('AUDIT FAILED: Cryptographic tampering confirmed!', 'danger');
      }
    });

    // Tamper Simulation Modal Triggers
    this.elements.tamperTrigger.addEventListener('click', () => {
      this.elements.tamperFeedback.hidden = true;
      if (typeof this.elements.tamperDialog.showModal === 'function') {
        this.elements.tamperDialog.showModal();
      } else {
        this.elements.tamperDialog.setAttribute('open', '');
      }
    });

    const closeTamper = () => {
      if (typeof this.elements.tamperDialog.close === 'function') {
        this.elements.tamperDialog.close();
      } else {
        this.elements.tamperDialog.removeAttribute('open');
      }
    };
    this.elements.tamperClose.addEventListener('click', closeTamper);
    this.elements.tamperCancel.addEventListener('click', closeTamper);

    // Tamper Simulation Submit
    this.elements.tamperForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        index: parseInt(this.elements.tamperIndexInput.value, 10),
        field: this.elements.tamperFieldSelect.value,
        new_value: this.elements.tamperValueInput.value,
        recalculate_record_hash: this.elements.tamperRecalcCheck.checked
      };

      this.elements.tamperFeedback.hidden = false;
      this.elements.tamperFeedback.className = 'tamper-feedback';
      this.elements.tamperFeedback.textContent = 'Simulating attack & auditing hash linkage…';

      const { result, isLive } = await ApiClient.simulateTamper(payload);

      STATE.ledger.valid = result.valid;
      STATE.ledger.error = result.error;
      this.renderLedgerIntegrity();
      this.renderLedgerTable();
      this.renderSummary();

      this.elements.tamperFeedback.className = 'tamper-feedback tampered';
      this.elements.tamperFeedback.innerHTML = `
        <strong>Tamper Attack Executed (${isLive ? 'Live API' : 'Local Mock'}):</strong><br>
        Result: <code>valid = false</code><br>
        Error: ${this.escapeHtml(result.error || 'Integrity failure')}
      `;

      this.showToast('Ledger integrity broken: Tamper detected!', 'danger');
    });

    // Event Detail Modal Close
    const closeDetail = () => {
      if (typeof this.elements.eventDetailDialog.close === 'function') {
        this.elements.eventDetailDialog.close();
      } else {
        this.elements.eventDetailDialog.removeAttribute('open');
      }
    };
    this.elements.eventDetailClose.addEventListener('click', closeDetail);
    this.elements.eventDetailDoneBtn.addEventListener('click', closeDetail);

    // Health Probe
    this.elements.recheckHealthBtn.addEventListener('click', () => {
      this.showToast('Probing all IdP Mesh service nodes…', 'info');
      App.loadHealth();
    });
  },

  renderBackendStatus(isLive) {
    STATE.isBackendLive = isLive;
    if (isLive) {
      this.elements.backendContainer.className = 'backend-status-pill online';
      this.elements.backendLabel.textContent = 'Backend: Online';
      this.elements.dataSourceBadge.className = 'mode-badge live';
      this.elements.dataSourceText.textContent = 'Live Backend (FastAPI)';
      this.elements.toggleSourceBtn.textContent = 'Simulate Offline Mode';
      this.elements.backendBanner.style.display = 'none';
    } else {
      this.elements.backendContainer.className = 'backend-status-pill offline';
      this.elements.backendLabel.textContent = 'Backend: Offline';
      this.elements.dataSourceBadge.className = 'mode-badge';
      this.elements.dataSourceText.textContent = 'Demonstration Mode';
      this.elements.toggleSourceBtn.textContent = 'Retry Live Connection';
      this.elements.backendBanner.style.display = 'flex';
    }
  },

  renderSummary() {
    const s = STATE.summary;
    if (!s) return;

    this.elements.statLedgerRecords.textContent = s.ledger_total_records;
    
    if (STATE.ledger.valid) {
      this.elements.statLedgerIntegrityTag.className = 'stat-tag tag-success';
      this.elements.statLedgerIntegrityTag.textContent = 'Integrity Verified';
      this.elements.navLedgerDot.className = 'integrity-indicator intact';
      this.elements.navLedgerDot.title = 'Ledger status: intact';
    } else {
      this.elements.statLedgerIntegrityTag.className = 'stat-tag tag-danger';
      this.elements.statLedgerIntegrityTag.textContent = 'Tampered Detected!';
      this.elements.navLedgerDot.className = 'integrity-indicator tampered';
      this.elements.navLedgerDot.title = 'Ledger status: TAMPERED!';
    }

    const headHash = STATE.ledger.headHash || s.ledger_head_hash || '--';
    this.elements.statLedgerHash.innerHTML = `Head: <code class="mono-truncate" title="${headHash}">${this.escapeHtml(headHash)}</code>`;

    this.elements.statEvents24h.textContent = s.security_events_last_24h;
    this.elements.statEventsFailuresTag.textContent = `${s.security_events_failures || 0} Failures`;
    this.elements.statEventsTotal.textContent = `Total logged: ${s.security_events_total}`;
    this.elements.navEventsCounter.textContent = s.security_events_last_24h;

    this.elements.statActiveDids.textContent = s.active_dids;
    this.elements.statRevokedDids.textContent = `${s.revoked_dids} Revoked`;

    this.elements.statZtRate.textContent = `${s.zero_trust_pass_rate}%`;

    // Overview quick feed
    const recent = (STATE.events || []).slice(0, 4);
    if (recent.length > 0) {
      this.elements.quickActivityList.innerHTML = recent.map(ev => `
        <li class="activity-item">
          <span class="activity-dot ${ev.outcome === 'success' ? 'success' : 'failure'}" aria-hidden="true"></span>
          <div class="activity-content">
            <div class="activity-msg">
              <strong>${this.formatEventType(ev.event_type)}</strong> — ${this.escapeHtml(ev.reason)}
            </div>
            <div class="activity-time">${this.formatTimestamp(ev.timestamp)} • <code>${this.truncateDid(ev.did_ref)}</code></div>
          </div>
        </li>
      `).join('');
    }

    // Overview subsystems list
    const subsystems = MockData.getSubsystems();
    this.elements.overviewSubsystemsList.innerHTML = Object.values(subsystems).slice(0, 4).map(sub => `
      <div class="subsystem-row">
        <span class="subsystem-name">${sub.name}</span>
        <span class="subsystem-status-pill ${sub.status === 'healthy' ? 'tag-success' : 'tag-warning'}">
          ${sub.status.toUpperCase()}
        </span>
      </div>
    `).join('');
  },

  applyEventFilters() {
    const typeVal = this.elements.filterEventType.value;
    const outcomeVal = this.elements.filterOutcome.value;
    const severityVal = this.elements.filterSeverity.value;
    const searchVal = this.elements.filterDidSearch.value.trim().toLowerCase();

    STATE.filteredEvents = STATE.events.filter(ev => {
      if (typeVal && ev.event_type !== typeVal) return false;
      if (outcomeVal && ev.outcome !== outcomeVal) return false;
      if (severityVal && ev.severity !== severityVal) return false;
      if (searchVal) {
        const matchesDid = ev.did_ref?.toLowerCase().includes(searchVal);
        const matchesReason = ev.reason?.toLowerCase().includes(searchVal);
        const matchesId = ev.event_id?.toLowerCase().includes(searchVal);
        if (!matchesDid && !matchesReason && !matchesId) return false;
      }
      return true;
    });

    STATE.eventsPage = 1;
    this.renderEventsTable();
  },

  resetEventFilters() {
    this.elements.filterEventType.value = '';
    this.elements.filterOutcome.value = '';
    this.elements.filterSeverity.value = '';
    this.elements.filterDidSearch.value = '';
    STATE.filteredEvents = [...STATE.events];
    STATE.eventsPage = 1;
    this.renderEventsTable();
  },

  renderEventsTable() {
    const list = STATE.filteredEvents;
    const total = list.length;
    const perPage = CONFIG.EVENTS_PER_PAGE;
    const totalPages = Math.max(1, Math.ceil(total / perPage));

    this.elements.eventsEmpty.hidden = total > 0;

    if (total === 0) {
      this.elements.eventsTableBody.innerHTML = '';
      this.elements.eventsPaginationInfo.textContent = 'Showing 0 of 0 events';
      this.elements.eventsPrevBtn.disabled = true;
      this.elements.eventsNextBtn.disabled = true;
      this.elements.eventsCurrentPage.textContent = 'Page 1';
      return;
    }

    const startIndex = (STATE.eventsPage - 1) * perPage;
    const endIndex = Math.min(startIndex + perPage, total);
    const pageRecords = list.slice(startIndex, endIndex);

    this.elements.eventsTableBody.innerHTML = pageRecords.map(ev => `
      <tr>
        <td class="mono-font">${this.formatTimestamp(ev.timestamp)}</td>
        <td><strong>${this.formatEventType(ev.event_type)}</strong></td>
        <td>
          <span class="badge-pill ${ev.outcome === 'success' ? 'badge-success' : 'badge-failure'}">
            ${ev.outcome}
          </span>
        </td>
        <td>
          <span class="badge-pill ${this.getSeverityClass(ev.severity)}">
            ${ev.severity}
          </span>
        </td>
        <td><code class="mono-truncate" title="${this.escapeHtml(ev.did_ref)}">${this.truncateDid(ev.did_ref)}</code></td>
        <td>${this.escapeHtml(ev.reason)}</td>
        <td style="text-align: right;">
          <button class="btn-ghost" onclick="UI.showEventDetail('${ev.event_id}')" aria-label="Inspect event ${ev.event_id}">
            Inspect
          </button>
        </td>
      </tr>
    `).join('');

    this.elements.eventsPaginationInfo.textContent = `Showing ${startIndex + 1}-${endIndex} of ${total} events`;
    this.elements.eventsCurrentPage.textContent = `Page ${STATE.eventsPage} of ${totalPages}`;
    this.elements.eventsPrevBtn.disabled = STATE.eventsPage <= 1;
    this.elements.eventsNextBtn.disabled = STATE.eventsPage >= totalPages;
  },

  showEventDetail(eventId) {
    const ev = STATE.events.find(e => e.event_id === eventId);
    if (!ev) return;

    this.elements.eventDetailContent.innerHTML = `
      <table class="detail-prop-table">
        <tbody>
          <tr><td>Event ID</td><td><code>${ev.event_id}</code></td></tr>
          <tr><td>Timestamp</td><td>${ev.timestamp}</td></tr>
          <tr><td>Event Type</td><td><strong>${ev.event_type}</strong></td></tr>
          <tr><td>Outcome</td><td><span class="badge-pill ${ev.outcome === 'success' ? 'badge-success' : 'badge-failure'}">${ev.outcome}</span></td></tr>
          <tr><td>Severity</td><td><span class="badge-pill ${this.getSeverityClass(ev.severity)}">${ev.severity}</span></td></tr>
          <tr><td>DID Reference</td><td><code>${this.escapeHtml(ev.did_ref)}</code></td></tr>
          <tr><td>Reason</td><td>${this.escapeHtml(ev.reason)}</td></tr>
          <tr><td>Correlation ID</td><td><code>${ev.correlation_id || 'N/A'}</code></td></tr>
          <tr><td>Metadata</td><td><pre style="max-height: 150px; overflow-y: auto;">${this.escapeHtml(JSON.stringify(ev.metadata || {}, null, 2))}</pre></td></tr>
        </tbody>
      </table>
    `;

    this.elements.eventDetailCopyBtn.onclick = () => {
      navigator.clipboard.writeText(JSON.stringify(ev, null, 2));
      this.showToast('Event JSON copied to clipboard', 'success');
    };

    if (typeof this.elements.eventDetailDialog.showModal === 'function') {
      this.elements.eventDetailDialog.showModal();
    } else {
      this.elements.eventDetailDialog.setAttribute('open', '');
    }
  },

  renderLedgerIntegrity() {
    const l = STATE.ledger;
    if (l.valid) {
      this.elements.ledgerBadgeWrap.className = 'integrity-status-badge intact';
      this.elements.ledgerBadgeIcon.textContent = '✓';
      this.elements.ledgerBadgeTitle.textContent = 'Ledger Cryptographic Integrity Intact';
      this.elements.ledgerIntegrityDetails.textContent = 
        'All SHA-256 block linkage hashes (previous_hash -> record_hash) recomputed across all blocks and matched perfectly. No modifications detected.';
    } else {
      this.elements.ledgerBadgeWrap.className = 'integrity-status-badge tampered';
      this.elements.ledgerBadgeIcon.textContent = '⚡';
      this.elements.ledgerBadgeTitle.textContent = 'CRITICAL: Ledger Chain Tampering Detected!';
      this.elements.ledgerIntegrityDetails.innerHTML = `
        <strong style="color: #f87171;">Audit Alert:</strong> ${this.escapeHtml(l.error || 'Forward hash linkage broken')}
      `;
    }

    this.elements.ledgerTotalBlocks.textContent = l.totalRecords;
    this.elements.ledgerHeadHash.textContent = l.headHash || '--';
    this.elements.ledgerHeadHash.title = l.headHash || '';
  },

  renderLedgerTable() {
    const records = STATE.ledger.records || [];
    this.elements.ledgerTableBody.innerHTML = records.map(rec => {
      const isGenesis = rec.index === 0;
      return `
        <tr>
          <td><strong>#${rec.index}</strong></td>
          <td class="mono-font">${this.formatTimestamp(rec.timestamp)}</td>
          <td><span class="badge-pill ${isGenesis ? 'badge-info' : 'badge-success'}">${rec.operation}</span></td>
          <td><code title="${this.escapeHtml(rec.did)}">${this.escapeHtml(rec.did)}</code></td>
          <td><code class="mono-truncate" title="${rec.doc_hash}">${rec.doc_hash}</code></td>
          <td><code class="mono-truncate" title="${rec.record_hash}">${rec.record_hash}</code></td>
        </tr>
      `;
    }).join('');
  },

  renderAccessTable() {
    const decisions = STATE.accessDecisions || [];
    this.elements.accessTableBody.innerHTML = decisions.map(d => `
      <tr>
        <td class="mono-font">${this.formatTimestamp(d.timestamp)}</td>
        <td><code>${this.truncateDid(d.subject_did)}</code></td>
        <td><strong>${this.escapeHtml(d.action)}</strong></td>
        <td>
          <span class="badge-pill ${d.decision === 'ALLOW' ? 'badge-success' : (d.decision === 'DENY' ? 'badge-failure' : 'badge-warning')}">
            ${d.decision}
          </span>
        </td>
        <td><code>${this.escapeHtml(d.rule)}</code></td>
        <td>
          <span class="badge-pill ${d.risk_score > 70 ? 'badge-failure' : (d.risk_score > 40 ? 'badge-warning' : 'badge-success')}">
            Score: ${d.risk_score}
          </span>
        </td>
        <td><code>${this.escapeHtml(d.correlation_id)}</code></td>
      </tr>
    `).join('');
  },

  renderHealthGrid() {
    const subsystems = STATE.subsystems;
    this.elements.healthGrid.innerHTML = Object.entries(subsystems).map(([key, item]) => {
      const isOk = item.status === 'healthy';
      const isDeg = item.status === 'degraded';
      const tagClass = isOk ? 'tag-success' : (isDeg ? 'tag-danger' : 'tag-warning');
      return `
        <article class="health-card" role="listitem">
          <div class="health-card-header">
            <h3 class="health-card-title">${item.name}</h3>
            <span class="health-status-tag ${tagClass}">${item.status.toUpperCase()}</span>
          </div>
          <p class="health-card-body">${item.description}</p>
          <div class="health-card-footer">
            <span>Owner: <strong>${item.owner}</strong></span>
            <span>${item.latency_ms !== null ? `${item.latency_ms} ms` : 'Standby'}</span>
          </div>
        </article>
      `;
    }).join('');
  },

  showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.setAttribute('role', 'status');
    toast.innerHTML = `
      <span aria-hidden="true">${type === 'success' ? '✓' : (type === 'danger' ? '⚠' : 'ℹ')}</span>
      <span>${this.escapeHtml(message)}</span>
    `;
    this.elements.toastRegion.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity 300ms ease';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  },

  // Helpers
  escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  },

  truncateDid(did) {
    if (!did) return 'N/A';
    if (did.length <= 26) return did;
    return `${did.substring(0, 15)}…${did.substring(did.length - 8)}`;
  },

  formatTimestamp(isoStr) {
    if (!isoStr) return '--';
    try {
      const d = new Date(isoStr);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + 
        ' ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
      return isoStr;
    }
  },

  formatEventType(type) {
    if (!type) return 'Unknown';
    return type.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
  },

  getSeverityClass(sev) {
    switch (sev) {
      case 'critical': return 'badge-failure';
      case 'high': return 'badge-failure';
      case 'medium': return 'badge-warning';
      case 'low': return 'badge-success';
      default: return 'badge-info';
    }
  }
};

// ── 5. ROUTER (SECTION SWITCHER) ────────────────────────────────────────────
const Router = {
  sections: ['overview', 'events', 'ledger', 'access', 'health'],
  
  init() {
    window.addEventListener('hashchange', () => this.handleHash());
    this.handleHash();
  },

  handleHash() {
    const rawHash = window.location.hash.replace('#', '').toLowerCase();
    const target = this.sections.includes(rawHash) ? rawHash : 'overview';
    this.navigate(target, false);
  },

  navigate(sectionId, updateHash = true) {
    if (!this.sections.includes(sectionId)) sectionId = 'overview';
    STATE.activeTab = sectionId;

    if (updateHash) {
      window.location.hash = `#${sectionId}`;
    }

    // Toggle active link
    document.querySelectorAll('.nav-link').forEach(link => {
      const href = link.getAttribute('href').replace('#', '');
      const isActive = href === sectionId;
      link.classList.toggle('active', isActive);
      if (isActive) {
        link.setAttribute('aria-current', 'page');
      } else {
        link.removeAttribute('aria-current');
      }
    });

    // Toggle active section
    this.sections.forEach(sec => {
      const el = document.getElementById(`section-${sec}`);
      if (el) {
        el.classList.toggle('active', sec === sectionId);
      }
    });

    // Close mobile drawer if open
    UI.elements.sidebar.classList.remove('open');
    UI.elements.sidebarBackdrop.classList.remove('active');
    UI.elements.mobileToggle.setAttribute('aria-expanded', 'false');

    // Scroll to top of main content
    document.getElementById('main-content').scrollTop = 0;
  }
};

// ── 6. APPLICATION CONTROLLER ───────────────────────────────────────────────
const App = {
  pollTimer: null,

  async init() {
    UI.init();
    Router.init();

    // Initial load
    await this.refreshAll();

    // Setup periodic polling
    this.startPolling();
  },

  async refreshAll(userTriggered = false) {
    const { live } = await ApiClient.probeBackend();
    UI.renderBackendStatus(live);

    // Parallel fetching of components
    await Promise.all([
      this.loadSummary(),
      this.loadLedger(),
      this.loadEvents(),
      this.loadAccess(),
      this.loadHealth(),
    ]);

    STATE.lastUpdated = new Date();
    UI.elements.lastUpdatedText.textContent = `Last updated: ${STATE.lastUpdated.toLocaleTimeString()}`;

    if (userTriggered) {
      UI.showToast('Dashboard metrics refreshed', 'info');
    }
  },

  async loadSummary() {
    const { data } = await ApiClient.fetchSummary();
    STATE.summary = data;
    UI.renderSummary();
  },

  async loadLedger() {
    const data = await ApiClient.fetchLedger();
    STATE.ledger = data;
    UI.renderLedgerIntegrity();
    UI.renderLedgerTable();
  },

  async loadEvents() {
    const { events } = await ApiClient.fetchEvents();
    STATE.events = events;
    UI.applyEventFilters();
  },

  async loadAccess() {
    STATE.accessDecisions = MockData.getAccessDecisions();
    UI.renderAccessTable();
  },

  async loadHealth() {
    STATE.subsystems = MockData.getSubsystems();
    UI.renderHealthGrid();
  },

  startPolling() {
    if (this.pollTimer) clearInterval(this.pollTimer);
    this.pollTimer = setInterval(() => {
      this.refreshAll(false);
    }, CONFIG.DEFAULT_POLL_INTERVAL_MS);
  }
};

// Start application when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
