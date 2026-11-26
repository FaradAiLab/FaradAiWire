export interface GatewayStatus {
  version?: string
  status: string
  active_filters: string[]
  active_filters_count: number
  gateway_id?: string
  ingress_port?: number
  ingress_host?: string
  ingress_url?: string
  guard_tier?: string
  guard_status?: {
    tier?: string
    custom_url?: string
    model?: string
    active?: boolean
  }
  guard_model?: string
  guard_endpoint?: string
  guard_latency_ms?: number
  hot_reload?: boolean
  allow_stdio?: boolean
  admin_auth_required?: boolean
}

export function isGuardActive(status?: GatewayStatus | null): boolean {
  return status?.guard_tier === 'neural_active' || Boolean(status?.guard_status?.active)
}

export interface SettingMeta {
  key: string
  category: 'limits' | 'timeouts' | 'guard' | 'maintenance' | string
  type?: 'int' | 'float' | 'string' | 'bool'
  data_type?: 'int' | 'float' | 'string' | 'bool'
  label: string
  description: string
  unit?: string
  min?: number
  max?: number
  step?: number
}

export interface SettingItem extends SettingMeta {
  value: any
  is_overridden: boolean
}

export interface SettingsResponse {
  status: string
  categories: string[]
  settings: SettingItem[]
}

export interface SecurityFiltersConfig {
  prefill_block: boolean
  rate_limiting: boolean
  loop_protection: boolean
  schema_validation: boolean
  dlp: boolean
  guard: boolean
  hitl: boolean
}

export function isAdminRole(role?: string): boolean {
  return (role || '').trim().toLowerCase() === 'admin'
}

export interface ApiKeyItem {
  id: string
  name: string
  agent_name?: string
  prefix: string
  key_prefix?: string
  raw_key?: string
  role?: string
  created_at: string
  last_used_at?: string
  revoked?: boolean
}

export interface CreatedApiKey {
  id: string
  name: string
  agent_name?: string
  api_key: string
  raw_key?: string
  key: string
  prefix?: string
  key_prefix?: string
  role?: string
  created_at?: string
}

export interface ProtocolConfig {
  id?: string
  protocol_id?: string
  name?: string
  protocol_name?: string
  description?: string
  type: string // "stdio", "sse", "http"
  command?: string
  args?: string[]
  env?: string[]
  url_or_command?: string
  auth_token?: string
  headers?: Record<string, string>
  allowed_tools?: string[]
}

export interface ToolMetadata {
  name: string
  raw_name?: string
  canonical_name?: string
  protocol_name?: string
  protocol_id?: string
  description?: string
  inputSchema?: Record<string, unknown>
}

export type ToolGovernanceMode =
  | 'autonomous'
  | 'guarded_block'
  | 'guarded_hitl'
  | 'strict_always_hitl'

export interface ToolOverrides {
  enabled_tools?: string[]
}

export interface RateLimitOverride {
  enabled?: boolean
  max_burst: number
  refill_rate: number
}

export interface LoopProtectionOverride {
  enabled: boolean
  max_repeat: number
  window_seconds: number
  exclude_tools?: string[]
}

export type FilterEnforcementMode = 'enforce' | 'audit' | 'off'

export interface SchemaValidationOverride {
  mode: FilterEnforcementMode
}

export interface GuardOverride {
  mode: FilterEnforcementMode
}

export interface AgentConfig {
  agent_id: string
  agent_name: string
  description?: string
  routing_mode: string // "aggregated" | "direct"
  protocols?: ProtocolConfig[]
  enabled_tools?: string[]
  tool_overrides?: ToolOverrides
  tool_governance?: Record<string, ToolGovernanceMode>
  retained_governance?: Record<string, Record<string, ToolGovernanceMode>>
  rate_limit?: RateLimitOverride
  loop_protection?: LoopProtectionOverride
  schema_validation?: SchemaValidationOverride
  guard?: GuardOverride
}

export interface AgentItem {
  name: string
  routing_mode: string
  config: AgentConfig
  tools?: ToolMetadata[]
  effective_tools?: ToolMetadata[]
  status: string
}

export interface ProtocolItem {
  id: string
  protocol_id?: string
  name: string
  protocol_name?: string
  description?: string
  type: string
  command?: string
  args?: string[]
  env?: string[]
  url_or_command?: string
  auth_token?: string
  headers?: Record<string, string>
  allowed_tools?: string[]
  status?: string
  created_at?: string
  updated_at?: string
}

export interface ToolSchemaRecord {
  tool_name: string
  protocol_id?: string
  schema_json: Record<string, unknown> | unknown
  sha256_hash: string
  first_seen_at?: string
  last_seen_at?: string
  is_pinned?: boolean
}

export interface PresetMetadata {
  id: string
  name: string
  description?: string
  category: 'devops' | 'data' | 'web' | 'productivity' | 'memory' | string
  type: string
  command?: string
  args?: string[]
  url?: string
  env_requirements?: string[]
  icon?: string
  doc_url?: string
}

export interface AuditEvent {
  id?: string
  timestamp: string
  trace_id?: string
  method?: string
  event_type: string
  severity: 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL' | 'AUDIT'
  decision?: string
  layer?: string
  action?: string
  agent?: string
  client_session_id?: string
  tool_name?: string
  phase?: string
  request_decision?: string
  response_decision?: string
  matched_rule?: string
  audited_rules?: string[]
  latency_ms?: number
  input_size_bytes?: number
  output_size_bytes?: number
  payload_preview?: string
  raw_payload_preview?: string
  original_payload?: string
  original_payload_preview?: string
  original_request?: string
  request?: string
  original_response?: string
  response?: string
  error_message?: string
  details?: Record<string, unknown>
  error?: string
  user_id?: string
  client_ip?: string
  api_key_id?: string
  human_approved?: boolean
  approved_by?: string
  approval_channel?: string
  hash_version?: string
  integrity_hash?: string
}

export type AnalyticsWindow = '1h' | '24h' | '7d'

export interface DroppedEventsStats {
  duckdb: number
  broker: number
  jsonl: number
  total: number
}

export interface AnalyticsSummary {
  enabled: boolean
  window: AnalyticsWindow | string
  generated_at?: string
  total_calls: number
  allowed_count: number
  blocked_count: number
  masked_count: number
  audit_count: number
  error_count: number
  block_rate: number
  p50_latency_ms: number
  p95_latency_ms: number
  p99_latency_ms: number
  top_rules: { rule: string; count: number }[]
  top_tools: { tool_name: string; count: number }[]
  dropped_events: DroppedEventsStats
  guard_latency_ms: number
}

export interface SecurityAuditRecord {
  id: string
  timestamp: string
  trace_id?: string
  event_type: string
  actor_id: string
  actor_role: string
  client_ip?: string
  resource_type?: string
  resource_id?: string
  action: string
  outcome: string
  reason?: string
  metadata?: Record<string, unknown>
  hash_version?: string
  integrity_hash: string
}

export interface TableIntegrityReport {
  checked: number
  v2_verified: number
  legacy_v1: number
  tampered_count?: number
  tampered_ids?: string[]
}

export interface SegmentVerifyError {
  segment: string
  line?: number
  reason: string
}

export interface AuditVerifyResponse {
  valid: boolean
  duckdb?: {
    valid: boolean
    hmac_enabled: boolean
    tool_audit_logs: TableIntegrityReport
    tool_audit_responses: TableIntegrityReport
    security_audit_logs: TableIntegrityReport
  }
  jsonl?: {
    valid: boolean
    segments_checked: number
    entries_checked: number
    hmac_enabled: boolean
    broken_segments?: SegmentVerifyError[]
  }
}

export interface ReadyzResponse {
  status: string
  draining: boolean
  components: Record<string, unknown>
}

export interface AuditQuerySummary {
  total: number
  allowed: number
  masked: number
  audit: number
  blocked: number
  avg_latency_ms: number
}

export interface AuditLogsQueryParams {
  limit?: number
  offset?: number
  decision?: string
  agent_name?: string
  tool_name?: string
  trace_id?: string
  matched_rule?: string
  q?: string
  since?: string
  until?: string
  summary?: boolean
}

export interface SecurityAuditQueryParams {
  limit?: number
  offset?: number
  event_type?: string
  actor_id?: string
  outcome?: string
  since?: string
  until?: string
}

export interface HITLApprovalRequest {
  call_id: string
  tool_name: string
  arguments: Record<string, unknown>
  risk_score: number
  threat_domain: string
  cwe: string
  decision_engine: string
  created_at: string
  expires_at: string
}

export type GuardInstallStatus = 'NOT_INSTALLED' | 'INSTALLING' | 'INSTALLED' | 'FAILED'
export type GuardThreatAction = 'hitl' | 'block'

export interface GuardModel {
  id: string
  name: string
  family: string
  paradigm?: 'generative_llm' | 'decision_model'
  parameter_size: string
  ram_required_mb: number
  disk_size_mb: number
  description: string
  recommended_for: string
  benchmark_accuracy: number
  benchmark_fp_rate: number
  benchmark_avg_latency_ms: number
  benchmark_p95_latency_ms: number
  num_layers?: number
  num_kv_heads?: number
  head_dim?: number
  context_window?: number
  install_status: GuardInstallStatus
  is_active: boolean
  default_action: GuardThreatAction
  critical_tools_json: string
  source_url: string
  ollama_source?: string
  docker_image?: string
  endpoint_url?: string
  runtime_type?: 'docker' | 'ollama'
  entrypoint_script?: string
  installed_at?: string
  updated_at: string
}

export interface HostResources {
  total_bytes: number
  available_bytes: number
  used_bytes: number
  swap_total_bytes: number
  swap_used_bytes: number
  cpu_percent: number
  cgroup_limited: boolean
  ollama_rss_bytes: number
}

export interface GuardProcessStatus {
  running: boolean
  model_id?: string
  pid: number
  memory_rss_mb: number
  health_status: 'HEALTHY' | 'DEGRADED' | 'STOPPED' | 'FAILED' | string
  started_at?: string
}

export interface GuardInstallProgress {
  model_id: string
  status: GuardInstallStatus
  step: string
  progress: number
  message?: string
  error?: string
  updated_at: string
}

// DLP & Policy Governance Types
export type DlpAction = 'mask' | 'block' | 'audit' | 'hitl'

export interface DlpRule {
  id: string
  name: string
  description: string
  category: string
  regex: string
  default_action: DlpAction
  cwe?: string
  severity?: string
  is_builtin: boolean
  created_at?: string
  updated_at?: string
}

export interface PolicyPack {
  id: string
  name: string
  description: string
  category: string
  rule_ids: string[]
  rules?: DlpRule[]
  is_builtin: boolean
  created_at?: string
  updated_at?: string
}

export interface RuleOverride {
  rule_id: string
  action: DlpAction
  enabled: boolean
}

export interface CustomPattern {
  name: string
  regex: string
  action: DlpAction
}

export interface ToolExemption {
  request: boolean
  response: boolean
}

export interface AgentDlpConfig {
  agent_name: string
  pack_ids: string[]
  overrides: RuleOverride[]
  custom_patterns: CustomPattern[]
  tool_exemptions?: Record<string, ToolExemption>
  created_at?: string
  updated_at?: string
}

export interface EffectiveRule {
  rule_id: string
  name: string
  description: string
  category: string
  regex: string
  default_action: DlpAction
  resolved_action: DlpAction
  effective_action: DlpAction
  is_bypassed: boolean
  is_overridden: boolean
  source_pack_ids: string[]
}

export interface CompiledAgentPolicy {
  agent_name: string
  enabled: boolean
  effective_rules: EffectiveRule[]
  custom_patterns: CustomPattern[]
  tool_exemptions: Record<string, ToolExemption>
}

export interface SmartRecommendation {
  pack_id: string
  pack_name: string
  rationale: string
  matched_tools?: string[]
}

export interface RecommendationRequest {
  protocol_types?: string[]
  protocol_names?: string[]
  tool_names?: string[]
  attached_packs?: string[]
}

export type ThemeMode = 'system' | 'light' | 'dark'

