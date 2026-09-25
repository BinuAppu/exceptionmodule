export type UserRole = 'user' | 'approver' | 'admin';
export type RequestStatus =
  | 'draft'
  | 'submitted'
  | 'pending_manager_approval'
  | 'manager_approved'
  | 'manager_rejected'
  | 'pending_delivery_head_approval'
  | 'delivery_head_approved'
  | 'delivery_head_rejected'
  | 'pending_approver_review'
  | 'clarification_required'
  | 'approved'
  | 'rejected'
  | 'active'
  | 'extension_requested'
  | 'extension_pending_approval'
  | 'expired'
  | 'cancelled'
  | 'withdrawn'
  | 'closed';
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type ApprovalAction = 'approve' | 'reject' | 'clarification';

export interface User {
  id: string;
  public_id?: string;
  email: string;
  full_name: string;
  display_name?: string;
  department?: string | null;
  job_title?: string | null;
  must_change_password?: boolean;
  is_break_glass?: boolean;
  mfa_enabled?: boolean;
  role: UserRole;
  roles?: UserRole[];
  is_active: boolean;
  last_login_at?: string | null;
  created_at?: string;
}

export interface AdminUser {
  id: string;
  public_id: string;
  email: string;
  display_name: string;
  department?: string | null;
  job_title?: string | null;
  manager_id?: string | null;
  status: 'active' | 'disabled' | 'locked';
  roles: UserRole[];
  is_break_glass: boolean;
  last_login_at?: string | null;
  version: number;
}

export interface AuthConfiguration {
  sso_enabled: boolean;
  sso_provider?: 'oidc' | 'saml' | null;
  sso_display_name?: string | null;
  local_break_glass_enabled: boolean;
  password_minimum_length: number;
}

export interface AuthSession {
  user: Omit<User, 'role' | 'is_active' | 'id' | 'full_name'> & {
    public_id: string;
    display_name: string;
  };
  roles: UserRole[];
  permissions: string[];
  csrf_token: string;
  idle_expires_at: string;
  absolute_expires_at: string;
}

export interface Category {
  id: string;
  code: string;
  name: string;
  description?: string | null;
  default_duration_days?: number | null;
  maximum_duration_days?: number | null;
  display_order: number;
  active: boolean;
  system: boolean;
  version: number;
}

export interface System {
  id: string;
  name: string;
  description?: string | null;
  owner?: string | null;
  is_active?: boolean;
}

export interface Control {
  id: string;
  name: string;
  description?: string | null;
  owner?: string | null;
}

export interface CustomField {
  id: string;
  label: string;
  field_type: 'text' | 'textarea' | 'select' | 'date' | 'number' | 'checkbox';
  options?: Array<{ label: string; value: string }>;
  required?: boolean;
  applies_to?: string[];
  order?: number;
  is_active?: boolean;
}

export type AdminFieldDataType =
  | 'text'
  | 'long_text'
  | 'number'
  | 'date'
  | 'datetime'
  | 'boolean'
  | 'dropdown'
  | 'multi_select'
  | 'user_selector'
  | 'application_selector'
  | 'attachment'
  | 'url';

export interface AdminField {
  id: string;
  key: string;
  label: string;
  description?: string | null;
  data_type: AdminFieldDataType;
  required: boolean;
  default_value?: unknown;
  placeholder?: string | null;
  validation: Record<string, unknown>;
  allowed_values: unknown[];
  visible_roles: string[];
  visible_categories: string[];
  editable_after_submission: boolean;
  display_order: number;
  active: boolean;
  version: number;
}

export interface RequestSummary {
  public_id: string;
  title: string;
  exception_type: string;
  category_name: string;
  requester_id: string;
  requester_name: string;
  department: string;
  application_name: string;
  environment: string;
  data_classification_code: string;
  risk_level: RiskLevel;
  status: RequestStatus;
  current_stage_key?: string | null;
  requested_start_date: string;
  expiry_date: string;
  extension_count: number;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface Attachment {
  id: string;
  original_filename: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  scan_status: string;
  evidence_type?: string | null;
  provided_by?: string | null;
  provided_at?: string | null;
  created_at: string;
}

export interface ApprovalRecord {
  id: string;
  stage_key: string;
  stage_name: string;
  approver_id: string;
  approver_name: string;
  delegated_from_id?: string | null;
  delegated_from_name?: string | null;
  status: 'pending' | 'clarification' | 'approved' | 'rejected' | 'cancelled';
  due_at: string;
  completed_at?: string | null;
  decision?: string | null;
  decision_comment?: string | null;
}

export interface RequestComment {
  id: string;
  author_id: string;
  author_name: string;
  kind: string;
  body: string;
  is_clarification_response: boolean;
  created_at: string;
}

export interface RequestAuditEvent {
  id: string;
  timestamp: string;
  actor?: string | null;
  action: string;
  result: string;
  summary: string;
  event_hash: string;
}

export interface AuditEvent {
  id: string;
  action: string;
  actor?: Pick<User, 'id' | 'full_name' | 'email'> | null;
  entity_type?: string;
  entity_id?: string;
  changes?: Record<string, { before?: unknown; after?: unknown }> | null;
  ip_address?: string | null;
  created_at: string;
}

export interface AIAnalysis {
  id: string;
  feature: string;
  status: string;
  prompt_version: string;
  risk_level?: string | null;
  confidence?: number | null;
  output: Record<string, unknown>;
  created_at: string;
  completed_at?: string | null;
  disclaimer: string;
}

export interface RequestDetail extends RequestSummary {
  description: string;
  business_justification: string;
  manager_id?: string | null;
  manager_name?: string | null;
  application_service_id?: string | null;
  application_owner?: string | null;
  business_owner: string;
  technology_owner: string;
  asset_system: string;
  cloud_account?: string | null;
  information_sensitivity?: string | null;
  regulatory_impact?: string | null;
  control_excepted: string;
  current_control: string;
  requested_exception: string;
  reason_control_cannot_follow: string;
  risk_description: string;
  business_impact: string;
  security_impact: string;
  compensating_controls: string;
  remediation_plan: string;
  remediation_owner_id?: string | null;
  remediation_owner_name?: string | null;
  remediation_target_date?: string | null;
  remediation_status: string;
  remediation_progress: number;
  remediation_closure_date?: string | null;
  requested_duration_days: number;
  additional_comments?: string | null;
  original_expiry_date: string;
  submitted_at?: string | null;
  activated_at?: string | null;
  expired_at?: string | null;
  closed_at?: string | null;
  approvals: ApprovalRecord[];
  comments: RequestComment[];
  attachments: Attachment[];
  custom_fields: Record<string, unknown>;
  ai_analyses: AIAnalysis[];
  audit_timeline: RequestAuditEvent[];
  can_edit?: boolean;
  can_decide_assignment_id?: string | null;
}

export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface DashboardSummary {
  total: number;
  drafts: number;
  pending: number;
  active: number;
  expiring_30_days: number;
  expired: number;
  extensions: number;
  pending_approvals?: number;
  sla_breaches?: number;
  status_counts: Array<{ status: RequestStatus; count: number }>;
  risk_counts: Array<{ risk: string; count: number }>;
  category_counts: Array<{ category: string; count: number }>;
}

export interface RiskLevelOption {
  id: string;
  code: RiskLevel;
  name: string;
  score: number;
  description: string;
}

export interface DataClassificationOption {
  code: string;
  name: string;
  rank: number;
  allow_ai: boolean;
  allow_export: boolean;
}

export interface FormOptions {
  categories: Category[];
  risk_levels: RiskLevelOption[];
  data_classifications: string[];
  data_classification_options: DataClassificationOption[];
  custom_fields: Array<Omit<AdminField, 'active' | 'version'> & {
    active?: boolean;
    is_active?: boolean;
    version?: number;
  }>;
  templates: RequestTemplate[];
  departments: string[];
}

export interface ApprovalQueueItem {
  assignment_id: string;
  request_id: string;
  title: string;
  stage_name: string;
  status: 'pending' | 'clarification';
  due_at: string;
  risk_level: RiskLevel;
  category: string;
  requester_name: string;
  application_name: string;
  data_classification_code: string;
  delegated: boolean;
}

export interface ApprovalSummary {
  pending_total: number;
  due_today: number;
  overdue: number;
  high_risk: number;
}

export interface ReportSummary {
  period_start: string;
  period_end: string;
  total_requests: number;
  approved: number;
  rejected: number;
  pending: number;
  overdue: number;
  median_approval_days?: number | null;
  status_breakdown: Array<{ status: RequestStatus; count: number }>;
  risk_breakdown: Array<{ risk: RiskLevel; count: number }>;
  category_breakdown: Array<{ category: string; count: number }>;
  department_breakdown: Array<{ department: string; count: number }>;
  monthly_volume: Array<{ month: string; count: number; approved: number }>;
}

export interface WorkflowStage {
  id: string;
  name: string;
  description?: string | null;
  approver_role?: UserRole | null;
  approver_ids?: string[];
  sequence: number;
  is_active: boolean;
}

export interface Workflow {
  id: string;
  name: string;
  description?: string | null;
  category_id?: string | null;
  is_default: boolean;
  is_active: boolean;
  stages: WorkflowStage[];
}

export interface RequestTemplate {
  id: string;
  name: string;
  description?: string | null;
  category_id?: string | null;
  is_active: boolean;
  default_values?: Record<string, unknown>;
  updated_at?: string;
}

export interface AppSettings {
  organization_name: string;
  support_email?: string;
  default_review_days: number;
  default_exception_days: number;
  reminder_days_before_expiry: number;
  require_mfa_for_approvers: boolean;
  session_timeout_minutes: number;
  password_policy?: Record<string, unknown>;
  updated_at?: string;
}

export interface SecuritySettings {
  mfa_required: boolean;
  sso_enabled: boolean;
  sso_provider?: string | null;
  local_login_enabled: boolean;
  password_minimum_length: number;
  session_timeout_minutes: number;
  ip_allowlist_enabled?: boolean;
  audit_retention_days?: number;
}

export type SsoProvider = 'oidc' | 'saml';

export interface SsoSettings {
  version: number;
  provider: SsoProvider;
  enabled: boolean;
  display_name: string;
  issuer: string;
  client_id: string;
  scopes: string;
  redirect_uri: string;
  required_acr: string;
  email_claim: string;
  name_claim: string;
  tenant_claim: string;
  tenant_value: string;
  allowed_domains: string[];
  auto_provision: boolean;
  idp_entity_id: string;
  sso_url: string;
  idp_x509_certificate: string;
  email_attribute: string;
  name_attribute: string;
  sp_entity_id: string;
  acs_url: string;
  client_secret_configured: boolean;
  signing_key_configured: boolean;
  metadata_url?: string | null;
  updated_at?: string | null;
}

export interface SsoValidationResult {
  valid: boolean;
  provider: SsoProvider;
  checks: Record<string, boolean>;
  errors?: string[];
  warnings?: string[];
}

export interface AISettings {
  enabled: boolean;
  provider?: string;
  model?: string;
  data_retention_enabled?: boolean;
  require_human_approval?: boolean;
  prompt_version?: string;
  updated_at?: string;
}

export interface AuditLog extends AuditEvent {
  ip_address?: string | null;
  user_agent?: string | null;
}

export interface Backup {
  id: string;
  filename: string;
  size?: number;
  created_at: string;
  created_by?: Pick<User, 'id' | 'full_name'> | null;
  status: 'completed' | 'failed' | 'in_progress';
  retention_until?: string | null;
}
