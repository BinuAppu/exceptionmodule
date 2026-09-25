import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, Check, FileText, Info, Paperclip, Save, Send, ShieldCheck, Trash2 } from 'lucide-react';
import { useEffect, useMemo, useState, type ChangeEvent, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Button, ErrorState, InlineError, LoadingState, PageHeader } from '../components/common';
import { useAuth } from '../contexts/AuthContext';
import { useToast } from '../contexts/ToastContext';
import { apiRequest } from '../lib/api';
import { formatFileSize } from '../lib/format';
import type { FormOptions, RequestDetail, UserRole } from '../types/api';

interface RequestCreatePayload {
  title: string;
  description: string;
  business_justification: string;
  category_id: string;
  exception_type: string;
  department: string;
  application_name: string;
  application_service_id: string | null;
  application_owner: string | null;
  business_owner: string;
  technology_owner: string;
  environment: string;
  asset_system: string;
  cloud_account: string | null;
  data_classification_code: string;
  information_sensitivity: string | null;
  regulatory_impact: string | null;
  control_excepted: string;
  current_control: string;
  requested_exception: string;
  reason_control_cannot_follow: string;
  risk_description: string;
  business_impact: string;
  security_impact: string;
  compensating_controls: string;
  remediation_plan: string;
  remediation_owner_id: null;
  remediation_target_date: string | null;
  requested_start_date: string;
  requested_expiry_date: string;
  risk_level_id: string;
  additional_comments: string | null;
  custom_fields: Record<string, unknown>;
}

type Intent = 'draft' | 'submit';
type FormErrors = Record<string, string | undefined>;

const requiredFields = [
  'title',
  'description',
  'business_justification',
  'category_id',
  'exception_type',
  'department',
  'application_name',
  'business_owner',
  'technology_owner',
  'environment',
  'asset_system',
  'data_classification_code',
  'control_excepted',
  'current_control',
  'requested_exception',
  'reason_control_cannot_follow',
  'risk_description',
  'business_impact',
  'security_impact',
  'compensating_controls',
  'remediation_plan',
  'requested_start_date',
  'requested_expiry_date',
  'risk_level_id',
] as const;

const minimumLengths: Record<string, number> = {
  description: 20,
  business_justification: 20,
  current_control: 10,
  requested_exception: 10,
  reason_control_cannot_follow: 10,
  risk_description: 10,
  business_impact: 5,
  security_impact: 5,
  compensating_controls: 10,
  remediation_plan: 10,
};

export default function NewRequestPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const { showToast } = useToast();
  const optionsQuery = useQuery({
    queryKey: ['request-form-options'],
    queryFn: () => apiRequest<FormOptions>('/request-form-options'),
  });
  const [files, setFiles] = useState<File[]>([]);
  const [categoryId, setCategoryId] = useState('');
  const [customValues, setCustomValues] = useState<Record<string, unknown>>({});
  const [errors, setErrors] = useState<FormErrors>({});
  const [attested, setAttested] = useState(false);

  const options = optionsQuery.data;
  const roles = useMemo<UserRole[]>(() => user?.roles?.length ? user.roles : user ? [user.role] : [], [user]);

  useEffect(() => {
    if (!options) return;
    setCustomValues((current) => {
      if (Object.keys(current).length) return current;
      return Object.fromEntries(
        options.custom_fields
          .filter((field) => (field.active ?? field.is_active ?? true))
          .filter((field) => !field.visible_roles.length || field.visible_roles.some((role) => roles.includes(role as UserRole)))
          .map((field) => [field.key, field.default_value ?? (field.data_type === 'multi_select' ? [] : field.data_type === 'boolean' ? false : '')]),
      );
    });
  }, [options, roles]);

  const mutation = useMutation({
    mutationFn: async ({ payload, intent, attachments }: { payload: RequestCreatePayload; intent: Intent; attachments: File[] }) => {
      const created = await apiRequest<RequestDetail>('/requests', { method: 'POST', body: payload });
      for (const file of attachments) {
        const form = new FormData();
        form.append('file', file);
        form.append('evidence_type', 'supporting_evidence');
        try {
          await apiRequest(`/requests/${created.public_id}/attachments`, { method: 'POST', body: form });
        } catch (error) {
          throw new Error(`Draft ${created.public_id} was created, but an attachment failed to upload: ${error instanceof Error ? error.message : 'upload failed'}`);
        }
      }
      if (intent === 'submit') {
        try {
          return await apiRequest<RequestDetail>(`/requests/${created.public_id}/submit`, {
            method: 'POST',
            body: { expected_version: created.version, attestation: true },
          });
        } catch (error) {
          throw new Error(`Draft ${created.public_id} was created, but submission failed: ${error instanceof Error ? error.message : 'submission failed'}`);
        }
      }
      return created;
    },
    onSuccess: async (request, variables) => {
      await queryClient.invalidateQueries({ queryKey: ['requests'] });
      await queryClient.invalidateQueries({ queryKey: ['dashboard'] });
      showToast(variables.intent === 'submit' ? 'Request submitted for review.' : 'Complete request saved as a draft.', 'success');
      navigate(`/requests/${request.public_id}`);
    },
  });

  const activeFields = useMemo(() => {
    if (!options) return [];
    return options.custom_fields
      .filter((field) => (field.active ?? field.is_active ?? true))
      .filter((field) => !field.visible_roles.length || field.visible_roles.some((role) => roles.includes(role as UserRole)))
      .filter((field) => !categoryId || !field.visible_categories.length || field.visible_categories.map(String).includes(categoryId))
      .sort((a, b) => a.display_order - b.display_order);
  }, [options, roles, categoryId]);

  if (optionsQuery.isLoading) return <div className="page form-page"><PageHeader eyebrow="Exception register" title="New exception request" /><LoadingState label="Loading request form…" rows={8} /></div>;
  if (optionsQuery.isError || !options) return <div className="page form-page"><PageHeader eyebrow="Exception register" title="New exception request" /><ErrorState error={optionsQuery.error ?? new Error('Request options are unavailable')} onRetry={() => void optionsQuery.refetch()} title="The request form could not be loaded" /></div>;

  const setError = (name: string, message?: string) => setErrors((current) => ({ ...current, [name]: message }));
  const value = (form: FormData, name: string) => String(form.get(name) ?? '').trim();
  const nullable = (form: FormData, name: string) => value(form, name) || null;

  const validate = (form: FormData): boolean => {
    const next: FormErrors = {};
    requiredFields.forEach((name) => {
      if (!value(form, name)) next[name] = 'This field is required.';
    });
    Object.entries(minimumLengths).forEach(([name, minimum]) => {
      if (value(form, name) && value(form, name).length < minimum) next[name] = `Enter at least ${minimum} characters.`;
    });
    if (value(form, 'requested_start_date') && value(form, 'requested_expiry_date') && new Date(value(form, 'requested_expiry_date')) < new Date(value(form, 'requested_start_date'))) {
      next.requested_expiry_date = 'Expiry must be on or after the start date.';
    }
    activeFields.filter((field) => field.required).forEach((field) => {
      const current = customValues[field.key];
      if (current === undefined || current === null || current === '' || (Array.isArray(current) && current.length === 0)) {
        next[`custom_${field.key}`] = 'This field is required.';
      }
    });
    setErrors(next);
    return Object.keys(next).length === 0;
  };

  const buildPayload = (form: FormData): RequestCreatePayload => ({
    title: value(form, 'title'),
    description: value(form, 'description'),
    business_justification: value(form, 'business_justification'),
    category_id: value(form, 'category_id'),
    exception_type: value(form, 'exception_type'),
    department: value(form, 'department'),
    application_name: value(form, 'application_name'),
    application_service_id: nullable(form, 'application_service_id'),
    application_owner: nullable(form, 'application_owner'),
    business_owner: value(form, 'business_owner'),
    technology_owner: value(form, 'technology_owner'),
    environment: value(form, 'environment'),
    asset_system: value(form, 'asset_system'),
    cloud_account: nullable(form, 'cloud_account'),
    data_classification_code: value(form, 'data_classification_code'),
    information_sensitivity: nullable(form, 'information_sensitivity'),
    regulatory_impact: nullable(form, 'regulatory_impact'),
    control_excepted: value(form, 'control_excepted'),
    current_control: value(form, 'current_control'),
    requested_exception: value(form, 'requested_exception'),
    reason_control_cannot_follow: value(form, 'reason_control_cannot_follow'),
    risk_description: value(form, 'risk_description'),
    business_impact: value(form, 'business_impact'),
    security_impact: value(form, 'security_impact'),
    compensating_controls: value(form, 'compensating_controls'),
    remediation_plan: value(form, 'remediation_plan'),
    remediation_owner_id: null,
    remediation_target_date: nullable(form, 'remediation_target_date'),
    requested_start_date: value(form, 'requested_start_date'),
    requested_expiry_date: value(form, 'requested_expiry_date'),
    risk_level_id: value(form, 'risk_level_id'),
    additional_comments: nullable(form, 'additional_comments'),
    custom_fields: Object.fromEntries(activeFields.map((field) => [field.key, customValues[field.key]])),
  });

  const process = (form: HTMLFormElement, intent: Intent) => {
    const formData = new FormData(form);
    if (!validate(formData)) {
      showToast('Review the highlighted fields before saving.', 'error');
      document.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus();
      return;
    }
    if (intent === 'submit' && !attested) {
      setError('attestation', 'Confirm the requester attestation before submitting.');
      showToast('Confirm the requester attestation before submitting.', 'error');
      return;
    }
    mutation.mutate({ payload: buildPayload(formData), intent, attachments: files });
  };

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    process(event.currentTarget, 'submit');
  };

  const saveDraft = (event: React.MouseEvent<HTMLButtonElement>) => {
    const form = event.currentTarget.closest('form');
    if (form) process(form, 'draft');
  };

  const handleFiles = (event: ChangeEvent<HTMLInputElement>) => setFiles(Array.from(event.target.files ?? []));
  const defaultRisk = options.risk_levels.find((risk) => risk.code === 'medium')?.id ?? options.risk_levels[0]?.id ?? '';
  const classificationOptions = options.data_classification_options;
  const defaultClassification = classificationOptions.find((item) => item.code === 'Internal')?.code ?? classificationOptions[0]?.code ?? '';

  return (
    <div className="page form-page">
      <Link className="back-link" to="/requests"><ArrowLeft size={17} />Back to requests</Link>
      <PageHeader eyebrow="Exception register" title="New exception request" description="Provide enough context for approvers to make an accountable decision. Drafts and submissions use the same validated baseline." />
      <form className="request-form" onSubmit={submit} noValidate>
        <div className="request-form__main">
          <FormSection number="1" title="Request context" description="Identify the business need and accountable owners.">
            <div className="form-grid form-grid--2">
              <Field id="title" label="Request title" required error={errors.title} help="A concise, specific description."><input id="title" name="title" required maxLength={240} defaultValue="" aria-invalid={Boolean(errors.title)} onChange={() => setError('title')} /></Field>
              <Field id="exception_type" label="Exception type" required error={errors.exception_type}><input id="exception_type" name="exception_type" required maxLength={120} aria-invalid={Boolean(errors.exception_type)} onChange={() => setError('exception_type')} placeholder="Policy exception" /></Field>
              <Field id="category_id" label="Category" required error={errors.category_id}><select id="category_id" name="category_id" required value={categoryId} aria-invalid={Boolean(errors.category_id)} onChange={(event) => { setCategoryId(event.target.value); setError('category_id'); }}><option value="">Select a category</option>{options.categories.filter((category) => category.active).map((category) => <option value={category.id} key={category.id}>{category.name}</option>)}</select></Field>
              <Field id="department" label="Department" required error={errors.department}><input id="department" name="department" required maxLength={160} defaultValue={user?.department ?? ''} aria-invalid={Boolean(errors.department)} onChange={() => setError('department')} /></Field>
              <div className="field field--span-2"><label htmlFor="description">Executive summary <span aria-hidden="true">*</span></label><textarea id="description" name="description" rows={3} required minLength={20} maxLength={30000} aria-invalid={Boolean(errors.description)} onChange={() => setError('description')} placeholder="What is being requested, by whom, and why now?" /><InlineError message={errors.description} /></div>
              <div className="field field--span-2"><label htmlFor="business_justification">Business justification <span aria-hidden="true">*</span></label><textarea id="business_justification" name="business_justification" rows={5} required minLength={20} maxLength={30000} aria-invalid={Boolean(errors.business_justification)} onChange={() => setError('business_justification')} placeholder="Explain why the normal policy or process cannot meet the business need." /><InlineError message={errors.business_justification} /></div>
              <div className="field field--span-2"><label htmlFor="business_impact">Business impact <span aria-hidden="true">*</span></label><textarea id="business_impact" name="business_impact" rows={3} required minLength={5} maxLength={30000} aria-invalid={Boolean(errors.business_impact)} onChange={() => setError('business_impact')} placeholder="Describe the expected benefit and impact of proceeding." /><InlineError message={errors.business_impact} /></div>
            </div>
          </FormSection>

          <FormSection number="2" title="Application and ownership" description="Identify the affected technology asset and accountable owners.">
            <div className="form-grid form-grid--2">
              <Field id="application_name" label="Application name" required error={errors.application_name}><input id="application_name" name="application_name" required maxLength={200} aria-invalid={Boolean(errors.application_name)} onChange={() => setError('application_name')} /></Field>
              <Field id="application_service_id" label="Service / asset ID"><input id="application_service_id" name="application_service_id" maxLength={120} /></Field>
              <Field id="application_owner" label="Application owner"><input id="application_owner" name="application_owner" maxLength={200} /></Field>
              <Field id="asset_system" label="Affected asset or system" required error={errors.asset_system}><input id="asset_system" name="asset_system" required maxLength={240} aria-invalid={Boolean(errors.asset_system)} onChange={() => setError('asset_system')} /></Field>
              <Field id="business_owner" label="Business owner" required error={errors.business_owner}><input id="business_owner" name="business_owner" required maxLength={200} defaultValue={user?.full_name ?? ''} aria-invalid={Boolean(errors.business_owner)} onChange={() => setError('business_owner')} /></Field>
              <Field id="technology_owner" label="Technology owner" required error={errors.technology_owner}><input id="technology_owner" name="technology_owner" required maxLength={200} aria-invalid={Boolean(errors.technology_owner)} onChange={() => setError('technology_owner')} /></Field>
              <Field id="environment" label="Environment" required error={errors.environment}><select id="environment" name="environment" required defaultValue="" aria-invalid={Boolean(errors.environment)} onChange={() => setError('environment')}><option value="">Select environment</option><option value="Development">Development</option><option value="Test">Test</option><option value="Staging">Staging</option><option value="Production">Production</option></select></Field>
              <Field id="cloud_account" label="Cloud account"><input id="cloud_account" name="cloud_account" maxLength={200} /></Field>
            </div>
          </FormSection>

          <FormSection number="3" title="Data, risk, and impact" description="Record the data classification and an accountable inherent-risk assessment.">
            <div className="form-grid form-grid--2">
              <Field id="data_classification_code" label="Data classification" required error={errors.data_classification_code}><select id="data_classification_code" name="data_classification_code" required defaultValue={defaultClassification} aria-invalid={Boolean(errors.data_classification_code)} onChange={() => setError('data_classification_code')}>{classificationOptions.map((item) => <option value={item.code} key={item.code}>{item.name}</option>)}</select></Field>
              <Field id="risk_level_id" label="Inherent risk" required error={errors.risk_level_id}><select id="risk_level_id" name="risk_level_id" required defaultValue={defaultRisk} aria-invalid={Boolean(errors.risk_level_id)} onChange={() => setError('risk_level_id')}>{options.risk_levels.filter((risk) => risk.score >= 0).map((risk) => <option value={risk.id} key={risk.id}>{risk.name} ({risk.score})</option>)}</select></Field>
              <Field id="information_sensitivity" label="Information sensitivity"><input id="information_sensitivity" name="information_sensitivity" maxLength={120} /></Field>
              <div className="field"><label htmlFor="regulatory_impact">Regulatory impact</label><textarea id="regulatory_impact" name="regulatory_impact" rows={3} maxLength={10000} /></div>
              <div className="field field--span-2"><label htmlFor="risk_description">Risk description <span aria-hidden="true">*</span></label><textarea id="risk_description" name="risk_description" rows={5} required minLength={10} maxLength={30000} aria-invalid={Boolean(errors.risk_description)} onChange={() => setError('risk_description')} placeholder="Describe the threat, likelihood, impact, and affected data or process." /><InlineError message={errors.risk_description} /></div>
              <div className="field field--span-2"><label htmlFor="security_impact">Security impact <span aria-hidden="true">*</span></label><textarea id="security_impact" name="security_impact" rows={4} required minLength={5} maxLength={30000} aria-invalid={Boolean(errors.security_impact)} onChange={() => setError('security_impact')} placeholder="Describe confidentiality, integrity, availability, identity, or control impact." /><InlineError message={errors.security_impact} /></div>
            </div>
          </FormSection>

          <FormSection number="4" title="Control and exception scope" description="Define the exact control boundary and approval period.">
            <div className="form-grid form-grid--2">
              <div className="field field--span-2"><label htmlFor="control_excepted">Control or requirement to except <span aria-hidden="true">*</span></label><input id="control_excepted" name="control_excepted" required maxLength={500} aria-invalid={Boolean(errors.control_excepted)} onChange={() => setError('control_excepted')} /><InlineError message={errors.control_excepted} /></div>
              <div className="field field--span-2"><label htmlFor="current_control">Current control <span aria-hidden="true">*</span></label><textarea id="current_control" name="current_control" rows={4} required minLength={10} maxLength={30000} aria-invalid={Boolean(errors.current_control)} onChange={() => setError('current_control')} /><InlineError message={errors.current_control} /></div>
              <div className="field field--span-2"><label htmlFor="requested_exception">Specific exception requested <span aria-hidden="true">*</span></label><textarea id="requested_exception" name="requested_exception" rows={4} required minLength={10} maxLength={30000} aria-invalid={Boolean(errors.requested_exception)} onChange={() => setError('requested_exception')} /><InlineError message={errors.requested_exception} /></div>
              <div className="field field--span-2"><label htmlFor="reason_control_cannot_follow">Why the control cannot be followed <span aria-hidden="true">*</span></label><textarea id="reason_control_cannot_follow" name="reason_control_cannot_follow" rows={4} required minLength={10} maxLength={30000} aria-invalid={Boolean(errors.reason_control_cannot_follow)} onChange={() => setError('reason_control_cannot_follow')} /><InlineError message={errors.reason_control_cannot_follow} /></div>
              <Field id="requested_start_date" label="Start date" required error={errors.requested_start_date}><input id="requested_start_date" name="requested_start_date" type="date" required aria-invalid={Boolean(errors.requested_start_date)} onChange={() => setError('requested_start_date')} /></Field>
              <Field id="requested_expiry_date" label="Expiry date" required error={errors.requested_expiry_date}><input id="requested_expiry_date" name="requested_expiry_date" type="date" required aria-invalid={Boolean(errors.requested_expiry_date)} onChange={() => setError('requested_expiry_date')} /></Field>
            </div>
          </FormSection>

          <FormSection number="5" title="Compensating controls and remediation" description="Document safeguards and a time-bound path back to compliance.">
            <div className="form-grid form-grid--2">
              <div className="field field--span-2"><label htmlFor="compensating_controls">Compensating controls <span aria-hidden="true">*</span></label><textarea id="compensating_controls" name="compensating_controls" rows={5} required minLength={10} maxLength={30000} aria-invalid={Boolean(errors.compensating_controls)} onChange={() => setError('compensating_controls')} placeholder="Describe monitoring, review, prevention, and detective controls." /><InlineError message={errors.compensating_controls} /></div>
              <div className="field field--span-2"><label htmlFor="remediation_plan">Remediation plan <span aria-hidden="true">*</span></label><textarea id="remediation_plan" name="remediation_plan" rows={5} required minLength={10} maxLength={30000} aria-invalid={Boolean(errors.remediation_plan)} onChange={() => setError('remediation_plan')} /><InlineError message={errors.remediation_plan} /></div>
              <Field id="remediation_target_date" label="Target completion date"><input id="remediation_target_date" name="remediation_target_date" type="date" /></Field>
              <div className="field field--span-2"><label htmlFor="additional_comments">Additional comments</label><textarea id="additional_comments" name="additional_comments" rows={3} maxLength={10000} /></div>
            </div>
          </FormSection>

          {activeFields.length ? <FormSection number="6" title="Additional information" description="Fields configured by administrators for this request form."><div className="form-grid form-grid--2">{activeFields.map((field) => <CustomFieldInput key={field.id} field={field} value={customValues[field.key]} error={errors[`custom_${field.key}`]} onChange={(next) => { setCustomValues((current) => ({ ...current, [field.key]: next })); setError(`custom_${field.key}`); }} />)}</div></FormSection> : null}

          <FormSection number={activeFields.length ? '7' : '6'} title="Supporting evidence" description="Attach material that helps reviewers verify the request. Files are quarantined and malware-scanned before download.">
            <label className="file-drop" htmlFor="request-files"><Paperclip size={23} aria-hidden="true" /><span><strong>Choose files to attach</strong><small>PDF, documents, images, or other approved evidence</small></span><input id="request-files" type="file" multiple onChange={handleFiles} /></label>
            {files.length ? <ul className="file-list">{files.map((file, index) => <li key={`${file.name}-${file.lastModified}`}><FileText size={18} /><span><strong>{file.name}</strong><small>{formatFileSize(file.size)}</small></span><button type="button" className="icon-button" onClick={() => setFiles((current) => current.filter((_, fileIndex) => fileIndex !== index))} aria-label={`Remove ${file.name}`}><Trash2 size={17} /></button></li>)}</ul> : null}
          </FormSection>
        </div>

        <aside className="request-form__aside" aria-label="Submission guidance">
          <div className="submission-guidance">
            <h2>Before you continue</h2>
            <ul><li><Check size={16} />The business need and control boundary are specific.</li><li><Check size={16} />Risk, data, application, and owners are identified.</li><li><Check size={16} />Compensating controls and remediation are documented.</li><li><Check size={16} />The exception has a defined expiry date.</li></ul>
            <div className="governance-note"><ShieldCheck size={19} /><div><strong>Human decision required</strong><p>AI-generated assistance is advisory. A named human approver must make and record the decision.</p></div></div>
            {mutation.isError ? <ErrorState error={mutation.error} title="Request operation did not complete" /> : null}
            <label className="checkbox-field"><input type="checkbox" checked={attested} onChange={(event) => { setAttested(event.target.checked); setError('attestation'); }} aria-invalid={Boolean(errors.attestation)} /><span><strong>Requester attestation</strong><small>I confirm this request is accurate and complete to the best of my knowledge.</small></span></label>
            <InlineError message={errors.attestation} />
            <Button type="submit" loading={mutation.isPending} className="button--full"><Send size={17} />Submit for approval</Button>
            <Button type="button" variant="secondary" className="button--full" disabled={mutation.isPending} onClick={saveDraft}><Save size={17} />Save complete draft</Button>
            <p className="submission-guidance__note"><Info size={15} />A draft uses the same required baseline and can be edited before submission.</p>
          </div>
        </aside>
      </form>
    </div>
  );
}

function Field({ id, label, required, error, help, children }: { id: string; label: string; required?: boolean; error?: string; help?: string; children: React.ReactNode }) {
  return <div className="field"><label htmlFor={id}>{label}{required ? <span aria-hidden="true"> *</span> : null}</label>{children}{help ? <span className="field-help">{help}</span> : null}<InlineError message={error} /></div>;
}

function FormSection({ number, title, description, children }: { number: string; title: string; description: string; children: React.ReactNode }) {
  return <section className="form-section"><div className="form-section__heading"><span aria-hidden="true">{number}</span><div><h2>{title}</h2><p>{description}</p></div></div><div className="form-section__body">{children}</div></section>;
}

function CustomFieldInput({ field, value, error, onChange }: { field: FormOptions['custom_fields'][number]; value: unknown; error?: string; onChange: (value: unknown) => void }) {
  const id = `custom-${field.id}`;
  const common = { id, required: field.required, 'aria-invalid': Boolean(error), 'aria-describedby': error ? `${id}-error` : undefined };
  let control: React.ReactNode;
  if (field.data_type === 'long_text') control = <textarea {...common} rows={4} value={String(value ?? '')} onChange={(event) => onChange(event.target.value)} />;
  else if (field.data_type === 'dropdown') control = <select {...common} value={String(value ?? '')} onChange={(event) => onChange(event.target.value)}><option value="">Select an option</option>{field.allowed_values.map((option) => <option value={String(option)} key={String(option)}>{String(option)}</option>)}</select>;
  else if (field.data_type === 'multi_select') control = <select {...common} multiple value={Array.isArray(value) ? value.map(String) : []} onChange={(event) => onChange(Array.from(event.target.selectedOptions, (option) => option.value))}>{field.allowed_values.map((option) => <option value={String(option)} key={String(option)}>{String(option)}</option>)}</select>;
  else if (field.data_type === 'boolean') control = <label className="checkbox-field"><input type="checkbox" checked={Boolean(value)} onChange={(event) => onChange(event.target.checked)} /><span><strong>{field.label}</strong></span></label>;
  else control = <input {...common} type={field.data_type === 'number' ? 'number' : field.data_type === 'date' ? 'date' : field.data_type === 'datetime' ? 'datetime-local' : field.data_type === 'url' ? 'url' : 'text'} value={String(value ?? '')} onChange={(event) => onChange(field.data_type === 'number' ? (event.target.value === '' ? '' : Number(event.target.value)) : event.target.value)} />;
  if (field.data_type === 'boolean') return <div className="field field--span-2">{control}{field.description ? <span className="field-help">{field.description}</span> : null}<InlineError message={error} /></div>;
  return <div className={`field ${field.data_type === 'long_text' ? 'field--span-2' : ''}`}><label htmlFor={id}>{field.label}{field.required ? <span aria-hidden="true"> *</span> : null}</label>{control}{field.description ? <span className="field-help">{field.description}</span> : null}<InlineError message={error} /></div>;
}
