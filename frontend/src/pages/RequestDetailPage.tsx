import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle, ArrowLeft, Building2, CalendarDays, Check, CheckCircle2, Clock3,
  Download, FileText, History, MessageSquare, Paperclip, Send, ShieldAlert,
  ShieldCheck, Upload, UserRound, XCircle,
} from 'lucide-react';
import { useRef, useState, type FormEvent } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { Dialog } from '../components/Dialog';
import { Button, ErrorState, InlineError, LoadingState, RiskBadge, StatusBadge } from '../components/common';
import { useToast } from '../contexts/ToastContext';
import { apiRequest } from '../lib/api';
import { formatDate, formatDateTime, formatFileSize, titleFromKey } from '../lib/format';
import type { RequestComment, RequestDetail } from '../types/api';

type Decision = 'approve' | 'reject' | 'request_clarification';
const decisionCopy: Record<Decision, { title: string; label: string; description: string }> = {
  approve: { title: 'Approve request', label: 'Approve', description: 'Record your human approval for the current workflow stage.' },
  reject: { title: 'Reject request', label: 'Reject', description: 'Record a human rejection and explain why the request cannot proceed.' },
  request_clarification: { title: 'Request clarification', label: 'Request clarification', description: 'Pause review and return the request to the requester with specific questions.' },
};

export default function RequestDetailPage() {
  const { id = '' } = useParams();
  const [searchParams] = useSearchParams();
  const queryClient = useQueryClient();
  const { showToast } = useToast();
  const [tab, setTab] = useState<'overview' | 'activity'>('overview');
  const [decision, setDecision] = useState<Decision | null>(null);
  const [comment, setComment] = useState('');
  const [fileError, setFileError] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const requestQuery = useQuery({
    queryKey: ['request', id],
    queryFn: () => apiRequest<RequestDetail>(`/requests/${id}`),
    enabled: Boolean(id),
  });
  const invalidate = async () => {
    await queryClient.invalidateQueries({ queryKey: ['request', id] });
    await queryClient.invalidateQueries({ queryKey: ['requests'] });
    await queryClient.invalidateQueries({ queryKey: ['dashboard'] });
  };
  const decisionMutation = useMutation({
    mutationFn: ({ assignmentId, value, note }: { assignmentId: string; value: Decision; note: string }) => apiRequest<RequestDetail>(`/approvals/${assignmentId}/decision`, {
      method: 'POST',
      headers: searchParams.get('action_token') ? { 'X-Approval-Action-Token': searchParams.get('action_token')! } : undefined,
      body: {
        expected_version: requestQuery.data!.version,
        decision: value,
        comment: note || undefined,
        reason: value === 'reject' || value === 'request_clarification' ? note : undefined,
        idempotency_key: crypto.randomUUID(),
      },
    }),
    onSuccess: async () => { await invalidate(); setDecision(null); setComment(''); showToast('Your decision was recorded.', 'success'); },
  });
  const commentMutation = useMutation({
    mutationFn: (body: string) => apiRequest<RequestComment>(`/requests/${id}/comments`, { method: 'POST', body: { body } }),
    onSuccess: async () => { await invalidate(); setComment(''); showToast('Comment added.', 'success'); },
  });
  const attachmentMutation = useMutation({
    mutationFn: (file: File) => { const data = new FormData(); data.append('file', file); data.append('evidence_type', 'supporting_evidence'); return apiRequest(`/requests/${id}/attachments`, { method: 'POST', body: data }); },
    onSuccess: async () => { await invalidate(); showToast('Attachment uploaded and queued for scanning.', 'success'); },
    onError: (error) => setFileError(error instanceof Error ? error.message : 'Upload failed.'),
  });
  const submitMutation = useMutation({
    mutationFn: () => apiRequest<RequestDetail>(`/requests/${id}/submit`, { method: 'POST', body: { expected_version: requestQuery.data!.version, attestation: true } }),
    onSuccess: async () => { await invalidate(); showToast('Request submitted for review.', 'success'); },
  });

  if (requestQuery.isLoading) return <div className="page"><Link className="back-link" to="/requests"><ArrowLeft size={17} />Back to requests</Link><LoadingState label="Loading request…" rows={8} /></div>;
  if (requestQuery.isError) return <div className="page"><Link className="back-link" to="/requests"><ArrowLeft size={17} />Back to requests</Link><ErrorState error={requestQuery.error} onRetry={() => void requestQuery.refetch()} title="Request could not be loaded" /></div>;

  const request = requestQuery.data!;
  const canDecide = Boolean(request.can_decide_assignment_id);
  const canSubmit = Boolean(request.can_edit && request.status === 'draft');

  const submitDecision = (event: FormEvent) => {
    event.preventDefault();
    if (!decision || !request.can_decide_assignment_id) return;
    if (decision !== 'approve' && !comment.trim()) return;
    decisionMutation.mutate({ assignmentId: request.can_decide_assignment_id, value: decision, note: comment.trim() });
  };
  const submitComment = (event: FormEvent) => { event.preventDefault(); if (comment.trim()) commentMutation.mutate(comment.trim()); };
  const upload = (file?: File) => { setFileError(null); if (file) attachmentMutation.mutate(file); if (fileInput.current) fileInput.current.value = ''; };

  return (
    <div className="page request-detail-page">
      <Link className="back-link" to="/requests"><ArrowLeft size={17} />Back to requests</Link>
      <header className="detail-header">
        <div className="detail-header__title">
          <div className="detail-header__badges"><StatusBadge status={request.status} /><RiskBadge risk={request.risk_level} /><span className="reference-label">{request.public_id}</span></div>
          <h1>{request.title}</h1>
          <p>Submitted by <strong>{request.requester_name}</strong> on {formatDate(request.created_at)} · Last updated {formatDateTime(request.updated_at)}</p>
        </div>
        <div className="detail-header__actions">
          {canSubmit ? <Button loading={submitMutation.isPending} onClick={() => { if (window.confirm('Submit this complete draft for approval?')) submitMutation.mutate(); }}><Send size={17} />Submit draft</Button> : null}
          {canDecide ? <><Button variant="secondary" onClick={() => { setDecision('request_clarification'); setComment(''); }}><MessageSquare size={17} />Clarify</Button><Button variant="danger" onClick={() => { setDecision('reject'); setComment(''); }}><XCircle size={17} />Reject</Button><Button onClick={() => { setDecision('approve'); setComment(''); }}><CheckCircle2 size={17} />Approve</Button></> : null}
        </div>
      </header>

      {request.status === 'draft' ? <div className="notice-banner notice-banner--warning"><AlertTriangle size={20} /><div><strong>Draft</strong><span>This request has not entered the approval workflow.</span></div></div> : null}
      {request.status === 'clarification_required' ? <div className="notice-banner notice-banner--warning"><AlertTriangle size={20} /><div><strong>Clarification requested</strong><span>The requester must respond before review can continue.</span></div></div> : null}
      {['approved', 'active'].includes(request.status) ? <div className="notice-banner notice-banner--success"><ShieldCheck size={20} /><div><strong>Human approval recorded</strong><span>This exception is approved and tracked against its effective period.</span></div></div> : null}
      {['rejected', 'manager_rejected', 'delivery_head_rejected'].includes(request.status) ? <div className="notice-banner notice-banner--danger"><XCircle size={20} /><div><strong>Request rejected</strong><span>A human reviewer recorded the rejection rationale in the audit trail.</span></div></div> : null}
      {submitMutation.isError ? <ErrorState error={submitMutation.error} title="Draft was not submitted" /> : null}

      <nav className="detail-tabs" aria-label="Request sections">
        <button type="button" className={tab === 'overview' ? 'active' : ''} aria-current={tab === 'overview' ? 'page' : undefined} onClick={() => setTab('overview')}>Request details</button>
        <button type="button" className={tab === 'activity' ? 'active' : ''} aria-current={tab === 'activity' ? 'page' : undefined} onClick={() => setTab('activity')}>Approvals & activity <span>{request.approvals.length + request.comments.length}</span></button>
      </nav>

      {tab === 'overview' ? (
        <div className="detail-layout">
          <div className="detail-main">
            <InfoSection title="Request summary" icon={<FileText size={19} />}><p className="prose">{request.description}</p></InfoSection>
            <InfoSection title="Business justification" icon={<Building2 size={19} />}><p className="prose">{request.business_justification}</p><div className="subsection"><h3>Business impact</h3><p className="prose">{request.business_impact}</p></div></InfoSection>
            <InfoSection title="Risk and security impact" icon={<ShieldAlert size={19} />}><div className="detail-facts"><div><span>Inherent risk</span><RiskBadge risk={request.risk_level} /></div><div><span>Data classification</span><strong>{request.data_classification_code}</strong></div></div><p className="prose">{request.risk_description}</p><div className="subsection"><h3>Security impact</h3><p className="prose">{request.security_impact}</p></div></InfoSection>
            <InfoSection title="Application and ownership" icon={<Building2 size={19} />}><dl className="detail-grid"><div><dt>Application</dt><dd>{request.application_name}</dd></div><div><dt>Asset / system</dt><dd>{request.asset_system}</dd></div><div><dt>Environment</dt><dd>{request.environment}</dd></div><div><dt>Business owner</dt><dd>{request.business_owner}</dd></div><div><dt>Technology owner</dt><dd>{request.technology_owner}</dd></div><div><dt>Department</dt><dd>{request.department}</dd></div></dl></InfoSection>
            <InfoSection title="Control and requested exception" icon={<CalendarDays size={19} />}><p className="prose"><strong>Control excepted:</strong> {request.control_excepted}</p><div className="subsection"><h3>Current control</h3><p className="prose">{request.current_control}</p></div><div className="subsection"><h3>Requested exception</h3><p className="prose">{request.requested_exception}</p></div><div className="subsection"><h3>Why the control cannot be followed</h3><p className="prose">{request.reason_control_cannot_follow}</p></div><div className="exception-window"><div><span>Start date</span><strong>{formatDate(request.requested_start_date)}</strong></div><div><span>Expiry date</span><strong>{formatDate(request.expiry_date)}</strong></div></div></InfoSection>
            <InfoSection title="Compensating controls" icon={<ShieldCheck size={19} />}><p className="prose">{request.compensating_controls}</p></InfoSection>
            <InfoSection title="Remediation plan" icon={<CheckCircle2 size={19} />}><p className="prose">{request.remediation_plan}</p><dl className="detail-grid"><div><dt>Owner</dt><dd>{request.remediation_owner_name ?? 'Not assigned'}</dd></div><div><dt>Target date</dt><dd>{formatDate(request.remediation_target_date)}</dd></div><div><dt>Status</dt><dd>{titleFromKey(request.remediation_status)}</dd></div><div><dt>Progress</dt><dd>{request.remediation_progress}%</dd></div></dl></InfoSection>
            {Object.keys(request.custom_fields).length ? <InfoSection title="Additional information" icon={<FileText size={19} />}><dl className="detail-grid">{Object.entries(request.custom_fields).map(([key, value]) => <div key={key}><dt>{titleFromKey(key)}</dt><dd>{formatValue(value)}</dd></div>)}</dl></InfoSection> : null}
          </div>
          <aside className="detail-aside">
            <InfoSection title="Request facts" icon={<UserRound size={19} />}><dl className="fact-list"><div><dt>Reference</dt><dd>{request.public_id}</dd></div><div><dt>Requester</dt><dd>{request.requester_name}</dd></div><div><dt>Category</dt><dd>{request.category_name}</dd></div><div><dt>Exception type</dt><dd>{request.exception_type}</dd></div><div><dt>Created</dt><dd>{formatDateTime(request.created_at)}</dd></div><div><dt>Version</dt><dd>{request.version}</dd></div></dl></InfoSection>
            <InfoSection title="Attachments" icon={<Paperclip size={19} />}>
              {request.attachments.length ? <ul className="attachment-list">{request.attachments.map((attachment) => <li key={attachment.id}><span className="attachment-list__icon"><FileText size={18} /></span><span><strong>{attachment.original_filename}</strong><small>{formatFileSize(attachment.size_bytes)} · {titleFromKey(attachment.scan_status)}</small></span>{attachment.scan_status === 'clean' ? <a className="icon-button" href={`/api/requests/${id}/attachments/${attachment.id}/download`} aria-label={`Download ${attachment.original_filename}`}><Download size={17} /></a> : null}</li>)}</ul> : <p className="muted-text">No supporting evidence attached.</p>}
              {request.can_edit ? <div className="attachment-upload"><input ref={fileInput} id="detail-attachment" type="file" className="sr-only" onChange={(event) => upload(event.target.files?.[0])} /><Button variant="secondary" size="sm" loading={attachmentMutation.isPending} onClick={() => fileInput.current?.click()}><Upload size={16} />Add attachment</Button><InlineError message={fileError} /></div> : null}
            </InfoSection>
            <InfoSection title="Approval progress" icon={<CheckCircle2 size={19} />}>{request.approvals.length ? <ol className="approval-progress">{request.approvals.map((approval, index) => <li key={approval.id} className={`approval-progress__${approval.status}`}><span>{approval.status === 'approved' ? <Check size={15} /> : index + 1}</span><div><strong>{approval.stage_name}</strong><small>{approval.approver_name} · {formatDate(approval.completed_at ?? approval.due_at)}</small></div></li>)}</ol> : <p className="muted-text">No approval assignments yet.</p>}</InfoSection>
          </aside>
        </div>
      ) : (
        <div className="activity-layout">
          <div>
            <InfoSection title="Approval assignments" icon={<CheckCircle2 size={19} />} description="Every stage must be completed by an authorized human reviewer.">{request.approvals.length ? <ol className="timeline">{request.approvals.map((approval) => <li key={approval.id}><span className={`timeline__marker timeline__marker--${approval.status}`}>{approval.status === 'approved' ? <Check size={15} /> : <Clock3 size={15} />}</span><div><div><strong>{approval.stage_name}</strong><span className="human-decision-label">{titleFromKey(approval.status)}</span></div><p>{approval.approver_name}{approval.delegated_from_name ? ` (delegated from ${approval.delegated_from_name})` : ''}</p>{approval.decision_comment ? <blockquote>{approval.decision_comment}</blockquote> : null}<time dateTime={approval.completed_at ?? approval.due_at}>{formatDateTime(approval.completed_at ?? approval.due_at)}</time></div></li>)}</ol> : <p className="muted-text">No approval activity has been recorded.</p>}</InfoSection>
            <InfoSection title="Comments" icon={<MessageSquare size={19} />}><form className="comment-form" onSubmit={submitComment}><div className="field"><label htmlFor="new-comment">Add a comment</label><textarea id="new-comment" rows={3} required value={comment} onChange={(event) => setComment(event.target.value)} placeholder="Add review context or answer a clarification request" /></div><div className="comment-form__actions"><Button type="submit" size="sm" loading={commentMutation.isPending} disabled={!comment.trim()}><Send size={16} />Post comment</Button></div>{commentMutation.isError ? <ErrorState error={commentMutation.error} /> : null}</form>{request.comments.length ? <ol className="comment-list">{request.comments.map((item) => <li key={item.id}><div className="comment-list__header"><strong>{item.author_name}</strong>{item.is_clarification_response ? <span className="tag">Clarification</span> : null}<time dateTime={item.created_at}>{formatDateTime(item.created_at)}</time></div><p>{item.body}</p></li>)}</ol> : <p className="muted-text">No comments yet.</p>}</InfoSection>
          </div>
          <aside className="activity-aside"><InfoSection title="Audit history" icon={<History size={19} />}>{request.audit_timeline.length ? <ol className="audit-list">{request.audit_timeline.map((event) => <li key={event.id}><strong>{titleFromKey(event.action)}</strong><span>{event.actor ?? 'System'}</span><time dateTime={event.timestamp}>{formatDateTime(event.timestamp)}</time></li>)}</ol> : <p className="muted-text">No audit events available.</p>}</InfoSection></aside>
        </div>
      )}

      <Dialog open={Boolean(decision)} title={decision ? decisionCopy[decision].title : 'Decision'} description={decision ? decisionCopy[decision].description : undefined} onClose={() => { if (!decisionMutation.isPending) { setDecision(null); setComment(''); } }} footer={<><Button variant="secondary" onClick={() => { setDecision(null); setComment(''); }}>Cancel</Button><Button variant={decision === 'reject' ? 'danger' : 'primary'} type="submit" form="approval-form" loading={decisionMutation.isPending} disabled={decision !== 'approve' && !comment.trim()}>{decision ? decisionCopy[decision].label : 'Confirm'}</Button></>}>
        <form id="approval-form" onSubmit={submitDecision}><div className="decision-authorship"><UserRound size={19} /><p><strong>You are making this decision.</strong><span>Your authenticated identity and timestamp will be recorded. AI assistance is not a substitute for judgment.</span></p></div><div className="field"><label htmlFor="decision-comment">{decision === 'approve' ? 'Decision note (optional)' : 'Rationale / clarification request'} {decision && decision !== 'approve' ? <span aria-hidden="true">*</span> : null}</label><textarea id="decision-comment" rows={5} required={decision !== 'approve'} value={comment} onChange={(event) => setComment(event.target.value)} /></div><InlineError message={decisionMutation.error instanceof Error ? decisionMutation.error.message : null} /></form>
      </Dialog>
    </div>
  );
}

function InfoSection({ title, icon, description, children }: { title: string; icon: React.ReactNode; description?: string; children: React.ReactNode }) {
  return <section className="detail-section"><div className="detail-section__header"><span>{icon}</span><div><h2>{title}</h2>{description ? <p>{description}</p> : null}</div></div><div className="detail-section__body">{children}</div></section>;
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return 'Not recorded';
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (Array.isArray(value)) return value.map(String).join(', ');
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}
