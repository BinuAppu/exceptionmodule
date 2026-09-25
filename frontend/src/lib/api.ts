const API_BASE = '/api';

type QueryValue = string | number | boolean | null | undefined;

export class ApiError extends Error {
  status: number;
  details?: unknown;

  constructor(status: number, message: string, details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

interface RequestOptions extends Omit<RequestInit, 'body'> {
  body?: unknown;
  query?: Record<string, QueryValue>;
}

function buildUrl(path: string, query?: Record<string, QueryValue>): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const url = `${API_BASE}${normalizedPath}`;
  if (!query) return url;

  const params = new URLSearchParams();
  Object.entries(query).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      params.set(key, String(value));
    }
  });
  const queryString = params.toString();
  return queryString ? `${url}?${queryString}` : url;
}

function isPayload(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function extractMessage(payload: unknown, fallback: string): Promise<string> {
  if (typeof payload === 'string' && payload.trim()) return payload;
  if (!isPayload(payload)) return fallback;
  if (typeof payload.detail === 'string') return payload.detail;
  if (typeof payload.message === 'string') return payload.message;
  if (typeof payload.error === 'string') return payload.error;
  if (isPayload(payload.error) && typeof payload.error.message === 'string') return payload.error.message;
  if (Array.isArray(payload.detail) && payload.detail.length) {
    const first = payload.detail[0];
    if (isPayload(first) && typeof first.msg === 'string') return first.msg;
  }
  if (isPayload(payload.error) && Array.isArray(payload.error.fields) && payload.error.fields.length) {
    const first = payload.error.fields[0];
    if (isPayload(first) && typeof first.message === 'string') return first.message;
  }
  return fallback;
}

export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { body, query, headers: suppliedHeaders, ...init } = options;
  const headers = new Headers(suppliedHeaders);

  let requestBody: BodyInit | undefined;
  if (body instanceof FormData || body instanceof Blob || typeof body === 'string') {
    requestBody = body as BodyInit;
  } else if (body !== undefined) {
    headers.set('Content-Type', 'application/json');
    requestBody = JSON.stringify(body);
  }
  if (!headers.has('Accept')) headers.set('Accept', 'application/json');
  const method = (init.method ?? 'GET').toUpperCase();
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && !headers.has('X-CSRF-Token')) {
    const csrf = document.cookie
      .split('; ')
      .find((entry) => entry.startsWith('em_csrf='))
      ?.split('=')[1];
    if (csrf) headers.set('X-CSRF-Token', decodeURIComponent(csrf));
  }

  let response: Response;
  try {
    response = await fetch(buildUrl(path, query), {
      ...init,
      headers,
      body: requestBody,
      credentials: 'include',
    });
  } catch {
    throw new ApiError(0, 'Unable to reach the server. Check your connection and try again.');
  }

  if (response.status === 204) return undefined as T;

  const contentType = response.headers.get('content-type') ?? '';
  const payload: unknown = contentType.includes('application/json')
    ? await response.json().catch(() => null)
    : await response.text().catch(() => '');

  if (!response.ok) {
    if (response.status === 401) {
      window.dispatchEvent(new CustomEvent('exception-manager:unauthorized'));
    }
    const message = await extractMessage(payload, `Request failed (${response.status})`);
    throw new ApiError(response.status, message, payload);
  }

  if (contentType.includes('text/html')) {
    throw new ApiError(
      502,
      'The server returned a web page instead of API data. Check that the API and frontend versions match.',
      payload,
    );
  }

  return payload as T;
}

export function toQuery(values: Record<string, QueryValue>): Record<string, QueryValue> {
  return values;
}
