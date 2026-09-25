import { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export class AppErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('Unhandled application error', error, info);
  }

  render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <main className="fatal-error-page" role="alert">
        <section className="fatal-error-card">
          <span className="fatal-error-card__icon" aria-hidden="true"><AlertTriangle size={27} /></span>
          <p className="eyebrow">Page error</p>
          <h1>This page could not be displayed</h1>
          <p>The workspace remained protected, but the page encountered an unexpected error. Reload the application or return to the dashboard.</p>
          <div className="fatal-error-card__actions">
            <button className="button button--primary button--md" type="button" onClick={() => window.location.reload()}><RefreshCw size={17} />Reload</button>
            <button className="button button--secondary button--md" type="button" onClick={() => { window.location.href = '/'; }}>Return to dashboard</button>
          </div>
          {import.meta.env.DEV ? <pre>{error.message}</pre> : null}
        </section>
      </main>
    );
  }
}
