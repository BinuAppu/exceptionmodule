import { FileQuestion } from 'lucide-react';
import { Link } from 'react-router-dom';
import { EmptyState } from '../components/common';

export default function NotFoundPage() {
  return (
    <div className="standalone-state">
      <EmptyState
        icon={<FileQuestion size={28} />}
        title="Page not found"
        description="The page may have moved, or you may not have access to it."
        action={<Link className="button button--primary button--md" to="/">Return to dashboard</Link>}
      />
    </div>
  );
}
