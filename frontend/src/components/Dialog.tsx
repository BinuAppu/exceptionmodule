import { X } from 'lucide-react';
import { useEffect, useRef, type ReactNode } from 'react';

interface DialogProps {
  open: boolean;
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  size?: 'sm' | 'md' | 'lg';
}
export function Dialog({ open, title, description, onClose, children, footer, size = 'md' }: DialogProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const titleId = `dialog-${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  useEffect(() => {
    if (open) window.setTimeout(() => dialogRef.current?.querySelector<HTMLElement>('input, select, textarea, button')?.focus(), 0);
  }, [open]);

  return (
    <dialog ref={dialogRef} className={`dialog dialog--${size}`} aria-labelledby={titleId} onCancel={(event) => { event.preventDefault(); onClose(); }} onClose={onClose}>
      <div className="dialog__header">
        <div><h2 id={titleId}>{title}</h2>{description ? <p>{description}</p> : null}</div>
        <button type="button" className="icon-button" onClick={onClose} aria-label="Close dialog"><X size={20} /></button>
      </div>
      <div className="dialog__body">{children}</div>
      {footer ? <div className="dialog__footer">{footer}</div> : null}
    </dialog>
  );
}
