import { Fragment } from "react";
import { useTranslation } from "react-i18next";

// Shared compact failure state: one line of error text followed by a retry
// link-button in the app's existing 11px accent link style (the button
// inherits the 11px size; preflight sets `font: inherit` on buttons).
// Announced as an alert, since it appears after an action the user awaits.
// The focus ring is drawn inside the button, so a parent that clips its
// overflow (a collapsing panel) cannot cut it off.

interface InlineRetryProps {
  message: string;
  onRetry: () => void;
  // The retried action is in flight. The button stays mounted and focusable
  // (no `disabled`, which would drop the focus), is marked busy and disabled
  // through aria and drawn like a disabled control, and ignores a press.
  busy?: boolean;
  // How many times the action has failed. A repeat failure leaves the same
  // text, which a screen reader would not announce again, so a new count
  // replaces the message's text node in the alert. Only the message is
  // replaced: the button stays the same element and keeps the focus.
  failureCount?: number;
}

export function InlineRetry({ message, onRetry, busy, failureCount }: InlineRetryProps) {
  const { t } = useTranslation();
  return (
    <p role="alert" className="text-[11px] text-danger">
      <Fragment key={failureCount}>{message}</Fragment>{" "}
      <button
        type="button"
        className="text-accent hover:underline cursor-pointer focus-visible:outline-offset-[-2px] aria-disabled:opacity-45 aria-disabled:pointer-events-none"
        aria-busy={busy}
        aria-disabled={busy}
        onClick={busy ? undefined : onRetry}
      >
        {t("common.retry")}
      </button>
    </p>
  );
}
