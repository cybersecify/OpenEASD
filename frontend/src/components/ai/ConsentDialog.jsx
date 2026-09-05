import React from 'react';
import { Button } from '../ui/button.jsx';
import {
  AlertDialog, AlertDialogCancel,
  AlertDialogContent, AlertDialogDescription,
  AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '../ui/alert-dialog.jsx';

/**
 * First-use consent dialog (D-013 as amended by D-014). Opened when the
 * operator flips the AI toggle on without current consent. The toggle never
 * flips optimistically — consent is stamped server-side by the accept POST.
 */
export function ConsentDialog({ open, onAccept, onCancel, accepting }) {
  return (
    <AlertDialog open={open} onOpenChange={v => { if (!v) onCancel(); }}>
      <AlertDialogContent className="bg-card border-border text-foreground max-w-lg">
        <AlertDialogHeader>
          <AlertDialogTitle>Send scan findings to Cloudflare Workers AI?</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="text-muted-foreground text-sm space-y-3 text-left">
              <p>
                When enabled, OpenEASD sends data from your scans — finding titles,
                severities, CVE IDs, affected hosts, ports, and service banners — to
                Cloudflare Workers AI, running on <strong>your own Cloudflare
                account</strong> with your API token. This is used to rank findings by
                exploitability with an explanation for each, to decide which follow-up
                scan steps are worth running, and to write plain-language report and
                alert summaries.
              </p>
              <p>
                OpenEASD records every call in an audit log (time, scan, purpose,
                model, token counts, number of findings sent) but never stores the
                prompt or response contents. Handling of the data on Cloudflare's side
                is governed by your agreement with Cloudflare.
              </p>
              <p>
                You can turn this off at any time; no further calls will be made.
                Note: while enabled, scan results no longer stay only on this machine.
              </p>
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={onCancel}>Cancel</AlertDialogCancel>
          <Button onClick={onAccept} disabled={accepting}>
            {accepting ? 'Enabling…' : 'Enable and send findings'}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
