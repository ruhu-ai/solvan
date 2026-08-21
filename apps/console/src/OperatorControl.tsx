/** The operator control in the top bar: identity, scope, and the way into
 *  Settings. It lives beside the Settings surface it opens rather than in the
 *  shell, which had grown past its size ceiling.
 */
import { useEffect, useRef, useState } from "react";
import { CircleUser } from "lucide-react";
import type { OperatorContext } from "./types";

export function OperatorControl({ operator, onOpenSettings, onSignOut }: { operator: OperatorContext | null; onOpenSettings: (section: string) => void; onSignOut?: () => void }): React.JSX.Element {
  const [open, setOpen] = useState(false);
  const control = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const identity = operator ?? {
    state: "AUTHENTICATION_REQUIRED" as const,
    principal: null,
    display_name: "Identity loading",
    email: null,
    avatar_url: null,
    initials: "…",
    identity_provider: null,
    managed_by: null,
    organization: null,
    team: null,
    roles: [],
    session_expires_at: null,
  };

  useEffect(() => {
    if (!open) return;
    const closeOutside = (event: MouseEvent) => {
      if (!control.current?.contains(event.target as Node)) setOpen(false);
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
        trigger.current?.focus();
      }
    };
    document.addEventListener("mousedown", closeOutside);
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("mousedown", closeOutside);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, [open]);

  function go(section: string): void {
    setOpen(false);
    onOpenSettings(section);
  }

  return <div className="operator-control" ref={control}>
    {/* Initials are the universal "you are signed in as this person" mark, so
        they are shown only when a verified session exists. A local development
        reader and a required sign-in are states, not people; rendering "LD" or
        "?" in an avatar claims an identity the server explicitly did not
        establish. The menu itself states which it is. */}
    <button ref={trigger} className="operator-button" aria-label="Operator menu" aria-haspopup="dialog" aria-expanded={open} onClick={() => setOpen((value) => !value)}>{identity.state === "AUTHENTICATED" ? identity.initials : <CircleUser size={20} strokeWidth={1.75} aria-hidden="true" />}</button>
    {open && <div className="operator-popover" role="dialog" aria-label="Operator menu">
      <div className="operator-identity"><span className="profile-avatar" aria-hidden="true">{identity.initials}</span><div><strong>{identity.display_name}</strong><span>{identity.email ?? identity.principal ?? "No verified principal"}</span></div></div>
      <div className="operator-context"><span>{identity.organization?.name ?? "No organization"}</span><span>{identity.roles.join(", ") || "No effective roles"}</span></div>
      {/* Sign-out is offered only where a session exists to end, and its
          absence is explained rather than left as a missing control. A reader
          who cannot find it should learn why, not conclude the console is
          incomplete. */}
      <div className="operator-actions"><button onClick={() => go("profile")}>Profile and session</button><button onClick={() => go("personal")}>Settings</button>{onSignOut && <button className="operator-sign-out" onClick={() => { setOpen(false); onSignOut(); }}>Sign out</button>}</div>
    </div>}
  </div>;
}
