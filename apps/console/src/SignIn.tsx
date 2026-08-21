/** The sign-in surface (specification 05 §4.2, specification 06).
 *
 *  Operators previously authenticated by running `gcloud auth
 *  print-identity-token` and pasting the result into a password field, once per
 *  consequential action. The verification behind that field was sound; the
 *  transport was a person performing an OAuth flow with their clipboard.
 *
 *  This page starts the flow instead. It is the product's front door, so it is
 *  anchored on the product: the provider is named on the button it sends you
 *  to, and nowhere else. Writing the provider into the title made a development
 *  host present a page about its identity provider rather than a page about
 *  Solvan.
 *
 *  One control, and no prose around it. A door explaining the building is a
 *  door people stop reading: what a session grants is enforced at every action
 *  and stated there, where it is the subject rather than a paragraph nobody has
 *  a reason to read yet.
 *
 *  A provider that is not the production one is marked on the control itself —
 *  "Continue with the test identity provider" is the marking, and it cannot be
 *  missed by somebody skimming, which a note below the button can.
 */

import { SolvanMark } from "./components";

/** Google's mark, so the button that goes to Google looks like it. */
function GoogleMark(): React.JSX.Element {
  return <svg viewBox="0 0 533.5 544.3" width="18" height="18" aria-hidden="true">
    <path fill="#4285F4" d="M533.5 278.4c0-18.5-1.5-37.1-4.7-55.3H272.1v104.8h147.7c-6.1 33.8-25.4 63.7-53.9 82.7v68h87c51-47 80.6-116.3 80.6-200.2z" />
    <path fill="#34A853" d="M272.1 544.3c73.5 0 135.5-24.1 180.6-65.4l-87-68c-24.2 16.5-55.3 25.9-93.6 25.9-71.9 0-132.8-48.6-154.6-113.9H27.9v71.1c46.3 92 139.2 150.3 244.2 150.3z" />
    <path fill="#FBBC04" d="M117.5 322.9c-11.4-33.8-11.4-70.4 0-104.2V147.6H27.9c-38.7 77.3-38.7 171.8 0 249.1l89.6-73.8z" />
    <path fill="#EA4335" d="M272.1 107.7c40.4-.6 79.5 14.8 109.3 43.1l81.5-81.5C405.2 24.9 339.4-.2 272.1 0 167.1 0 74.2 58.3 27.9 150.3l89.6 71.1C139.3 156.3 200.2 107.7 272.1 107.7z" />
  </svg>;
}

export function SignIn({
  apiUrl,
  returnPath,
  reason,
  provider = "Google",
  providerIsProduction = true,
}: {
  apiUrl: string;
  returnPath: string;
  reason?: string;
  provider?: string;
  providerIsProduction?: boolean;
}): React.JSX.Element {
  const target = `${apiUrl}/api/auth/login?return_path=${encodeURIComponent(returnPath)}`;
  return <main className="sign-in-page">
    <div className="sign-in-stack">
      {/* The product, named once. The provider is named on the control that
          goes to it and nowhere else, so a development host cannot present a
          page about its identity provider. */}
      <span className="sign-in-mark" aria-hidden="true"><SolvanMark size={34} /></span>
      <p className="sign-in-wordmark">Solvan</p>
      <h1 id="sign-in-title">Welcome back — sign in to continue</h1>

      <section className="card sign-in-card" aria-labelledby="sign-in-title">
        {reason && <p className="inline-notice" role="status">{reason}</p>}
        {/* A link rather than a fetch: the flow is a redirect, and the browser
            must carry the response itself.

            One control, and everything that used to be explained around it is
            gone. What signing in does and does not grant is not a thing to read
            at a door — it is enforced at every action, where it is the subject:
            approving, connecting an estate, or changing policy each
            verifies recent presence for that one operation, and says so there. */}
        <a className="sign-in-action" href={target}>
          {providerIsProduction && <GoogleMark />}
          <span>Continue with {provider}</span>
        </a>
      </section>
    </div>
  </main>;
}
