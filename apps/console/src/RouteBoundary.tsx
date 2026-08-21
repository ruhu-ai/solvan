/** Contains a render failure to the route that caused it.
 *
 *  Without this, one screen reading a key the projection no longer carries
 *  unmounts the whole application and leaves the operator a blank page during
 *  an incident. A console that cannot render one view still has to be able to
 *  say so, keep its navigation, and let the operator reach the other eight.
 *
 *  The failure is reported, never interpreted. The boundary does not retry and
 *  does not substitute a default view, because a screen that failed to render
 *  its state has not established what that state is.
 */
import { Component, type ErrorInfo, type ReactNode } from "react";
import { CircleX } from "lucide-react";

type Props = { route: string; children: ReactNode };
type State = { message: string | null };

export class RouteBoundary extends Component<Props, State> {
  state: State = { message: null };

  static getDerivedStateFromError(error: unknown): State {
    return { message: error instanceof Error ? error.message : "Unknown render failure" };
  }

  componentDidUpdate(previous: Props): void {
    // A new route gets a clean attempt; the previous failure said nothing
    // about this one.
    if (previous.route !== this.props.route && this.state.message !== null) {
      this.setState({ message: null });
    }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error(`Console route "${this.props.route}" failed to render`, error, info.componentStack);
  }

  render(): ReactNode {
    if (this.state.message === null) return this.props.children;
    return (
      <section className="state-page danger-panel" role="alert">
        <span className="state-symbol"><CircleX size={24} strokeWidth={1.75} aria-hidden="true" /></span>
        <h1>{this.props.route} could not be displayed</h1>
        <p>
          Nothing on this screen can be trusted to be complete, so none of it is shown. Other
          screens are unaffected and no work has changed. Reload after the projection is corrected.
        </p>
        <code>{this.state.message}</code>
      </section>
    );
  }
}
