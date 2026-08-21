import type {
  Dispatch,
  KeyboardEventHandler,
  PointerEventHandler,
  RefObject,
  SetStateAction,
  UIEventHandler,
} from "react";
import type { ThreadParticipant } from "./AskCollaboration";
import type { SteerState, ThreadItem, TurnBudget } from "./AskSupport";
import type {
  AskPart,
  AskResponse,
  CatchUpBrief,
  GuidanceSuggestion,
  PublicActivity,
  SuggestedQuestion,
  ThreadSummary,
} from "./conversation";

export type AskRailViewProps = {
  recordId: string;
  surface: "rail" | "page";
  title: string;
  eyebrow: string;
  composerLabel: string;
  composerPlaceholder: string;
  showClose: boolean;
  showSubscription: boolean;
  apiUrl: string;
  authority: string;
  onClose: () => void;
  width: number;
  startDrag: PointerEventHandler<HTMLDivElement>;
  onDrag: PointerEventHandler<HTMLDivElement>;
  endDrag: PointerEventHandler<HTMLDivElement>;
  nudge: KeyboardEventHandler<HTMLDivElement>;
  subscriptionPending: boolean;
  following: boolean;
  toggleSubscription: () => Promise<void>;
  closeRef: RefObject<HTMLButtonElement | null>;
  identityToken: string;
  setIdentityToken: Dispatch<SetStateAction<string>>;
  subscriptionError: string | null;
  actionError: string | null;
  dismissActionError: () => void;
  scrollRef: RefObject<HTMLDivElement | null>;
  handleScroll: UIEventHandler<HTMLDivElement>;
  brief: CatchUpBrief | null;
  items: ThreadItem[];
  budget: TurnBudget;
  cancelQueued: (answer: AskResponse) => Promise<void>;
  abortRunning: (answer: AskResponse) => Promise<void>;
  ask: (text: string) => Promise<void>;
  pending: boolean;
  question: string;
  identityHeaders: () => Record<string, string>;
  hydrateTranscript: (threadId: string) => Promise<void>;
  steers: Record<string, SteerState>;
  draftSteer: (key: string, part: AskPart) => Promise<void>;
  decideSteer: (key: string, accept: boolean) => Promise<void>;
  endRef: RefObject<HTMLDivElement | null>;
  newMessagesWaiting: boolean;
  scrollToLatest: () => void;
  suggested: SuggestedQuestion[];
  guidanceSuggestions: GuidanceSuggestion[];
  allQuestions: boolean;
  setAllQuestions: Dispatch<SetStateAction<boolean>>;
  composerRef: RefObject<HTMLTextAreaElement | null>;
  setQuestion: Dispatch<SetStateAction<string>>;
  runningAnswer: AskResponse | null;
  stopAndSend: () => Promise<void>;
  renderApprovalPart: (actionId: string) => React.ReactNode;
  activityByMessage: Record<string, PublicActivity>;
  threadId: string | null;
  threads: ThreadSummary[];
  startNewThread: () => void;
  selectThread: (threadId: string) => Promise<void>;
  participants: ThreadParticipant[];
  accessRequests: Array<{
    request_id: string;
    requested_principal: string;
    requested_by_principal: string;
    expires_at: string;
  }>;
  refreshCollaboration: () => Promise<void>;
  requestAccess: (principal: string) => Promise<void>;
  selectMention: (principal: string) => void;
  attachments: File[];
  setAttachments: Dispatch<SetStateAction<File[]>>;
  attachmentInputRef: RefObject<HTMLInputElement | null>;
  attachmentNotice: string | null;
};
