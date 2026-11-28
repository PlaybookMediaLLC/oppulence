import type {
    RequestPermissionRequest,
    RequestPermissionResponse,
    PermissionOption,
    PermissionOptionKind,
} from '@agentclientprotocol/sdk';
import type { ApprovalPolicy, PermissionDecision, PermissionAsk } from './types.js';

// Tool kinds that don't mutate local state or perform outbound network fetches — eligible for `auto-approve-reads`.
const READ_KINDS = new Set(['read', 'search', 'think']);
// Explicit allowlist of ACP tool kinds permitted to receive coarse kind-wide sticky "always allow" grants.
// High-risk and catch-all kinds (`execute`, `delete`, `fetch`, `other`, `switch_mode`, or undefined) are excluded.
const STICKY_ALWAYS_ALLOW_KINDS = new Set(['read', 'search', 'think', 'edit', 'move']);

function toAsk(request: RequestPermissionRequest): PermissionAsk {
    const tc = request.toolCall;
    const kind = tc.kind ?? undefined;
    const title = tc.title ?? kind ?? 'Tool call';
    return {
        toolCallId: tc.toolCallId ?? undefined,
        title,
        kind,
        isRead: kind ? READ_KINDS.has(kind) : false,
    };
}

// Map a desired decision to one of the options the agent actually offered.
// Never silently escalate `allow_once` to `allow_always`.
function pickOption(options: PermissionOption[], decision: PermissionDecision): PermissionOption | undefined {
    const order: Record<PermissionDecision, PermissionOptionKind[]> = {
        allow_always: ['allow_always', 'allow_once'],
        allow_once: ['allow_once'],
        reject: ['reject_once', 'reject_always'],
    };
    for (const kind of order[decision]) {
        const found = options.find((o) => o.kind === kind);
        if (found) return found;
    }
    return undefined;
}

function selected(optionId: string): RequestPermissionResponse {
    return { outcome: { outcome: 'selected', optionId } };
}

function canUseStickyAlwaysAllow(ask: PermissionAsk): boolean {
    return Boolean(ask.kind && STICKY_ALWAYS_ALLOW_KINDS.has(ask.kind));
}

// A request's identity for "always allow" memory: prefer tool kind, else title.
function memoryKey(ask: PermissionAsk): string {
    return ask.kind ? `kind:${ask.kind}` : `title:${ask.title}`;
}

export interface PermissionBrokerOptions {
    policy: ApprovalPolicy;
    // Called only when the policy can't decide on its own (the "ask" path).
    ask: (ask: PermissionAsk) => Promise<PermissionDecision>;
    // Notified of every resolved request so the engine can emit a stream event.
    onResolved?: (ask: PermissionAsk, decision: PermissionDecision, auto: boolean) => void;
}

// Decides how to answer the agent's requestPermission calls. Holds per-session
// "always allow" memory so a one-time approval sticks for the rest of the run.
export class PermissionBroker {
    private readonly opts: PermissionBrokerOptions;
    private readonly alwaysAllow = new Set<string>();

    constructor(opts: PermissionBrokerOptions) {
        this.opts = opts;
    }

    async resolve(request: RequestPermissionRequest): Promise<RequestPermissionResponse> {
        const ask = toAsk(request);
        const key = memoryKey(ask);
        const stickyAllowed = canUseStickyAlwaysAllow(ask);

        const finish = (decision: PermissionDecision, auto: boolean): RequestPermissionResponse => {
            const effectiveDecision: PermissionDecision =
                decision === 'allow_always' && !stickyAllowed && this.opts.policy !== 'yolo'
                    ? 'allow_once'
                    : decision;
            if (effectiveDecision === 'allow_always' && stickyAllowed) {
                this.alwaysAllow.add(key);
            }
            this.opts.onResolved?.(ask, effectiveDecision, auto);
            const opt = pickOption(request.options, effectiveDecision);
            if (!opt) {
                // Never fail open by falling back to options[0] (typically allow_once)
                // when rejecting or when no matching permission option exists.
                return { outcome: { outcome: 'cancelled' } };
            }
            return selected(opt.optionId);
        };

        // 1. Sticky "always allow" from earlier this session (safe kinds only).
        if (stickyAllowed && this.alwaysAllow.has(key)) return finish('allow_always', true);

        // 2. Policy-level auto decisions.
        if (this.opts.policy === 'yolo') return finish('allow_always', true);
        if (this.opts.policy === 'auto-approve-reads' && ask.isRead) return finish('allow_once', true);

        // 3. Ask the user.
        const decision = await this.opts.ask(ask);
        return finish(decision, false);
    }
}
