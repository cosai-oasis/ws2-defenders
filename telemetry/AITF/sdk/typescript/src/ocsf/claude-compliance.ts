/**
 * AITF integration for the Anthropic Claude Compliance API.
 *
 * Normalizes records from the Compliance API **Activity Feed**
 * (`GET /v1/compliance/activities`) into AITF / OCSF telemetry so Claude
 * Enterprise audit activity can be correlated alongside the rest of an
 * organization's AI telemetry and forwarded to a SIEM/XDR.
 *
 * Docs: https://platform.claude.com/docs/en/manage-claude/compliance-api
 *
 * The feed produces *hundreds* of forward-compatible activity types. Rather
 * than enumerate them, this mapper classifies each activity by keyword into the
 * existing OCSF class it reuses (per OCSF's "reuse objects and profiles" model):
 *
 *     authentication / sso / session   -> IAM Authentication (3002)
 *     user / member / invite / scim    -> IAM Account Change (3001)
 *     role / group / permission        -> IAM User Access Management (3005)
 *     chat / file / project / content  -> Application Web Resources Activity (6001)
 *     compliance / export / api key    -> Application API Activity (6003)
 *     everything else (unknown types)  -> Application API Activity (6003), activity Other
 *
 * Unknown / future activity and actor types are passed through (Anthropic's
 * forward-compatibility guidance) rather than dropped.
 */

import { ClaudeComplianceAttributes as C } from "../semantic-conventions/attributes";
import {
  AIBaseEvent,
  OCSFActor,
  OCSFClassUID,
  OCSFDevice,
  OCSFEnrichment,
  OCSFObservable,
  OCSFSeverity,
  OCSFStatus,
  createBaseEvent,
  createMetadata,
} from "./schema";

// --- classification --------------------------------------------------------

/** Result of classifying a Compliance activity `type`. */
export interface ClassifyResult {
  categoryUid: number;
  classUid: number;
  activityId: number;
  category: string;
}

/**
 * (categoryUid, classUid, categoryLabel) keyed by ordered keyword groups.
 * First matching group wins; order matters (auth before account, etc.).
 */
const KEYWORD_CLASS: ReadonlyArray<[readonly string[], number, number, string]> = [
  [
    [
      "login",
      "logout",
      "signin",
      "sign_in",
      "sign_out",
      "sso",
      "mfa",
      "session",
      "authenticat",
      "password",
    ],
    3,
    OCSFClassUID.AUTHENTICATION,
    "authentication",
  ],
  [
    ["role", "permission", "privilege", "group", "access_grant"],
    3,
    OCSFClassUID.USER_ACCESS_MANAGEMENT,
    "access_management",
  ],
  [
    ["user", "member", "invite", "scim", "directory", "provision", "seat"],
    3,
    OCSFClassUID.ACCOUNT_CHANGE,
    "account_change",
  ],
  [
    [
      "chat",
      "file",
      "project",
      "attachment",
      "message",
      "document",
      "artifact",
      "content",
      "setting",
      "policy",
    ],
    6,
    OCSFClassUID.WEB_RESOURCES_ACTIVITY,
    "content",
  ],
  [
    ["compliance", "api_key", "export", "workspace"],
    6,
    OCSFClassUID.API_ACTIVITY,
    "administration",
  ],
];

/**
 * verb keyword -> generic activity_id (Create/Read/Update/Delete/Other style).
 */
const VERB_ACTIVITY: ReadonlyArray<[readonly string[], number]> = [
  [
    ["created", "added", "uploaded", "invited", "granted", "enabled", "started", "initiated"],
    1,
  ], // Create / Logon
  [["deleted", "removed", "revoked", "disabled", "ended", "completed"], 4], // Delete
  [["updated", "edited", "changed", "renamed", "modified"], 3], // Update
  [["viewed", "read", "downloaded", "exported", "listed", "accessed"], 2], // Read
];

/**
 * Map a Compliance activity `type` to its OCSF classification.
 */
export function classify(activityType: string): ClassifyResult {
  const t = (activityType || "").toLowerCase();

  let categoryUid = 6;
  let classUid: number = OCSFClassUID.API_ACTIVITY;
  let category = "other";
  for (const [keywords, cat, cls, label] of KEYWORD_CLASS) {
    if (keywords.some((k) => t.includes(k))) {
      categoryUid = cat;
      classUid = cls;
      category = label;
      break;
    }
  }

  // Authentication uses Logon(1)/Logoff(2) semantics.
  if (classUid === OCSFClassUID.AUTHENTICATION) {
    let activityId: number;
    if (["logout", "sign_out", "signout"].some((k) => t.includes(k))) {
      activityId = 2;
    } else if (["login", "sign_in", "signin", "sso"].some((k) => t.includes(k))) {
      activityId = 1;
    } else {
      activityId = 99;
    }
    return { categoryUid, classUid, activityId, category };
  }

  let activityId = 99;
  for (const [verbs, aid] of VERB_ACTIVITY) {
    if (verbs.some((v) => t.includes(v))) {
      activityId = aid;
      break;
    }
  }
  return { categoryUid, classUid, activityId, category };
}

// --- actor -----------------------------------------------------------------

/** Translate the Compliance actor union into an OCSF actor. */
function buildActor(actorRaw: Record<string, unknown>): OCSFActor {
  const actor = actorRaw || {};
  const uid =
    actor.user_id ?? actor.api_key_id ?? actor.admin_api_key_id ?? actor.directory_id;
  const user: Record<string, unknown> = { type: actor.type };
  if (uid !== undefined && uid !== null) {
    user.uid = String(uid);
  }
  const email = actor.email_address ?? actor.unauthenticated_email_address;
  if (email) {
    user.email_addr = email;
    user.name = email;
  }
  return { user };
}

// --- activity feed poller --------------------------------------------------

const ACTIVITIES_BASE_URL = "https://api.anthropic.com/v1/compliance/activities";
const MAX_LIMIT = 5000;

/** Options for {@link iterActivities}. */
export interface ActivityFeedOptions {
  activityTypes?: string[];
  organizationIds?: string[];
  actorIds?: string[];
  createdAtGte?: string;
  createdAtLt?: string;
  afterId?: string;
  /** Page size, 1..5000. Defaults to 100. */
  limit?: number;
  /** Override the feed endpoint. Defaults to the public Anthropic endpoint. */
  baseUrl?: string;
  /** Injectable fetch implementation for testing. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

/**
 * Page through `GET /v1/compliance/activities`, yielding raw Activity records.
 *
 * Mirrors the Python `iter_activities` poller: cursor pagination via
 * `after_id` / `last_id` / `has_more`, array-bracket repeatable filters, and
 * `x-api-key` authentication.
 *
 * Docs: https://platform.claude.com/docs/en/manage-claude/compliance-activity-feed
 */
export async function* iterActivities(
  apiKey: string,
  opts: ActivityFeedOptions = {},
): AsyncGenerator<Record<string, unknown>> {
  const limit = opts.limit ?? 100;
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_LIMIT) {
    throw new Error(`limit must be between 1 and ${MAX_LIMIT}`);
  }

  const baseUrl = opts.baseUrl ?? ACTIVITIES_BASE_URL;
  const doFetch = opts.fetchImpl ?? fetch;

  const buildParams = (): URLSearchParams => {
    const params = new URLSearchParams();
    params.append("limit", String(limit));
    for (const value of opts.activityTypes ?? []) {
      params.append("activity_types[]", value);
    }
    for (const value of opts.organizationIds ?? []) {
      params.append("organization_ids[]", value);
    }
    for (const value of opts.actorIds ?? []) {
      params.append("actor_ids[]", value);
    }
    if (opts.createdAtGte) {
      params.append("created_at.gte", opts.createdAtGte);
    }
    if (opts.createdAtLt) {
      params.append("created_at.lt", opts.createdAtLt);
    }
    return params;
  };

  let cursor = opts.afterId;
  for (;;) {
    const params = buildParams();
    if (cursor) {
      params.append("after_id", cursor);
    }
    const url = `${baseUrl}?${params.toString()}`;
    const resp = await doFetch(url, { headers: { "x-api-key": apiKey } });
    if (!resp.ok) {
      throw new Error(
        `Claude Compliance Activity Feed request failed with status ${resp.status}`,
      );
    }
    const payload = (await resp.json()) as {
      data?: Record<string, unknown>[];
      has_more?: boolean;
      last_id?: string;
    };

    for (const activity of payload.data ?? []) {
      yield activity;
    }

    if (!payload.has_more) {
      break;
    }
    cursor = payload.last_id;
    if (!cursor) {
      break;
    }
  }
}

// --- mapper ----------------------------------------------------------------

/** A single Compliance Activity Feed record (forward-compatible). */
export type ClaudeComplianceActivity = Record<string, unknown>;

/** Maps Claude Compliance Activity records to OCSF events (reuse model). */
export class ClaudeComplianceMapper {
  static readonly PRODUCT = {
    name: "Anthropic Claude Compliance API",
    vendor_name: "Anthropic",
    version: "v1",
  } as const;

  /** Map a single Activity Feed record to an OCSF event. */
  mapActivity(activity: ClaudeComplianceActivity): AIBaseEvent {
    const activityType = String(activity.type ?? "unknown");
    const { categoryUid, classUid, activityId, category } = classify(activityType);

    const actorRaw = (activity.actor as Record<string, unknown>) ?? {};
    let device: OCSFDevice | undefined;
    const ip = actorRaw.ip_address;
    const userAgent = actorRaw.user_agent;
    if (ip) {
      device = { ip: String(ip) };
    }

    // Carry the activity-specific fields as enrichments + observables.
    const enrichments: OCSFEnrichment[] = [
      { name: C.ACTIVITY_TYPE, value: activityType, provider: "claude_compliance" },
      { name: C.ACTIVITY_CATEGORY, value: category, provider: "claude_compliance" },
    ];
    const fieldMap: ReadonlyArray<[string, string]> = [
      ["id", C.ACTIVITY_ID],
      ["organization_id", C.ORGANIZATION_ID],
      ["organization_uuid", C.ORGANIZATION_UUID],
      ["claude_chat_id", C.CHAT_ID],
      ["claude_project_id", C.PROJECT_ID],
      ["claude_file_id", C.FILE_ID],
      ["filename", C.FILENAME],
    ];
    for (const [key, attr] of fieldMap) {
      if (activity[key] !== undefined && activity[key] !== null) {
        enrichments.push({ name: attr, value: String(activity[key]) });
      }
    }
    if (actorRaw.type) {
      enrichments.push({ name: C.ACTOR_TYPE, value: String(actorRaw.type) });
    }
    if (userAgent) {
      enrichments.push({ name: C.ACTOR_USER_AGENT, value: String(userAgent) });
    }

    const observables: OCSFObservable[] = [];
    const email = actorRaw.email_address ?? actorRaw.unauthenticated_email_address;
    if (email) {
      observables.push({ name: C.ACTOR_EMAIL, type: "Email Address", value: String(email) });
    }
    if (ip) {
      observables.push({ name: C.ACTOR_IP, type: "IP Address", value: String(ip) });
    }
    if (actorRaw.user_id) {
      observables.push({ name: C.ACTOR_USER_ID, type: "User", value: String(actorRaw.user_id) });
    }

    // Failures are encoded in the type for most events; default Success.
    const statusId = ["failed", "denied", "rejected", "error"].some((k) =>
      activityType.toLowerCase().includes(k)
    )
      ? OCSFStatus.FAILURE
      : OCSFStatus.SUCCESS;

    const metadata = createMetadata();
    metadata.product = { ...ClaudeComplianceMapper.PRODUCT };

    const options: Partial<AIBaseEvent> = {
      category_uid: categoryUid,
      activity_id: activityId,
      severity_id: OCSFSeverity.INFORMATIONAL,
      status_id: statusId,
      message: activityType,
      metadata,
      actor: buildActor(actorRaw),
      device,
      enrichments,
      observables,
    };
    if (activity.created_at) {
      options.time = String(activity.created_at);
    }
    return createBaseEvent(classUid, options);
  }

  /** Map a page of Activity records to OCSF events. */
  mapActivities(activities: ClaudeComplianceActivity[]): AIBaseEvent[] {
    return activities.map((a) => this.mapActivity(a));
  }
}
