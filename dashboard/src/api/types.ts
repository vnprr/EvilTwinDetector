// Readable names for the generated API types. Never edit schema.d.ts by hand:
// it is generated from the backend's OpenAPI document (`npm run api:types`).
import type { components } from "./schema";

type Schemas = components["schemas"];

export type AccessPoint = Schemas["AccessPoint"];
export type AccessPointDetail = Schemas["AccessPointDetail"];
export type Alert = Schemas["Alert"];
export type AlertDetail = Schemas["AlertDetail"];
export type EffectiveConfig = Schemas["EffectiveConfig"];
export type Evidence = Schemas["Evidence"];
export type MetricSample = Schemas["MetricSample"];
export type SensorStatus = Schemas["SensorStatus"];
export type Stats = Schemas["Stats"];
export type TimelineEntry = Schemas["TimelineEntry"];
export type TrustedProfiles = Schemas["TrustedProfiles"];

export type Verdict = AccessPoint["status"];
