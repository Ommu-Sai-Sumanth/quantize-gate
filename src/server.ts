import express, { Request, Response } from "express";
import crypto from "crypto";

const app = express();
app.use(express.json({ limit: "50mb" }));

const PORT = Number(process.env.PORT) || 3000;

type Obj = Record<string, any>;

interface InventoryItem {
  name: string;
  bytes: number;
  sha256: string;
}

interface FrozenCandidate {
  name: string;
  status: "frozen" | "unsupported" | "invalid";
  inventory: InventoryItem[];
  totalBytes: number | null;
  packageDigest: string | null;
  reasonCodes: string[];
}

interface FreezeResponse {
  freezeId: string;
  candidates: FrozenCandidate[];
}

interface StoredFreeze {
  fingerprint: string;
  response: FreezeResponse;
}

const freezes = new Map<string, StoredFreeze>();

/* ============================================================
   BASIC HELPERS
   ============================================================ */

function isObject(v: unknown): v is Obj {
  return (
    typeof v === "object" &&
    v !== null &&
    !Array.isArray(v)
  );
}

function nonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

function finiteNonNegative(v: unknown): v is number {
  return (
    typeof v === "number" &&
    Number.isFinite(v) &&
    v >= 0
  );
}

function safeNonNegativeInteger(v: unknown): v is number {
  return (
    typeof v === "number" &&
    Number.isSafeInteger(v) &&
    v >= 0
  );
}

function unitNumber(v: unknown): v is number {
  return (
    typeof v === "number" &&
    Number.isFinite(v) &&
    v >= 0 &&
    v <= 1
  );
}

function binary(v: unknown): v is number {
  return v === 0 || v === 1;
}

function utf8Compare(a: string, b: string): number {
  return Buffer.compare(
    Buffer.from(a, "utf8"),
    Buffer.from(b, "utf8")
  );
}

function sortCodes(codes: string[]): string[] {
  return [...new Set(codes)].sort(utf8Compare);
}

function sha256Text(text: string): string {
  return crypto
    .createHash("sha256")
    .update(Buffer.from(text, "utf8"))
    .digest("hex");
}

function compact(value: unknown): string {
  return JSON.stringify(value);
}

function fingerprint(value: unknown): string {
  return sha256Text(compact(value));
}

function round12(value: number): number {
  return Number(value.toFixed(12));
}

function invalidInput(res: Response): void {
  res
    .status(400)
    .type("application/json")
    .send(JSON.stringify({
      error: "INVALID_INPUT"
    }));
}

/* ============================================================
   FILE INVENTORY
   ============================================================ */

function makeInventory(files: unknown): {
  valid: boolean;
  inventory: InventoryItem[];
  totalBytes: number | null;
  packageDigest: string | null;
} {
  if (!isObject(files)) {
    return {
      valid: false,
      inventory: [],
      totalBytes: null,
      packageDigest: null
    };
  }

  const names = Object.keys(files);

  if (names.length === 0) {
    return {
      valid: false,
      inventory: [],
      totalBytes: null,
      packageDigest: null
    };
  }

  for (const name of names) {
    if (
      !nonEmptyString(name) ||
      typeof files[name] !== "string"
    ) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null
      };
    }
  }

  names.sort(utf8Compare);

  const inventory: InventoryItem[] = [];
  let total = 0;

  for (const name of names) {
    const text = files[name] as string;

    const bytes = Buffer.byteLength(
      text,
      "utf8"
    );

    total += bytes;

    if (!Number.isSafeInteger(total)) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null
      };
    }

    inventory.push({
      name,
      bytes,
      sha256: sha256Text(text)
    });
  }

  return {
    valid: true,
    inventory,
    totalBytes: total,
    packageDigest: sha256Text(
      compact(inventory)
    )
  };
}

/* ============================================================
   FREEZE ENVELOPE VALIDATION
   ============================================================ */

function validFreezeEnvelope(body: Obj): boolean {
  if (body.phase !== "freeze") {
    return false;
  }

  if (
    !nonEmptyString(body.freezeId) ||
    body.freezeId.length > 128
  ) {
    return false;
  }

  if (!nonEmptyString(body.calibrationDigest)) {
    return false;
  }

  if (!nonEmptyString(body.tokenizerDigest)) {
    return false;
  }

  if (!Array.isArray(body.allowedUnsupportedReasons)) {
    return false;
  }

  if (
    !Array.isArray(body.candidates) ||
    body.candidates.length === 0
  ) {
    return false;
  }

  const reasons = new Set<string>();

  for (
    const reason of body.allowedUnsupportedReasons
  ) {
    if (
      !nonEmptyString(reason) ||
      reasons.has(reason)
    ) {
      return false;
    }

    reasons.add(reason);
  }

  const names = new Set<string>();

  for (const raw of body.candidates) {
    if (!isObject(raw)) {
      return false;
    }

    if (!nonEmptyString(raw.name)) {
      return false;
    }

    if (names.has(raw.name)) {
      return false;
    }

    names.add(raw.name);

    if (typeof raw.loadable !== "boolean") {
      return false;
    }

    /*
     * Files are deliberately NOT rejected here.
     *
     * Invalid candidate files are candidate-level
     * invalidity, not HTTP INVALID_INPUT.
     */

    if (
      raw.calibrationDigest !== undefined &&
      typeof raw.calibrationDigest !== "string"
    ) {
      return false;
    }

    if (
      raw.tokenizerDigest !== undefined &&
      typeof raw.tokenizerDigest !== "string"
    ) {
      return false;
    }

    if (
      raw.unsupportedReason !== undefined &&
      typeof raw.unsupportedReason !== "string"
    ) {
      return false;
    }
  }

  return true;
}

/* ============================================================
   FREEZE OPERATION
   ============================================================ */

function freeze(body: Obj): FreezeResponse {
  const freezeId = body.freezeId as string;
  const expectedCalibration =
    body.calibrationDigest as string;
  const expectedTokenizer =
    body.tokenizerDigest as string;

  const allowed = new Set<string>(
    body.allowedUnsupportedReasons as string[]
  );

  const output: FrozenCandidate[] = [];

  for (const raw of body.candidates as unknown[]) {
    const candidate = raw as Obj;
    const name = candidate.name as string;

    const inventory = makeInventory(
      candidate.files
    );

    /*
     * Invalid files.
     */
    if (!inventory.valid) {
      output.push({
        name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes: [
          "INVALID_INPUT"
        ]
      });

      continue;
    }

    const codes: string[] = [];

    let isUnsupported = false;

    if (
      typeof candidate.unsupportedReason ===
      "string"
    ) {
      const reason =
        candidate.unsupportedReason;

      if (!allowed.has(reason)) {
        codes.push(
          "UNALLOWED_UNSUPPORTED_REASON"
        );
      } else {
        isUnsupported = true;
      }
    }

    /*
     * Allowed unsupported candidates do not need
     * loadability/digest matching.
     */
    if (!isUnsupported) {
      if (candidate.loadable !== true) {
        codes.push("NOT_LOADABLE");
      }

      if (
        candidate.calibrationDigest !==
        expectedCalibration
      ) {
        codes.push("CALIBRATION_MISMATCH");
      }

      if (
        candidate.tokenizerDigest !==
        expectedTokenizer
      ) {
        codes.push("TOKENIZER_MISMATCH");
      }
    }

    const reasonCodes = sortCodes(codes);

    let status:
      | "frozen"
      | "unsupported"
      | "invalid";

    if (reasonCodes.length > 0) {
      status = "invalid";
    } else if (isUnsupported) {
      status = "unsupported";
    } else {
      status = "frozen";
    }

    output.push({
      name,
      status,
      inventory: inventory.inventory,
      totalBytes: inventory.totalBytes,
      packageDigest: inventory.packageDigest,
      reasonCodes
    });
  }

  output.sort((a, b) =>
    utf8Compare(a.name, b.name)
  );

  return {
    freezeId,
    candidates: output
  };
}

/* ============================================================
   SELECT ENVELOPE VALIDATION
   ============================================================ */

function validSelectEnvelope(body: Obj): boolean {
  if (body.phase !== "select") {
    return false;
  }

  if (!nonEmptyString(body.freezeId)) {
    return false;
  }

  if (!Array.isArray(body.candidates)) {
    return false;
  }

  if (!Array.isArray(body.rows)) {
    return false;
  }

  if (!isObject(body.policy)) {
    return false;
  }

  if (!isObject(body.latencies)) {
    return false;
  }

  return true;
}

/* ============================================================
   SELECT HELPERS
   ============================================================ */

function namesOf(
  candidates: unknown[]
): string[] {
  const names: string[] = [];

  for (const raw of candidates) {
    if (
      isObject(raw) &&
      typeof raw.name === "string"
    ) {
      names.push(raw.name);
    }
  }

  return names;
}

function sameSet(
  a: string[],
  b: string[]
): boolean {
  if (a.length !== b.length) {
    return false;
  }

  const aa = new Set(a);
  const bb = new Set(b);

  if (aa.size !== bb.size) {
    return false;
  }

  for (const x of aa) {
    if (!bb.has(x)) {
      return false;
    }
  }

  return true;
}

/* ============================================================
   ACCURACY
   ============================================================ */

interface AccuracyResult {
  valid: boolean;
  aggregate: number | null;
  slices: Record<string, number>;
}

function calculateAccuracy(
  rows: unknown[],
  candidateName: string
): AccuracyResult {
  if (rows.length === 0) {
    return {
      valid: false,
      aggregate: null,
      slices: {}
    };
  }

  let correct = 0;

  const sliceTotal =
    new Map<string, number>();

  const sliceCorrect =
    new Map<string, number>();

  for (const raw of rows) {
    if (!isObject(raw)) {
      return {
        valid: false,
        aggregate: null,
        slices: {}
      };
    }

    if (!binary(raw.label)) {
      return {
        valid: false,
        aggregate: null,
        slices: {}
      };
    }

    if (!nonEmptyString(raw.slice)) {
      return {
        valid: false,
        aggregate: null,
        slices: {}
      };
    }

    if (!isObject(raw.predictions)) {
      return {
        valid: false,
        aggregate: null,
        slices: {}
      };
    }

    const prediction =
      raw.predictions[candidateName];

    if (!binary(prediction)) {
      return {
        valid: false,
        aggregate: null,
        slices: {}
      };
    }

    const slice = raw.slice as string;

    sliceTotal.set(
      slice,
      (sliceTotal.get(slice) ?? 0) + 1
    );

    if (prediction === raw.label) {
      correct++;

      sliceCorrect.set(
        slice,
        (sliceCorrect.get(slice) ?? 0) + 1
      );
    }
  }

  const slices: Record<string, number> = {};

  for (const [
    slice,
    total
  ] of sliceTotal.entries()) {
    slices[slice] = round12(
      (sliceCorrect.get(slice) ?? 0) /
      total
    );
  }

  return {
    valid: true,
    aggregate: round12(
      correct / rows.length
    ),
    slices
  };
}

/* ============================================================
   SELECT OPERATION
   ============================================================ */

function select(body: Obj): Obj {
  const freezeId =
    body.freezeId as string;

  const stored =
    freezes.get(freezeId);

  /*
   * Freeze doesn't exist.
   */
  if (!stored) {
    return {
      freezeId,
      selected: null,
      results: [],
      packageManifest: null
    };
  }

  const frozen =
    stored.response.candidates;

  const supplied =
    body.candidates as unknown[];

  const rows =
    body.rows as unknown[];

  const policy =
    body.policy as Obj;

  const latencies =
    body.latencies as Obj;

  const frozenNames =
    frozen.map(c => c.name);

  const suppliedNames =
    namesOf(supplied);

  /*
   * Candidate lineage.
   */
  const candidateOrder =
    Array.isArray(policy.candidateOrder)
      ? policy.candidateOrder
      : [];

  const candidateOrderStrings =
    candidateOrder.every(
      x => typeof x === "string"
    );

  const uniqueSupplied =
    new Set(suppliedNames).size ===
    suppliedNames.length;

  const uniqueOrder =
    candidateOrderStrings &&
    new Set(candidateOrder).size ===
    candidateOrder.length;

  const lineageValid =
    supplied.length === frozen.length &&
    uniqueSupplied &&
    sameSet(
      suppliedNames,
      frozenNames
    ) &&
    candidateOrderStrings &&
    uniqueOrder &&
    candidateOrder.length ===
      frozenNames.length &&
    sameSet(
      candidateOrder as string[],
      frozenNames
    );

  /*
   * Policy.
   */
  const maxBytes =
    policy.maxBytes;

  const aggregateFloor =
    policy.aggregateFloor;

  const requiredSlices =
    policy.requiredSlices;

  const maxLatencyMs =
    policy.maxLatencyMs;

  let policyValid =
    safeNonNegativeInteger(maxBytes) &&
    unitNumber(aggregateFloor) &&
    isObject(requiredSlices) &&
    finiteNonNegative(maxLatencyMs);

  if (
    Array.isArray(requiredSlices)
  ) {
    policyValid = false;
  }

  if (
    !Array.isArray(policy.candidateOrder)
  ) {
    policyValid = false;
  }

  /*
   * Maps.
   */
  const suppliedMap =
    new Map<string, Obj>();

  for (const raw of supplied) {
    if (
      isObject(raw) &&
      typeof raw.name === "string"
    ) {
      suppliedMap.set(
        raw.name,
        raw
      );
    }
  }

  const frozenMap =
    new Map<string, FrozenCandidate>();

  for (const c of frozen) {
    frozenMap.set(
      c.name,
      c
    );
  }

  const orderMap =
    new Map<string, number>();

  if (candidateOrderStrings) {
    (candidateOrder as string[]).forEach(
      (name, index) => {
        orderMap.set(name, index);
      }
    );
  }

  const results: Obj[] = [];

  for (const frozenCandidate of frozen) {
    const name =
      frozenCandidate.name;

    const codes: string[] = [];

    if (!lineageValid) {
      codes.push(
        "INVALID_LINEAGE"
      );
    }

    if (!policyValid) {
      codes.push(
        "INVALID_POLICY"
      );
    }

    /*
     * Find submitted candidate.
     */
    const submitted =
      suppliedMap.get(name);

    if (!submitted) {
      codes.push(
        "INVALID_MANIFEST"
      );
    }

    /*
     * Recompute inventory.
     */
    let totalBytes:
      number | null =
        frozenCandidate.totalBytes;

    if (submitted) {
      const recomputed =
        makeInventory(
          submitted.files
        );

      if (!recomputed.valid) {
        totalBytes = null;

        codes.push(
          "INVALID_MANIFEST"
        );
      } else {
        totalBytes =
          recomputed.totalBytes;

        if (
          recomputed.totalBytes !==
            frozenCandidate.totalBytes ||
          recomputed.packageDigest !==
            frozenCandidate.packageDigest ||
          JSON.stringify(
            recomputed.inventory
          ) !==
            JSON.stringify(
              frozenCandidate.inventory
            )
        ) {
          codes.push(
            "INVALID_MANIFEST"
          );
        }
      }
    }

    /*
     * Latency.
     */
    let latencyMs:
      number | null = null;

    const suppliedLatency =
      latencies[name];

    if (
      finiteNonNegative(
        suppliedLatency
      )
    ) {
      latencyMs =
        suppliedLatency;
    }

    /*
     * Predictions.
     */
    const accuracy =
      calculateAccuracy(
        rows,
        name
      );

    let aggregate:
      number | null =
        null;

    let slices:
      Record<string, number> = {};

    if (!accuracy.valid) {
      codes.push(
        "INVALID_PREDICTIONS"
      );
    } else {
      aggregate =
        accuracy.aggregate;

      slices =
        accuracy.slices;
    }

    /*
     * Aggregate floor.
     */
    if (
      aggregate !== null &&
      unitNumber(aggregateFloor) &&
      aggregate <
        (aggregateFloor as number)
    ) {
      codes.push(
        "AGGREGATE_FLOOR"
      );
    }

    /*
     * Slice floors.
     */
    if (isObject(requiredSlices)) {
      for (const sliceName of Object.keys(
        requiredSlices
      )) {
        const floor =
          requiredSlices[sliceName];

        if (!unitNumber(floor)) {
          codes.push(
            "INVALID_POLICY"
          );
          continue;
        }

        if (!(sliceName in slices)) {
          codes.push(
            `MISSING_SLICE:${sliceName}`
          );
          continue;
        }

        if (
          slices[sliceName] <
          (floor as number)
        ) {
          codes.push(
            `SLICE_FLOOR:${sliceName}`
          );
        }
      }
    }

    /*
     * Size.
     */
    if (
      totalBytes === null ||
      !safeNonNegativeInteger(totalBytes) ||
      !safeNonNegativeInteger(maxBytes) ||
      totalBytes >
        (maxBytes as number)
    ) {
      codes.push(
        "SIZE_LIMIT"
      );
    }

    /*
     * Latency.
     */
    if (
      latencyMs === null ||
      !finiteNonNegative(maxLatencyMs) ||
      latencyMs >
        (maxLatencyMs as number)
    ) {
      codes.push(
        "LATENCY_LIMIT"
      );
    }

    const reasonCodes =
      sortCodes(codes);

    const admitted =
      frozenCandidate.status === "frozen" &&
      reasonCodes.length === 0;

    results.push({
      name,
      aggregate,
      slices,
      totalBytes,
      latencyMs,
      admitted,
      reasonCodes
    });
  }

  /*
   * Results must follow candidateOrder.
   */
  results.sort((a, b) => {
    const an = a.name as string;
    const bn = b.name as string;

    const ai =
      orderMap.has(an)
        ? (orderMap.get(an) as number)
        : Number.MAX_SAFE_INTEGER;

    const bi =
      orderMap.has(bn)
        ? (orderMap.get(bn) as number)
        : Number.MAX_SAFE_INTEGER;

    if (ai !== bi) {
      return ai - bi;
    }

    return utf8Compare(an, bn);
  });

  /*
   * Select admitted candidate:
   *
   * smaller bytes
   * lower latency
   * candidate order
   * UTF-8 name
   */
  const admitted =
    results.filter(
      x => x.admitted === true
    );

  admitted.sort((a, b) => {
    const ab =
      a.totalBytes as number;

    const bb =
      b.totalBytes as number;

    if (ab !== bb) {
      return ab - bb;
    }

    const al =
      a.latencyMs as number;

    const bl =
      b.latencyMs as number;

    if (al !== bl) {
      return al - bl;
    }

    const ai =
      orderMap.has(a.name as string)
        ? (orderMap.get(
            a.name as string
          ) as number)
        : Number.MAX_SAFE_INTEGER;

    const bi =
      orderMap.has(b.name as string)
        ? (orderMap.get(
            b.name as string
          ) as number)
        : Number.MAX_SAFE_INTEGER;

    if (ai !== bi) {
      return ai - bi;
    }

    return utf8Compare(
      a.name as string,
      b.name as string
    );
  });

  let selected:
    string | null = null;

  let packageManifest:
    FrozenCandidate | null = null;

  if (admitted.length > 0) {
    selected =
      admitted[0].name as string;

    packageManifest =
      frozenMap.get(selected) ?? null;
  }

  return {
    freezeId,
    selected,
    results,
    packageManifest
  };
}

/* ============================================================
   ROUTE
   ============================================================ */

app.post(
  "/quantize",
  (req: Request, res: Response) => {
    const body: unknown = req.body;

    if (!isObject(body)) {
      return invalidInput(res);
    }

    /*
     * Phase must be exactly freeze/select.
     */
    if (
      body.phase !== "freeze" &&
      body.phase !== "select"
    ) {
      return invalidInput(res);
    }

    /* --------------------------------------------------------
       FREEZE
       -------------------------------------------------------- */

    if (body.phase === "freeze") {
      if (!validFreezeEnvelope(body)) {
        return invalidInput(res);
      }

      const freezeId =
        body.freezeId as string;

      const fp =
        fingerprint(body);

      const previous =
        freezes.get(freezeId);

      /*
       * Same request = exact replay.
       */
      if (previous) {
        if (
          previous.fingerprint !== fp
        ) {
          return res
            .status(409)
            .type("application/json")
            .send(
              JSON.stringify({
                error:
                  "FREEZE_ID_CONFLICT"
              })
            );
        }

        return res
          .type("application/json")
          .send(
            JSON.stringify(
              previous.response
            )
          );
      }

      /*
       * Generate and persist.
       */
      const response =
        freeze(body);

      freezes.set(
        freezeId,
        {
          fingerprint: fp,
          response
        }
      );

      return res
        .type("application/json")
        .send(
          JSON.stringify(response)
        );
    }

    /* --------------------------------------------------------
       SELECT
       -------------------------------------------------------- */

    if (body.phase === "select") {
      if (!validSelectEnvelope(body)) {
        return invalidInput(res);
      }

      const response =
        select(body);

      return res
        .type("application/json")
        .send(
          JSON.stringify(response)
        );
    }

    return invalidInput(res);
  }
);

/* ============================================================
   HEALTH
   ============================================================ */

app.get(
  "/",
  (_req: Request, res: Response) => {
    res.json({
      service: "quantize-gate",
      status: "ok"
    });
  }
);

/* ============================================================
   START
   ============================================================ */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `quantize-gate listening on ${PORT}`
    );
  }
);
