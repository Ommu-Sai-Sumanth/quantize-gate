import express, { Request, Response } from "express";
import crypto from "crypto";

const app = express();

app.use(express.json({ limit: "25mb" }));

const PORT = Number(process.env.PORT) || 3000;

/* =========================================================
   Types
   ========================================================= */

type JsonObject = Record<string, unknown>;

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

const freezeStore = new Map<string, StoredFreeze>();

/* =========================================================
   Basic helpers
   ========================================================= */

function isObject(value: unknown): value is JsonObject {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function isNonEmptyString(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0
  );
}

function isFiniteNonNegative(
  value: unknown
): value is number {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= 0
  );
}

function isSafeNonNegativeInteger(
  value: unknown
): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0
  );
}

function isUnitNumber(
  value: unknown
): value is number {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= 1
  );
}

function utf8Compare(
  a: string,
  b: string
): number {
  return Buffer.compare(
    Buffer.from(a, "utf8"),
    Buffer.from(b, "utf8")
  );
}

function sortedUnique(
  codes: string[]
): string[] {
  return Array.from(new Set(codes))
    .sort(utf8Compare);
}

function sha256(
  value: string
): string {
  return crypto
    .createHash("sha256")
    .update(Buffer.from(value, "utf8"))
    .digest("hex");
}

function compactJson(
  value: unknown
): string {
  return JSON.stringify(value);
}

function fingerprint(
  value: unknown
): string {
  return sha256(
    compactJson(value)
  );
}

function sendInvalidInput(
  res: Response
): void {
  res
    .status(400)
    .type("application/json")
    .send(
      JSON.stringify({
        error: "INVALID_INPUT"
      })
    );
}

/* =========================================================
   Inventory
   ========================================================= */

function buildInventory(
  files: unknown
): {
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

  const seen = new Set<string>();

  for (const filename of names) {
    if (
      !isNonEmptyString(filename) ||
      seen.has(filename) ||
      typeof files[filename] !== "string"
    ) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null
      };
    }

    seen.add(filename);
  }

  names.sort(utf8Compare);

  const inventory: InventoryItem[] = [];

  let totalBytes = 0;

  for (const filename of names) {
    const text =
      files[filename] as string;

    const bytes =
      Buffer.byteLength(
        text,
        "utf8"
      );

    const fileDigest =
      sha256(text);

    totalBytes += bytes;

    if (
      !Number.isSafeInteger(totalBytes)
    ) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null
      };
    }

    inventory.push({
      name: filename,
      bytes,
      sha256: fileDigest
    });
  }

  const packageDigest =
    sha256(
      compactJson(inventory)
    );

  return {
    valid: true,
    inventory,
    totalBytes,
    packageDigest
  };
}

/* =========================================================
   Freeze request validation
   ========================================================= */

function validateFreezeRequest(
  body: JsonObject
): boolean {
  if (body.phase !== "freeze") {
    return false;
  }

  if (
    !isNonEmptyString(body.freezeId) ||
    body.freezeId.length > 128
  ) {
    return false;
  }

  if (
    !isNonEmptyString(
      body.calibrationDigest
    )
  ) {
    return false;
  }

  if (
    !isNonEmptyString(
      body.tokenizerDigest
    )
  ) {
    return false;
  }

  if (
    !Array.isArray(
      body.allowedUnsupportedReasons
    )
  ) {
    return false;
  }

  if (
    !Array.isArray(body.candidates) ||
    body.candidates.length === 0
  ) {
    return false;
  }

  const reasons =
    body.allowedUnsupportedReasons as unknown[];

  const reasonSet =
    new Set<string>();

  for (const reason of reasons) {
    if (
      !isNonEmptyString(reason) ||
      reasonSet.has(reason)
    ) {
      return false;
    }

    reasonSet.add(reason);
  }

  const names =
    new Set<string>();

  const candidates =
    body.candidates as unknown[];

  for (const raw of candidates) {
    if (!isObject(raw)) {
      return false;
    }

    if (!isNonEmptyString(raw.name)) {
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
     * These fields are optional according to the
     * contract. If supplied, they must be strings.
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

    /*
     * Files must be an object. Detailed file
     * validation happens at candidate level.
     */
    if (!isObject(raw.files)) {
      return false;
    }
  }

  return true;
}

/* =========================================================
   Freeze
   ========================================================= */

function performFreeze(
  body: JsonObject
): FreezeResponse {
  const freezeId =
    body.freezeId as string;

  const calibrationDigest =
    body.calibrationDigest as string;

  const tokenizerDigest =
    body.tokenizerDigest as string;

  const allowedReasons =
    body.allowedUnsupportedReasons as unknown[];

  const allowed =
    new Set<string>();

  for (const reason of allowedReasons) {
    if (typeof reason === "string") {
      allowed.add(reason);
    }
  }

  const candidates =
    body.candidates as unknown[];

  const output: FrozenCandidate[] = [];

  for (const raw of candidates) {
    const candidate =
      raw as JsonObject;

    const name =
      candidate.name as string;

    const inventoryResult =
      buildInventory(
        candidate.files
      );

    /*
     * Invalid file inventory:
     * candidate itself becomes invalid.
     */
    if (!inventoryResult.valid) {
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

    let unsupported = false;

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
        unsupported = true;
      }
    }

    /*
     * Unsupported candidates do not need to
     * satisfy loadability/lineage checks.
     */
    if (!unsupported) {
      if (
        candidate.loadable !== true
      ) {
        codes.push(
          "NOT_LOADABLE"
        );
      }

      if (
        candidate.calibrationDigest !==
        calibrationDigest
      ) {
        codes.push(
          "CALIBRATION_MISMATCH"
        );
      }

      if (
        candidate.tokenizerDigest !==
        tokenizerDigest
      ) {
        codes.push(
          "TOKENIZER_MISMATCH"
        );
      }
    }

    const reasonCodes =
      sortedUnique(codes);

    let status:
      | "frozen"
      | "unsupported"
      | "invalid";

    if (reasonCodes.length > 0) {
      status = "invalid";
    } else if (unsupported) {
      status = "unsupported";
    } else {
      status = "frozen";
    }

    output.push({
      name,
      status,
      inventory:
        inventoryResult.inventory,
      totalBytes:
        inventoryResult.totalBytes,
      packageDigest:
        inventoryResult.packageDigest,
      reasonCodes
    });
  }

  output.sort(
    (a, b) =>
      utf8Compare(a.name, b.name)
  );

  return {
    freezeId,
    candidates: output
  };
}

/* =========================================================
   Selection validation
   ========================================================= */

function validateSelectRequest(
  body: JsonObject
): boolean {
  if (body.phase !== "select") {
    return false;
  }

  if (
    !isNonEmptyString(body.freezeId)
  ) {
    return false;
  }

  if (
    !Array.isArray(body.candidates)
  ) {
    return false;
  }

  if (
    !Array.isArray(body.rows)
  ) {
    return false;
  }

  if (
    !isObject(body.policy)
  ) {
    return false;
  }

  if (
    !isObject(body.latencies)
  ) {
    return false;
  }

  return true;
}

/* =========================================================
   Candidate lineage verification
   ========================================================= */

function candidateNames(
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

function sameStringSet(
  a: string[],
  b: string[]
): boolean {
  if (a.length !== b.length) {
    return false;
  }

  const aa =
    new Set(a);

  const bb =
    new Set(b);

  if (aa.size !== bb.size) {
    return false;
  }

  for (const value of aa) {
    if (!bb.has(value)) {
      return false;
    }
  }

  return true;
}

/* =========================================================
   Accuracy
   ========================================================= */

function isBinary(
  value: unknown
): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    (value === 0 || value === 1)
  );
}

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

  const totals =
    new Map<string, number>();

  const correctBySlice =
    new Map<string, number>();

  for (const raw of rows) {
    if (!isObject(raw)) {
      return {
        valid: false,
        aggregate: null,
        slices: {}
      };
    }

    if (
      !isBinary(raw.label) ||
      !isNonEmptyString(raw.slice) ||
      !isObject(raw.predictions)
    ) {
      return {
        valid: false,
        aggregate: null,
        slices: {}
      };
    }

    const prediction =
      raw.predictions[candidateName];

    if (!isBinary(prediction)) {
      return {
        valid: false,
        aggregate: null,
        slices: {}
      };
    }

    const slice =
      raw.slice;

    totals.set(
      slice,
      (totals.get(slice) ?? 0) + 1
    );

    if (
      prediction === raw.label
    ) {
      correct++;
      correctBySlice.set(
        slice,
        (correctBySlice.get(slice) ?? 0) + 1
      );
    }
  }

  const slices:
    Record<string, number> = {};

  for (const [
    slice,
    total
  ] of totals) {
    const good =
      correctBySlice.get(slice) ?? 0;

    slices[slice] =
      round12(good / total);
  }

  return {
    valid: true,
    aggregate:
      round12(correct / rows.length),
    slices
  };
}

/* =========================================================
   Rounding
   ========================================================= */

function round12(
  value: number
): number {
  return Number(
    value.toFixed(12)
  );
}

/* =========================================================
   Select
   ========================================================= */

function performSelect(
  body: JsonObject
): JsonObject {
  const freezeId =
    body.freezeId as string;

  const stored =
    freezeStore.get(freezeId);

  /*
   * Freeze ID doesn't exist.
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
    body.policy as JsonObject;

  const latencies =
    body.latencies as JsonObject;

  const frozenNames =
    frozen.map(c => c.name);

  const suppliedNames =
    candidateNames(supplied);

  const candidateOrderRaw =
    Array.isArray(
      policy.candidateOrder
    )
      ? policy.candidateOrder
      : [];

  const candidateOrder =
    candidateOrderRaw.filter(
      (x): x is string =>
        typeof x === "string"
    );

  const lineageValid =
    supplied.length ===
      frozen.length &&
    suppliedNames.every(
      name =>
        suppliedNames.filter(
          x => x === name
        ).length === 1
    ) &&
    sameStringSet(
      suppliedNames,
      frozenNames
    ) &&
    candidateOrder.length ===
      frozenNames.length &&
    new Set(candidateOrder).size ===
      candidateOrder.length &&
    sameStringSet(
      candidateOrder,
      frozenNames
    );

  /*
   * Policy validation.
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
    isSafeNonNegativeInteger(
      maxBytes
    ) &&
    isUnitNumber(
      aggregateFloor
    ) &&
    isObject(
      requiredSlices
    ) &&
    isFiniteNonNegative(
      maxLatencyMs
    );

  if (Array.isArray(requiredSlices)) {
    policyValid = false;
  }

  if (
    new Set(candidateOrder).size !==
    candidateOrder.length
  ) {
    policyValid = false;
  }

  /*
   * Maps.
   */
  const suppliedMap =
    new Map<string, JsonObject>();

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

  for (const candidate of frozen) {
    frozenMap.set(
      candidate.name,
      candidate
    );
  }

  const orderMap =
    new Map<string, number>();

  candidateOrder.forEach(
    (name, index) => {
      orderMap.set(
        name,
        index
      );
    }
  );

  const results: JsonObject[] = [];

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

    const suppliedCandidate =
      suppliedMap.get(name);

    if (!suppliedCandidate) {
      codes.push(
        "INVALID_MANIFEST"
      );
    }

    /*
     * Recompute manifest from supplied
     * candidate files.
     */
    let totalBytes:
      number | null =
        frozenCandidate.totalBytes;

    if (suppliedCandidate) {
      const inventory =
        buildInventory(
          suppliedCandidate.files
        );

      if (!inventory.valid) {
        totalBytes = null;

        codes.push(
          "INVALID_MANIFEST"
        );
      } else {
        totalBytes =
          inventory.totalBytes;

        if (
          inventory.packageDigest !==
            frozenCandidate.packageDigest ||
          inventory.totalBytes !==
            frozenCandidate.totalBytes ||
          JSON.stringify(
            inventory.inventory
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

    if (
      isFiniteNonNegative(
        latencies[name]
      )
    ) {
      latencyMs =
        latencies[name] as number;
    }

    /*
     * Accuracy.
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
      isUnitNumber(aggregateFloor) &&
      aggregate <
        (aggregateFloor as number)
    ) {
      codes.push(
        "AGGREGATE_FLOOR"
      );
    }

    /*
     * Required slices.
     */
    if (isObject(requiredSlices)) {
      for (const sliceName of Object.keys(
        requiredSlices
      )) {
        const floor =
          requiredSlices[sliceName];

        if (!isUnitNumber(floor)) {
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
      !isSafeNonNegativeInteger(
        totalBytes
      ) ||
      !isSafeNonNegativeInteger(
        maxBytes
      ) ||
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
      !isFiniteNonNegative(
        maxLatencyMs
      ) ||
      latencyMs >
        (maxLatencyMs as number)
    ) {
      codes.push(
        "LATENCY_LIMIT"
      );
    }

    const reasonCodes =
      sortedUnique(codes);

    const admitted =
      frozenCandidate.status ===
        "frozen" &&
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
   * Results order = candidateOrder.
   * UTF-8 name is fallback.
   */
  results.sort((a, b) => {
    const an =
      a.name as string;

    const bn =
      b.name as string;

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

    return utf8Compare(
      an,
      bn
    );
  });

  /*
   * Winner:
   * 1. smaller bytes
   * 2. lower latency
   * 3. candidate order
   * 4. UTF-8 name
   */
  const admitted =
    results.filter(
      result =>
        result.admitted === true
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

/* =========================================================
   POST /quantize
   ========================================================= */

app.post(
  "/quantize",
  (
    req: Request,
    res: Response
  ) => {
    const body: unknown =
      req.body;

    if (!isObject(body)) {
      return sendInvalidInput(res);
    }

    /*
     * Unknown/missing phase.
     */
    if (
      body.phase !== "freeze" &&
      body.phase !== "select"
    ) {
      return sendInvalidInput(res);
    }

    /* -----------------------------------------------------
       FREEZE
       ----------------------------------------------------- */

    if (body.phase === "freeze") {
      if (
        !validateFreezeRequest(body)
      ) {
        return sendInvalidInput(res);
      }

      const freezeId =
        body.freezeId as string;

      const requestFingerprint =
        fingerprint(body);

      const existing =
        freezeStore.get(
          freezeId
        );

      /*
       * Replay.
       */
      if (existing) {
        if (
          existing.fingerprint !==
          requestFingerprint
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
              existing.response
            )
          );
      }

      /*
       * Rejected freeze requests must not
       * reserve the freezeId.
       */
      const response =
        performFreeze(body);

      freezeStore.set(
        freezeId,
        {
          fingerprint:
            requestFingerprint,
          response
        }
      );

      return res
        .type("application/json")
        .send(
          JSON.stringify(response)
        );
    }

    /* -----------------------------------------------------
       SELECT
       ----------------------------------------------------- */

    if (body.phase === "select") {
      if (
        !validateSelectRequest(body)
      ) {
        return sendInvalidInput(res);
      }

      const response =
        performSelect(body);

      return res
        .type("application/json")
        .send(
          JSON.stringify(response)
        );
    }
  }
);

/* =========================================================
   Health check
   ========================================================= */

app.get(
  "/",
  (
    _req: Request,
    res: Response
  ) => {
    res.json({
      service: "quantize-gate",
      status: "ok"
    });
  }
);

/* =========================================================
   Server
   ========================================================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `quantize-gate listening on port ${PORT}`
    );
  }
);
