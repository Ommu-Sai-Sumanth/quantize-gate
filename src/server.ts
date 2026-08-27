import express, { Request, Response } from "express";
import crypto from "crypto";

const app = express();

app.use(express.json({ limit: "10mb" }));

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

const freezes = new Map<string, StoredFreeze>();

/* =========================================================
   Helpers
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

function isSafeNonNegativeInteger(
  value: unknown
): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0
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

function isFiniteUnit(
  value: unknown
): value is number {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= 1
  );
}

function utf8Compare(a: string, b: string): number {
  return Buffer.compare(
    Buffer.from(a, "utf8"),
    Buffer.from(b, "utf8")
  );
}

function sortedUniqueStrings(
  values: string[]
): string[] {
  return Array.from(new Set(values))
    .sort(utf8Compare);
}

function sha256Utf8(value: string): string {
  return crypto
    .createHash("sha256")
    .update(Buffer.from(value, "utf8"))
    .digest("hex");
}

function round12(value: number): number {
  return Number(value.toFixed(12));
}

function compactJson(value: unknown): string {
  return JSON.stringify(value);
}

function fingerprint(value: unknown): string {
  return sha256Utf8(compactJson(value));
}

function sendInvalidInput(res: Response): void {
  res
    .status(400)
    .type("application/json")
    .send(JSON.stringify({
      error: "INVALID_INPUT"
    }));
}

/* =========================================================
   File inventory
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

  for (const name of names) {
    if (
      !isNonEmptyString(name) ||
      seen.has(name) ||
      typeof files[name] !== "string"
    ) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null
      };
    }

    seen.add(name);
  }

  const sortedNames = names.sort(utf8Compare);

  const inventory: InventoryItem[] = [];

  let totalBytes = 0;

  for (const name of sortedNames) {
    const text = files[name] as string;
    const bytes = Buffer.byteLength(text, "utf8");
    const sha256 = sha256Utf8(text);

    inventory.push({
      name,
      bytes,
      sha256
    });

    totalBytes += bytes;

    if (!Number.isSafeInteger(totalBytes)) {
      return {
        valid: false,
        inventory: [],
        totalBytes: null,
        packageDigest: null
      };
    }
  }

  const packageDigest = sha256Utf8(
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
   Freeze validation
   ========================================================= */

function validateFreezeRequest(
  body: unknown
): boolean {
  if (!isObject(body)) {
    return false;
  }

  if (body.phase !== "freeze") {
    return false;
  }

  if (!isNonEmptyString(body.freezeId)) {
    return false;
  }

  if (body.freezeId.length > 128) {
    return false;
  }

  if (!isNonEmptyString(body.calibrationDigest)) {
    return false;
  }

  if (!isNonEmptyString(body.tokenizerDigest)) {
    return false;
  }

  if (!Array.isArray(body.allowedUnsupportedReasons)) {
    return false;
  }

  if (!Array.isArray(body.candidates)) {
    return false;
  }

  if (body.candidates.length === 0) {
    return false;
  }

  const reasons = body.allowedUnsupportedReasons;

  const reasonSet = new Set<string>();

  for (const reason of reasons) {
    if (
      !isNonEmptyString(reason) ||
      reasonSet.has(reason)
    ) {
      return false;
    }

    reasonSet.add(reason);
  }

  const names = new Set<string>();

  for (const candidate of body.candidates) {
    if (!isObject(candidate)) {
      return false;
    }

    if (!isNonEmptyString(candidate.name)) {
      return false;
    }

    if (names.has(candidate.name)) {
      return false;
    }

    names.add(candidate.name);

    if (typeof candidate.loadable !== "boolean") {
      return false;
    }

    if (
      candidate.calibrationDigest !== undefined &&
      typeof candidate.calibrationDigest !== "string"
    ) {
      return false;
    }

    if (
      candidate.tokenizerDigest !== undefined &&
      typeof candidate.tokenizerDigest !== "string"
    ) {
      return false;
    }

    if (
      candidate.unsupportedReason !== undefined &&
      typeof candidate.unsupportedReason !== "string"
    ) {
      return false;
    }

    if (!isObject(candidate.files)) {
      return false;
    }

    const fileNames = Object.keys(candidate.files);

    if (fileNames.length === 0) {
      return false;
    }

    const fileSet = new Set<string>();

    for (const filename of fileNames) {
      if (
        !isNonEmptyString(filename) ||
        fileSet.has(filename) ||
        typeof candidate.files[filename] !== "string"
      ) {
        return false;
      }

      fileSet.add(filename);
    }
  }

  return true;
}

/* =========================================================
   Freeze operation
   ========================================================= */

function freeze(
  body: JsonObject
): FreezeResponse {
  const freezeId = body.freezeId as string;
  const requestCalibration =
    body.calibrationDigest as string;
  const requestTokenizer =
    body.tokenizerDigest as string;

  const allowed =
    body.allowedUnsupportedReasons as string[];

  const allowedSet = new Set(allowed);

  const candidates =
    body.candidates as unknown[];

  const output: FrozenCandidate[] = [];

  for (const raw of candidates) {
    const candidate = raw as JsonObject;

    const name = candidate.name as string;

    const inventoryResult =
      buildInventory(candidate.files);

    const reasonCodes: string[] = [];

    if (!inventoryResult.valid) {
      reasonCodes.push("INVALID_INPUT");

      output.push({
        name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes: sortedUniqueStrings(reasonCodes)
      });

      continue;
    }

    const unsupportedReason =
      candidate.unsupportedReason;

    let unsupported = false;

    if (typeof unsupportedReason === "string") {
      if (!allowedSet.has(unsupportedReason)) {
        reasonCodes.push(
          "UNALLOWED_UNSUPPORTED_REASON"
        );
      } else {
        unsupported = true;
      }
    }

    if (!unsupported) {
      if (candidate.loadable !== true) {
        reasonCodes.push("NOT_LOADABLE");
      }

      if (
        candidate.calibrationDigest !==
        requestCalibration
      ) {
        reasonCodes.push(
          "CALIBRATION_MISMATCH"
        );
      }

      if (
        candidate.tokenizerDigest !==
        requestTokenizer
      ) {
        reasonCodes.push(
          "TOKENIZER_MISMATCH"
        );
      }
    }

    const codes =
      sortedUniqueStrings(reasonCodes);

    let status:
      | "frozen"
      | "unsupported"
      | "invalid";

    if (codes.length > 0) {
      status = "invalid";
    } else if (unsupported) {
      status = "unsupported";
    } else {
      status = "frozen";
    }

    output.push({
      name,
      status,
      inventory: inventoryResult.inventory,
      totalBytes: inventoryResult.totalBytes,
      packageDigest: inventoryResult.packageDigest,
      reasonCodes: codes
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

/* =========================================================
   Accuracy helpers
   ========================================================= */

function isBinaryPrediction(
  value: unknown
): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    (value === 0 || value === 1)
  );
}

function calculateAccuracy(
  rows: unknown[],
  candidateName: string
): {
  valid: boolean;
  aggregate: number | null;
  slices: Record<string, number>;
  presentSlices: Set<string>;
} {
  const sliceCorrect = new Map<
    string,
    number
  >();

  const sliceTotal = new Map<
    string,
    number
  >();

  let correct = 0;

  for (const raw of rows) {
    if (!isObject(raw)) {
      return {
        valid: false,
        aggregate: null,
        slices: {},
        presentSlices: new Set()
      };
    }

    const label = raw.label;

    if (
      !isBinaryPrediction(label) ||
      !isNonEmptyString(raw.slice) ||
      !isObject(raw.predictions)
    ) {
      return {
        valid: false,
        aggregate: null,
        slices: {},
        presentSlices: new Set()
      };
    }

    const prediction =
      raw.predictions[candidateName];

    if (!isBinaryPrediction(prediction)) {
      return {
        valid: false,
        aggregate: null,
        slices: {},
        presentSlices: new Set()
      };
    }

    if (prediction === label) {
      correct++;
    }

    const slice = raw.slice;

    sliceTotal.set(
      slice,
      (sliceTotal.get(slice) ?? 0) + 1
    );

    if (prediction === label) {
      sliceCorrect.set(
        slice,
        (sliceCorrect.get(slice) ?? 0) + 1
      );
    }
  }

  if (rows.length === 0) {
    return {
      valid: false,
      aggregate: null,
      slices: {},
      presentSlices: new Set()
    };
  }

  const slices: Record<string, number> = {};

  for (const [slice, total] of sliceTotal) {
    const good = sliceCorrect.get(slice) ?? 0;

    slices[slice] =
      round12(good / total);
  }

  return {
    valid: true,
    aggregate: round12(
      correct / rows.length
    ),
    slices,
    presentSlices: new Set(sliceTotal.keys())
  };
}

/* =========================================================
   Selection validation
   ========================================================= */

function validateSelectRequest(
  body: unknown
): boolean {
  if (!isObject(body)) {
    return false;
  }

  if (body.phase !== "select") {
    return false;
  }

  if (!isNonEmptyString(body.freezeId)) {
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

  if (body.candidates.length === 0) {
    return false;
  }

  if (body.rows.length === 0) {
    return false;
  }

  return true;
}

/* =========================================================
   Select operation
   ========================================================= */

function select(
  body: JsonObject
): JsonObject {
  const freezeId =
    body.freezeId as string;

  const stored = freezes.get(freezeId);

  if (!stored) {
    return {
      freezeId,
      selected: null,
      results: [],
      packageManifest: null
    };
  }

  const suppliedCandidates =
    body.candidates as unknown[];

  const rows =
    body.rows as unknown[];

  const policy =
    body.policy as JsonObject;

  const latencies =
    body.latencies as JsonObject;

  const frozen =
    stored.response.candidates;

  const result: JsonObject = {
    freezeId,
    selected: null,
    results: [],
    packageManifest: null
  };

  const results: JsonObject[] = [];

  /*
   * Verify candidate names.
   */
  const frozenNames =
    new Set(frozen.map(c => c.name));

  const suppliedNames: string[] = [];

  for (const raw of suppliedCandidates) {
    if (!isObject(raw)) {
      continue;
    }

    if (typeof raw.name === "string") {
      suppliedNames.push(raw.name);
    }
  }

  const suppliedNameSet =
    new Set(suppliedNames);

  const candidateOrder =
    Array.isArray(policy.candidateOrder)
      ? policy.candidateOrder.filter(
          (x): x is string =>
            typeof x === "string"
        )
      : [];

  const orderSet =
    new Set(candidateOrder);

  const lineageValid =
    suppliedCandidates.length ===
      frozen.length &&
    suppliedNames.length ===
      suppliedCandidates.length &&
    suppliedNameSet.size ===
      suppliedNames.length &&
    suppliedNameSet.size ===
      frozenNames.size &&
    [...frozenNames].every(
      name => suppliedNameSet.has(name)
    ) &&
    orderSet.size === candidateOrder.length &&
    orderSet.size === frozenNames.size &&
    [...frozenNames].every(
      name => orderSet.has(name)
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

  const policyValid =
    isSafeNonNegativeInteger(maxBytes) &&
    isFiniteUnit(aggregateFloor) &&
    isObject(requiredSlices) &&
    isFiniteNonNegative(maxLatencyMs) &&
    candidateOrder.every(
      name => typeof name === "string"
    );

  /*
   * Recompute supplied manifests.
   */
  const suppliedByName =
    new Map<string, JsonObject>();

  for (const raw of suppliedCandidates) {
    if (isObject(raw) &&
        typeof raw.name === "string") {
      suppliedByName.set(
        raw.name,
        raw
      );
    }
  }

  const frozenByName =
    new Map(
      frozen.map(candidate => [
        candidate.name,
        candidate
      ])
    );

  for (const frozenCandidate of frozen) {
    const name =
      frozenCandidate.name;

    const codes: string[] = [];

    if (!lineageValid) {
      codes.push("INVALID_LINEAGE");
    }

    if (!policyValid) {
      codes.push("INVALID_POLICY");
    }

    const supplied =
      suppliedByName.get(name);

    if (!supplied) {
      codes.push("INVALID_MANIFEST");
    }

    const storedCandidate =
      frozenByName.get(name);

    let totalBytes:
      number | null =
        storedCandidate?.totalBytes ??
        null;

    let latencyMs:
      number | null = null;

    if (
      isObject(latencies) &&
      isFiniteNonNegative(latencies[name])
    ) {
      latencyMs =
        latencies[name] as number;
    }

    let aggregate:
      number | null = null;

    let slices:
      Record<string, number> = {};

    let predictionValid = true;

    if (rows.length === 0) {
      predictionValid = false;
    } else {
      const accuracy =
        calculateAccuracy(
          rows,
          name
        );

      if (!accuracy.valid) {
        predictionValid = false;
      } else {
        aggregate =
          accuracy.aggregate;

        slices =
          accuracy.slices;
      }
    }

    if (!predictionValid) {
      codes.push("INVALID_PREDICTIONS");
    }

    /*
     * Manifest verification.
     */
    if (supplied) {
      const files =
        supplied.files;

      const manifest =
        buildInventory(files);

      if (!manifest.valid) {
        codes.push("INVALID_MANIFEST");
        totalBytes = null;
      } else {
        totalBytes =
          manifest.totalBytes;

        if (
          manifest.totalBytes !==
            storedCandidate?.totalBytes ||
          manifest.packageDigest !==
            storedCandidate?.packageDigest
        ) {
          codes.push("INVALID_MANIFEST");
        }
      }
    }

    if (
      aggregate !== null &&
      aggregate < (aggregateFloor as number)
    ) {
      codes.push("AGGREGATE_FLOOR");
    }

    if (isObject(requiredSlices)) {
      for (const sliceName of Object.keys(
        requiredSlices
      )) {
        const floor =
          requiredSlices[sliceName];

        if (!isFiniteUnit(floor)) {
          codes.push("INVALID_POLICY");
          continue;
        }

        if (!(sliceName in slices)) {
          codes.push(
            `MISSING_SLICE:${sliceName}`
          );
          continue;
        }

        if (slices[sliceName] < floor) {
          codes.push(
            `SLICE_FLOOR:${sliceName}`
          );
        }
      }
    }

    if (
  totalBytes === null ||
  !isSafeNonNegativeInteger(totalBytes) ||
  totalBytes > (maxBytes as number)
) {
      codes.push("SIZE_LIMIT");
    }

    if (
      latencyMs === null ||
      latencyMs > (maxLatencyMs as number)
    ) {
      codes.push("LATENCY_LIMIT");
    }

    const uniqueCodes =
      sortedUniqueStrings(codes);

    const admitted =
      frozenCandidate.status === "frozen" &&
      uniqueCodes.length === 0;

    results.push({
      name,
      aggregate,
      slices,
      totalBytes,
      latencyMs,
      admitted,
      reasonCodes: uniqueCodes
    });
  }

  /*
   * Order results by candidateOrder,
   * UTF-8 name fallback.
   */
  const orderIndex =
    new Map<string, number>();

  candidateOrder.forEach(
    (name, index) =>
      orderIndex.set(name, index)
  );

  results.sort((a, b) => {
    const an = a.name as string;
    const bn = b.name as string;

    const ai =
      orderIndex.get(an) ?? Number.MAX_SAFE_INTEGER;

    const bi =
      orderIndex.get(bn) ?? Number.MAX_SAFE_INTEGER;

    if (ai !== bi) {
      return ai - bi;
    }

    return utf8Compare(an, bn);
  });

  /*
   * Choose admitted candidate:
   * bytes ascending,
   * latency ascending,
   * candidate order.
   */
  const admitted =
    results.filter(
      r => r.admitted === true
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
      orderIndex.get(
        a.name as string
      ) ?? Number.MAX_SAFE_INTEGER;

    const bi =
      orderIndex.get(
        b.name as string
      ) ?? Number.MAX_SAFE_INTEGER;

    if (ai !== bi) {
      return ai - bi;
    }

    return utf8Compare(
      a.name as string,
      b.name as string
    );
  });

  if (admitted.length > 0) {
    const winner =
      admitted[0].name as string;

    result.selected = winner;

    const frozenWinner =
      frozenByName.get(winner);

    result.packageManifest =
      frozenWinner ?? null;
  }

  result.results = results;

  return result;
}

/* =========================================================
   POST /quantize
   ========================================================= */

app.post(
  "/quantize",
  (req: Request, res: Response) => {
    const body: unknown = req.body;

    if (!isObject(body)) {
      return sendInvalidInput(res);
    }

    const phase = body.phase;

    if (
      phase !== "freeze" &&
      phase !== "select"
    ) {
      return sendInvalidInput(res);
    }

    /*
     * =====================================================
     * FREEZE
     * =====================================================
     */

    if (phase === "freeze") {
      if (!validateFreezeRequest(body)) {
        return sendInvalidInput(res);
      }

      const freezeId =
        body.freezeId as string;

      /*
       * Fingerprint only accepted freeze
       * input.
       */
      const inputFingerprint =
        fingerprint(body);

      const existing =
        freezes.get(freezeId);

      if (existing) {
        if (
          existing.fingerprint !==
          inputFingerprint
        ) {
          return res
            .status(409)
            .type("application/json")
            .send(JSON.stringify({
              error:
                "FREEZE_ID_CONFLICT"
            }));
        }

        return res
          .type("application/json")
          .send(
            JSON.stringify(
              existing.response
            )
          );
      }

      const response =
        freeze(body);

      freezes.set(
        freezeId,
        {
          fingerprint:
            inputFingerprint,
          response
        }
      );

      return res
        .type("application/json")
        .send(
          JSON.stringify(response)
        );
    }

    /*
     * =====================================================
     * SELECT
     * =====================================================
     */

    if (phase === "select") {
      if (!validateSelectRequest(body)) {
        return sendInvalidInput(res);
      }

      const freezeId =
        body.freezeId as string;

      if (!freezes.has(freezeId)) {
        return res
          .type("application/json")
          .send(
            JSON.stringify({
              freezeId,
              selected: null,
              results: [],
              packageManifest: null
            })
          );
      }

      const response =
        select(body);

      return res
        .type("application/json")
        .send(
          JSON.stringify(response)
        );
    }
  }
);

/* =========================================================
   Health endpoint
   ========================================================= */

app.get(
  "/",
  (_req: Request, res: Response) => {
    res.json({
      service: "quantize-gate",
      status: "ok"
    });
  }
);

/* =========================================================
   Start
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
