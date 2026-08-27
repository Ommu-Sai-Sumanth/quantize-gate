import express from "express";
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

const store = new Map<string, StoredFreeze>();

function obj(v: unknown): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(v: unknown): v is string {
  return typeof v === "string";
}

function nonEmpty(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

function finiteNonNegative(v: unknown): v is number {
  return (
    typeof v === "number" &&
    Number.isFinite(v) &&
    v >= 0
  );
}

function safeInt(v: unknown): v is number {
  return (
    typeof v === "number" &&
    Number.isSafeInteger(v) &&
    v >= 0
  );
}

function unit(v: unknown): v is number {
  return (
    typeof v === "number" &&
    Number.isFinite(v) &&
    v >= 0 &&
    v <= 1
  );
}

function utf8cmp(a: string, b: string): number {
  return Buffer.compare(
    Buffer.from(a, "utf8"),
    Buffer.from(b, "utf8")
  );
}

function codes(values: string[]): string[] {
  return [...new Set(values)].sort(utf8cmp);
}

function sha256(value: string): string {
  return crypto
    .createHash("sha256")
    .update(Buffer.from(value, "utf8"))
    .digest("hex");
}

function fp(value: unknown): string {
  return sha256(JSON.stringify(value));
}

function invalid(res: express.Response) {
  return res
    .status(400)
    .type("application/json")
    .send(JSON.stringify({
      error: "INVALID_INPUT"
    }));
}

/* ============================================================
   INVENTORY
   ============================================================ */

function inventoryFor(files: unknown) {
  if (!obj(files)) {
    return {
      valid: false,
      inventory: [] as InventoryItem[],
      totalBytes: null as number | null,
      packageDigest: null as string | null
    };
  }

  const names = Object.keys(files);

  if (names.length === 0) {
    return {
      valid: false,
      inventory: [] as InventoryItem[],
      totalBytes: null as number | null,
      packageDigest: null as string | null
    };
  }

  for (const name of names) {
    if (
      !name ||
      typeof files[name] !== "string"
    ) {
      return {
        valid: false,
        inventory: [] as InventoryItem[],
        totalBytes: null as number | null,
        packageDigest: null as string | null
      };
    }
  }

  names.sort(utf8cmp);

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
      sha256: sha256(text)
    });
  }

  return {
    valid: true,
    inventory,
    totalBytes: total,
    packageDigest: sha256(
      JSON.stringify(inventory)
    )
  };
}

/* ============================================================
   FREEZE
   ============================================================ */

function doFreeze(body: Obj): FreezeResponse {
  const freezeId = body.freezeId as string;

  const calibrationDigest =
    body.calibrationDigest as string;

  const tokenizerDigest =
    body.tokenizerDigest as string;

  const allowed = new Set<string>(
    Array.isArray(body.allowedUnsupportedReasons)
      ? body.allowedUnsupportedReasons.filter(
          (x: unknown): x is string =>
            typeof x === "string"
        )
      : []
  );

  const output: FrozenCandidate[] = [];

  for (const raw of body.candidates as unknown[]) {
    /*
     * Envelope validation guarantees candidates are objects,
     * but malformed candidates are handled defensively here.
     */
    if (!obj(raw)) {
      continue;
    }

    const name =
      typeof raw.name === "string"
        ? raw.name
        : "";

    const inv =
      inventoryFor(raw.files);

    if (!inv.valid) {
      output.push({
        name,
        status: "invalid",
        inventory: [],
        totalBytes: null,
        packageDigest: null,
        reasonCodes: ["INVALID_INPUT"]
      });

      continue;
    }

    const reasons: string[] = [];

    let unsupported = false;

    if (typeof raw.unsupportedReason === "string") {
      if (
        allowed.has(
          raw.unsupportedReason
        )
      ) {
        unsupported = true;
      } else {
        reasons.push(
          "UNALLOWED_UNSUPPORTED_REASON"
        );
      }
    }

    if (!unsupported) {
      if (raw.loadable !== true) {
        reasons.push("NOT_LOADABLE");
      }

      if (
        raw.calibrationDigest !==
        calibrationDigest
      ) {
        reasons.push(
          "CALIBRATION_MISMATCH"
        );
      }

      if (
        raw.tokenizerDigest !==
        tokenizerDigest
      ) {
        reasons.push(
          "TOKENIZER_MISMATCH"
        );
      }
    }

    const reasonCodes =
      codes(reasons);

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
      inventory: inv.inventory,
      totalBytes: inv.totalBytes,
      packageDigest: inv.packageDigest,
      reasonCodes
    });
  }

  output.sort(
    (a, b) =>
      utf8cmp(a.name, b.name)
  );

  return {
    freezeId,
    candidates: output
  };
}

/* ============================================================
   SELECT
   ============================================================ */

function accuracyFor(
  rows: unknown[],
  candidate: string
) {
  if (rows.length === 0) {
    return {
      valid: false,
      aggregate: null as number | null,
      slices: {} as Record<string, number>
    };
  }

  let correct = 0;

  const totalBySlice =
    new Map<string, number>();

  const correctBySlice =
    new Map<string, number>();

  for (const raw of rows) {
    if (!obj(raw)) {
      return {
        valid: false,
        aggregate: null,
        slices: {}
      };
    }

    if (
      !Number.isInteger(raw.label) ||
      (raw.label !== 0 && raw.label !== 1)
    ) {
      return {
        valid: false,
        aggregate: null,
        slices: {}
      };
    }

    if (
      typeof raw.slice !== "string" ||
      raw.slice.length === 0
    ) {
      return {
        valid: false,
        aggregate: null,
        slices: {}
      };
    }

    if (!obj(raw.predictions)) {
      return {
        valid: false,
        aggregate: null,
        slices: {}
      };
    }

    const prediction =
      raw.predictions[candidate];

    if (
      !Number.isInteger(prediction) ||
      (prediction !== 0 &&
       prediction !== 1)
    ) {
      return {
        valid: false,
        aggregate: null,
        slices: {}
      };
    }

    const slice = raw.slice;

    totalBySlice.set(
      slice,
      (totalBySlice.get(slice) ?? 0) + 1
    );

    if (prediction === raw.label) {
      correct++;

      correctBySlice.set(
        slice,
        (correctBySlice.get(slice) ?? 0) + 1
      );
    }
  }

  const slices: Record<string, number> = {};

  for (
    const [slice, total]
    of totalBySlice
  ) {
    slices[slice] = Number(
      (
        (correctBySlice.get(slice) ?? 0) /
        total
      ).toFixed(12)
    );
  }

  return {
    valid: true,
    aggregate: Number(
      (correct / rows.length).toFixed(12)
    ),
    slices
  };
}

function doSelect(body: Obj): Obj {
  const freezeId =
    body.freezeId as string;

  const saved =
    store.get(freezeId);

  if (!saved) {
    return {
      freezeId,
      selected: null,
      results: [],
      packageManifest: null
    };
  }

  const frozen =
    saved.response.candidates;

  const submitted =
    body.candidates as unknown[];

  const rows =
    body.rows as unknown[];

  const policy =
    body.policy as Obj;

  const latencies =
    body.latencies as Obj;

  const suppliedNames =
    submitted
      .filter(obj)
      .map(x => x.name)
      .filter(
        (x): x is string =>
          typeof x === "string"
      );

  const frozenNames =
    frozen.map(x => x.name);

  const candidateOrder =
    Array.isArray(policy.candidateOrder)
      ? policy.candidateOrder
      : [];

  const uniqueSubmitted =
    new Set(suppliedNames).size ===
    suppliedNames.length;

  const uniqueOrder =
    candidateOrder.every(
      (x: unknown) =>
        typeof x === "string"
    ) &&
    new Set(candidateOrder).size ===
      candidateOrder.length;

  const lineageValid =
    suppliedNames.length ===
      frozenNames.length &&
    uniqueSubmitted &&
    suppliedNames.every(
      (x: string) =>
        frozenNames.includes(x)
    ) &&
    candidateOrder.length ===
      frozenNames.length &&
    uniqueOrder &&
    (candidateOrder as string[]).every(
      (x: string) =>
        frozenNames.includes(x)
    );

  const maxBytes =
    policy.maxBytes;

  const aggregateFloor =
    policy.aggregateFloor;

  const requiredSlices =
    policy.requiredSlices;

  const maxLatencyMs =
    policy.maxLatencyMs;

  let policyValid =
    safeInt(maxBytes) &&
    unit(aggregateFloor) &&
    obj(requiredSlices) &&
    finiteNonNegative(maxLatencyMs);

  if (!Array.isArray(policy.candidateOrder)) {
    policyValid = false;
  }

  const submittedMap =
    new Map<string, Obj>();

  for (const raw of submitted) {
    if (
      obj(raw) &&
      typeof raw.name === "string"
    ) {
      submittedMap.set(
        raw.name,
        raw
      );
    }
  }

  const orderMap =
    new Map<string, number>();

  if (uniqueOrder) {
    (
      candidateOrder as string[]
    ).forEach(
      (name, index) => {
        orderMap.set(
          name,
          index
        );
      }
    );
  }

  const results: Obj[] = [];

  for (const frozenCandidate of frozen) {
    const name =
      frozenCandidate.name;

    const reasons: string[] = [];

    if (!lineageValid) {
      reasons.push(
        "INVALID_LINEAGE"
      );
    }

    if (!policyValid) {
      reasons.push(
        "INVALID_POLICY"
      );
    }

    const supplied =
      submittedMap.get(name);

    let totalBytes:
      number | null =
        frozenCandidate.totalBytes;

    if (!supplied) {
      totalBytes = null;

      reasons.push(
        "INVALID_MANIFEST"
      );
    } else {
      const inv =
        inventoryFor(
          supplied.files
        );

      if (!inv.valid) {
        totalBytes = null;

        reasons.push(
          "INVALID_MANIFEST"
        );
      } else if (
        inv.totalBytes !==
          frozenCandidate.totalBytes ||
        inv.packageDigest !==
          frozenCandidate.packageDigest ||
        JSON.stringify(inv.inventory) !==
          JSON.stringify(
            frozenCandidate.inventory
          )
      ) {
        reasons.push(
          "INVALID_MANIFEST"
        );
      } else {
        totalBytes =
          inv.totalBytes;
      }
    }

    let latencyMs:
      number | null = null;

    if (
      finiteNonNegative(
        latencies[name]
      )
    ) {
      latencyMs =
        latencies[name];
    }

    const accuracy =
      accuracyFor(
        rows,
        name
      );

    let aggregate:
      number | null = null;

    let slices:
      Record<string, number> = {};

    if (!accuracy.valid) {
      reasons.push(
        "INVALID_PREDICTIONS"
      );
    } else {
      aggregate =
        accuracy.aggregate;

      slices =
        accuracy.slices;
    }

    if (
      aggregate !== null &&
      unit(aggregateFloor) &&
      aggregate <
        (aggregateFloor as number)
    ) {
      reasons.push(
        "AGGREGATE_FLOOR"
      );
    }

    if (obj(requiredSlices)) {
      for (
        const sliceName of
        Object.keys(requiredSlices)
      ) {
        const floor =
          requiredSlices[sliceName];

        if (!unit(floor)) {
          reasons.push(
            "INVALID_POLICY"
          );
          continue;
        }

        if (!(sliceName in slices)) {
          reasons.push(
            `MISSING_SLICE:${sliceName}`
          );
          continue;
        }

        if (
          slices[sliceName] <
          (floor as number)
        ) {
          reasons.push(
            `SLICE_FLOOR:${sliceName}`
          );
        }
      }
    }

    if (
      totalBytes === null ||
      !safeInt(maxBytes) ||
      totalBytes >
        (maxBytes as number)
    ) {
      reasons.push(
        "SIZE_LIMIT"
      );
    }

    if (
      latencyMs === null ||
      !finiteNonNegative(maxLatencyMs) ||
      latencyMs >
        (maxLatencyMs as number)
    ) {
      reasons.push(
        "LATENCY_LIMIT"
      );
    }

    const reasonCodes =
      codes(reasons);

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

  results.sort(
    (a, b) => {
      const ai =
        orderMap.has(a.name)
          ? orderMap.get(a.name)!
          : Number.MAX_SAFE_INTEGER;

      const bi =
        orderMap.has(b.name)
          ? orderMap.get(b.name)!
          : Number.MAX_SAFE_INTEGER;

      if (ai !== bi) {
        return ai - bi;
      }

      return utf8cmp(
        a.name,
        b.name
      );
    }
  );

  const winners =
    results.filter(
      x => x.admitted === true
    );

  winners.sort(
    (a, b) => {
      if (
        a.totalBytes !==
        b.totalBytes
      ) {
        return (
          (a.totalBytes as number) -
          (b.totalBytes as number)
        );
      }

      if (
        a.latencyMs !==
        b.latencyMs
      ) {
        return (
          (a.latencyMs as number) -
          (b.latencyMs as number)
        );
      }

      const ai =
        orderMap.get(a.name) ??
        Number.MAX_SAFE_INTEGER;

      const bi =
        orderMap.get(b.name) ??
        Number.MAX_SAFE_INTEGER;

      if (ai !== bi) {
        return ai - bi;
      }

      return utf8cmp(
        a.name,
        b.name
      );
    }
  );

  let selected:
    string | null = null;

  let packageManifest:
    FrozenCandidate | null = null;

  if (winners.length > 0) {
    selected =
      winners[0].name;

    packageManifest =
      frozen.find(
        x => x.name === selected
      ) ?? null;
  }

  return {
    freezeId,
    selected,
    results,
    packageManifest
  };
}

/* ============================================================
   HTTP ENDPOINT
   ============================================================ */

app.post(
  "/quantize",
  (req, res) => {
    const body: unknown = req.body;

    if (!obj(body)) {
      return invalid(res);
    }

    /*
     * Only the operation/phase itself is HTTP-level
     * validation. Everything else is handled according
     * to the freeze/select contract.
     */
    if (
      body.phase !== "freeze" &&
      body.phase !== "select"
    ) {
      return invalid(res);
    }

    /* ---------------- FREEZE ---------------- */

    if (body.phase === "freeze") {
      /*
       * These are genuinely required envelope fields.
       */
      if (
        !nonEmpty(body.freezeId) ||
        body.freezeId.length > 128 ||
        !nonEmpty(body.calibrationDigest) ||
        !nonEmpty(body.tokenizerDigest) ||
        !Array.isArray(
          body.allowedUnsupportedReasons
        ) ||
        !Array.isArray(body.candidates) ||
        body.candidates.length === 0
      ) {
        return invalid(res);
      }

      /*
       * Required top-level arrays/strings are valid.
       * Candidate-level problems are handled by doFreeze().
       */
      const id =
        body.freezeId;

      const requestFp =
        fp(body);

      const existing =
        store.get(id);

      if (existing) {
        if (
          existing.fingerprint !==
          requestFp
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
        doFreeze(body);

      store.set(
        id,
        {
          fingerprint: requestFp,
          response
        }
      );

      return res
        .type("application/json")
        .send(
          JSON.stringify(response)
        );
    }

    /* ---------------- SELECT ---------------- */

    if (body.phase === "select") {
      if (
        !nonEmpty(body.freezeId) ||
        !Array.isArray(body.candidates) ||
        !Array.isArray(body.rows) ||
        !obj(body.policy)
      ) {
        return invalid(res);
      }

      const response =
        doSelect(body);

      return res
        .type("application/json")
        .send(
          JSON.stringify(response)
        );
    }

    return invalid(res);
  }
);

/* ============================================================
   HEALTH
   ============================================================ */

app.get(
  "/",
  (_req, res) => {
    res.json({
      service: "quantize-gate",
      status: "ok"
    });
  }
);

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `quantize-gate listening on ${PORT}`
    );
  }
);
