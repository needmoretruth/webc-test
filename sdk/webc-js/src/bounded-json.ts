/**
 * Iterative, resource-bounded snapshots of already-decoded hostile JSON.
 *
 * Responsibilities: copy JSON primitives, dense arrays, and plain records
 * without invoking property getters; reject exotic/accessor/non-JSON values;
 * enforce depth, node, array, and cumulative UTF-8 string budgets. It does not
 * validate a protocol schema, parse wire bytes, or compute canonical hashes.
 * Data flows from an untrusted decoded value into a detached plain snapshot.
 * The security boundary is descriptor-based copying: later validation and
 * hashing never re-read attacker-controlled getters or Proxy `get` traps.
 */

/** Resource ceilings for one detached JSON snapshot. */
export interface BoundedJsonSnapshotLimits {
  /** Human-readable input name included in fail-closed errors. */
  readonly label: string;
  /** Maximum root-to-leaf property depth, with the root at depth zero. */
  readonly maxDepth: number;
  /** Maximum total primitive/container nodes copied. */
  readonly maxNodes: number;
  /** Maximum length of any one dense JSON array. */
  readonly maxArrayLength: number;
  /** Maximum cumulative UTF-8 bytes across object keys and string values. */
  readonly maxStringBytes: number;
  /** Human-readable form of `maxStringBytes`, such as `256 KiB`. */
  readonly stringByteLimitLabel: string;
  /** Optional protocol name for an array that exceeds `maxArrayLength`. */
  readonly arrayLimitLabel?: string;
}

interface SnapshotTask {
  readonly source: unknown;
  readonly parent: Record<string, unknown> | unknown[];
  readonly key: string | number;
  readonly depth: number;
  readonly label: string;
}

/**
 * Returns a detached JSON snapshot without recursively traversing the input.
 *
 * Accessors, sparse/extended arrays, symbol keys, exotic prototypes, unsafe
 * numbers, invalid UTF-16, and values exceeding a configured resource ceiling
 * fail before protocol validation or canonical hashing.
 */
export function boundedJsonSnapshot(value: unknown, limits: BoundedJsonSnapshotLimits): unknown {
  validateLimits(limits);
  const root: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  const tasks: SnapshotTask[] = [{ source: value, parent: root, key: "value", depth: 0, label: limits.label }];
  let scheduledNodes = 1;
  let stringBytes = 0;

  const consumeString = (text: string, label: string): void => {
    const bytes = wellFormedUtf8ByteLength(text, label);
    stringBytes += bytes;
    if (stringBytes > limits.maxStringBytes) {
      throw new Error(`${limits.label} exceeds its ${limits.stringByteLimitLabel} string budget`);
    }
  };

  while (tasks.length > 0) {
    const task = tasks.pop();
    if (task === undefined) break;
    if (task.depth > limits.maxDepth) {
      throw new Error(`${limits.label} exceeds its JSON depth limit`);
    }

    const source = task.source;
    if (source === null || typeof source === "boolean") {
      assignSnapshotValue(task.parent, task.key, source);
      continue;
    }
    if (typeof source === "string") {
      consumeString(source, task.label);
      assignSnapshotValue(task.parent, task.key, source);
      continue;
    }
    if (typeof source === "number") {
      if (!Number.isSafeInteger(source)) {
        throw new Error(`${task.label} contains an unsafe JSON number`);
      }
      assignSnapshotValue(task.parent, task.key, source);
      continue;
    }
    if (typeof source !== "object") {
      throw new Error(`${task.label} contains a non-JSON value`);
    }

    if (Array.isArray(source)) {
      if (Object.getPrototypeOf(source) !== Array.prototype) {
        throw new Error(`${task.label} must use the ordinary Array prototype`);
      }
      const lengthDescriptor = Object.getOwnPropertyDescriptor(source, "length");
      if (lengthDescriptor === undefined || !("value" in lengthDescriptor)
        || !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < 0) {
        throw new Error(`${task.label} has an invalid array length`);
      }
      const length = lengthDescriptor.value as number;
      if (length > limits.maxArrayLength) {
        throw new Error(`${limits.arrayLimitLabel ?? `${task.label} array`} exceeds its item limit`);
      }
      const ownKeys = Reflect.ownKeys(source);
      if (ownKeys.length !== length + 1 || !ownKeys.includes("length")) {
        throw new Error(`${task.label} must be a dense JSON array without extra properties`);
      }
      scheduleNodes(length);
      const target = new Array<unknown>(length);
      assignSnapshotValue(task.parent, task.key, target);
      for (let index = length - 1; index >= 0; index -= 1) {
        const key = String(index);
        const descriptor = Object.getOwnPropertyDescriptor(source, key);
        if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
          throw new Error(`${task.label} contains an accessor or sparse array item`);
        }
        tasks.push({
          source: descriptor.value,
          parent: target,
          key: index,
          depth: task.depth + 1,
          label: `${task.label}[${index}]`,
        });
      }
      continue;
    }

    const prototype = Object.getPrototypeOf(source);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error(`${task.label} must be a plain JSON object`);
    }
    const keys = Reflect.ownKeys(source);
    if (keys.some((key) => typeof key !== "string")) {
      throw new Error(`${task.label} contains a symbol property`);
    }
    scheduleNodes(keys.length);
    const target: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    assignSnapshotValue(task.parent, task.key, target);
    for (let index = keys.length - 1; index >= 0; index -= 1) {
      const key = keys[index] as string;
      consumeString(key, `${task.label} property name`);
      const descriptor = Object.getOwnPropertyDescriptor(source, key);
      if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
        throw new Error(`${task.label} contains an accessor property or a non-enumerable property`);
      }
      tasks.push({
        source: descriptor.value,
        parent: target,
        key,
        depth: task.depth + 1,
        label: `${task.label}.${key}`,
      });
    }
  }

  return root.value;

  function scheduleNodes(count: number): void {
    scheduledNodes += count;
    if (scheduledNodes > limits.maxNodes) {
      throw new Error(`${limits.label} exceeds its JSON node budget`);
    }
  }
}

/** Returns exact UTF-8 bytes while rejecting strings Rust `String` cannot hold. */
export function wellFormedUtf8ByteLength(value: string, label: string): number {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit <= 0x7f) {
      bytes += 1;
    } else if (unit <= 0x7ff) {
      bytes += 2;
    } else if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        throw new Error(`${label} contains an unpaired UTF-16 surrogate`);
      }
      bytes += 4;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new Error(`${label} contains an unpaired UTF-16 surrogate`);
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

function assignSnapshotValue(
  parent: Record<string, unknown> | unknown[],
  key: string | number,
  value: unknown,
): void {
  if (Array.isArray(parent)) {
    parent[key as number] = value;
    return;
  }
  Object.defineProperty(parent, key, {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
}

function validateLimits(limits: BoundedJsonSnapshotLimits): void {
  for (const [name, value] of [
    ["maxDepth", limits.maxDepth],
    ["maxNodes", limits.maxNodes],
    ["maxArrayLength", limits.maxArrayLength],
    ["maxStringBytes", limits.maxStringBytes],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new Error(`bounded JSON ${name} must be a positive safe integer`);
    }
  }
}
