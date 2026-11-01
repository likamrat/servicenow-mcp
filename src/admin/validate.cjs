function validate(schema, value, label = "arguments", depth = 0) {
  if (depth > 20) throw new Error("Arguments exceed supported nesting.");
  const actual = value === null ? "null" : Array.isArray(value) ? "array" : typeof value;
  const types = schema.type === undefined ? [] : Array.isArray(schema.type) ? schema.type : [schema.type];
  if (types.length && !types.some(type => type === actual || type === "integer" && Number.isInteger(value)))
    throw new Error(`Invalid type for ${label}.`);
  if (Object.hasOwn(schema, "const") && value !== schema.const) throw new Error(`Invalid confirmation for ${label}.`);
  if (schema.enum && !schema.enum.includes(value)) throw new Error(`Unsupported ${label}.`);
  if (typeof value === "number" && (!Number.isFinite(value) ||
      schema.minimum !== undefined && value < schema.minimum || schema.maximum !== undefined && value > schema.maximum))
    throw new Error(`Out-of-range ${label}.`);
  if (typeof value === "string") {
    if (schema.pattern && !new RegExp(schema.pattern).test(value) || schema.maxLength !== undefined && value.length > schema.maxLength ||
        schema.format === "uuid" && !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value))
      throw new Error(`Invalid ${label}.`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems || schema.maxItems !== undefined && value.length > schema.maxItems ||
        schema.uniqueItems && new Set(value.map(item => JSON.stringify(item))).size !== value.length)
      throw new Error(`Invalid item count for ${label}.`);
    if (schema.items) for (const item of value) validate(schema.items, item, label, depth + 1);
  } else if (value && typeof value === "object") {
    const keys = Object.keys(value);
    if (schema.minProperties !== undefined && keys.length < schema.minProperties || schema.maxProperties !== undefined && keys.length > schema.maxProperties ||
        (schema.required || []).some(key => !Object.hasOwn(value, key)))
      throw new Error(`Missing or excessive ${label}.`);
    for (const key of keys) {
      if (["__proto__", "prototype", "constructor"].includes(key)) throw new Error("Unsafe argument key.");
      if (Object.hasOwn(schema.properties || {}, key)) validate(schema.properties[key], value[key], key, depth + 1);
      else if (schema.additionalProperties === false) throw new Error(`Unexpected ${label} field.`);
      else if (schema.additionalProperties && typeof schema.additionalProperties === "object")
        validate(schema.additionalProperties, value[key], key, depth + 1);
    }
  }
}

module.exports = { validate };
