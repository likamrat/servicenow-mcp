const { validate } = require("./admin/validate.cjs");
const SCOPE = "Incident.Manage";
const USER_SCOPE = "User.Manage";
const USER_ACCESS_SCOPE = "User.Access.Manage";
const MANAGEMENT_SCOPES = [SCOPE, USER_SCOPE, USER_ACCESS_SCOPE];
const guid = { type: "string", pattern: "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$" };
const authProperties = { tenant_id: guid, audience: guid, client_id: guid };

class CoworkAuthError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}
async function createEntraVerifier(config, { key, now = Date.now } = {}) {
  validate({ type: "object", properties: authProperties, required: Object.keys(authProperties) }, config, "Entra policy");
  const tenant = config.tenant_id, audience = config.audience, client = config.client_id;
  const issuer = `https://login.microsoftonline.com/${tenant}/v2.0`;
  const { jwtVerify, createRemoteJWKSet, customFetch } = await import("jose");
  const verificationKey = key || createRemoteJWKSet(
    new URL(`https://login.microsoftonline.com/${tenant}/discovery/v2.0/keys`),
    { timeoutDuration: 5000, cooldownDuration: 30000, cacheMaxAge: 600000,
      [customFetch]: async (url, options) => {
        let response;
        try { response = await fetch(url, { ...options, redirect: "error" }); }
        catch { throw new CoworkAuthError(503, "authorization_keys_unavailable"); }
        if (response.status !== 200) {
          await response.body?.cancel();
          throw new CoworkAuthError(503, "authorization_keys_unavailable");
        }
        return response;
      } });
  return async token => {
    if (typeof token !== "string" || token.length > 16384 ||
        !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token))
      throw new CoworkAuthError(401, "invalid_token");
    let payload;
    try {
      ({ payload } = await jwtVerify(token, verificationKey, {
        algorithms: ["RS256"], issuer, audience, clockTolerance: 30, currentDate: new Date(now()),
        requiredClaims: ["iss", "aud", "exp", "nbf", "iat", "tid", "oid", "azp", "ver"],
      }));
    } catch (error) {
      if (error instanceof CoworkAuthError) throw error;
      if (["ERR_JWKS_TIMEOUT", "ERR_JWKS_INVALID"].includes(error.code) || error instanceof TypeError)
        throw new CoworkAuthError(503, "authorization_keys_unavailable");
      throw new CoworkAuthError(401, "invalid_token");
    }
    if (payload.ver !== "2.0" || payload.tid !== tenant || payload.aud !== audience ||
        ![payload.iat, payload.nbf, payload.exp].every(Number.isInteger) ||
        payload.iat > Math.floor(now() / 1000) + 30 || payload.exp <= payload.iat)
      throw new CoworkAuthError(401, "invalid_token");
    const scopes = typeof payload.scp === "string" ? MANAGEMENT_SCOPES.filter(scope => payload.scp.split(" ").includes(scope)) : [];
    if (payload.idtyp === "app" || !scopes.length)
      throw new CoworkAuthError(403, "delegated_management_scope_required");
    if (payload.azp !== client || typeof payload.oid !== "string" || !new RegExp(guid.pattern).test(payload.oid))
      throw new CoworkAuthError(403, "requester_not_authorized");
    return Object.freeze({ tenant_id: tenant, object_id: payload.oid, client_id: client, scopes: Object.freeze(scopes) });
  };
}
module.exports = { SCOPE, USER_SCOPE, USER_ACCESS_SCOPE, MANAGEMENT_SCOPES, authProperties, CoworkAuthError, createEntraVerifier };
