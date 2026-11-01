function requestHostname(value) {
  if (typeof value !== "string") return null;
  const match = /^(\[[0-9a-f:]+\]|[a-z0-9.-]+)(?::(\d+))?$/i.exec(value);
  if (!match || !URL.canParse(`http://${value}`)) return null;
  if (!match[1].startsWith("[") && (match[1].length > 253 ||
      match[1].split(".").some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)))) return null;
  if (match[2] && (Number(match[2]) < 1 || Number(match[2]) > 65535)) return null;
  const host = new URL(`http://${value}`).hostname;
  return host === match[1].toLowerCase() ? host : null;
}
function requestOrigin(value) {
  if (typeof value !== "string" || !URL.canParse(value)) return null;
  const url = new URL(value);
  return ["http:", "https:"].includes(url.protocol) && value === url.origin ? value : null;
}
function requestBoundary({ allowedHosts, allowedOrigins }) {
  return (req, res, next) => {
    const hosts = req.headersDistinct.host;
    if (hosts?.length !== 1 || !allowedHosts.has(requestHostname(hosts[0])))
      return res.status(403).json({ error: "Request host is not allowed." });
    const origins = req.headersDistinct.origin || [];
    if (origins.length > 1 || origins.length === 1 && !allowedOrigins.has(requestOrigin(origins[0])))
      return res.status(403).json({ error: "Request origin is not allowed." });
    next();
  };
}
module.exports = { requestHostname, requestOrigin, requestBoundary };
