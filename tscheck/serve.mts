import http from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { handleApi } from "./src/server/api.server.ts";
const APP = "../deploy/app/";
const types: Record<string, string> = { webp: "image/webp", jpg: "image/jpeg", svg: "image/svg+xml" };
http.createServer(async (req, res) => {
  const url = new URL(req.url!, "http://localhost:8787");
  const chunks: Buffer[] = []; for await (const c of req) chunks.push(c as Buffer);
  let r: Response;
  if (url.pathname.startsWith("/api/")) {
    const h = new Headers(); for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") h.set(k, v);
    h.set("CF-Connecting-IP", "127.0.0." + (Number(process.env.IPN || 1)));
    r = await handleApi(new Request(url, { method: req.method, headers: h, body: chunks.length ? Buffer.concat(chunks) : undefined }), url.pathname.slice(5));
  } else if (url.pathname === "/") r = new Response(readFileSync(APP + "src/site/home.html"), { headers: { "Content-Type": "text/html; charset=utf-8" } });
  else if (url.pathname === "/admin") r = new Response(readFileSync(APP + "src/site/admin.html"), { headers: { "Content-Type": "text/html; charset=utf-8" } });
  else if (existsSync(APP + "public" + url.pathname)) r = new Response(readFileSync(APP + "public" + url.pathname), { headers: { "Content-Type": types[url.pathname.split(".").pop()!] || "application/octet-stream" } });
  else r = new Response("not found", { status: 404 });
  const hdr: Record<string, string | string[]> = {}; r.headers.forEach((v, k) => { if (k !== "set-cookie") hdr[k] = v; });
  const sc = r.headers.getSetCookie(); if (sc.length) hdr["set-cookie"] = sc;
  res.writeHead(r.status, hdr); res.end(Buffer.from(await r.arrayBuffer()));
}).listen(8787, () => console.log("listening 8787"));
