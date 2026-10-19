/**
 * Hoàng Dũng Real Estate — Cloudflare Worker
 * - /api/*      → máy chủ (tài khoản, mã xác minh, yêu cầu tư vấn, quản trị) — xem src/api.ts
 * - còn lại     → trang tĩnh trong thư mục public/ (index.html, admin.html, ảnh) do Cloudflare phục vụ trực tiếp
 */
import { handleApi, type Env } from "./api";

type WorkerEnv = Env & { ASSETS: { fetch(req: Request): Promise<Response> } };

const SECURITY: Record<string, string> = {
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), accelerometer=(self), gyroscope=(self), magnetometer=(self)",
  "X-Frame-Options": "SAMEORIGIN",
};

function withHeaders(res: Response): Response {
  const h = new Headers(res.headers);
  for (const [k, v] of Object.entries(SECURITY)) h.set(k, v);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}

export default {
  async fetch(request: Request, env: WorkerEnv): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return withHeaders(await handleApi(request, url.pathname.slice(5), env));
    if (url.pathname === "/admin/") return Response.redirect(url.origin + "/admin", 301);
    const res = await env.ASSETS.fetch(request);
    // trang chủ: điền địa chỉ thật của website vào thẻ chia sẻ mạng xã hội (og:url, og:image, canonical)
    if ((url.pathname === "/" || url.pathname === "/index.html") && (res.headers.get("Content-Type") ?? "").includes("text/html")) {
      const html = (await res.text()).replaceAll("__SITE__", url.origin);
      const h = new Headers(res.headers); h.delete("Content-Length"); h.set("Cache-Control", "public, max-age=0, must-revalidate");
      return withHeaders(new Response(html, { status: res.status, headers: h }));
    }
    return withHeaders(res);
  },
};
