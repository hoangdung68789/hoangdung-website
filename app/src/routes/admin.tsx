import { createFileRoute } from "@tanstack/react-router";
import adminHtml from "../site/admin.html?raw";

// Trang quản trị — tách biệt hoàn toàn với khách hàng (tài khoản quản trị riêng, không lập chỉ mục tìm kiếm).
export const Route = createFileRoute("/admin")({
  server: {
    handlers: {
      GET: async () =>
        new Response(adminHtml, {
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "X-Robots-Tag": "noindex, nofollow",
          },
        }),
    },
  },
});
