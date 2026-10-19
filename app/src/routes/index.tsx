import { createFileRoute } from "@tanstack/react-router";
import homeHtml from "../site/home.html?raw";

// Trang chủ: phục vụ nguyên bản dựng website Hoàng Dũng Real Estate (HTML tĩnh, ảnh ở /img).
export const Route = createFileRoute("/")({
  server: {
    handlers: {
      GET: async () =>
        new Response(homeHtml, {
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "public, max-age=0, must-revalidate",
          },
        }),
    },
  },
});
