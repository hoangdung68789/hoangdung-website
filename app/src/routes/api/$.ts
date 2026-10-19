import { createFileRoute } from "@tanstack/react-router";
import { handleApi } from "../../server/api.server";

export const Route = createFileRoute("/api/$")({
  server: {
    handlers: {
      GET: async ({ request, params }) => handleApi(request, params._splat ?? ""),
      POST: async ({ request, params }) => handleApi(request, params._splat ?? ""),
    },
  },
});
