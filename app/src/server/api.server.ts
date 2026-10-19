// Bản Higgsfield: dùng chung lõi máy chủ với bản Cloudflare (api.core.ts)
import { handleApi as core, type Env } from "./api.core";
import { bindings } from "../lib/bindings.server";

export function handleApi(request: Request, path: string): Promise<Response> {
  return core(request, path, bindings() as unknown as Env);
}
