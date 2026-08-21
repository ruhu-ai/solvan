/** One authenticated call to the projection API.
 *
 *  A console-origin path that never reaches the API answers 200 with the SPA
 *  shell, so `response.ok` alone reported success for commands that were never
 *  executed. Content type is therefore part of the success condition, not a
 *  parsing detail, and every consequential write goes through here.
 */

export type ApiResult<T> = { ok: true; body: T } | { ok: false; detail: string };

export async function callApi<T>(input: string, init?: RequestInit): Promise<ApiResult<T>> {
  let response: Response;
  try {
    response = await fetch(input, init);
  } catch {
    return { ok: false, detail: "the authenticated projection API is unreachable" };
  }
  const contentType = (response.headers.get("content-type") ?? "").split(";")[0].trim();
  if (contentType !== "application/json") {
    return { ok: false, detail: `${response.status} · expected a JSON API response, received ${contentType || "no content type"}` };
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return { ok: false, detail: `${response.status} · malformed JSON response` };
  }
  if (!response.ok) {
    const refusal = body as { detail?: string; reason_codes?: string[] } | null;
    return { ok: false, detail: refusal?.detail ?? refusal?.reason_codes?.join(", ") ?? `closed error ${response.status}` };
  }
  return { ok: true, body: body as T };
}
