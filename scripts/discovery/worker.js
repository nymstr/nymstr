// Cloudflare Worker: returns the nymstr discovery-server Nym address.
// Deploy to api.nymstr.com. Reads from KV so updates don't require redeploy.
//
// Bindings expected:
//   DISCOVERY_KV  -> Workers KV namespace containing key "address"

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== "/api/v1/address") {
      return new Response("not found", { status: 404 });
    }
    if (request.method !== "GET") {
      return new Response("method not allowed", { status: 405 });
    }

    const address = await env.DISCOVERY_KV.get("address");
    if (!address) {
      return new Response(JSON.stringify({ error: "address not configured" }), {
        status: 503,
        headers: { "content-type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ address }), {
      headers: {
        "content-type": "application/json",
        "cache-control": "public, max-age=300",
        "access-control-allow-origin": "*",
      },
    });
  },
};
