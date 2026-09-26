const blacklistUrls = []
const whitelistOrigins = [".*"]

function isListedInWhitelist(uri, listing) {
	let isListed = false

	if (typeof uri === "string") {
		listing.forEach((pattern) => {
			if (uri.match(pattern) !== null) {
				isListed = true
			}
		})
	} else {
		isListed = true
	}

	return isListed
}

export default {
	async fetch(request, env) {
		try {
			return await handleRequest(request, env)
		} catch (err) {
			return new Response(
				"Worker error: " + (err?.stack || err?.message || String(err)),
				{
					status: 500,
					headers: { "content-type": "text/plain" }
				}
			)
		}
	}
}

async function handleRequest(request, env) {
	const isPreflightRequest = request.method === "OPTIONS"
	const originUrl = new URL(request.url)

	const ip = request.headers.get("CF-Connecting-IP") || "unknown"
	const { success } = await env.IP_RATE_LIMITER.limit({ key: ip })

	if (!success) {
		return new Response("Too many requests", {
			status: 429
		})
	}

	function setupCORSHeaders(headers) {
		headers.set("Access-Control-Allow-Origin", request.headers.get("Origin") || "*")

		if (isPreflightRequest) {
			headers.set(
				"Access-Control-Allow-Methods",
				request.headers.get("access-control-request-method") || "*"
			)

			const requestedHeaders = request.headers.get("access-control-request-headers")
			if (requestedHeaders) {
				headers.set("Access-Control-Allow-Headers", requestedHeaders)
			}

			headers.delete("X-Content-Type-Options")
		}

		return headers
	}

	let targetUrl
	try {
		targetUrl = decodeURIComponent(originUrl.search.substr(1))
	} catch (e) {
		throw new Error("Invalid target URL encoding: " + e.message)
	}

	const originHeader = request.headers.get("Origin")

	if (
		!isListedInWhitelist(targetUrl, blacklistUrls) &&
		isListedInWhitelist(originHeader, whitelistOrigins)
	) {
		let customHeaders = request.headers.get("x-cors-headers")

		if (customHeaders) {
			try {
				customHeaders = JSON.parse(customHeaders)
			} catch (e) {
				throw new Error("Invalid x-cors-headers JSON: " + e.message)
			}
		}

		if (originUrl.search.startsWith("?")) {
			const filteredHeaders = {}

			for (const [key, value] of request.headers.entries()) {
				if (
					!key.match("^origin") &&
					!key.match("eferer") &&
					!key.match("^cf-") &&
					!key.match("^x-forw") &&
					!key.match("^x-cors-headers")
				) {
					filteredHeaders[key] = value
				}
			}

			if (customHeaders) {
				Object.entries(customHeaders).forEach(([k, v]) => {
					filteredHeaders[k] = v
				})
			}

			const newRequest = new Request(targetUrl, {
				method: request.method,
				body: request.body,
				redirect: "follow",
				headers: filteredHeaders
			})

			let response
			try {
				response = await fetch(newRequest)
			} catch (e) {
				throw new Error("Fetch failed: " + (e?.stack || e?.message || e))
			}

			const responseHeaders = new Headers(response.headers)

			const exposedHeaders = []
			const allResponseHeaders = {}

			for (const [key, value] of response.headers.entries()) {
				exposedHeaders.push(key)
				allResponseHeaders[key] = value
			}

			exposedHeaders.push("cors-received-headers")

			const finalHeaders = setupCORSHeaders(responseHeaders)
			finalHeaders.set("Access-Control-Expose-Headers", exposedHeaders.join(","))
			finalHeaders.set("cors-received-headers", JSON.stringify(allResponseHeaders))

			const body = isPreflightRequest ? null : await response.arrayBuffer()

			return new Response(body, {
				status: isPreflightRequest ? 200 : response.status,
				statusText: isPreflightRequest ? "OK" : response.statusText,
				headers: finalHeaders
			})
		}

		let responseHeaders = setupCORSHeaders(new Headers())

		return new Response("CORS proxy worker", {
			status: 200,
			headers: responseHeaders
		})
	}

	return new Response("Forbidden", { status: 403 })
}