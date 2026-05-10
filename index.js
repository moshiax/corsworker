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

addEventListener("fetch", (event) => {
	event.respondWith(handleRequest(event).catch(err => {
		return new Response(
			"Worker error: " + (err?.stack || err?.message || String(err)),
			{
				status: 500,
				headers: { "content-type": "text/plain" }
			}
		)
	}))
})

async function handleRequest(event) {
	const isPreflightRequest = event.request.method === "OPTIONS"
	const originUrl = new URL(event.request.url)

	function setupCORSHeaders(headers) {
		headers.set("Access-Control-Allow-Origin", event.request.headers.get("Origin") || "*")

		if (isPreflightRequest) {
			headers.set(
				"Access-Control-Allow-Methods",
				event.request.headers.get("access-control-request-method") || "*"
			)

			const requestedHeaders = event.request.headers.get("access-control-request-headers")
			if (requestedHeaders) {
				headers.set("Access-Control-Allow-Headers", requestedHeaders)
			}

			headers.delete("X-Content-Type-Options")
		}

		return headers
	}

	let targetUrl
	try {
		targetUrl = decodeURIComponent(decodeURIComponent(originUrl.search.substr(1)))
	} catch (e) {
		throw new Error("Invalid target URL encoding: " + e.message)
	}

	const originHeader = event.request.headers.get("Origin")

	if (
		!isListedInWhitelist(targetUrl, blacklistUrls) &&
		isListedInWhitelist(originHeader, whitelistOrigins)
	) {
		let customHeaders = event.request.headers.get("x-cors-headers")

		if (customHeaders) {
			try {
				customHeaders = JSON.parse(customHeaders)
			} catch (e) {
				throw new Error("Invalid x-cors-headers JSON: " + e.message)
			}
		}

		if (originUrl.search.startsWith("?")) {
			const filteredHeaders = {}

			for (const [key, value] of event.request.headers.entries()) {
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
				method: event.request.method,
				body: event.request.body,
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