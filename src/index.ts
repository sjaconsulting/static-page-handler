/**
 * Cloudflare Worker Script for Serving Static Files from R2 Based on Hostname and Path
 *
 * Description:
 * This Worker script handles HTTP requests to serve static files stored in a Cloudflare R2 bucket.
 * It maps incoming requests to specific file paths within the R2 bucket based on the request's
 * hostname and pathname. This allows for serving static content on multiple domains using a
 * single Worker and R2 bucket, with a structured directory setup in R2 to separate files by hostname.
 *
 * Features:
 * - Supports multiple hostnames with custom paths for static files.
 * - Uses a directory structure in R2 to organize files per hostname.
 * - Handles GET, PUT, and DELETE HTTP methods.
 * - Authorization for PUT and DELETE methods using a pre-shared secret.
 * - Allow list for GET requests to restrict accessible paths.
 *
 * Configuration:
 * - HOST_PATH_MAP: Object mapping hostnames to their respective path-to-file mappings.
 * - ALLOW_LIST: Array of paths allowed for GET requests without authorization.
 * - STATIC_PAGE_HANDLER_AUTH_KEY_SECRET: Environment variable storing the pre-shared secret for authorization.
 * - MY_BUCKET: Binding to the Cloudflare R2 bucket where files are stored.
 *
 * Usage:
 * - Deploy this script as a Cloudflare Worker.
 * - Set up environment variables and bindings (STATIC_PAGE_HANDLER_AUTH_KEY_SECRET and MY_BUCKET).
 * - Define hostnames and path mappings in HOST_PATH_MAP.
 * - Add allowed paths to ALLOW_LIST for GET requests.
 *
 * Security:
 * - PUT and DELETE requests require the "X-Custom-Auth-Key" header matching STATIC_PAGE_HANDLER_AUTH_KEY_SECRET.
 * - GET requests are restricted to paths specified in ALLOW_LIST.
 * - Only mapped hostnames and paths are served; others return a 404 Not Found.
 *
 * Author: Suzanne Aldrich
 * Date: Oct-11-2024
 */

// Mapping of hostnames and their corresponding paths
const HOST_PATH_MAP = {
	"static-page-handler.sjaconsulting.workers.dev": {
		"/security/acknowledgements": "security-acknowledgement.html",
		"/security/policy": "security-policy.html",
		"/security/hiring": "security-hiring.html",
	  },
	"crafty.social": {
	  "/security/acknowledgements": "security-acknowledgement.html",
	  "/security/policy": "security-policy.html",
	  "/security/hiring": "security-hiring.html",
	},
	"example2.com": {
	  "/security.txt": "example2/security.txt",
	  "/disclaimer-policy.txt": "example2/disclaimer-policy.txt",
	},
	// Add more host-path mappings as needed
  };
  
  // Allow list for file access based on path
  const ALLOW_LIST = [
	"/security/acknowledgements",
	"/security/policy",
	"/security/hiring",
	// Add more paths as needed
  ];
  
  // Access the STATIC_PAGE_HANDLER_AUTH_KEY_SECRET from the environment
  const authKeySecret = env.STATIC_PAGE_HANDLER_AUTH_KEY_SECRET;
  
  // Check requests for a pre-shared secret
  const hasValidHeader = (request) => {
	  return request.headers.get("X-Custom-Auth-Key") === authKeySecret;
  };
  
  function authorizeRequest(request, env, key) {
	switch (request.method) {
	  case "PUT":
	  case "DELETE":
		return hasValidHeader(request, env);
	  case "GET":
		return ALLOW_LIST.includes(key);
	  default:
		return false;
	}
  }
  
  export default {
	async fetch(request, env, ctx) {
	  const url = new URL(request.url);
	  const host = url.hostname; // Get the hostname from the request
	  const key = url.pathname;   // Get the pathname from the request
  
	  // Check if the host is mapped
	  if (!HOST_PATH_MAP[host] || !HOST_PATH_MAP[host][key]) {
		return new Response("Not Found", { status: 404 });
	  }
  
	  // Authorize the request based on the key
	  if (!authorizeRequest(request, env, key)) {
		return new Response("Forbidden", { status: 403 });
	  }
  
	  // Determine the file path in R2 based on hostname and request path
	  const filePath = HOST_PATH_MAP[host][key];
  
	  switch (request.method) {
		case "PUT":
		  // Store the file in R2
		  await env.MY_BUCKET.put(filePath, request.body);
		  return new Response(`Put ${filePath} successfully!`, { status: 201 });
  
		case "GET":
		  // Fetch the object from R2
		  const object = await env.MY_BUCKET.get(filePath);
  
		  if (object === null) {
			return new Response("Object Not Found", { status: 404 });
		  }
  
		  const headers = new Headers();
		  object.writeHttpMetadata(headers); // Set appropriate HTTP headers
		  headers.set("etag", object.httpEtag); // Set the ETag for cache validation
  
		  return new Response(object.body, {
			headers,
		  });
  
		case "DELETE":
		  // Delete the file from R2
		  await env.MY_BUCKET.delete(filePath);
		  return new Response("Deleted!", { status: 204 });
  
		default:
		  return new Response("Method Not Allowed", {
			status: 405,
			headers: {
			  Allow: "PUT, GET, DELETE",
			},
		  });
	  }
	},
  };
  