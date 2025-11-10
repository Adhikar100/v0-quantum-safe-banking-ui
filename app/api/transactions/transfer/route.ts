export async function POST(request: Request) {
  try {
    console.log("[v0] API Route: Received transfer request")

    const body = await request.json()
    console.log("[v0] API Route: Request body:", body)

    const backendUrl = process.env.BACKEND_URL || "http://localhost:8000"
    console.log("[v0] API Route: Forwarding to backend:", backendUrl)

    const response = await fetch(`${backendUrl}/api/transactions/transfer`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    })

    console.log("[v0] API Route: Backend response status:", response.status)

    if (!response.ok) {
      const error = await response.json()
      console.log("[v0] API Route: Backend error:", error)
      return Response.json(error, { status: response.status })
    }

    const data = await response.json()
    console.log("[v0] API Route: Backend success:", data)
    return Response.json(data)
  } catch (error) {
    console.log("[v0] API Route: Error occurred:", error)
    return Response.json({ detail: error instanceof Error ? error.message : "Internal server error" }, { status: 500 })
  }
}
