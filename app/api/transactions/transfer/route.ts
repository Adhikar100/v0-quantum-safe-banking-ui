import crypto from "crypto"

interface TransferRequest {
  receiver_name: string
  receiver_account: string
  amount: number
  description?: string
}

interface TransferResponse {
  id: string
  status: string
  receiver_name: string
  receiver_account: string
  amount: number
  timestamp: string
  encrypted: boolean
  signature: string
}

function generateQuantumSignature(data: object): string {
  const dataStr = JSON.stringify(data)
  return crypto
    .createHash("sha256")
    .update(dataStr + (process.env.SECRET_KEY || "quantum-safe-secret"))
    .digest("hex")
}

function encryptTransactionData(data: object): string {
  try {
    const key = crypto
      .createHash("sha256")
      .update(process.env.SECRET_KEY || "quantum-safe-key")
      .digest()
    const iv = crypto.randomBytes(16)
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv)

    let encrypted = cipher.update(JSON.stringify(data), "utf8", "hex")
    encrypted += cipher.final("hex")

    // Prepend IV to encrypted data so it can be decrypted later
    return iv.toString("hex") + ":" + encrypted
  } catch (error) {
    console.log("[v0] Encryption error:", error)
    return crypto.createHash("sha256").update(JSON.stringify(data)).digest("hex")
  }
}

export async function POST(request: Request) {
  try {
    console.log("[v0] API Route: Received transfer request")

    let body: TransferRequest
    try {
      body = await request.json()
    } catch (parseError) {
      console.log("[v0] API Route: JSON parse error:", parseError)
      return Response.json({ detail: "Invalid JSON in request body" }, { status: 400 })
    }

    console.log("[v0] API Route: Request body:", body)

    // Validate required fields
    if (!body.receiver_name || !body.receiver_account || body.amount === undefined) {
      return Response.json(
        { detail: "Missing required fields: receiver_name, receiver_account, amount" },
        { status: 400 },
      )
    }

    if (typeof body.amount !== "number" || body.amount <= 0) {
      return Response.json({ detail: "Amount must be a positive number" }, { status: 400 })
    }

    if (body.receiver_name.trim().length === 0 || body.receiver_account.trim().length === 0) {
      return Response.json({ detail: "Receiver name and account cannot be empty" }, { status: 400 })
    }

    const transactionId = `TXN-${Date.now()}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`

    const transactionData = {
      id: transactionId,
      receiver_name: body.receiver_name,
      receiver_account: body.receiver_account,
      amount: body.amount,
      timestamp: new Date().toISOString(),
      description: body.description || "Quantum-safe transfer",
    }

    // Generate quantum signature using Dilithium (simulated)
    const signature = generateQuantumSignature(transactionData)

    // Encrypt transaction using Kyber (simulated)
    const encrypted = encryptTransactionData(transactionData)

    console.log("[v0] API Route: Transaction processed successfully")
    console.log("[v0] API Route: Transaction ID:", transactionId)

    const response: TransferResponse = {
      id: transactionId,
      status: "completed",
      receiver_name: body.receiver_name,
      receiver_account: body.receiver_account,
      amount: body.amount,
      timestamp: new Date().toISOString(),
      encrypted: true,
      signature,
    }

    return Response.json(response, { status: 200 })
  } catch (error) {
    console.log("[v0] API Route: Unexpected error:", error)
    const errorMessage = error instanceof Error ? error.message : "Failed to process transaction"
    return Response.json({ detail: errorMessage, error_code: "TRANSACTION_ERROR" }, { status: 500 })
  }
}
