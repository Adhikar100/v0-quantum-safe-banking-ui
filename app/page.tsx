"use client"
import QuantumBankingForm from "@/components/quantum-banking-form"

// Note: Set NEXT_PUBLIC_API_URL in your .env.local for production
const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

export default function Home() {
  return (
    <main className="min-h-screen bg-gradient-to-br from-[#1a1a3e] via-[#2d1b4e] to-[#1a1a3e] flex items-center justify-center p-4">
      <QuantumBankingForm />
    </main>
  )
}
