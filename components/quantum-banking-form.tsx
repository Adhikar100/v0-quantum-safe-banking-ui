"use client"

import { useState } from "react"
import { Lock, Shield, ChevronRight } from "lucide-react"

type Step = "receiver" | "account" | "amount" | "confirm"

export default function QuantumBankingForm() {
  const [currentStep, setCurrentStep] = useState<Step>("receiver")
  const [receiverName, setReceiverName] = useState("")
  const [accountNumber, setAccountNumber] = useState("")
  const [amount, setAmount] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [success, setSuccess] = useState("")

  const steps: { key: Step; label: string; icon: string }[] = [
    { key: "receiver", label: "Receiver Info", icon: "👤" },
    { key: "account", label: "Account", icon: "🏦" },
    { key: "amount", label: "Amount", icon: "💰" },
    { key: "confirm", label: "Confirm", icon: "✓" },
  ]

  const stepIndex = steps.findIndex((s) => s.key === currentStep)

  const handleNext = async () => {
    setError("")

    if (currentStep === "receiver" && !receiverName.trim()) {
      setError("Please enter receiver name")
      return
    }
    if (currentStep === "account" && !accountNumber.trim()) {
      setError("Please enter account number")
      return
    }
    if (currentStep === "amount" && !amount.trim()) {
      setError("Please enter amount")
      return
    }

    if (currentStep === "confirm") {
      setLoading(true)
      try {
        const API_URL = process.env.NEXT_PUBLIC_API_URL || "/api"

        console.log("[v0] Starting transfer with:", {
          receiver_name: receiverName,
          receiver_account: accountNumber,
          amount: Number.parseFloat(amount),
        })

        const response = await fetch(`${API_URL}/transactions/transfer`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            receiver_name: receiverName,
            receiver_account: accountNumber,
            amount: Number.parseFloat(amount),
            description: "Quantum-safe transfer",
          }),
        })

        const responseData = await response.json()
        console.log("[v0] API Response:", responseData)

        if (!response.ok) {
          throw new Error(responseData.detail || "Transfer failed")
        }

        setSuccess(`Transaction ID: ${responseData.id} - Transfer initiated successfully!`)

        // Reset form
        setTimeout(() => {
          setReceiverName("")
          setAccountNumber("")
          setAmount("")
          setCurrentStep("receiver")
          setSuccess("")
        }, 3000)
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : "Transfer failed"
        console.log("[v0] Error occurred:", errorMessage)
        setError(errorMessage)
      } finally {
        setLoading(false)
      }
    } else {
      const nextStepIndex = stepIndex + 1
      if (nextStepIndex < steps.length) {
        setCurrentStep(steps[nextStepIndex].key)
      }
    }
  }

  const handleCancel = () => {
    setCurrentStep("receiver")
    setReceiverName("")
    setAccountNumber("")
    setAmount("")
    setError("")
    setSuccess("")
  }

  return (
    <div className="w-full max-w-2xl">
      {/* Main Card */}
      <div className="bg-gradient-to-br from-[#2d1b4e] to-[#1f1540] border border-[#4a3f7e] rounded-3xl p-8 shadow-2xl">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-3">
            <Lock className="w-8 h-8 text-cyan-400" />
            <h1 className="text-3xl font-bold text-cyan-400">Quantum-Safe Banking</h1>
          </div>
          <p className="text-gray-400 text-sm">Secure Money Transfer System</p>
        </div>

        {/* Security Badge */}
        <div className="flex justify-center mb-8">
          <div className="border border-cyan-400 bg-cyan-400/5 rounded-full px-4 py-2 flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span className="text-cyan-400 text-sm font-medium">Protected by CRYSTALS-Kyber & Dilithium</span>
          </div>
        </div>

        {/* Step Indicators */}
        <div className="flex justify-between mb-10">
          {steps.map((step, index) => (
            <div key={step.key} className="flex flex-col items-center gap-2 flex-1">
              {/* Circle Indicator */}
              <div
                className={`w-12 h-12 rounded-full flex items-center justify-center transition-all duration-300 ${
                  index < stepIndex
                    ? "bg-cyan-400 text-white"
                    : index === stepIndex
                      ? "bg-cyan-400 text-white ring-2 ring-cyan-400/30"
                      : "bg-gray-500/20 text-gray-400 border border-gray-500/40"
                }`}
              >
                {index < stepIndex ? "✓" : index + 1}
              </div>
              {/* Label */}
              <span
                className={`text-xs font-medium transition-colors ${
                  index <= stepIndex ? "text-cyan-400" : "text-gray-400"
                }`}
              >
                {step.label}
              </span>
            </div>
          ))}
        </div>

        {/* Security Info Box */}
        <div className="bg-teal-500/10 border border-teal-500/30 rounded-lg p-4 mb-8">
          <div className="flex items-start gap-3">
            <Lock className="w-5 h-5 text-teal-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-teal-400 font-semibold text-sm">Quantum Security:</p>
              <p className="text-gray-300 text-sm">
                All transactions are encrypted using NIST-approved post-quantum algorithms resistant to quantum
                computing attacks.
              </p>
            </div>
          </div>
        </div>

        {error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-6 text-red-400 text-sm">{error}</div>
        )}

        {success && (
          <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3 mb-6 text-green-400 text-sm">
            {success}
          </div>
        )}

        {/* Form Content */}
        {currentStep === "receiver" && (
          <div className="space-y-6">
            <div>
              <label className="block text-gray-300 text-sm font-medium mb-3">Enter the Receiver Name</label>
              <input
                type="text"
                placeholder="John Doe"
                value={receiverName}
                onChange={(e) => setReceiverName(e.target.value)}
                className="w-full bg-gray-700/30 border border-gray-600/50 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/30 transition-all"
              />
            </div>

            {/* Buttons */}
            <div className="flex gap-4">
              <button
                onClick={handleCancel}
                className="flex-1 bg-transparent border border-gray-600 text-white font-semibold py-3 rounded-lg hover:bg-gray-700/20 hover:border-gray-500 transition-all duration-200"
              >
                CANCEL
              </button>
              <button
                onClick={handleNext}
                disabled={!receiverName.trim()}
                className="flex-1 bg-gradient-to-r from-cyan-400 to-blue-400 text-white font-semibold py-3 rounded-lg hover:from-cyan-300 hover:to-blue-300 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                NEXT
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* Account Step */}
        {currentStep === "account" && (
          <div className="space-y-6">
            <div>
              <label className="block text-gray-300 text-sm font-medium mb-3">Enter Receiver Account Number</label>
              <input
                type="text"
                placeholder="1234567890"
                value={accountNumber}
                onChange={(e) => setAccountNumber(e.target.value)}
                className="w-full bg-gray-700/30 border border-gray-600/50 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/30 transition-all"
              />
            </div>

            <div className="flex gap-4">
              <button
                onClick={handleCancel}
                className="flex-1 bg-transparent border border-gray-600 text-white font-semibold py-3 rounded-lg hover:bg-gray-700/20 hover:border-gray-500 transition-all duration-200"
              >
                CANCEL
              </button>
              <button
                onClick={handleNext}
                disabled={!accountNumber.trim()}
                className="flex-1 bg-gradient-to-r from-cyan-400 to-blue-400 text-white font-semibold py-3 rounded-lg hover:from-cyan-300 hover:to-blue-300 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                NEXT
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* Amount Step */}
        {currentStep === "amount" && (
          <div className="space-y-6">
            <div>
              <label className="block text-gray-300 text-sm font-medium mb-3">Enter Transfer Amount</label>
              <input
                type="number"
                placeholder="0.00"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                className="w-full bg-gray-700/30 border border-gray-600/50 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/30 transition-all"
              />
            </div>

            <div className="flex gap-4">
              <button
                onClick={handleCancel}
                className="flex-1 bg-transparent border border-gray-600 text-white font-semibold py-3 rounded-lg hover:bg-gray-700/20 hover:border-gray-500 transition-all duration-200"
              >
                CANCEL
              </button>
              <button
                onClick={handleNext}
                disabled={!amount.trim()}
                className="flex-1 bg-gradient-to-r from-cyan-400 to-blue-400 text-white font-semibold py-3 rounded-lg hover:from-cyan-300 hover:to-blue-300 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                NEXT
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* Confirm Step */}
        {currentStep === "confirm" && (
          <div className="space-y-6">
            <div className="bg-gray-700/20 border border-gray-600/50 rounded-lg p-6 space-y-4">
              <div className="flex justify-between items-center py-2 border-b border-gray-600/30">
                <span className="text-gray-400">Receiver Name:</span>
                <span className="text-cyan-400 font-semibold">{receiverName}</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-gray-600/30">
                <span className="text-gray-400">Account Number:</span>
                <span className="text-cyan-400 font-semibold">{accountNumber}</span>
              </div>
              <div className="flex justify-between items-center py-2">
                <span className="text-gray-400">Amount:</span>
                <span className="text-cyan-400 font-bold text-lg">${amount}</span>
              </div>
            </div>

            <div className="flex gap-4">
              <button
                onClick={handleCancel}
                className="flex-1 bg-transparent border border-gray-600 text-white font-semibold py-3 rounded-lg hover:bg-gray-700/20 hover:border-gray-500 transition-all duration-200"
              >
                CANCEL
              </button>
              <button
                onClick={handleNext}
                disabled={loading}
                className="flex-1 bg-gradient-to-r from-cyan-400 to-blue-400 text-white font-semibold py-3 rounded-lg hover:from-cyan-300 hover:to-blue-300 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {loading ? "Processing..." : "CONFIRM"}
                {!loading && <ChevronRight className="w-4 h-4" />}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Footer Note */}
      <div className="text-center mt-6 text-gray-500 text-xs">
        <p>Your transactions are protected by post-quantum cryptography</p>
      </div>
    </div>
  )
}
