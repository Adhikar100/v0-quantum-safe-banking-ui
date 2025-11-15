"use client"

import type React from "react"

import { useState } from "react"
import { Lock, Shield, ChevronRight, AlertCircle, CheckCircle2 } from "lucide-react"

type Step = "receiver" | "account" | "amount" | "confirm"

export default function QuantumBankingForm() {
  const [currentStep, setCurrentStep] = useState<Step>("receiver")
  const [receiverName, setReceiverName] = useState("")
  const [accountNumber, setAccountNumber] = useState("")
  const [amount, setAmount] = useState("")
  const [bankName, setBankName] = useState("national")
  const [generalError, setGeneralError] = useState("")
  const [success, setSuccess] = useState("")
  const [submitting, setSubmitting] = useState(false)

  const steps: { key: Step; label: string }[] = [
    { key: "receiver", label: "Receiver Info" },
    { key: "account", label: "Account" },
    { key: "amount", label: "Amount" },
    { key: "confirm", label: "Confirm" },
  ]

  const stepIndex = steps.findIndex((s) => s.key === currentStep)

  const handleNext = async () => {
    setGeneralError("")

    if (currentStep === "receiver" && !receiverName.trim()) {
      setGeneralError("Please enter receiver name")
      return
    }
    if (currentStep === "account" && !accountNumber.trim()) {
      setGeneralError("Please enter account number")
      return
    }
    if (currentStep === "amount" && !amount.trim()) {
      setGeneralError("Please enter amount")
      return
    }

    if (currentStep === "confirm") {
      setSubmitting(true)
      try {
        const response = await fetch("/api/transactions/transfer", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            receiver_name: receiverName,
            receiver_account: accountNumber,
            amount: Number.parseFloat(amount),
            description: "Quantum-safe transfer",
          }),
        })

        const data = await response.json()
        if (!response.ok) {
          throw new Error(data.detail || "Transfer failed")
        }

        setSuccess(`Transaction ID: ${data.id} - Transfer initiated successfully!`)
        setTimeout(() => {
          handleCancel()
        }, 3000)
      } catch (err) {
        setGeneralError(err instanceof Error ? err.message : "Transfer failed")
      } finally {
        setSubmitting(false)
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
    setBankName("national")
    setGeneralError("")
    setSuccess("")
  }

  return (
    <div className="w-full max-w-2xl">
      <div className="bg-gradient-to-br from-slate-900 to-slate-800 border border-slate-700 rounded-3xl p-8 shadow-2xl">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-3">
            <Lock className="w-8 h-8" style={{ color: "#DC143C" }} />
            <h1 className="text-3xl font-bold" style={{ color: "#DC143C" }}>
              Quantum-Safe Banking
            </h1>
          </div>
          <p className="text-gray-400 text-sm">Secure Money Transfer System</p>
        </div>

        <div className="flex justify-center mb-8">
          <div
            className="border rounded-full px-4 py-2 flex items-center gap-2"
            style={{ borderColor: "#00A651", backgroundColor: "rgba(0, 166, 81, 0.05)" }}
          >
            <Shield className="w-4 h-4" style={{ color: "#00A651" }} />
            <span className="text-sm font-medium" style={{ color: "#00A651" }}>
              Protected by CRYSTALS-Kyber & Dilithium
            </span>
          </div>
        </div>

        <div className="flex justify-between items-center mb-10">
          {steps.map((step, index) => (
            <div key={step.key} className="flex items-center gap-0 flex-1">
              <div
                className={`w-12 h-12 rounded-full flex items-center justify-center transition-all duration-300 flex-shrink-0 ${
                  index < stepIndex
                    ? "text-white border border-gray-600"
                    : index === stepIndex
                      ? "ring-2"
                      : "bg-gray-500/20 text-gray-400 border border-gray-500/40"
                }`}
                style={
                  index < stepIndex || index === stepIndex ? { backgroundColor: "#DC143C", borderColor: "#DC143C" } : {}
                }
              >
                {index < stepIndex ? "✓" : index + 1}
              </div>

              {index < steps.length - 1 && (
                <div
                  className={`flex-1 h-1 mx-2 transition-all duration-300 ${
                    index < stepIndex ? "bg-gray-500/20" : "bg-gray-500/20"
                  }`}
                  style={index < stepIndex ? { backgroundColor: "#DC143C" } : {}}
                />
              )}

              {index === steps.length - 1 && <div className="flex-1" />}
            </div>
          ))}
        </div>

        {/* Display step label */}
        <div className="flex justify-between mb-10">
          {steps.map((step, index) => (
            <div key={`label-${step.key}`} className="flex-1 text-center">
              <span
                className="text-xs font-medium transition-colors"
                style={{ color: index <= stepIndex ? "#DC143C" : "#9CA3AF" }}
              >
                {step.label}
              </span>
            </div>
          ))}
        </div>

        <div
          className="rounded-lg p-4 mb-8"
          style={{ backgroundColor: "rgba(0, 166, 81, 0.1)", border: "1px solid rgba(0, 166, 81, 0.3)" }}
        >
          <div className="flex items-start gap-3">
            <Lock className="w-5 h-5 flex-shrink-0 mt-0.5" style={{ color: "#00A651" }} />
            <div>
              <p className="font-semibold text-sm" style={{ color: "#00A651" }}>
                Quantum Security:
              </p>
              <p className="text-gray-300 text-sm">
                All transactions are encrypted using NIST-approved post-quantum algorithms resistant to quantum
                computing attacks.
              </p>
            </div>
          </div>
        </div>

        {generalError && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-6 text-red-400 text-sm flex items-center gap-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            {generalError}
          </div>
        )}

        {success && (
          <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3 mb-6 text-green-400 text-sm flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
            {success}
          </div>
        )}

        {/* Receiver Info Step */}
        {currentStep === "receiver" && (
          <div className="space-y-6">
            <div>
              <label className="block text-gray-300 text-sm font-medium mb-3">Enter the Receiver Name</label>
              <input
                type="text"
                placeholder="John Doe"
                value={receiverName}
                onChange={(e) => setReceiverName(e.target.value)}
                className="w-full bg-gray-700/30 border border-gray-600/50 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-1 transition-all"
                style={{ "--tw-ring-color": "#DC143C" } as React.CSSProperties}
                onFocus={(e) => (e.target.style.borderColor = "#DC143C")}
                onBlur={(e) => (e.target.style.borderColor = "")}
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
                className="flex-1 text-white font-semibold py-3 rounded-lg transition-all duration-200 flex items-center justify-center gap-2 hover:opacity-90"
                style={{ backgroundColor: "#DC143C" }}
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
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-gray-300 text-sm font-medium mb-3">Select Bank</label>
                <select
                  value={bankName}
                  onChange={(e) => setBankName(e.target.value)}
                  className="w-full bg-gray-700/30 border border-gray-600/50 rounded-lg px-4 py-3 text-white focus:outline-none focus:ring-1 transition-all"
                  style={{ "--tw-ring-color": "#DC143C" } as React.CSSProperties}
                >
                  <option value="national">National Bank</option>
                  <option value="himalayan">Himalayan Bank</option>
                  <option value="nabil">Nabil Bank</option>
                </select>
              </div>
              <div>
                <label className="block text-gray-300 text-sm font-medium mb-3">Account Number</label>
                <input
                  type="text"
                  placeholder="1234567890"
                  value={accountNumber}
                  onChange={(e) => setAccountNumber(e.target.value)}
                  className="w-full bg-gray-700/30 border border-gray-600/50 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-1 transition-all"
                  onFocus={(e) => (e.target.style.borderColor = "#DC143C")}
                  onBlur={(e) => (e.target.style.borderColor = "")}
                />
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
                className="flex-1 text-white font-semibold py-3 rounded-lg transition-all duration-200 flex items-center justify-center gap-2 hover:opacity-90"
                style={{ backgroundColor: "#DC143C" }}
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
              <label className="block text-gray-300 text-sm font-medium mb-3">Enter Transfer Amount (NPR)</label>
              <input
                type="number"
                placeholder="0.00"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                className="w-full bg-gray-700/30 border border-gray-600/50 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-1 transition-all"
                onFocus={(e) => (e.target.style.borderColor = "#DC143C")}
                onBlur={(e) => (e.target.style.borderColor = "")}
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
                className="flex-1 text-white font-semibold py-3 rounded-lg transition-all duration-200 flex items-center justify-center gap-2 hover:opacity-90"
                style={{ backgroundColor: "#DC143C" }}
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
                <span className="font-semibold" style={{ color: "#DC143C" }}>
                  {receiverName}
                </span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-gray-600/30">
                <span className="text-gray-400">Account Number:</span>
                <span className="font-semibold" style={{ color: "#DC143C" }}>
                  {accountNumber}
                </span>
              </div>
              <div className="flex justify-between items-center py-2">
                <span className="text-gray-400">Amount:</span>
                <span className="font-bold text-lg" style={{ color: "#DC143C" }}>
                  NPR{" "}
                  {Number.parseFloat(amount).toLocaleString("en-US", {
                    minimumFractionDigits: 2,
                    maximumFractionDigits: 2,
                  })}
                </span>
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
                disabled={submitting}
                className="flex-1 text-white font-semibold py-3 rounded-lg transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 hover:opacity-90"
                style={{ backgroundColor: "#DC143C" }}
              >
                {submitting ? "Processing..." : "CONFIRM"}
                {!submitting && <ChevronRight className="w-4 h-4" />}
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="text-center mt-6 text-gray-500 text-xs">
        <p>Your transactions are protected by post-quantum cryptography</p>
      </div>
    </div>
  )
}
