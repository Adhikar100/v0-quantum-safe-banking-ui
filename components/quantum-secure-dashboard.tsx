"use client"

import { useState, useEffect } from "react"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { AlertCircle, Lock, Shield, Key, CheckCircle, AlertTriangle } from "lucide-react"

interface SecurityInfo {
  kyberStatus: "active" | "rotating" | "expired"
  dilithiumStatus: "active" | "rotating" | "expired"
  lastKeyRotation: string
  daysUntilRotation: number
  mfaEnabled: boolean
  trustScore: number
}

interface QuantumTransactionUI {
  transactionId: string
  status: "pending" | "encrypting" | "signing" | "confirmed" | "failed"
  encryptionProgress: number
  riskLevel: "low" | "medium" | "high" | "critical"
  timestamp: string
}

export default function QuantumSecureDashboard() {
  const [securityInfo, setSecurityInfo] = useState<SecurityInfo | null>(null)
  const [activeTransaction, setActiveTransaction] = useState<QuantumTransactionUI | null>(null)
  const [showKeyRotation, setShowKeyRotation] = useState(false)
  const [isRotatingKeys, setIsRotatingKeys] = useState(false)

  useEffect(() => {
    // Fetch security info on mount
    fetchSecurityInfo()
  }, [])

  const fetchSecurityInfo = async () => {
    try {
      const response = await fetch("/api/security/info")
      const data = await response.json()
      // Mock security info for demo
      setSecurityInfo({
        kyberStatus: "active",
        dilithiumStatus: "active",
        lastKeyRotation: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        daysUntilRotation: 60,
        mfaEnabled: true,
        trustScore: 98,
      })
    } catch (error) {
      console.error("Failed to fetch security info:", error)
    }
  }

  const handleKeyRotation = async () => {
    setIsRotatingKeys(true)
    try {
      const response = await fetch("/api/quantum/keys/rotate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          user_id: 1,
          security_level: "LEVEL_3",
        }),
      })
      const data = await response.json()
      if (data.success) {
        setShowKeyRotation(false)
        fetchSecurityInfo()
      }
    } catch (error) {
      console.error("Key rotation failed:", error)
    } finally {
      setIsRotatingKeys(false)
    }
  }

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case "low":
        return "text-green-500 bg-green-50 border-green-200"
      case "medium":
        return "text-yellow-600 bg-yellow-50 border-yellow-200"
      case "high":
        return "text-orange-600 bg-orange-50 border-orange-200"
      case "critical":
        return "text-red-600 bg-red-50 border-red-200"
      default:
        return "text-gray-600 bg-gray-50 border-gray-200"
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "confirmed":
        return "text-green-600"
      case "failed":
        return "text-red-600"
      case "encrypting":
      case "signing":
        return "text-blue-600"
      default:
        return "text-gray-600"
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-4 md:p-8">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Shield className="w-8 h-8 text-cyan-400" />
            <h1 className="text-3xl font-bold text-white">Quantum-Safe Banking Dashboard</h1>
          </div>
          <p className="text-slate-400">Protected by CRYSTALS-Kyber & Dilithium quantum cryptography</p>
        </div>

        {/* Security Overview */}
        {securityInfo && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
            {/* Kyber Status Card */}
            <Card className="bg-slate-800 border-slate-700 p-6">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Key className="w-5 h-5 text-cyan-400" />
                  <h3 className="font-semibold text-white">CRYSTALS-Kyber</h3>
                </div>
                {securityInfo.kyberStatus === "active" && <CheckCircle className="w-5 h-5 text-green-500" />}
              </div>
              <p className="text-sm text-slate-400 mb-2">Key Encapsulation</p>
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-cyan-400">192-bit Security</span>
                <span
                  className={`text-xs px-2 py-1 rounded ${securityInfo.kyberStatus === "active" ? "bg-green-900 text-green-200" : "bg-yellow-900 text-yellow-200"}`}
                >
                  {securityInfo.kyberStatus.toUpperCase()}
                </span>
              </div>
            </Card>

            {/* Dilithium Status Card */}
            <Card className="bg-slate-800 border-slate-700 p-6">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Lock className="w-5 h-5 text-purple-400" />
                  <h3 className="font-semibold text-white">CRYSTALS-Dilithium</h3>
                </div>
                {securityInfo.dilithiumStatus === "active" && <CheckCircle className="w-5 h-5 text-green-500" />}
              </div>
              <p className="text-sm text-slate-400 mb-2">Digital Signature</p>
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-purple-400">192-bit Security</span>
                <span
                  className={`text-xs px-2 py-1 rounded ${securityInfo.dilithiumStatus === "active" ? "bg-green-900 text-green-200" : "bg-yellow-900 text-yellow-200"}`}
                >
                  {securityInfo.dilithiumStatus.toUpperCase()}
                </span>
              </div>
            </Card>

            {/* Trust Score Card */}
            <Card className="bg-slate-800 border-slate-700 p-6">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Shield className="w-5 h-5 text-emerald-400" />
                  <h3 className="font-semibold text-white">Trust Score</h3>
                </div>
                <CheckCircle className="w-5 h-5 text-emerald-500" />
              </div>
              <p className="text-sm text-slate-400 mb-2">Account Security</p>
              <div className="flex items-center gap-3">
                <div className="flex-1 bg-slate-700 rounded-full h-2">
                  <div
                    className="bg-gradient-to-r from-cyan-400 to-emerald-400 h-full rounded-full"
                    style={{ width: `${securityInfo.trustScore}%` }}
                  />
                </div>
                <span className="text-lg font-bold text-emerald-400">{securityInfo.trustScore}%</span>
              </div>
            </Card>
          </div>
        )}

        {/* Key Management Section */}
        <Card className="bg-slate-800 border-slate-700 p-6 mb-8">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Key className="w-5 h-5 text-cyan-400" />
              Quantum Key Management
            </h2>
            <Button
              onClick={() => setShowKeyRotation(!showKeyRotation)}
              variant="outline"
              className="border-cyan-400 text-cyan-400 hover:bg-cyan-950"
            >
              {securityInfo?.daysUntilRotation! < 7 ? "Rotate Now" : "Schedule Rotation"}
            </Button>
          </div>

          {showKeyRotation && (
            <div className="bg-slate-700 rounded p-4 mb-4">
              <p className="text-sm text-slate-300 mb-4">
                Rotating quantum keys will generate new CRYSTALS-Kyber and Dilithium key pairs. Your old keys will be
                securely archived.
              </p>
              <div className="flex gap-3">
                <Button
                  onClick={handleKeyRotation}
                  disabled={isRotatingKeys}
                  className="bg-cyan-500 hover:bg-cyan-600 text-white"
                >
                  {isRotatingKeys ? "Rotating..." : "Confirm Rotation"}
                </Button>
                <Button
                  onClick={() => setShowKeyRotation(false)}
                  variant="outline"
                  className="border-slate-600 text-slate-300"
                >
                  Cancel
                </Button>
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-slate-700 rounded p-4">
              <p className="text-sm text-slate-400 mb-2">Last Key Rotation</p>
              <p className="text-white font-mono text-sm">{securityInfo?.lastKeyRotation.split("T")[0]}</p>
            </div>
            <div className="bg-slate-700 rounded p-4">
              <p className="text-sm text-slate-400 mb-2">Days Until Rotation</p>
              <p
                className={`font-bold text-lg ${securityInfo?.daysUntilRotation! < 7 ? "text-orange-400" : "text-emerald-400"}`}
              >
                {securityInfo?.daysUntilRotation} days
              </p>
            </div>
          </div>
        </Card>

        {/* Transaction Monitor */}
        {activeTransaction && (
          <Card className="bg-slate-800 border-slate-700 p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white">Transaction Status</h2>
              <span className={`text-sm font-semibold ${getStatusColor(activeTransaction.status)}`}>
                {activeTransaction.status.toUpperCase()}
              </span>
            </div>

            {/* Status Progress */}
            <div className="mb-6">
              <div className="flex items-center justify-between text-sm mb-2">
                <span className="text-slate-400">Encryption & Signing</span>
                <span className="text-cyan-400">{activeTransaction.encryptionProgress}%</span>
              </div>
              <div className="w-full bg-slate-700 rounded-full h-2">
                <div
                  className="bg-gradient-to-r from-cyan-400 to-purple-400 h-full rounded-full transition-all"
                  style={{ width: `${activeTransaction.encryptionProgress}%` }}
                />
              </div>
            </div>

            {/* Risk Assessment */}
            <div className={`rounded-lg border p-4 mb-4 ${getRiskColor(activeTransaction.riskLevel)}`}>
              <div className="flex items-center gap-2 mb-2">
                {activeTransaction.riskLevel === "low" ? (
                  <CheckCircle className="w-5 h-5" />
                ) : (
                  <AlertTriangle className="w-5 h-5" />
                )}
                <span className="font-semibold capitalize">Risk Level: {activeTransaction.riskLevel}</span>
              </div>
              <p className="text-sm opacity-90">
                {activeTransaction.riskLevel === "low"
                  ? "Transaction appears normal"
                  : "Please verify transaction details"}
              </p>
            </div>

            {/* Details */}
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <p className="text-slate-400 mb-1">Transaction ID</p>
                <p className="font-mono text-cyan-400">{activeTransaction.transactionId.slice(0, 16)}...</p>
              </div>
              <div>
                <p className="text-slate-400 mb-1">Timestamp</p>
                <p className="font-mono text-slate-300">{new Date(activeTransaction.timestamp).toLocaleTimeString()}</p>
              </div>
            </div>
          </Card>
        )}

        {/* Security Info Alert */}
        <div className="bg-cyan-950 border border-cyan-700 rounded-lg p-4 flex gap-3">
          <AlertCircle className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-cyan-300 font-semibold mb-1">Quantum-Safe Security</p>
            <p className="text-sm text-cyan-200">
              All transactions are encrypted using NIST-approved post-quantum cryptography (CRYSTALS-Kyber for key
              exchange and CRYSTALS-Dilithium for digital signatures) resistant to quantum computing attacks.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
