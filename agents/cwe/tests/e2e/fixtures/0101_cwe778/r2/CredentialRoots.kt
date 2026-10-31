// Feature 0101, CWE-778 Concept A: pin, biometric, keychain and kerberos name a
// security operation. Every handler hands its failure on unlogged: all report.

class PinGate(private val pinStore: PinStore, private val kdc: Kdc) {
    fun checkPin(entered: String): Result<Unit> {
        try {
            pinStore.compare(entered)
            return Result.success(Unit)
        } catch (e: Exception) { // EXPECT: finding
            return Result.failure(e)
        }
    }

    fun unlockBiometric(prompt: BiometricPrompt, info: PromptInfo): Result<Unit> {
        try {
            prompt.show(info)
            return Result.success(Unit)
        } catch (e: Exception) { // EXPECT: finding
            return Result.failure(e)
        }
    }

    fun readKeychainItem(name: String): Result<String> {
        try {
            return Result.success(store.read(name))
        } catch (e: Exception) { // EXPECT: finding
            return Result.failure(e)
        }
    }

    fun obtainKerberosTicket(realm: String): Result<Ticket> {
        try {
            return Result.success(kdc.request(realm))
        } catch (e: Exception) { // EXPECT: finding
            return Result.failure(e)
        }
    }

    fun loadSpinnerFrames(name: String): Result<Frames> {
        try {
            return Result.success(frames.read(name))
        } catch (e: Exception) { // EXPECT: clean
            return Result.failure(e)
        }
    }
}
