import crypto, {CipherCCM, DiffieHellman} from "crypto"
import findDiffieHellmanPrimeForByteLength from "../util/findDiffieHellmanPrimeForByteLength";

describe("AES-256-GCM With Diffie-Hellman Keys |", () => {

    /**
     * Diffie Hellman
     */
    const prime = 251
    const generator = 1177

    let serverKeys: DiffieHellman
    let clientKeys: DiffieHellman

    const keyRing: {[key:string]: Buffer | string} = {}

    /**
     * AES-256-GCM
     */
    let serverCipher: CipherCCM
    let IV: Buffer
    let authTag: string

    const message = "Data to be encrypted."
    let encrypted = ""

    let payload: Buffer

    /**
     * __________ KEY GENERATION __________
     */

    beforeAll(() => {
        /**
         * Setup Diffie Hellman Keys
         */
        serverKeys = crypto.createDiffieHellman(prime, generator)
        clientKeys = crypto.createDiffieHellman(serverKeys.getPrime(), serverKeys.getGenerator())

        keyRing["server"] = serverKeys.generateKeys()
        keyRing["client"] = clientKeys.generateKeys()

        keyRing["serverShared"] = serverKeys.computeSecret(clientKeys.getPublicKey())
        keyRing["clientShared"] = clientKeys.computeSecret(serverKeys.getPublicKey())

        /**
         * Setup AES-256-GCM Cipheriv
         */

        IV = crypto.randomBytes(24)
        serverCipher = crypto.createCipheriv("aes-256-gcm", keyRing["serverShared"], IV)

        encrypted = serverCipher.update(message, "utf8", "hex")
        encrypted += serverCipher.final("hex")

        authTag = serverCipher.getAuthTag().toString("hex")

        payload = Buffer.from(IV.toString("hex") + encrypted + authTag)
    })

    test("Find 32-byte prime for hex encoding", () => {
        const length = 32
        expect(findDiffieHellmanPrimeForByteLength(length)).toEqual({[prime]: length})
    })

    test("Compare Secrets", () => {
        expect(keyRing["serverShared"]).toEqual(keyRing["clientShared"])
    })

    /**
     * __________ CIPHERIV ENCRYPTION __________
     */

    test("Encrypted w/ AES-256-gcm", () => {
        serverCipher = crypto.createCipheriv("aes-256-gcm", keyRing["serverShared"], IV)

        encrypted = serverCipher.update(message, "utf8", "hex")
        encrypted += serverCipher.final("hex")

        expect(encrypted).toBeDefined()
        expect(encrypted).toHaveLength(42)
    })

    test("Log Encryption Data Table", () => {
        const hexIV = IV.toString("hex")

        console.table([{
            data: hexIV,
            length: hexIV.length,
        }, {
            data: encrypted,
            length: encrypted.length,
        }, {
            data: authTag,
            length: authTag.length
        }])

        expect(hexIV).toHaveLength(48)
        expect(encrypted).toHaveLength(42)
        expect(authTag).toHaveLength(32)
    })

    /**
     * __________ PAYLOAD __________
     */

    test("Check Payload", () => {
        expect(payload).toBeDefined()
        expect(payload).toHaveLength(122)
    })

    test("Deconstruct Payload", () => {
        const hexIV = IV.toString("hex")

        const destructuredIV = payload.subarray(0, hexIV.length).toString()
        const destructuredData = payload.subarray(hexIV.length, payload.length - 32).toString()
        const destructuredTag = payload.subarray(payload.length - authTag.length).toString()

        console.table([{
            data: destructuredIV,
            length: destructuredIV.length,
        }, {
            data: destructuredData,
            length: destructuredData.length,
        }, {
            data: destructuredTag,
            length: destructuredTag.length
        }])

        expect(hexIV).toEqual(destructuredIV)
        expect(encrypted).toEqual(destructuredData)
        expect(authTag).toEqual(destructuredTag)
    })

    test("Decrypt Payload", () => {
        const hexIV = IV.toString("hex")

        const destructuredIV = payload.subarray(0, hexIV.length).toString()
        const destructuredData = payload.subarray(hexIV.length, payload.length - 32).toString()
        const destructuredTag = payload.subarray(payload.length - authTag.length).toString()

        const clientDecipher = crypto.createDecipheriv(
            "aes-256-gcm",
            keyRing["clientShared"],
            Buffer.from(destructuredIV,"hex")
        ).setAuthTag(Buffer.from(destructuredTag, "hex"))

        const decrypted = clientDecipher
            .update(Buffer.from(destructuredData, "hex"), undefined, "utf8")
            + clientDecipher.final("utf8")

        expect(decrypted).toEqual(message)
    })
})