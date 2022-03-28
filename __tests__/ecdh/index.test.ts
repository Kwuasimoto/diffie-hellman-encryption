import crypto, {ECDH, getCurves} from "crypto";

describe("Elliptical Curve Diffie-Hellman Keys |", () => {

    const curve = "secp256k1"

    let serverKeys: ECDH
    let clientKeys: ECDH

    const keyRing: {[key:string]: Buffer} = {}

    beforeAll(() => {
        serverKeys = crypto.createECDH(curve)
        clientKeys = crypto.createECDH(curve)

        keyRing["server"] = serverKeys.generateKeys()
        keyRing["client"] = clientKeys.generateKeys()

        keyRing["serverShared"] = serverKeys.computeSecret(keyRing["client"])
        keyRing["clientShared"] = clientKeys.computeSecret(keyRing["server"])
    })

    test("List Curves", () => {
        console.log(getCurves())
    })

    test("Compare Secrets", () => {
        expect(keyRing["serverShared"]).toEqual(keyRing["clientShared"])
    })

    test("Key Lengths", () => {
        console.log(keyRing["serverShared"].length)
        console.log(keyRing["clientShared"].length)
    })
})