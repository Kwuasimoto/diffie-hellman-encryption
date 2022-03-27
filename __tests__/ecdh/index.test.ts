import crypto, {ECDH} from "crypto";

describe("Elliptical Curve Diffie-Hellman Keys |", () => {

    const curve = "sect409r1"

    let serverKeys: ECDH
    let clientKeys: ECDH

    const keyRing: {[key:string]: Buffer} = {}

    beforeAll(() => {
        serverKeys = crypto.createECDH(curve)
        clientKeys = crypto.createECDH(curve)

        keyRing["server"] = serverKeys.generateKeys()
        keyRing["client"] = clientKeys.generateKeys()
    })

    // test("List Curves", () => {
    //     console.log(getCurves())
    // })

    test("Compare Secrets", () => {
        expect(serverKeys.computeSecret(keyRing["client"]))
            .toEqual(clientKeys.computeSecret(keyRing["server"]))
    })
})