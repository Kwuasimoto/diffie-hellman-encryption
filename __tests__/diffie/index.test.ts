import crypto, {DiffieHellman} from 'crypto'

describe("Diffie-Hellman Keys |", () => {

    const prime = 479
    const generator = 1337

    let serverKeys: DiffieHellman
    let clientKeys: DiffieHellman

    const keyRing: {[key:string]: Buffer} = {}

    /**
     * Generate the keys.
     */
    beforeAll(() => {
        serverKeys = crypto.createDiffieHellman(prime, generator)
        clientKeys = crypto.createDiffieHellman(serverKeys.getPrime(), serverKeys.getGenerator())

        keyRing["server"] = serverKeys.generateKeys()
        keyRing["client"] = clientKeys.generateKeys()
    })

    test("Compare Secrets", () => {
        expect(serverKeys.computeSecret(keyRing["client"]))
            .toEqual(clientKeys.computeSecret(keyRing["server"]))
    })
})