import crypto, {DiffieHellman} from "crypto";
import isPrime from "./isPrime";

export default function findDiffieHellmanPrimeForByteLength(length: number = 32, start: number = 2, primeRange: number = 300) {
    const table: {[key:string]: number} = {}

    for(let prime = start; prime < primeRange; prime++){

        if(isPrime(prime)){

            let serverKeyRing: DiffieHellman
            let clientKeyRing: DiffieHellman

            let sharedSecret!:  Buffer

            try{
                serverKeyRing = crypto.createDiffieHellman(prime)
                clientKeyRing = crypto.createDiffieHellman(serverKeyRing.getPrime(), serverKeyRing.getGenerator())

                clientKeyRing.generateKeys()
                serverKeyRing.generateKeys()

                sharedSecret = serverKeyRing.computeSecret(clientKeyRing.getPublicKey())
            } catch (e: any) {}

            if(sharedSecret && sharedSecret.length === length){
                table[`${prime}`] = sharedSecret.length
            }
        }
    }

    return table
}