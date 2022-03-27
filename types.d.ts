declare module "crypto" {
    /**
     * Fix typing issues w/ keyObject.getPrime() returning a buffer.
     */
    function createDiffieHellman(primeLength: number | NodeJS.ArrayBufferView, generator?: number | NodeJS.ArrayBufferView): DiffieHellman
}