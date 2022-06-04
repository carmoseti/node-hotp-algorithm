import * as crypto from "crypto";

const doubleDigits: number[] = [0, 2, 4, 6, 8, 1, 3, 5, 7, 9]
/*
* Luhn algorithm
* */
const calculateChecksum = (num: number, digits: number): number => {
    let isDoubleDigit: boolean = true
    let total: number = 0

    while (0 < digits--) {
        let digit: number = num % 10
        num /= 10
        if (isDoubleDigit)
            digit = doubleDigits[digit]

        total += digit
        isDoubleDigit = !isDoubleDigit
    }

    let result: number = total % 10
    if (result > 0)
        result = 10 - result

    return result
}

const hmacSHA1 = (key: string, text: string): Buffer => {
    return crypto.createHmac('sha1', key).update(text).digest()
}

const digitsPower: number[] = [
    1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000
]

const generateOTP = (secret: string, movingFactor: number, codeDigits: number, addChecksum: boolean, truncationOffset: number): string => {
    let result: string = null
    const digits: number = addChecksum ? (codeDigits + 1) : codeDigits

    const text: Buffer = Buffer.alloc(8)
    for (let i = text.length - 1; i >= 0; i--) {
        // tslint:disable-next-line:no-bitwise
        text[i] = (movingFactor & 0xff)
        // tslint:disable-next-line:no-bitwise
        movingFactor >>= 8
    }

    const hash: Buffer = hmacSHA1(secret, text.toString())

    // tslint:disable-next-line:no-bitwise
    let offset: number = hash[hash.length - 1] & 0xf
    if ((0 <= truncationOffset) && (truncationOffset < (hash.length - 4))) {
        offset = truncationOffset
    }

    // tslint:disable-next-line:no-bitwise
    const binary: number = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff)
    let otp: number = binary % digitsPower[codeDigits]

    if (addChecksum) {
        otp = (otp * 10) + calculateChecksum(otp, codeDigits)
    }

    result = String(otp)
    while (result.length < digits) {
        result = "0" + result
    }
    return result
}

const program = () => {
    const secret: string = "12345678901234567890"

    console.log(`Count\tHexadecimal HMAC-SHA-1(secret, count)\t\tOTP`)
    for (let a = 0; a < 10; a++) {
        console.log(`${a}\t${
            hmacSHA1(secret, String(a)).toString('hex')
        }\t${
            generateOTP(secret, a, 6, false, -1)
        }`)
    }
}

program()