package com.allan.limcoin

import org.apache.commons.codec.digest.DigestUtils
import java.time.LocalDateTime

class Block(val timestamp: LocalDateTime,
            val transaction: Transaction,
            val signature: String,
            var hash: String = "0",
            var previousHash: String = "",
            var nonce:Int = 0) {

    init {
        this.hash = calculateHash()
    }

    fun calculateHash() = DigestUtils.sha256Hex("$timestamp$transaction$previousHash$nonce")

    fun proofOfWork(difficult:Int) {
        while(this.hash.substring(0, difficult) != "0".repeat(difficult)) {
            this.nonce++
            this.hash = this.calculateHash()
        }
    }

}