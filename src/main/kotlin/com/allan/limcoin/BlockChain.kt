package com.allan.limcoin
import java.time.LocalDateTime

class BlockChain( val chain:MutableList<Block> = mutableListOf(), val difficult:Int = 1, val keyGenerator: KeyGenerator = KeyGenerator()) {

    init {
        chain.add(createGensisBlock())
    }

    fun createGensisBlock() = Block(LocalDateTime.now(), Transaction("","",0.0), "")

    fun getLatestBlock() = this.chain.last()

    fun addBlock(newBlock: Block) {
        newBlock.previousHash = this.getLatestBlock().hash
        newBlock.proofOfWork(difficult)


        val isValid = keyGenerator.verifySignedData(newBlock.transaction.toString().toByteArray(Charsets.UTF_8),
                                      newBlock.signature,
                                      keyGenerator.getPublicKey(newBlock.transaction.from)
                                     )

        if(isValid) {
            this.chain.add(newBlock)
        }
    }

    fun isChainValid(): Boolean {
        chain.zipWithNext{ first, second ->
            if( first.hash != first.calculateHash()) {
                return false
            }
            if(second.previousHash != first.hash) {
                return false
            }
        }
        return true
    }

}

