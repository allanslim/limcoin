package com.allan.limcoin

import org.hamcrest.CoreMatchers.`is`
import org.hamcrest.CoreMatchers.notNullValue
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.time.LocalDateTime


class LimCoinTest {

    private val keyGenerator = KeyGenerator()
    private val privateKeyInString = "MHsCAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQEEYTBfAgEBBBiRhoUqgPjn6BpoPQOrepv53VwweGUYfXWgCgYIKoZIzj0DAQGhNAMyAAQW0ZEmk6+pmtmS5BYVkJsRUscH+NX0ZWr40Wuz7SbIvO1mBQMM4vflc9bxm/Q9tzg="
    private val publicKeyInString = "MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEFtGRJpOvqZrZkuQWFZCbEVLHB/jV9GVq+NFrs+0myLztZgUDDOL35XPW8Zv0Pbc4"

    val blockChain = BlockChain()

    @Before
    fun setUp() {
    }

    @After
    fun tearDown() {
    }

    @Test
    fun `should create private and public key`() {

        val keyPair = keyGenerator.generateKeyPairInString()

        assertThat(keyPair, `is`(notNullValue()))

        assertThat(keyPair.privateKey,`is`(notNullValue()))
        assertThat(keyPair.publicKey,`is`(notNullValue()))

    }

    @Test
    fun `should create Keys from string values`() {
        val privateKey = keyGenerator.getPrivateKey(privateKeyInString)
        val publicKey = keyGenerator.getPublicKey(publicKeyInString)
        assertThat(privateKey, `is`(notNullValue()))
        assertThat(publicKey, `is`(notNullValue()))
    }

    @Test
    fun `private key should be able to sign data`() {

        val publicKey = keyGenerator.getPublicKey(publicKeyInString)

        val data = "sample data to be signed"
        val signedData = keyGenerator.signData(data.toByteArray(Charsets.UTF_8), privateKeyInString)
        val isVerified = keyGenerator.verifySignedData(data.toByteArray(Charsets.UTF_8), signedData,  publicKey)
        assertThat(isVerified, `is`(true))
    }

    @Test
    fun `should add block to Blockchain and BlockChain should be valid`() {

        val user1 = keyGenerator.generateKeyPairInString()
        val user2 = keyGenerator.generateKeyPairInString()
        val user3 = keyGenerator.generateKeyPairInString()
        val user4 = keyGenerator.generateKeyPairInString()

        val transaction1 = Transaction(user1.publicKey, user2.publicKey, 350.00)
        val transactionSignedByUser1 = keyGenerator.signData(transaction1.toString().toByteArray(Charsets.UTF_8), user1.privateKey)
        blockChain.addBlock(Block(LocalDateTime.now(), transaction1, transactionSignedByUser1))

        val transaction2 = Transaction(user3.publicKey, user2.publicKey, 350.00)
        val transactionSignedByUser3 = keyGenerator.signData(transaction2.toString().toByteArray(Charsets.UTF_8), user3.privateKey)
        blockChain.addBlock(Block(LocalDateTime.now(), transaction2, transactionSignedByUser3))


        val transaction3 = Transaction(user4.publicKey, user2.publicKey, 350.00)
        val transactionSignedByUser4 = keyGenerator.signData(transaction3.toString().toByteArray(Charsets.UTF_8), user4.privateKey)
        blockChain.addBlock(Block(LocalDateTime.now(), transaction3, transactionSignedByUser4))

        val isChainValid = blockChain.isChainValid()
        assertThat(isChainValid, `is`(true))
    }

}