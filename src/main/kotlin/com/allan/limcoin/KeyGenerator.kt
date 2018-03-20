package com.allan.limcoin

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

class KeyGenerator {

    private var keyFactory: KeyFactory

    companion object {
        val ellipticCurveDigitalSignatureAlgorithm = "ECDSA"
        val bouncyCastleProvider = "BC"
    }


    init {
        Security.addProvider(BouncyCastleProvider())
        keyFactory = KeyFactory.getInstance(ellipticCurveDigitalSignatureAlgorithm, bouncyCastleProvider)
    }

    fun generateKey(): KeyPair {
        val ecNamedCurveTable = ECNamedCurveTable.getParameterSpec("prime192v1")

        val keyPairGenerator = KeyPairGenerator.getInstance(ellipticCurveDigitalSignatureAlgorithm, bouncyCastleProvider)
        keyPairGenerator.initialize(ecNamedCurveTable, SecureRandom())
        return keyPairGenerator.generateKeyPair()
    }

    fun generateKeyPairInString(): KeyPairInString {
        val keyPair = generateKey()
        return KeyPairInString(privateKeyToString(keyPair.private), publicKeyToString(keyPair.public))
    }

    fun getPrivateKey(privateKey: String): PrivateKey {
        val privateKeyInByteArray = Base64.getDecoder().decode(privateKey)
        val pkcS8EncodedKeySpec = PKCS8EncodedKeySpec(privateKeyInByteArray)
        return keyFactory.generatePrivate(pkcS8EncodedKeySpec)
    }

    fun getPublicKey(publicKey: String): PublicKey {
        val publicKeyInByteArray = Base64.getDecoder().decode(publicKey)
        val x509EncodedKeySpec = X509EncodedKeySpec(publicKeyInByteArray)
        return keyFactory.generatePublic(x509EncodedKeySpec)
    }

    fun publicKeyToString(publicKey: PublicKey): String {
        val publicKeySpec = keyFactory.getKeySpec(publicKey, X509EncodedKeySpec::class.java)
        return Base64.getEncoder().encodeToString(publicKeySpec.encoded)
    }

    fun privateKeyToString(privateKey: PrivateKey): String {
        val privateKeySpec = keyFactory.getKeySpec(privateKey,  PKCS8EncodedKeySpec::class.java)
        return Base64.getEncoder().encodeToString(privateKeySpec.encoded)
}

    fun generateSignature(privateKey: PrivateKey): Signature {
        val signature = Signature.getInstance("ECDSA", "BC")
        signature.initSign(privateKey)
        return signature
    }

    fun signDataToByteArray( data: ByteArray, privateKey: PrivateKey): ByteArray {
        val signature = generateSignature(privateKey)
        signature.update(data)
        return signature.sign()
    }

    fun signData( data: ByteArray, privateKeyInString: String): String {
        val privateKey = getPrivateKey(privateKeyInString)
        return Base64.getEncoder().encodeToString(signDataToByteArray(data, privateKey))
    }

    fun verifySignedData(data: ByteArray, signedData: ByteArray, publicKey: PublicKey):Boolean {
        val signature = Signature.getInstance("ECDSA", "BC")
        signature.initVerify(publicKey)
        signature.update(data)
        return signature.verify(signedData)
    }

    fun verifySignedData(data: ByteArray,
                         signedDataInString: String,
                         publicKey: PublicKey):Boolean {
        val signedData = Base64.getDecoder().decode(signedDataInString)
        return verifySignedData(data, signedData,  publicKey)
    }
}