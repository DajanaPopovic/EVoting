package evoting;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;

public class CryptoUtils {
    public static final String KEY_ALGORITHM = "RSA";
    public static final int KEY_SIZE = 2048;
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    public static final String SYMMETRIC_ALGORITHM = "AES/GCM/NoPadding";
    public static final int SYMMETRIC_KEY_SIZE = 256;
    public static final String HMAC_ALGORITHM = "HmacSHA256";
    public static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    // Generate RSA key pair
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(KEY_ALGORITHM, PROVIDER);
        gen.initialize(KEY_SIZE);
        return gen.generateKeyPair();
    }

    // Generate symmetric key (AES)
    public static SecretKey generateSymmetricKey() throws Exception {
        KeyGenerator gen = KeyGenerator.getInstance("AES", PROVIDER);
        gen.init(SYMMETRIC_KEY_SIZE);
        return gen.generateKey();
    }

    // Create self-signed CA certificate
    public static X509Certificate createCACertificate(KeyPair caKeyPair, String cn, int validityDays) throws Exception {
        X500Name issuer = new X500Name("CN=" + cn);
        X500Name subject = issuer;
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = Date.from(Instant.now());
        Date notAfter = Date.from(Instant.now().plusSeconds(validityDays * 86400L));

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, caKeyPair.getPublic());

        // Basic Constraints: CA=true
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        // Key Usage: keyCertSign, cRLSign
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(PROVIDER).build(caKeyPair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider(PROVIDER).getCertificate(holder);
    }

    // Create end-entity certificate signed by CA
    public static X509Certificate createUserCertificate(KeyPair userKeyPair, X509Certificate caCert,
                                                        PrivateKey caPrivateKey, String cn,
                                                        boolean isOrganizer) throws Exception {
        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=" + cn);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = Date.from(Instant.now());
        Date notAfter = Date.from(Instant.now().plusSeconds(365 * 86400L)); // 1 year validity

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, userKeyPair.getPublic());

        // Basic Constraints: end entity
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        // Key Usage: digitalSignature, keyEncipherment (for encryption)
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        // Extended Key Usage: clientAuth for all users
        KeyPurposeId[] purposes = {KeyPurposeId.id_kp_clientAuth};
        if (isOrganizer) {
            purposes = new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_emailProtection};
        }
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purposes));

        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(PROVIDER).build(caPrivateKey);
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider(PROVIDER).getCertificate(holder);
    }

    // Encrypt vote data with symmetric key (AES/GCM)
    public static byte[] encryptSymmetric(byte[] plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM, PROVIDER);
        byte[] iv = new byte[12];
        SecureRandom random = SecureRandom.getInstanceStrong();
        random.nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] ciphertext = cipher.doFinal(plaintext);
        // Prepend IV
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        return result;
    }

    // Decrypt symmetric
    public static byte[] decryptSymmetric(byte[] encrypted, SecretKey key) throws Exception {
        byte[] iv = new byte[12];
        byte[] ciphertext = new byte[encrypted.length - 12];
        System.arraycopy(encrypted, 0, iv, 0, 12);
        System.arraycopy(encrypted, 12, ciphertext, 0, ciphertext.length);
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM, PROVIDER);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(ciphertext);
    }

    // Encrypt symmetric key with RSA public key
    public static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    // Decrypt symmetric key with RSA private key
    public static byte[] decryptRSA(byte[] encrypted, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encrypted);
    }

    // HMAC-SHA256
    public static byte[] computeHMAC(byte[] data, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM, PROVIDER);
        mac.init(key);
        return mac.doFinal(data);
    }

    // Digital signature
    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM, PROVIDER);
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    public static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM, PROVIDER);
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    // Store private key + certificate in PKCS12 keystore
    public static void saveToPKCS12(PrivateKey privKey, X509Certificate cert, String password, String filePath) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", PROVIDER);
        ks.load(null, null);
        ks.setKeyEntry("user", privKey, password.toCharArray(), new X509Certificate[]{cert});
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            ks.store(fos, password.toCharArray());
        }
    }

    // Load from PKCS12
    public static KeyStore loadPKCS12(String filePath, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", PROVIDER);
        try (FileInputStream fis = new FileInputStream(filePath)) {
            ks.load(fis, password.toCharArray());
        }
        return ks;
    }

    // Create subordinate CA certificate signed by root CA (or another CA)
    public static X509Certificate createSubCACertificate(KeyPair caKeyPair, X509Certificate issuerCert,
                                                         PrivateKey issuerPrivateKey, String cn, int validityDays) throws Exception {
        X500Name issuer = new X500Name(issuerCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=" + cn);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = Date.from(Instant.now());
        Date notAfter = Date.from(Instant.now().plusSeconds(validityDays * 86400L));

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, caKeyPair.getPublic());

        // Basic Constraints: CA=true (subordinate CA)
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        // Key Usage: keyCertSign, cRLSign (for CA)
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(PROVIDER).build(issuerPrivateKey);
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider(PROVIDER).getCertificate(holder);
    }
}