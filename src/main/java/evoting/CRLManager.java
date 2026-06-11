package evoting;

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;

public class CRLManager {

    public static void generateCRLAndSave(CA ca, int nextUpdateDays, String filePath) throws Exception {
        X509CRL crl = generateCRL(ca, nextUpdateDays);
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(crl.getEncoded());
        }
    }

    public static X509CRL generateCRL(CA ca, int nextUpdateDays) throws Exception {
        X500Principal issuerPrincipal = ca.getCertificate().getSubjectX500Principal();
        Date thisUpdate = Date.from(Instant.now());
        JcaX509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(issuerPrincipal, thisUpdate);

        Date nextUpdate = Date.from(Instant.now().plusSeconds(nextUpdateDays * 86400L));
        crlBuilder.setNextUpdate(nextUpdate);

        // Use serial numbers from CA (not full certificates)
        for (BigInteger serial : ca.getRevokedSerialNumbers()) {
            crlBuilder.addCRLEntry(serial,
                    Date.from(Instant.now()),
                    CRLReason.privilegeWithdrawn);
        }

        X509CRLHolder holder = crlBuilder.build(
                new JcaContentSignerBuilder(CryptoUtils.SIGNATURE_ALGORITHM)
                        .setProvider(CryptoUtils.PROVIDER)
                        .build(ca.getPrivateKey())
        );
        return new JcaX509CRLConverter().setProvider(CryptoUtils.PROVIDER).getCRL(holder);
    }

    public static X509CRL loadCRL(String filePath) throws Exception {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(fis);
        }
    }

    public static boolean isRevoked(X509Certificate cert, X509CRL crl) {
        return crl.isRevoked(cert);
    }

    public static List<BigInteger> getRevokedSerialNumbers(X509CRL crl) {
        List<BigInteger> serials = new ArrayList<>();
        Set<? extends X509CRLEntry> revokedSet = (Set<? extends X509CRLEntry>) crl.getRevokedCertificates();
        if (revokedSet != null) {
            for (X509CRLEntry entry : revokedSet) {
                serials.add(entry.getSerialNumber());
            }
        }
        return serials;
    }

    public static boolean verifyCRLSignature(X509CRL crl, X509Certificate caCert) {
        try {
            crl.verify(caCert.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}