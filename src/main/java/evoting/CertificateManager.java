package evoting;

import java.io.File;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;

public class CertificateManager {
    private final CA rootCA;
    private final OrganizationalCA orgCA;
    private final VoterCA voterCA;
    private final String caDir;  // directory where CRL files are stored

    public CertificateManager(CA rootCA, OrganizationalCA orgCA, VoterCA voterCA, String caDir) {
        this.rootCA = rootCA;
        this.orgCA = orgCA;
        this.voterCA = voterCA;
        this.caDir = caDir;
    }

    public X509Certificate issueOrganizerCertificate(String cn, KeyPair userKeyPair) throws Exception {
        // Signed by OrganizationalCA
        return CryptoUtils.createUserCertificate(userKeyPair, orgCA.getCertificate(),
                orgCA.getPrivateKey(), cn, true);
    }

    public X509Certificate issueVoterCertificate(String cn, KeyPair userKeyPair) throws Exception {
        // Signed by VoterCA
        return CryptoUtils.createUserCertificate(userKeyPair, voterCA.getCertificate(),
                voterCA.getPrivateKey(), cn, false);
    }

    // Validate certificate chain and CRL status
    public boolean validateCertificate(X509Certificate userCert, CA issuingCA, boolean checkCRL) {
        try {
            // 1. Verify signature by issuing CA
            userCert.verify(issuingCA.getCertificate().getPublicKey());
            // 2. Check validity period
            userCert.checkValidity();
            // 3. Check CRL if required
            if (checkCRL) {
                String crlPath = (issuingCA instanceof OrganizationalCA) ?
                        caDir + "org.crl" : caDir + "voter.crl";
                File crlFile = new File(crlPath);
                if (crlFile.exists()) {
                    X509CRL crl = CRLManager.loadCRL(crlPath);
                    // Provjera potpisa CRL-a prije upotrebe
                    if (!CRLManager.verifyCRLSignature(crl, issuingCA.getCertificate())) {
                        return false;
                    }
                    if (CRLManager.isRevoked(userCert, crl)) {
                        return false;
                    }
                } else {
                    if (issuingCA.isRevoked(userCert)) return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}