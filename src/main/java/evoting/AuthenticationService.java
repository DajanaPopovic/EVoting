package evoting;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class AuthenticationService {
    private final StorageService storage;

    public AuthenticationService(StorageService storage) {
        this.storage = storage;
    }

    public User login(String certFilePath, String username, String password) {

        KeyStore ks = null;
        X509Certificate userCert = null;
        boolean certLoaded = false;
        String cnFromCert = null;
        try {
            ks = CryptoUtils.loadPKCS12(certFilePath, password);
            userCert = (X509Certificate) ks.getCertificate("user");
            if (userCert != null) {
                certLoaded = true;
                cnFromCert = extractCN(userCert.getSubjectX500Principal().getName());
            }
        } catch (Exception e) {

        }


        User targetUser = null;
        if (certLoaded && cnFromCert != null) {
            targetUser = storage.findUserByUsername(cnFromCert);
        }
        if (targetUser == null && username != null && !username.isEmpty()) {
            targetUser = storage.findUserByUsername(username);
        }


        boolean success = false;
        String failureReason = null;

        if (!certLoaded || userCert == null) {
            failureReason = "Invalid certificate file or password.";
        } else if (targetUser == null) {
            failureReason = "User not found.";
        } else {
            // Validacija sertifikata (izdavalac, rok, CRL)
            String issuerDN = userCert.getIssuerX500Principal().getName();
            CA issuingCA = null;
            if (issuerDN.contains("CN=OrgCA")) issuingCA = storage.getOrgCA();
            else if (issuerDN.contains("CN=VoterCA")) issuingCA = storage.getVoterCA();
            else issuingCA = storage.getRootCA();

            if (issuingCA == null) {
                failureReason = "Unknown issuer CA.";
            } else {
                boolean valid = storage.getCertificateManager().validateCertificate(userCert, issuingCA, true);
                if (!valid) {
                    failureReason = "Certificate validation failed (expired, invalid signature, or revoked).";
                } else if (!cnFromCert.equals(username)) {
                    failureReason = "Certificate common name does not match username.";
                } else if (!targetUser.checkPassword(password)) {
                    failureReason = "Wrong password.";
                } else {

                    success = true;
                }
            }
        }

        if (!success) {

            if (targetUser != null) {
                recordFailedAttempt(targetUser);
            } else {
                System.out.println("Login failed: " + (failureReason != null ? failureReason : "Unknown error"));
            }
            if (failureReason != null) System.out.println(failureReason);
            return null;
        }


        try {
            PrivateKey privateKey = (PrivateKey) ks.getKey("user", password.toCharArray());
            targetUser.setPrivateKey(privateKey);
        } catch (Exception e) {
            System.out.println("Failed to load private key.");
            return null;
        }
        targetUser.setCertificate(userCert);

        return targetUser;
    }

    private void recordFailedAttempt(User user) {
        user.incrementFailedAttempts();
        storage.saveUsers();
        System.out.println("Failed login attempt " + user.getFailedLoginAttempts() + "/3 for user " + user.getUsername());
        if (user.getFailedLoginAttempts() >= 3) {
            X509Certificate cert = user.getCertificate();
            if (cert != null) {
                CA ca = getIssuingCA(cert);
                if (ca != null) {
                    revokeUserCertificate(user, ca);
                }
            } else {
                System.out.println("Cannot revoke – no certificate for user " + user.getUsername());
            }
        }
    }

    private void revokeUserCertificate(User user, CA ca) {
        try {
            X509Certificate cert = user.getCertificate();
            if (cert != null) {
                ca.revokeCertificate(cert);
                storage.saveCA(ca);
                System.out.println("Certificate for user " + user.getUsername() + " has been REVOKED.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private CA getIssuingCA(X509Certificate userCert) {
        String issuerDN = userCert.getIssuerX500Principal().getName();
        if (issuerDN.contains("CN=OrgCA")) return storage.getOrgCA();
        else if (issuerDN.contains("CN=VoterCA")) return storage.getVoterCA();
        else return storage.getRootCA();
    }

    private String extractCN(String dn) {
        String[] parts = dn.split(",");
        for (String part : parts) {
            part = part.trim();
            if (part.startsWith("CN=")) return part.substring(3);
        }
        return null;
    }
}