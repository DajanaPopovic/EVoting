package evoting;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;
import java.math.BigInteger;

public class CA {
    private final String name;
    private final X509Certificate certificate;
    private final PrivateKey privateKey;
    private final List<BigInteger> revokedSerialNumbers;

    public CA(String name, X509Certificate cert, PrivateKey privKey) {
        this.name = name;
        this.certificate = cert;
        this.privateKey = privKey;
        this.revokedSerialNumbers = new ArrayList<>();
    }

    public String getName() { return name; }
    public X509Certificate getCertificate() { return certificate; }
    public PrivateKey getPrivateKey() { return privateKey; }
    public List<BigInteger> getRevokedSerialNumbers() { return revokedSerialNumbers; }

    public void revokeCertificate(X509Certificate cert) {
        BigInteger serial = cert.getSerialNumber();
        if (!revokedSerialNumbers.contains(serial)) {
            revokedSerialNumbers.add(serial);
        }
    }

    public boolean isRevoked(X509Certificate cert) {
        return revokedSerialNumbers.contains(cert.getSerialNumber());
    }


}

// Specific CA types
class RootCA extends CA {
    public RootCA(X509Certificate cert, PrivateKey privKey) {
        super("RootCA", cert, privKey);
    }
}

class OrganizationalCA extends CA {
    public OrganizationalCA(X509Certificate cert, PrivateKey privKey) {
        super("OrgCA", cert, privKey);
    }
}

class VoterCA extends CA {
    public VoterCA(X509Certificate cert, PrivateKey privKey) {
        super("VoterCA", cert, privKey);
    }
}