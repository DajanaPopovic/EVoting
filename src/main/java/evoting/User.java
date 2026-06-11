package evoting;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public abstract class User implements Serializable {
    private static final long serialVersionUID = 2L;
    protected String username;
    protected String passwordHash; // SHA-256 hash
    protected byte[] salt;
    protected String certificatePath;
    protected int failedLoginAttempts;
    private transient PrivateKey privateKey;// not stored – loaded at login
    protected X509Certificate certificate; // serializable – stored on disk



    public User(String username, String plainPassword) {
        this.username = username;
        this.salt = generateSalt();
        this.passwordHash = hashPasswordWithSalt(plainPassword, this.salt);
        this.failedLoginAttempts = 0;
    }

    private static byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private static String hashPasswordWithSalt(String password, byte[] salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] hash = md.digest(password.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public boolean checkPassword(String plainPassword) {
        String hash = hashPasswordWithSalt(plainPassword, this.salt);
        return passwordHash.equals(hash);
    }

    public String getUsername() { return username; }
    public String getCertificatePath() { return certificatePath; }
    public void setCertificatePath(String path) { this.certificatePath = path; }
    public int getFailedLoginAttempts() { return failedLoginAttempts; }
    public void incrementFailedAttempts() { failedLoginAttempts++; }
    public PrivateKey getPrivateKey() { return privateKey; }
    public void setPrivateKey(PrivateKey privateKey) { this.privateKey = privateKey; }
    public X509Certificate getCertificate() { return certificate; }
    public void setCertificate(X509Certificate certificate) { this.certificate = certificate; }
    public abstract String getRole();
}

class Organizer extends User {
    private String organizationName;
    private String identificationNumber;

    public Organizer(String username, String password, String orgName, String idNumber) {
        super(username, password);
        this.organizationName = orgName;
        this.identificationNumber = idNumber;
    }

    @Override
    public String getRole() { return "organizer"; }
    public String getOrganizationName() { return organizationName; }
    public String getIdentificationNumber() { return identificationNumber; }
}

class Voter extends User {
    private String firstName;
    private String lastName;

    public Voter(String username, String password, String firstName, String lastName) {
        super(username, password);
        this.firstName = firstName;
        this.lastName = lastName;
    }

    @Override
    public String getRole() { return "voter"; }
    public String getFirstName() { return firstName; }
    public String getLastName() { return lastName; }
}