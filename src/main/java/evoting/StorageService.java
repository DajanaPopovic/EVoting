package evoting;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;
import java.math.BigInteger;
import java.io.Console;
import java.util.Scanner;

public class StorageService {
    private static final String DATA_DIR = "./evoting_data/";
    private static final String USERS_FILE = DATA_DIR + "users.ser";
    private static final String POLLS_FILE = DATA_DIR + "polls.ser";
    private static final String CA_DIR = DATA_DIR + "ca/";
    private static final String USER_CERTS_DIR = DATA_DIR + "user_certs/";
    private static final String REPORTS_DIR = DATA_DIR + "reports/";
    private static final String CA_KEYSTORE_FILE = CA_DIR + "ca_keystore.p12";

    private Map<String, User> users;
    private Map<Integer, Poll> polls;
    private int nextPollId;

    private RootCA rootCA;
    private OrganizationalCA orgCA;
    private VoterCA voterCA;
    private CertificateManager certManager;

    public StorageService() {
        createDirs();
        loadData();
        initCAIfNeeded();
    }

    private void createDirs() {
        new File(DATA_DIR).mkdirs();
        new File(CA_DIR).mkdirs();
        new File(USER_CERTS_DIR).mkdirs();
        new File(REPORTS_DIR).mkdirs();
    }

    @SuppressWarnings("unchecked")
    private void loadData() {
        File uf = new File(USERS_FILE);
        if (uf.exists()) {
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(uf))) {
                users = (Map<String, User>) ois.readObject();
            } catch (Exception e) { e.printStackTrace(); }
        }
        if (users == null) users = new HashMap<>();

        File pf = new File(POLLS_FILE);
        if (pf.exists()) {
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(pf))) {
                polls = (Map<Integer, Poll>) ois.readObject();
                nextPollId = polls.keySet().stream().max(Integer::compareTo).orElse(0) + 1;
            } catch (Exception e) { e.printStackTrace(); }
        }
        if (polls == null) {
            polls = new HashMap<>();
            nextPollId = 1;
        }
    }

    private void initCAIfNeeded() {
        try {
            File caKeystoreFile = new File(CA_KEYSTORE_FILE);
            String password = getCAKeystorePassword(); // interactive password entry

            if (!caKeystoreFile.exists()) {
                // First run: generate all CA keys and certificates
                KeyPair rootPair = CryptoUtils.generateRSAKeyPair();
                X509Certificate rootCert = CryptoUtils.createCACertificate(rootPair, "RootCA", 3650);
                savePrivateKey(rootPair.getPrivate(), rootCert, "root", password, CA_KEYSTORE_FILE);
                rootCA = new RootCA(rootCert, rootPair.getPrivate());

                KeyPair orgPair = CryptoUtils.generateRSAKeyPair();
                X509Certificate orgCert = CryptoUtils.createSubCACertificate(orgPair, rootCert, rootPair.getPrivate(), "OrgCA", 365);
                savePrivateKey(orgPair.getPrivate(), orgCert, "org", password, CA_KEYSTORE_FILE);
                orgCA = new OrganizationalCA(orgCert, orgPair.getPrivate());

                KeyPair voterPair = CryptoUtils.generateRSAKeyPair();
                X509Certificate voterCert = CryptoUtils.createSubCACertificate(voterPair, rootCert, rootPair.getPrivate(), "VoterCA", 365);
                savePrivateKey(voterPair.getPrivate(), voterCert, "voter", password, CA_KEYSTORE_FILE);
                voterCA = new VoterCA(voterCert, voterPair.getPrivate());

                // Generate initial CRL files (empty)
                CRLManager.generateCRLAndSave(orgCA, 7, CA_DIR + "org.crl");
                CRLManager.generateCRLAndSave(voterCA, 7, CA_DIR + "voter.crl");
            } else {
                // Load existing CA from keystore using the provided password
                X509Certificate rootCert = loadCertificateFromKeystore(CA_KEYSTORE_FILE, "root", password);
                PrivateKey rootKey = loadPrivateKey(CA_KEYSTORE_FILE, "root", password);
                rootCA = new RootCA(rootCert, rootKey);

                X509Certificate orgCert = loadCertificateFromKeystore(CA_KEYSTORE_FILE, "org", password);
                PrivateKey orgKey = loadPrivateKey(CA_KEYSTORE_FILE, "org", password);
                orgCA = new OrganizationalCA(orgCert, orgKey);

                X509Certificate voterCert = loadCertificateFromKeystore(CA_KEYSTORE_FILE, "voter", password);
                PrivateKey voterKey = loadPrivateKey(CA_KEYSTORE_FILE, "voter", password);
                voterCA = new VoterCA(voterCert, voterKey);

                loadCRLs(); // load revocation lists from CRL files
            }
            certManager = new CertificateManager(rootCA, orgCA, voterCA, CA_DIR);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize CA", e);
        }
    }

    private void loadCRLs() throws Exception {
        File orgCrlFile = new File(CA_DIR + "org.crl");
        if (orgCrlFile.exists()) {
            X509CRL orgCrl = CRLManager.loadCRL(CA_DIR + "org.crl");
            if (!CRLManager.verifyCRLSignature(orgCrl, orgCA.getCertificate())) {
                throw new SecurityException("OrgCA CRL signature verification failed");
            }
            orgCA.getRevokedSerialNumbers().clear();
            List<BigInteger> serials = CRLManager.getRevokedSerialNumbers(orgCrl);
            orgCA.getRevokedSerialNumbers().addAll(serials);
        }
        File voterCrlFile = new File(CA_DIR + "voter.crl");
        if (voterCrlFile.exists()) {
            X509CRL voterCrl = CRLManager.loadCRL(CA_DIR + "voter.crl");
            voterCA.getRevokedSerialNumbers().clear();
            List<BigInteger> serials = CRLManager.getRevokedSerialNumbers(voterCrl);
            voterCA.getRevokedSerialNumbers().addAll(serials);
        }
    }

    private void savePrivateKey(PrivateKey key, X509Certificate cert, String alias, String password, String path) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", CryptoUtils.PROVIDER);
        File file = new File(path);
        if (file.exists()) {

            try (FileInputStream fis = new FileInputStream(file)) {
                ks.load(fis, password.toCharArray());
            }
        } else {
            ks.load(null, null);
        }

        ks.setKeyEntry(alias, key, password.toCharArray(), new X509Certificate[]{cert});

        try (FileOutputStream fos = new FileOutputStream(path)) {
            ks.store(fos, password.toCharArray());
        }
    }

    private X509Certificate loadCertificateFromKeystore(String keystorePath, String alias, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", CryptoUtils.PROVIDER);
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, password.toCharArray());
        }
        return (X509Certificate) ks.getCertificate(alias);
    }

    private PrivateKey loadPrivateKey(String keystorePath, String alias, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", CryptoUtils.PROVIDER);
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, password.toCharArray());
        }
        return (PrivateKey) ks.getKey(alias, password.toCharArray());
    }


    private String getCAKeystorePassword() {
        String envPwd = System.getenv("CA_KEYSTORE_PWD");
        if (envPwd != null && !envPwd.isEmpty()) {
            return envPwd;
        }
        Console console = System.console();
        if (console != null) {
            char[] pwd = console.readPassword("Enter CA keystore password: ");
            return new String(pwd);
        } else {
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter CA keystore password: ");
            return scanner.nextLine();
        }
    }


    public void registerOrganizer(String username, String orgName, String idNumber, String password) {
        if (users.containsKey(username)) {
            System.out.println("Username already exists.");
            return;
        }
        Organizer org = new Organizer(username, password, orgName, idNumber);
        generateAndStoreUserCertificate(org, password, true);
        users.put(username, org);
        saveUsers();
        System.out.println("Organizer registered. Certificate saved to: " + org.getCertificatePath());
    }

    public void registerVoter(String firstName, String lastName, String username, String password) {
        if (users.containsKey(username)) {
            System.out.println("Username already exists.");
            return;
        }
        Voter voter = new Voter(username, password, firstName, lastName);
        generateAndStoreUserCertificate(voter, password, false);
        users.put(username, voter);
        saveUsers();
        System.out.println("Voter registered. Certificate saved to: " + voter.getCertificatePath());
    }

    private void generateAndStoreUserCertificate(User user, String plainPassword, boolean isOrganizer) {
        try {
            KeyPair userPair = CryptoUtils.generateRSAKeyPair();
            String cn = user.getUsername();
            X509Certificate cert;
            if (isOrganizer) {
                cert = certManager.issueOrganizerCertificate(cn, userPair);
            } else {
                cert = certManager.issueVoterCertificate(cn, userPair);
            }
            user.setCertificate(cert);
            String certPath = USER_CERTS_DIR + user.getUsername() + ".p12";
            CryptoUtils.saveToPKCS12(userPair.getPrivate(), cert, plainPassword, certPath);
            user.setCertificatePath(certPath);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate certificate", e);
        }
    }


    public void saveUsers() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(USERS_FILE))) {
            oos.writeObject(users);
        } catch (Exception e) { e.printStackTrace(); }
    }

    public void savePoll(Poll poll) {
        polls.put(poll.getId(), poll);
        savePolls();
    }

    private void savePolls() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(POLLS_FILE))) {
            oos.writeObject(polls);
        } catch (Exception e) { e.printStackTrace(); }
    }

    public void addVoteToPoll(int pollId, Vote vote) {
        Poll poll = polls.get(pollId);
        if (poll != null) {
            poll.addVote(vote);
            savePoll(poll);
        }
    }

    public void saveReport(int pollId, String report, byte[] signature) {
        try {
            File dir = new File(REPORTS_DIR);
            dir.mkdirs();
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(REPORTS_DIR + pollId + ".rep"))) {
                oos.writeObject(report);
                oos.writeObject(signature);
            }
        } catch (Exception e) { e.printStackTrace(); }
    }


    public User findUserByUsername(String username) {
        return users.get(username);
    }

    public Poll getPollById(int id) {
        return polls.get(id);
    }

    public List<Poll> getPollsByOrganizer(String orgUsername) {
        return polls.values().stream()
                .filter(p -> p.getOrganizerUsername().equals(orgUsername))
                .collect(Collectors.toList());
    }

    public List<Poll> getActivePolls() {
        LocalDateTime now = LocalDateTime.now();
        return polls.values().stream()
                .filter(p -> p.isActive() && p.getStatus() != Poll.PollStatus.TALLIED)
                .collect(Collectors.toList());
    }

    public int getNextPollId() {
        return nextPollId++;
    }

    public RootCA getRootCA() { return rootCA; }
    public OrganizationalCA getOrgCA() { return orgCA; }
    public VoterCA getVoterCA() { return voterCA; }
    public CertificateManager getCertificateManager() { return certManager; }

    //  CRL update after revocation
    public void saveCA(CA ca) {
        try {
            if (ca instanceof OrganizationalCA) {
                CRLManager.generateCRLAndSave(ca, 7, CA_DIR + "org.crl");
            } else if (ca instanceof VoterCA) {
                CRLManager.generateCRLAndSave(ca, 7, CA_DIR + "voter.crl");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}