package evoting;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.security.PrivateKey;


public class VotingService {
    private final StorageService storage;

    public VotingService(StorageService storage) {
        this.storage = storage;
    }

    public void createPoll(Organizer org, String title, String desc, String startStr, String endStr, String[] options) {
        try {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");
            LocalDateTime start = LocalDateTime.parse(startStr, formatter);
            LocalDateTime end = LocalDateTime.parse(endStr, formatter);

            LocalDateTime now = LocalDateTime.now();
            if (start.isBefore(now)) {
                System.out.println("Start time cannot be in the past. Please enter a future date and time.");
                return;
            }

            if (start.isAfter(end)) {
                System.out.println("Start must be before end.");
                return;
            }
            List<String> opts = Arrays.asList(options);
            if (opts.size() < 2 || opts.size() > 5) {
                System.out.println("Options must be between 2 and 5.");
                return;
            }
            int newId = storage.getNextPollId();
            Poll poll = new Poll(newId, title, desc, start, end, opts, org.getUsername());
            storage.savePoll(poll);
            System.out.println("Poll created with ID: " + newId);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void listPollsForOrganizer(Organizer org) {
        List<Poll> polls = storage.getPollsByOrganizer(org.getUsername());
        if (polls.isEmpty()) {
            System.out.println("No polls created.");
            return;
        }
        for (Poll p : polls) {
            String status = p.getStatus().toString();
            System.out.printf("ID: %d | Title: %s | Status: %s | Votes: %d%n",
                    p.getId(), p.getTitle(), status, p.getVotes().size());
        }
    }

    public void listActivePolls() {
        List<Poll> active = storage.getActivePolls();
        if (active.isEmpty()) {
            System.out.println("No active polls at the moment.");
            return;
        }
        for (Poll p : active) {
            System.out.printf("ID: %d | Title: %s | Ends at: %s%n",
                    p.getId(), p.getTitle(), p.getEndTime());
        }
    }

    public void castVote(Voter voter, int pollId, Scanner scanner) {
        Poll poll = storage.getPollById(pollId);
        if (poll == null) {
            System.out.println("Poll not found.");
            return;
        }
        if (!poll.isActive()) {
            System.out.println("Poll is not active.");
            return;
        }
        // Check if voter already voted (optional, but good practice)
        boolean alreadyVoted = poll.getVotes().stream().anyMatch(v -> v.getVoterUsername().equals(voter.getUsername()));
        if (alreadyVoted) {
            System.out.println("You have already voted in this poll.");
            return;
        }

        // Show options
        System.out.println("Options:");
        for (int i = 0; i < poll.getOptions().size(); i++) {
            System.out.println((i+1) + ". " + poll.getOptions().get(i));
        }
        System.out.print("Your choice (1-" + poll.getOptions().size() + "): ");
        int choice = Integer.parseInt(scanner.nextLine()) - 1;
        if (choice < 0 || choice >= poll.getOptions().size()) {
            System.out.println("Invalid choice.");
            return;
        }

        try {
            // Generate symmetric key for this vote
            SecretKey symmetricKey = CryptoUtils.generateSymmetricKey();
            // Encrypt the choice (as byte)
            byte[] plainChoice = new byte[]{(byte) choice};
            byte[] encryptedVote = CryptoUtils.encryptSymmetric(plainChoice, symmetricKey);

            // Encrypt symmetric key with organizer's public key
            // Need organizer's public key from their certificate
            Organizer org = (Organizer) storage.findUserByUsername(poll.getOrganizerUsername());
            if (org == null) {
                System.out.println("Organizer not found.");
                return;
            }

            if (org.getCertificate() == null) {
                System.out.println("Organizer certificate not found.");
                return;
            }
            PublicKey orgPublicKey = org.getCertificate().getPublicKey();
            byte[] encryptedKey = CryptoUtils.encryptRSA(symmetricKey.getEncoded(), orgPublicKey);

            // Prepare metadata for HMAC (pollId, voterUsername, timestamp)
            LocalDateTime now = LocalDateTime.now();
            String metaStr = pollId + "|" + voter.getUsername() + "|" + now.toString();
            byte[] metaBytes = metaStr.getBytes("UTF-8");

            byte[] hmac = CryptoUtils.computeHMAC(metaBytes, symmetricKey);

            // Sign the encrypted vote + encrypted key with voter's private key
            byte[] dataToSign = concat(encryptedVote, encryptedKey);
            byte[] signature = CryptoUtils.signData(dataToSign, voter.getPrivateKey());

            Vote vote = new Vote(pollId, voter.getUsername(), now, encryptedVote, encryptedKey, hmac, signature);
            storage.addVoteToPoll(pollId, vote);
            System.out.println("Vote cast successfully. You can later verify it.");

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Voting failed: " + e.getMessage());
        }
    }

    public void verifyVote(Voter voter, int pollId) {
        Poll poll = storage.getPollById(pollId);
        if (poll == null) {
            System.out.println("Poll not found.");
            return;
        }
        Vote vote = poll.getVotes().stream()
                .filter(v -> v.getVoterUsername().equals(voter.getUsername()))
                .findFirst().orElse(null);
        if (vote == null) {
            System.out.println("No vote found from you in this poll.");
            return;
        }
        try {
            if (voter.getCertificate() == null) {
                System.out.println("Certificate not loaded.");
                return;
            }
            byte[] dataToSign = concat(vote.getEncryptedVoteData(), vote.getEncryptedSymmetricKey());
            boolean sigValid = CryptoUtils.verifySignature(dataToSign, vote.getVoterSignature(),
                    voter.getCertificate().getPublicKey());
            if (!sigValid) {
                System.out.println("Signature verification FAILED – vote may have been tampered.");
                return;
            }
            System.out.println("Your vote is recorded correctly (signature valid). Content remains secret.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void tallyVotes(Organizer org, int pollId) {
        Poll poll = storage.getPollById(pollId);
        if (poll == null) {
            System.out.println("Poll not found.");
            return;
        }
        if (!poll.getOrganizerUsername().equals(org.getUsername())) {
            System.out.println("You are not the organizer of this poll.");
            return;
        }
        if (LocalDateTime.now().isBefore(poll.getEndTime())) {
            System.out.println("Voting period has not ended yet.");
            return;
        }
        if (poll.isTallied()) {
            System.out.println("Votes already tallied. Results: " + Arrays.toString(poll.getResults()));
            return;
        }

        try {
            // Decrypt each vote using organizer's private key
            int[] counts = new int[poll.getOptions().size()];
            PrivateKey orgPrivateKey = org.getPrivateKey();
            for (Vote vote : poll.getVotes()) {
                // Decrypt symmetric key
                byte[] symKeyEnc = vote.getEncryptedSymmetricKey();
                byte[] symKeyBytes = CryptoUtils.decryptRSA(symKeyEnc, orgPrivateKey);
                SecretKey symKey = new SecretKeySpec(symKeyBytes, "AES");
                // Decrypt vote choice
                byte[] encryptedChoice = vote.getEncryptedVoteData();
                byte[] plainChoice = CryptoUtils.decryptSymmetric(encryptedChoice, symKey);
                int choice = plainChoice[0] & 0xFF;
                if (choice >= 0 && choice < counts.length) {
                    counts[choice]++;
                } else {
                    System.out.println("Invalid choice in vote from " + vote.getVoterUsername());
                }
                // Optionally verify HMAC using symKey (metadata integrity)
                String metaStr = vote.getPollId() + "|" + vote.getVoterUsername() + "|" + vote.getTimestamp().toString();
                byte[] computedHMAC = CryptoUtils.computeHMAC(metaStr.getBytes("UTF-8"), symKey);
                if (!Arrays.equals(computedHMAC, vote.getMetadataHMAC())) {
                    System.out.println("Warning: HMAC mismatch for vote from " + vote.getVoterUsername());
                }
            }
            poll.setResults(counts);
            poll.setTallied(true);
            poll.setStatus(Poll.PollStatus.TALLIED);
            storage.savePoll(poll);

            // Generate digitally signed report
            String report = generateReport(poll, counts);
            byte[] reportSignature = CryptoUtils.signData(report.getBytes("UTF-8"), orgPrivateKey);
            storage.saveReport(pollId, report, reportSignature);
            System.out.println("Tally complete. Results:");
            for (int i = 0; i < counts.length; i++) {
                System.out.println(poll.getOptions().get(i) + ": " + counts[i]);
            }
            System.out.println("Signed report saved.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String generateReport(Poll poll, int[] counts) {
        StringBuilder sb = new StringBuilder();
        sb.append("Poll ID: ").append(poll.getId()).append("\n");
        sb.append("Title: ").append(poll.getTitle()).append("\n");
        sb.append("End time: ").append(poll.getEndTime()).append("\n");
        sb.append("Results:\n");
        for (int i = 0; i < counts.length; i++) {
            sb.append(poll.getOptions().get(i)).append(": ").append(counts[i]).append("\n");
        }
        sb.append("Generated at: ").append(LocalDateTime.now());
        return sb.toString();
    }

    private byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}