package evoting;

import java.io.Serializable;
import java.time.LocalDateTime;

public class Vote implements Serializable {
    private static final long serialVersionUID = 1L;
    private int pollId;
    private String voterUsername;
    private LocalDateTime timestamp;
    private byte[] encryptedVoteData;      // AES encrypted choice (int)
    private byte[] encryptedSymmetricKey;  // RSA encrypted with organizer's public key
    private byte[] metadataHMAC;           // HMAC of (pollId, voterUsername, timestamp)
    private byte[] voterSignature;         // digital signature over (encryptedVoteData + encryptedSymmetricKey)

    public Vote(int pollId, String voterUsername, LocalDateTime ts,
                byte[] encVote, byte[] encKey, byte[] hmac, byte[] signature) {
        this.pollId = pollId;
        this.voterUsername = voterUsername;
        this.timestamp = ts;
        this.encryptedVoteData = encVote;
        this.encryptedSymmetricKey = encKey;
        this.metadataHMAC = hmac;
        this.voterSignature = signature;
    }

    public int getPollId() { return pollId; }
    public String getVoterUsername() { return voterUsername; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public byte[] getEncryptedVoteData() { return encryptedVoteData; }
    public byte[] getEncryptedSymmetricKey() { return encryptedSymmetricKey; }
    public byte[] getMetadataHMAC() { return metadataHMAC; }
    public byte[] getVoterSignature() { return voterSignature; }
}