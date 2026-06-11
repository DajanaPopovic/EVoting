package evoting;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class Poll implements Serializable {
    private static final long serialVersionUID = 1L;
    private int id;
    private String title;
    private String description;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private List<String> options;
    private String organizerUsername;
    private PollStatus status;
    private List<Vote> votes;
    private int[] results; // after tallying
    private boolean tallied;

    public enum PollStatus { CREATED, ACTIVE, CLOSED, TALLIED }

    public Poll(int id, String title, String desc, LocalDateTime start, LocalDateTime end,
                List<String> options, String organizerUsername) {
        this.id = id;
        this.title = title;
        this.description = desc;
        this.startTime = start;
        this.endTime = end;
        this.options = new ArrayList<>(options);
        this.organizerUsername = organizerUsername;
        this.status = PollStatus.CREATED;
        this.votes = new ArrayList<>();
        this.tallied = false;
    }

    // Getters and setters
    public int getId() { return id; }
    public String getTitle() { return title; }
    public String getDescription() { return description; }
    public LocalDateTime getStartTime() { return startTime; }
    public LocalDateTime getEndTime() { return endTime; }
    public List<String> getOptions() { return options; }
    public String getOrganizerUsername() { return organizerUsername; }
    public PollStatus getStatus() { return status; }
    public void setStatus(PollStatus status) { this.status = status; }
    public List<Vote> getVotes() { return votes; }
    public void addVote(Vote vote) { votes.add(vote); }
    public int[] getResults() { return results; }
    public void setResults(int[] results) { this.results = results; }
    public boolean isTallied() { return tallied; }
    public void setTallied(boolean tallied) { this.tallied = tallied; }

    public boolean isActive() {
        LocalDateTime now = LocalDateTime.now();
        return now.isAfter(startTime) && now.isBefore(endTime);
    }
}