package evoting;

import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.LocalDateTime;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {

        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        StorageService storage = new StorageService();
        AuthenticationService auth = new AuthenticationService(storage);
        VotingService voting = new VotingService(storage);

        try (Scanner scanner = new Scanner(System.in)) {
            while (true) {
                System.out.println("\n=== E-VOTING SYSTEM ===");
                System.out.println("1. Register");
                System.out.println("2. Login");
                System.out.println("3. Exit");
                System.out.print("Choice: ");
                String choice = scanner.nextLine();

                switch (choice) {
                    case "1":
                        register(scanner, storage);
                        break;
                    case "2":
                        login(scanner, auth, voting);
                        break;
                    case "3":
                        System.out.println("Goodbye.");
                        return;
                    default:
                        System.out.println("Invalid choice.");
                }
            }
        }
    }

    private static void register(Scanner scanner, StorageService storage) {
        System.out.print("Account type (organizer/voter): ");
        String type = scanner.nextLine();
        if (type.equalsIgnoreCase("organizer")) {
            System.out.print("Username: ");
            String username = scanner.nextLine();
            System.out.print("Organization name: ");
            String orgName = scanner.nextLine();
            System.out.print("Identification number: ");
            String idNumber = scanner.nextLine();
            System.out.print("Password: ");
            String password = scanner.nextLine();
            storage.registerOrganizer(username, orgName, idNumber, password);
        } else if (type.equalsIgnoreCase("voter")) {
            System.out.print("First name: ");
            String firstName = scanner.nextLine();
            System.out.print("Last name: ");
            String lastName = scanner.nextLine();
            System.out.print("Username: ");
            String username = scanner.nextLine();
            System.out.print("Password: ");
            String password = scanner.nextLine();
            storage.registerVoter(firstName, lastName, username, password);
        } else {
            System.out.println("Invalid type.");
        }
    }

    private static void login(Scanner scanner, AuthenticationService auth, VotingService voting) {
        System.out.print("Path to your certificate file (.p12): ");
        String certPath = scanner.nextLine();
        System.out.print("Username: ");
        String username = scanner.nextLine();
        System.out.print("Password: ");
        String password = scanner.nextLine();

        User user = auth.login(certPath, username, password);
        if (user == null) {
            System.out.println("Login failed.");
            return;
        }

        System.out.println("Login successful. Welcome, " + user.getUsername());
        if (user instanceof Organizer) {
            organizerMenu(scanner, voting, (Organizer) user);
        } else if (user instanceof Voter) {
            voterMenu(scanner, voting, (Voter) user);
        }
    }

    private static void organizerMenu(Scanner scanner, VotingService voting, Organizer org) {
        while (true) {
            System.out.println("\n--- ORGANIZER MENU ---");
            System.out.println("1. Create new poll");
            System.out.println("2. List my polls");
            System.out.println("3. Tally votes (after end date)");
            System.out.println("4. Logout");
            System.out.print("Choice: ");
            String choice = scanner.nextLine();

            switch (choice) {
                case "1":
                    System.out.print("Title: ");
                    String title = scanner.nextLine();
                    System.out.print("Description: ");
                    String desc = scanner.nextLine();

                    String startStr = null;
                    String endStr = null;
                    boolean validDates = false;
                    while (!validDates) {
                        System.out.print("Start (yyyy-MM-dd HH:mm): ");
                        startStr = scanner.nextLine().trim();
                        System.out.print("End (yyyy-MM-dd HH:mm): ");
                        endStr = scanner.nextLine().trim();
                        try {
                            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");
                            LocalDateTime.parse(startStr, formatter);
                            LocalDateTime.parse(endStr, formatter);
                            validDates = true;
                        } catch (DateTimeParseException e) {
                            System.out.println("Invalid date format. Please use yyyy-MM-dd HH:mm (e.g., 2026-04-18 21:23).");
                        }
                    }

                    int num = 0;
                    boolean validNum = false;
                    while (!validNum) {
                        System.out.print("Number of options (2-5): ");
                        String numStr = scanner.nextLine();
                        try {
                            num = Integer.parseInt(numStr);
                            if (num >= 2 && num <= 5) {
                                validNum = true;
                            } else {
                                System.out.println("Please enter a number between 2 and 5.");
                            }
                        } catch (NumberFormatException e) {
                            System.out.println("Invalid input. Please enter a number (2-5).");
                        }
                    }

                    String[] options = new String[num];
                    for (int i = 0; i < num; i++) {
                        System.out.print("Option " + (i+1) + ": ");
                        options[i] = scanner.nextLine();
                    }
                    voting.createPoll(org, title, desc, startStr, endStr, options);
                    break;
                case "2":
                    voting.listPollsForOrganizer(org);
                    break;
                case "3":
                    int pollId = 0;
                    boolean validId = false;
                    while (!validId) {
                        System.out.print("Enter poll ID to tally: ");
                        String idStr = scanner.nextLine();
                        try {
                            pollId = Integer.parseInt(idStr);
                            validId = true;
                        } catch (NumberFormatException e) {
                            System.out.println("Invalid poll ID. Please enter a number.");
                        }
                    }
                    voting.tallyVotes(org, pollId);
                    break;
                case "4":
                    return;
                default:
                    System.out.println("Invalid choice.");
            }
        }
    }

    private static void voterMenu(Scanner scanner, VotingService voting, Voter voter) {
        while (true) {
            System.out.println("\n--- VOTER MENU ---");
            System.out.println("1. List active polls");
            System.out.println("2. Vote");
            System.out.println("3. Verify my last vote");
            System.out.println("4. Logout");
            System.out.print("Choice: ");
            String choice = scanner.nextLine();

            switch (choice) {
                case "1":
                    voting.listActivePolls();
                    break;
                case "2":
                    int pollId = 0;
                    boolean validPollId = false;
                    while (!validPollId) {
                        System.out.print("Enter poll ID to vote: ");
                        String idStr = scanner.nextLine();
                        try {
                            pollId = Integer.parseInt(idStr);
                            validPollId = true;
                        } catch (NumberFormatException e) {
                            System.out.println("Invalid poll ID. Please enter a number.");
                        }
                    }
                    voting.castVote(voter, pollId, scanner);
                    break;
                case "3":
                    int pollIdVer = 0;
                    boolean validVerId = false;
                    while (!validVerId) {
                        System.out.print("Enter poll ID: ");
                        String idStr = scanner.nextLine();
                        try {
                            pollIdVer = Integer.parseInt(idStr);
                            validVerId = true;
                        } catch (NumberFormatException e) {
                            System.out.println("Invalid poll ID. Please enter a number.");
                        }
                    }
                    voting.verifyVote(voter, pollIdVer);
                    break;
                case "4":
                    return;
                default:
                    System.out.println("Invalid choice.");
            }
        }
    }
}