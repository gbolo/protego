package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/brianvoe/gofakeit/v7"
)

var (
	baseURL     string
	adminSecret string
	numUsers    int
)

type User struct {
	ID              string   `json:"id"`
	Secret          string   `json:"secret"`
	Description     string   `json:"description"`
	Enabled         bool     `json:"enabled"`
	ACLAllowAll     bool     `json:"acl_allow_all"`
	ACLAllowedHosts []string `json:"acl_allowed_hosts,omitempty"`
	DNSNames        []string `json:"dns_names,omitempty"`
	TTLMinutes      int      `json:"ttl_minutes"`
}

type ChallengeResponse struct {
	Message   string `json:"message"`
	UserID    string `json:"user_id"`
	IPAddress string `json:"ip_address"`
}

func init() {
	flag.StringVar(&baseURL, "url", getEnv("PROTEGO_URL", "http://localhost:8081"), "Protego server base URL")
	flag.StringVar(&adminSecret, "admin-secret", getEnv("PROTEGO_ADMIN_SECRET", "supersecret"), "Admin secret for API authentication")
	flag.IntVar(&numUsers, "users", 20, "Number of users to create")
	flag.Parse()

	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())
	gofakeit.Seed(time.Now().UnixNano())
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	log.Printf("Starting fake data generation...")
	log.Printf("Protego URL: %s", baseURL)
	log.Printf("Number of users to create: %d", numUsers)

	// Create users
	users := make([]User, 0, numUsers)
	log.Println("\n=== Creating Users ===")
	for i := 0; i < numUsers; i++ {
		user := generateUser()
		if err := createUser(user); err != nil {
			log.Printf("❌ Failed to create user %s: %v", user.ID, err)
			continue
		}
		users = append(users, user)
		log.Printf("✅ Created user: %s (%s)", user.ID, user.Description)
	}

	if len(users) == 0 {
		log.Fatal("No users were created successfully")
	}

	// Perform challenges for 80% of users
	numChallenges := int(float64(len(users)) * 0.8)
	log.Printf("\n=== Performing Challenges for %d users (80%%) ===", numChallenges)

	// Shuffle users to randomly select which ones to challenge
	shuffledUsers := make([]User, len(users))
	copy(shuffledUsers, users)
	rand.Shuffle(len(shuffledUsers), func(i, j int) {
		shuffledUsers[i], shuffledUsers[j] = shuffledUsers[j], shuffledUsers[i]
	})

	successfulChallenges := 0
	totalChallengeAttempts := 0

	for i := 0; i < numChallenges; i++ {
		user := shuffledUsers[i]
		// Random number of challenges between 1 and 3
		numUserChallenges := rand.Intn(3) + 1

		for j := 0; j < numUserChallenges; j++ {
			totalChallengeAttempts++
			ip := gofakeit.IPv4Address()
			if err := performChallenge(user.ID, user.Secret, ip); err != nil {
				log.Printf("❌ Challenge failed for user %s from IP %s: %v", user.ID, ip, err)
			} else {
				successfulChallenges++
				log.Printf("✅ Challenge successful for user %s from IP %s", user.ID, ip)
			}
			// Small delay between challenges
			time.Sleep(100 * time.Millisecond)
		}
	}

	log.Printf("\n=== Summary ===")
	log.Printf("Total users created: %d", len(users))
	log.Printf("Users with challenges: %d", numChallenges)
	log.Printf("Total challenge attempts: %d", totalChallengeAttempts)
	log.Printf("Successful challenges (IPs whitelisted): %d", successfulChallenges)
	log.Println("✅ Fake data generation complete!")
}

func generateUser() User {
	// Generate TTL between 6 hours and 7 days
	ttlOptions := []int{
		360,   // 6 hours
		1440,  // 1 day
		2880,  // 2 days
		10080, // 7 days
	}

	// Generate random allowed hosts (80% chance of having some)
	var allowedHosts []string
	if rand.Float64() < 0.8 {
		numHosts := rand.Intn(8) + 1
		for i := 0; i < numHosts; i++ {
			allowedHosts = append(allowedHosts, gofakeit.DomainName())
		}
	}

	return User{
		ID:              gofakeit.Email(),
		Secret:          gofakeit.Password(true, true, true, true, false, 16),
		Description:     fmt.Sprintf("%s - %s", gofakeit.Name(), gofakeit.JobTitle()),
		Enabled:         rand.Float64() > 0.10, // 10% chance of being disabled
		ACLAllowAll:     rand.Float64() < 0.20, // 20% chance of allow all
		ACLAllowedHosts: allowedHosts,
		TTLMinutes:      ttlOptions[rand.Intn(len(ttlOptions))],
	}
}

func createUser(user User) error {
	url := fmt.Sprintf("%s/api/v1/user", baseURL)

	jsonData, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Admin-Secret", adminSecret)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

func performChallenge(userID, secret, ip string) error {
	url := fmt.Sprintf("%s/api/v1/challenge", baseURL)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-ID", userID)
	req.Header.Set("User-Secret", secret)
	req.Header.Set("X-Real-IP", ip)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var challengeResp ChallengeResponse
	if err := json.Unmarshal(body, &challengeResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	return nil
}
