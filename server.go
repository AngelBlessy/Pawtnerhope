package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// 5. FUNCTIONS AND ERROR HANDLING
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrTokenExpired       = errors.New("token has expired")
	ErrPetNotFound        = errors.New("pet not found")
	ErrInvalidPayment     = errors.New("invalid payment details")
	ErrEmailFailed        = errors.New("email delivery failed")
	ErrTokenGeneration    = errors.New("failed to generate token")
	ErrAccountLocked      = errors.New("After 2 unsuccessful attempts, your account is blocked for 3 minutes. Try again after that.")
)

const (
	authTokenTTL           = 7 * 24 * time.Hour
	loginFailureLimit      = 2
	loginLockoutDuration   = 3 * time.Minute
	ipRateLimitWindow      = time.Hour
	loginRateLimitPerIP    = 5
	registerRateLimitPerIP = 5
)

// 6. INTERFACE
type Filterable interface {
	Filter(pets []Pet) []Pet
	Name() string
}

// 4. MAP AND STRUCTS
type Pet struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Species      string            `json:"species"`
	Breed        string            `json:"breed"`
	ImageURL     string            `json:"imageUrl" bson:"imageUrl,omitempty"`
	Age          int               `json:"age"`
	Gender       string            `json:"gender"`
	Description  string            `json:"description"`
	Status       string            `json:"status"` // Available, Adopted, Under Care
	IsVaccinated bool              `json:"isVaccinated"`
	CreatedAt    time.Time         `json:"createdAt"`
	Tags         []string          `json:"tags"`       // 3. ARRAY AND SLICE
	Attributes   map[string]string `json:"attributes"` // 4. MAP AND STRUCTS
}

type Service struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Price       float64  `json:"price"`
	Duration    int      `json:"duration"` // in minutes
	Available   bool     `json:"available"`
	Features    []string `json:"features"`
}

type ContactForm struct {
	Name    string    `json:"name"`
	Email   string    `json:"email"`
	Purpose string    `json:"purpose"`
	Message string    `json:"message"`
	SentAt  time.Time `json:"sentAt"`
}

type ServiceBooking struct {
	ID          string    `json:"id"`
	ServiceID   string    `json:"serviceId"`
	PetName     string    `json:"petName"`
	OwnerName   string    `json:"ownerName"`
	Email       string    `json:"email"`
	Phone       string    `json:"phone"`
	Date        string    `json:"date"`
	Time        string    `json:"time"`
	Notes       string    `json:"notes"`
	Status      string    `json:"status"`
	BookedAt    time.Time `json:"bookedAt"`
	ReviewNotes string    `json:"reviewNotes,omitempty"`
	ReviewedAt  time.Time `json:"reviewedAt,omitempty"`
	ReviewedBy  string    `json:"reviewedBy,omitempty"`
}

type ServiceReview struct {
	ID           string    `json:"id"`
	BookingID    string    `json:"bookingId"`
	ServiceID    string    `json:"serviceId"`
	ReviewerName string    `json:"reviewerName"`
	Email        string    `json:"email"`
	Rating       int       `json:"rating"`
	Comment      string    `json:"comment"`
	CreatedAt    time.Time `json:"createdAt"`
}

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	Password  string    `json:"-"` // excluded from JSON output
	Role      string    `json:"role"`
	IsAdmin   bool      `json:"isadmin" bson:"isadmin"`
	CreatedAt time.Time `json:"createdAt"`
	IsActive  bool      `json:"isActive"`
}

type AuthToken struct {
	Token     string    `json:"token"`
	UserID    string    `json:"userId"`
	ExpiresAt time.Time `json:"expiresAt"`
	Role      string    `json:"role"`
	IsAdmin   bool      `json:"isadmin"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
}

type Donation struct {
	ID                 string    `json:"id"`
	DonorName          string    `json:"donorName"`
	DonorEmail         string    `json:"donorEmail"`
	Amount             float64   `json:"amount"`
	PaymentMethod      string    `json:"paymentMethod"`
	TransactionID      string    `json:"transactionId"`
	Status             string    `json:"status"` // Pending, Completed, Failed
	CreatedAt          time.Time `json:"createdAt"`
	PaymentViaDeeplink bool      `json:"paymentViaDeeplink"` // true when paid via mobile UPI deeplink
}

type Receipt struct {
	ReceiptID  string    `json:"receiptId"`
	DonationID string    `json:"donationId"`
	DonorName  string    `json:"donorName"`
	Amount     float64   `json:"amount"`
	IssuedAt   time.Time `json:"issuedAt"`
	Message    string    `json:"message"`
}

type AdoptionInquiry struct {
	ID          string    `json:"id"`
	PetID       string    `json:"petId"`
	AdopterName string    `json:"adopterName"`
	Email       string    `json:"email"`
	Phone       string    `json:"phone"`
	Message     string    `json:"message"`
	Status      string    `json:"status"` // Pending, Approved, Rejected
	CreatedAt   time.Time `json:"createdAt"`
}

// 11. GOROUTINES AND CHANNELS
type NotificationJob struct {
	To      string
	Subject string
	Body    string
	JobType string
}

type PaymentConfirmation struct {
	DonationID    string
	Success       bool
	TransactionID string
	Error         string
}

type PendingRegistration struct {
	Email          string
	Username       string
	HashedPassword string
	Code           string
	ExpiresAt      time.Time
}

type LoginAttemptState struct {
	FailedAttempts int
	LockedUntil    time.Time
}

type RateLimitState struct {
	Count       int
	WindowStart time.Time
}

// SMTP config (loaded from .env)
var (
	smtpUser string
	smtpPass string
	smtpHost string = "smtp.gmail.com"
	smtpPort string = "587"
)

// loadEnv reads KEY=VALUE lines from a .env file and calls os.Setenv.
func loadEnv(filename string) {
	f, err := os.Open(filename)
	if err != nil {
		return // .env is optional
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if os.Getenv(key) == "" { // don't override real env vars
				os.Setenv(key, val)
			}
		}
	}
}

// 1. VARIABLES, VALUES AND TYPES
var (
	serverStartTime time.Time = time.Now()
	serverVersion   string    = "1.0.0"
	maxPets         int       = 100

	// 3. ARRAY AND SLICE
	pets            []Pet
	services        []Service
	contactMessages []ContactForm
	bookings        []ServiceBooking
	serviceReviews  []ServiceReview
	users           []User
	donations       []Donation
	inquiries       []AdoptionInquiry

	// 4. MAP AND STRUCTS
	petsByID     map[string]*Pet
	servicesByID map[string]*Service
	bookingsByID map[string]*ServiceBooking
	reviewsByID  map[string]*ServiceReview
	usersByEmail map[string]*User
	tokenStore   map[string]*AuthToken
	statusCounts map[string]int
	serviceStats map[string]map[string]interface{}
	petsByBreed  map[string][]string

	// 10. CONCURRENCY
	notificationCh   chan NotificationJob
	paymentCh        chan Donation
	paymentConfirmCh chan PaymentConfirmation
	mu               sync.Mutex

	emailShouldFail bool = false

	// MongoDB
	mongoClient *mongo.Client
	mongoDB     *mongo.Database

	// Pending email verifications
	pendingRegs           map[string]*PendingRegistration
	loginAttemptsByEmail  map[string]*LoginAttemptState
	loginRateLimitByIP    map[string]*RateLimitState
	registerRateLimitByIP map[string]*RateLimitState
)

func initializeData() {
	petsByID = make(map[string]*Pet)
	servicesByID = make(map[string]*Service)
	bookingsByID = make(map[string]*ServiceBooking)
	reviewsByID = make(map[string]*ServiceReview)
	usersByEmail = make(map[string]*User)
	tokenStore = make(map[string]*AuthToken)
	statusCounts = make(map[string]int)
	serviceStats = make(map[string]map[string]interface{})
	petsByBreed = make(map[string][]string)

	// 3. ARRAY AND SLICE
	pets = make([]Pet, 0, maxPets)
	services = make([]Service, 0, 20)
	contactMessages = make([]ContactForm, 0)
	bookings = make([]ServiceBooking, 0)
	serviceReviews = make([]ServiceReview, 0)
	users = make([]User, 0)
	donations = make([]Donation, 0)
	inquiries = make([]AdoptionInquiry, 0)

	notificationCh = make(chan NotificationJob, 100)
	paymentCh = make(chan Donation, 50)
	paymentConfirmCh = make(chan PaymentConfirmation, 50)
	pendingRegs = make(map[string]*PendingRegistration)
	loginAttemptsByEmail = make(map[string]*LoginAttemptState)
	loginRateLimitByIP = make(map[string]*RateLimitState)
	registerRateLimitByIP = make(map[string]*RateLimitState)

	samplePets := []Pet{
		{
			ID:           "pet-001",
			Name:         "Max",
			Species:      "Dog",
			Breed:        "Golden Retriever",
			Age:          3,
			Gender:       "Male",
			Description:  "Friendly and energetic dog looking for a loving home",
			Status:       "Available",
			IsVaccinated: true,
			CreatedAt:    time.Now().AddDate(0, -2, 0),
			Tags:         []string{"Friendly", "Energetic", "House-trained"},
			Attributes:   map[string]string{"Color": "Golden", "Size": "Large", "Weight": "30kg"},
		},
		{
			ID:           "pet-002",
			Name:         "Luna",
			Species:      "Cat",
			Breed:        "Persian",
			Age:          2,
			Gender:       "Female",
			Description:  "Calm and affectionate cat, perfect for apartments",
			Status:       "Available",
			IsVaccinated: true,
			CreatedAt:    time.Now().AddDate(0, -1, -15),
			Tags:         []string{"Calm", "Indoor", "Affectionate"},
			Attributes:   map[string]string{"Color": "White", "Size": "Medium", "Weight": "4kg"},
		},
		{
			ID:           "pet-003",
			Name:         "Charlie",
			Species:      "Dog",
			Breed:        "Beagle",
			Age:          1,
			Gender:       "Male",
			Description:  "Playful puppy with lots of energy",
			Status:       "Under Care",
			IsVaccinated: false,
			CreatedAt:    time.Now().AddDate(0, 0, -10),
			Tags:         []string{"Playful", "Young", "Needs Training"},
			Attributes:   map[string]string{"Color": "Brown and White", "Size": "Medium", "Weight": "12kg"},
		},
	}

	// 2. LOOPING STRUCTURES
	for i, pet := range samplePets {
		pets = append(pets, pet)
		petsByID[pet.ID] = &pets[i]
		statusCounts[pet.Status]++
		petsByBreed[pet.Breed] = append(petsByBreed[pet.Breed], pet.ID)
	}

	sampleServices := []Service{
		{
			ID:          "svc-001",
			Name:        "Pet Grooming",
			Category:    "Care",
			Description: "Complete grooming service including bath, haircut, and nail trimming",
			Price:       1500.00,
			Duration:    90,
			Available:   true,
			Features:    []string{"Bath", "Haircut", "Nail Trimming", "Ear Cleaning"},
		},
		{
			ID:          "svc-002",
			Name:        "Veterinary Checkup",
			Category:    "Medical",
			Description: "Comprehensive health checkup by certified veterinarians",
			Price:       2000.00,
			Duration:    60,
			Available:   true,
			Features:    []string{"Physical Exam", "Vaccination", "Health Certificate"},
		},
		{
			ID:          "svc-003",
			Name:        "Dog Training",
			Category:    "Training",
			Description: "Basic obedience training for dogs",
			Price:       3000.00,
			Duration:    120,
			Available:   true,
			Features:    []string{"Basic Commands", "Socialization", "Behavioral Correction"},
		},
		{
			ID:          "svc-004",
			Name:        "Pet Boarding",
			Category:    "Care",
			Description: "Safe and comfortable boarding facilities",
			Price:       800.00,
			Duration:    1440,
			Available:   true,
			Features:    []string{"24/7 Care", "Play Area", "Regular Meals"},
		},
	}

	// 2. LOOPING STRUCTURES
	for i := 0; i < len(sampleServices); i++ {
		services = append(services, sampleServices[i])
		servicesByID[sampleServices[i].ID] = &services[i]
		serviceStats[sampleServices[i].ID] = map[string]interface{}{
			"bookings":  0,
			"revenue":   0.0,
			"rating":    4.5,
			"reviews":   0,
			"available": sampleServices[i].Available,
		}
	}

	// Seed default admin user
	adminUser := User{
		ID:        "usr-admin",
		Email:     "admin@pawtner.com",
		Username:  "admin",
		Password:  hashPassword("admin123"),
		Role:      "admin",
		IsAdmin:   true,
		CreatedAt: time.Now(),
		IsActive:  true,
	}
	users = append(users, adminUser)
	usersByEmail[adminUser.Email] = &users[len(users)-1]
}

// 2. CONTROL FLOW
func validatePet(pet Pet) (bool, []string) {
	errs := make([]string, 0)

	if pet.Name == "" {
		errs = append(errs, "Pet name is required")
	}

	if pet.Species == "" {
		errs = append(errs, "Species is required")
	}

	if pet.Age < 0 || pet.Age > 30 {
		errs = append(errs, "Age must be between 0 and 30")
	}

	switch pet.Status {
	case "Available", "Adopted", "Under Care":
	default:
		errs = append(errs, "Invalid status")
	}

	return len(errs) == 0, errs
}

func calculateStatistics() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["petsByStatus"] = statusCounts

	speciesCount := make(map[string]int)
	for _, pet := range pets {
		speciesCount[pet.Species]++
	}
	stats["petsBySpecies"] = speciesCount

	if len(pets) > 0 {
		totalAge := 0
		vaccinatedCount := 0

		// 2. LOOPING
		for _, pet := range pets {
			totalAge += pet.Age
			if pet.IsVaccinated {
				vaccinatedCount++
			}
		}

		stats["averageAge"] = float64(totalAge) / float64(len(pets))
		stats["vaccinationRate"] = float64(vaccinatedCount) / float64(len(pets)) * 100
	}

	stats["totalPets"] = len(pets)
	stats["totalServices"] = len(services)
	stats["totalBookings"] = len(bookings)
	stats["totalReviews"] = len(serviceReviews)
	stats["totalMessages"] = len(contactMessages)
	stats["totalDonations"] = len(donations)
	stats["totalInquiries"] = len(inquiries)
	stats["totalUsers"] = len(users)

	return stats
}

func recalculateServiceReviewStats() {
	ratingTotals := make(map[string]int)
	reviewCounts := make(map[string]int)

	for _, review := range serviceReviews {
		ratingTotals[review.ServiceID] += review.Rating
		reviewCounts[review.ServiceID]++
	}

	for serviceID, stats := range serviceStats {
		count := reviewCounts[serviceID]
		stats["reviews"] = count
		if count == 0 {
			stats["rating"] = 0.0
			continue
		}
		stats["rating"] = float64(ratingTotals[serviceID]) / float64(count)
	}
}

// 6. INTERFACE (structre implenting the Filterable interface)
type SpeciesFilter struct {
	Species string
}

func (f SpeciesFilter) Filter(petList []Pet) []Pet {
	result := make([]Pet, 0)
	for _, p := range petList {
		if strings.EqualFold(p.Species, f.Species) {
			result = append(result, p)
		}
	}
	return result
}

func (f SpeciesFilter) Name() string { return "SpeciesFilter" }

type StatusFilter struct {
	Status string
}

func (f StatusFilter) Filter(petList []Pet) []Pet {
	result := make([]Pet, 0)
	for _, p := range petList {
		if p.Status == f.Status {
			result = append(result, p)
		}
	}
	return result
}

func (f StatusFilter) Name() string { return "StatusFilter" }

type AgeRangeFilter struct {
	Min int
	Max int
}

func (f AgeRangeFilter) Filter(petList []Pet) []Pet {
	result := make([]Pet, 0)
	for _, p := range petList {
		if (f.Min == 0 || p.Age >= f.Min) && (f.Max == 0 || p.Age <= f.Max) {
			result = append(result, p)
		}
	}
	return result
}

func (f AgeRangeFilter) Name() string { return "AgeRangeFilter" }

func ApplyFilters(petList []Pet, filters []Filterable) []Pet {
	result := petList
	for _, filter := range filters {
		result = filter.Filter(result)
	}
	return result
}

// 5. FUNCTIONS AND ERROR HANDLING
func hashPassword(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("bcrypt error: %v", err)
		return ""
	}
	return string(hash)
}

func checkPassword(hashed, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain)) == nil
}

func generateToken(userID string) string {
	expiresAt := time.Now().Add(authTokenTTL)
	claims := jwt.RegisteredClaims{
		Subject:   userID,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := jwtToken.SignedString(getJWTSecret())
	if err != nil {
		log.Printf("[ERROR] Failed to sign JWT for %s: %v", userID, err)
		return ""
	}
	return signed
}

func getJWTSecret() []byte {
	secret := strings.TrimSpace(os.Getenv("JWT_SECRET"))
	if secret == "" {
		secret = "pawtner-hope-dev-secret-change-me"
	}
	return []byte(secret)
}

func normalizeEmail(email string) string {
	return strings.TrimSpace(strings.ToLower(email))
}

func getRequestIP(r *http.Request) string {
	if forwardedFor := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwardedFor != "" {
		parts := strings.Split(forwardedFor, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func consumeRateLimit(store map[string]*RateLimitState, key string, limit int, now time.Time) (bool, time.Time) {
	mu.Lock()
	defer mu.Unlock()

	state, exists := store[key]
	if !exists || now.Sub(state.WindowStart) >= ipRateLimitWindow {
		store[key] = &RateLimitState{
			Count:       1,
			WindowStart: now,
		}
		return true, now.Add(ipRateLimitWindow)
	}
	if state.Count >= limit {
		return false, state.WindowStart.Add(ipRateLimitWindow)
	}
	state.Count++
	return true, state.WindowStart.Add(ipRateLimitWindow)
}

func currentLoginLockout(email string, now time.Time) time.Time {
	mu.Lock()
	defer mu.Unlock()

	state, exists := loginAttemptsByEmail[email]
	if !exists {
		return time.Time{}
	}
	if state.LockedUntil.IsZero() {
		return time.Time{}
	}
	if !now.Before(state.LockedUntil) {
		state.FailedAttempts = 0
		state.LockedUntil = time.Time{}
		return time.Time{}
	}
	return state.LockedUntil
}

func recordFailedLoginAttempt(email string, now time.Time) time.Time {
	mu.Lock()
	defer mu.Unlock()

	state, exists := loginAttemptsByEmail[email]
	if !exists {
		state = &LoginAttemptState{}
		loginAttemptsByEmail[email] = state
	} else if !state.LockedUntil.IsZero() && !now.Before(state.LockedUntil) {
		state.FailedAttempts = 0
		state.LockedUntil = time.Time{}
	}

	state.FailedAttempts++
	if state.FailedAttempts >= loginFailureLimit {
		state.FailedAttempts = 0
		state.LockedUntil = now.Add(loginLockoutDuration)
		return state.LockedUntil
	}
	return time.Time{}
}

func failedLoginAttemptCount(email string) int {
	mu.Lock()
	defer mu.Unlock()

	state, exists := loginAttemptsByEmail[email]
	if !exists {
		return 0
	}
	return state.FailedAttempts
}

func clearFailedLoginAttempts(email string) {
	mu.Lock()
	defer mu.Unlock()
	delete(loginAttemptsByEmail, email)
}

func Register(email, username, password string) (*User, error) {
	email = normalizeEmail(email)
	if email == "" || username == "" || password == "" {
		return nil, errors.New("email, username and password are required")
	}

	mu.Lock()
	defer mu.Unlock()

	if _, exists := usersByEmail[email]; exists {
		return nil, ErrUserAlreadyExists
	}

	user := User{
		ID:        fmt.Sprintf("usr-%03d", len(users)+1),
		Email:     email,
		Username:  username,
		Password:  hashPassword(password),
		Role:      "user",
		CreatedAt: time.Now(),
		IsActive:  true,
	}
	users = append(users, user)
	usersByEmail[email] = &users[len(users)-1]
	return &users[len(users)-1], nil
}

func Login(email, password string) (*AuthToken, error) {
	email = normalizeEmail(email)
	if email == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	user, err := getUserByEmailLive(email)
	if err != nil || !checkPassword(user.Password, password) {
		return nil, ErrInvalidCredentials
	}

	token := AuthToken{
		Token:     generateToken(user.ID),
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(authTokenTTL),
		Role:      user.Role,
		IsAdmin:   user.IsAdmin,
		Username:  user.Username,
		Email:     user.Email,
	}
	if token.Token == "" {
		return nil, ErrTokenGeneration
	}
	return &token, nil
}

func ValidateToken(tokenStr string) (*User, error) {
	if tokenStr == "" {
		return nil, ErrInvalidCredentials
	}

	claims := &jwt.RegisteredClaims{}
	parsedToken, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidCredentials
		}
		return getJWTSecret(), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidCredentials
	}
	if !parsedToken.Valid || strings.TrimSpace(claims.Subject) == "" {
		return nil, ErrInvalidCredentials
	}
	userID := strings.TrimSpace(claims.Subject)

	user, err := getUserByIDLive(userID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}

func getUserByEmailLive(email string) (*User, error) {
	email = strings.TrimSpace(strings.ToLower(email))

	if usersColl() != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var user User
		err := usersColl().FindOne(ctx, bson.M{"email": email}).Decode(&user)
		if err == nil {
			return &user, nil
		}
		if !errors.Is(err, mongo.ErrNoDocuments) {
			log.Printf("[WARN] Live user lookup by email failed for %s: %v", email, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	user, exists := usersByEmail[email]
	if !exists {
		return nil, ErrInvalidCredentials
	}
	userCopy := *user
	return &userCopy, nil
}

func getUserByIDLive(userID string) (*User, error) {
	if usersColl() != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var user User
		err := usersColl().FindOne(ctx, bson.M{"id": userID}).Decode(&user)
		if err == nil {
			return &user, nil
		}
		if !errors.Is(err, mongo.ErrNoDocuments) {
			log.Printf("[WARN] Live user lookup by id failed for %s: %v", userID, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	for i := range users {
		if users[i].ID == userID {
			userCopy := users[i]
			return &userCopy, nil
		}
	}
	return nil, ErrInvalidCredentials
}

func requireAdmin(w http.ResponseWriter, r *http.Request) (*User, bool) {
	authHeader := r.Header.Get("Authorization")
	tokenStr := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	if tokenStr == "" {
		respondError(w, http.StatusUnauthorized, "Missing token")
		return nil, false
	}

	user, err := ValidateToken(tokenStr)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Invalid or expired token")
		return nil, false
	}

	if !user.IsAdmin && strings.ToLower(user.Role) != "admin" {
		respondError(w, http.StatusForbidden, "Admin access required")
		return nil, false
	}

	return user, true
}

func UpdatePet(id string, update Pet) (*Pet, error) {
	mu.Lock()
	defer mu.Unlock()

	pet, exists := petsByID[id]
	if !exists {
		return nil, ErrPetNotFound
	}

	if update.Name != "" {
		pet.Name = update.Name
	}
	if update.Species != "" {
		pet.Species = update.Species
	}
	if update.Breed != "" {
		pet.Breed = update.Breed
	}
	if strings.TrimSpace(update.ImageURL) != "" {
		pet.ImageURL = strings.TrimSpace(update.ImageURL)
	}
	if update.Age > 0 {
		pet.Age = update.Age
	}
	if update.Status != "" {
		oldStatus := pet.Status
		pet.Status = update.Status
		statusCounts[oldStatus]--
		statusCounts[update.Status]++
	}
	if update.Description != "" {
		pet.Description = update.Description
	}
	return pet, nil
}

func DeletePet(id string) error {
	mu.Lock()
	defer mu.Unlock()

	pet, exists := petsByID[id]
	if !exists {
		return ErrPetNotFound
	}

	statusCounts[pet.Status]--
	delete(petsByID, id)

	for i, p := range pets {
		if p.ID == id {
			pets = append(pets[:i], pets[i+1:]...)
			break
		}
	}
	return nil
}

func ProcessDonation(donation *Donation) (*Receipt, error) {
	if donation.Amount < 1 {
		return nil, ErrInvalidPayment
	}
	if donation.DonorName == "" || donation.DonorEmail == "" {
		return nil, errors.New("donor name and email are required")
	}
	if donation.PaymentMethod == "" {
		return nil, errors.New("payment method is required")
	}

	donation.ID = fmt.Sprintf("don-%03d", len(donations)+1)
	donation.TransactionID = fmt.Sprintf("txn-%d", time.Now().UnixNano())
	donation.Status = "Completed"
	donation.CreatedAt = time.Now()

	mu.Lock()
	donations = append(donations, *donation)
	mu.Unlock()

	if err := syncDonationToDB(*donation); err != nil {
		mu.Lock()
		donations = donations[:len(donations)-1]
		mu.Unlock()
		return nil, fmt.Errorf("failed to save donation to database")
	}

	receipt := GenerateReceipt(*donation)
	return &receipt, nil
}

func GenerateReceipt(donation Donation) Receipt {
	return Receipt{
		ReceiptID:  fmt.Sprintf("rcpt-%d", time.Now().UnixNano()),
		DonationID: donation.ID,
		DonorName:  donation.DonorName,
		Amount:     donation.Amount,
		IssuedAt:   time.Now(),
		Message:    fmt.Sprintf("Thank you %s for your generous donation of ₹%.2f to Pawtner Hope Foundation!", donation.DonorName, donation.Amount),
	}
}

// ── Email templates ───────────────────────────────────────────────────────────

const welcomeEmailTpl = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Welcome</title></head>
<body style="margin:0;padding:0;background:#faf8f5;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#faf8f5;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(44,36,22,.08);">
        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#d4a574,#b8844f);padding:40px 48px;text-align:center;">
          <div style="font-size:36px;margin-bottom:8px;">🐾</div>
          <h1 style="margin:0;color:#fff;font-size:26px;font-weight:700;letter-spacing:-0.5px;">Pawtner Hope Foundation</h1>
          <p style="margin:8px 0 0;color:rgba(255,255,255,.8);font-size:14px;">Spreading love, one paw at a time</p>
        </td></tr>
        <!-- Body -->
        <tr><td style="padding:40px 48px;">
          <h2 style="margin:0 0 16px;color:#2c2416;font-size:22px;">Welcome, {{.Username}}! 👋</h2>
          <p style="margin:0 0 16px;color:#555;font-size:15px;line-height:1.7;">Your account has been created successfully. We're so glad to have you as part of our community of animal lovers.</p>
          <p style="margin:0 0 24px;color:#555;font-size:15px;line-height:1.7;">Here's what you can do now:</p>
          <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
            <tr><td style="padding:12px 16px;background:#fdf6ef;border-left:3px solid #d4a574;border-radius:4px;margin-bottom:10px;">
              <span style="color:#b8844f;font-weight:600;">🐶 Adopt a Pet</span>
              <span style="color:#666;font-size:14px;"> — Browse our animals and submit an adoption inquiry.</span>
            </td></tr>
            <tr><td style="height:8px;"></td></tr>
            <tr><td style="padding:12px 16px;background:#fdf6ef;border-left:3px solid #d4a574;border-radius:4px;">
              <span style="color:#b8844f;font-weight:600;">💛 Donate</span>
              <span style="color:#666;font-size:14px;"> — Help us rescue and care for more animals.</span>
            </td></tr>
          </table>
          <p style="margin:0 0 4px;color:#888;font-size:13px;">Account details</p>
          <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #eee;border-radius:8px;overflow:hidden;">
            <tr style="background:#f9f9f9;"><td style="padding:10px 16px;color:#888;font-size:13px;width:120px;">Email</td><td style="padding:10px 16px;color:#2c2416;font-size:13px;">{{.Email}}</td></tr>
            <tr><td style="padding:10px 16px;color:#888;font-size:13px;">Username</td><td style="padding:10px 16px;color:#2c2416;font-size:13px;">{{.Username}}</td></tr>
            <tr style="background:#f9f9f9;"><td style="padding:10px 16px;color:#888;font-size:13px;">Member since</td><td style="padding:10px 16px;color:#2c2416;font-size:13px;">{{.Date}}</td></tr>
          </table>
        </td></tr>
        <!-- CTA -->
        <tr><td style="padding:0 48px 40px;text-align:center;">
          <a href="https://pawtner-hope.fly.dev/adoption.html" style="display:inline-block;background:#d4a574;color:#fff;text-decoration:none;padding:14px 36px;border-radius:50px;font-size:15px;font-weight:600;">Browse Pets for Adoption →</a>
        </td></tr>
        <!-- Footer -->
        <tr><td style="background:#f5f0eb;padding:24px 48px;text-align:center;">
          <p style="margin:0;color:#aaa;font-size:12px;">© 2024 Pawtner Hope Foundation. If you didn't create this account, please ignore this email.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`

const receiptEmailTpl = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Donation Receipt</title></head>
<body style="margin:0;padding:0;background:#faf8f5;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#faf8f5;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(44,36,22,.08);">
        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#d4a574,#b8844f);padding:40px 48px;text-align:center;">
          <div style="font-size:36px;margin-bottom:8px;">🐾</div>
          <h1 style="margin:0;color:#fff;font-size:26px;font-weight:700;">Donation Receipt</h1>
          <p style="margin:8px 0 0;color:rgba(255,255,255,.8);font-size:14px;">Pawtner Hope Foundation</p>
        </td></tr>
        <!-- Amount hero -->
        <tr><td style="padding:36px 48px 24px;text-align:center;border-bottom:1px solid #f0ebe4;">
          <p style="margin:0 0 4px;color:#999;font-size:13px;text-transform:uppercase;letter-spacing:.8px;">Amount Received</p>
          <p style="margin:0;color:#b8844f;font-size:48px;font-weight:700;">₹{{.Amount}}</p>
        </td></tr>
        <!-- Details -->
        <tr><td style="padding:28px 48px;">
          <p style="margin:0 0 16px;color:#2c2416;font-size:16px;font-weight:600;">Thank you, {{.DonorName}}! 💛</p>
          <p style="margin:0 0 24px;color:#555;font-size:15px;line-height:1.7;">Your generous donation helps us rescue, care for, and re-home abandoned pets. Every rupee makes a real difference in an animal's life.</p>
          <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #eee;border-radius:10px;overflow:hidden;margin-bottom:24px;">
            <tr style="background:#f9f9f9;"><td style="padding:12px 16px;color:#888;font-size:13px;width:150px;">Receipt No.</td><td style="padding:12px 16px;color:#2c2416;font-size:13px;font-family:monospace;">{{.ReceiptID}}</td></tr>
            <tr><td style="padding:12px 16px;color:#888;font-size:13px;">Donation ID</td><td style="padding:12px 16px;color:#2c2416;font-size:13px;font-family:monospace;">{{.DonationID}}</td></tr>
            <tr style="background:#f9f9f9;"><td style="padding:12px 16px;color:#888;font-size:13px;">UPI Txn / UTR</td><td style="padding:12px 16px;color:#2c2416;font-size:13px;font-family:monospace;">{{.TransactionID}}</td></tr>
            <tr><td style="padding:12px 16px;color:#888;font-size:13px;">Date</td><td style="padding:12px 16px;color:#2c2416;font-size:13px;">{{.Date}}</td></tr>
            <tr style="background:#f9f9f9;"><td style="padding:12px 16px;color:#888;font-size:13px;">Donor Email</td><td style="padding:12px 16px;color:#2c2416;font-size:13px;">{{.DonorEmail}}</td></tr>
          </table>
          <div style="background:#fdf6ef;border-radius:10px;padding:16px 20px;">
            <p style="margin:0;color:#b8844f;font-size:13px;">🔒 This is an official receipt for your tax records. Please save this email.</p>
          </div>
        </td></tr>
        <!-- CTA -->
        <tr><td style="padding:0 48px 40px;text-align:center;">
          <a href="https://pawtner-hope.fly.dev/donate.html" style="display:inline-block;background:#d4a574;color:#fff;text-decoration:none;padding:14px 36px;border-radius:50px;font-size:15px;font-weight:600;">Donate Again →</a>
        </td></tr>
        <!-- Footer -->
        <tr><td style="background:#f5f0eb;padding:24px 48px;text-align:center;">
          <p style="margin:0 0 6px;color:#aaa;font-size:12px;">© 2024 Pawtner Hope Foundation</p>
          <p style="margin:0;color:#bbb;font-size:12px;">Questions? Email us at pawtnerhopefoundation@gmail.com</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`

// renderTemplate renders an HTML template string with the given data.
func renderTemplate(tplStr string, data interface{}) (string, error) {
	tpl, err := template.New("").Parse(tplStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// SendEmail sends an HTML email via Gmail SMTP.
func SendEmail(to, subject, htmlBody string) error {
	if to == "" || subject == "" {
		return ErrEmailFailed
	}
	if emailShouldFail {
		return ErrEmailFailed
	}
	if smtpUser == "" || smtpPass == "" {
		log.Printf("[EMAIL-SKIP] SMTP not configured. To: %s | Subject: %s", to, subject)
		return nil
	}

	header := fmt.Sprintf(
		"From: Pawtner Hope Foundation <%s>\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n",
		smtpUser, to, subject,
	)
	message := []byte(header + htmlBody)

	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
	addr := smtpHost + ":" + smtpPort
	if err := smtp.SendMail(addr, auth, smtpUser, []string{to}, message); err != nil {
		log.Printf("[EMAIL-ERROR] To: %s | %v", to, err)
		return fmt.Errorf("%w: %v", ErrEmailFailed, err)
	}
	log.Printf("[EMAIL-SENT] To: %s | Subject: %s", to, subject)
	return nil
}

func SendEmailWithRetry(to, subject, body string, maxRetries int) error {
	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := SendEmail(to, subject, body); err != nil {
			lastErr = err
			log.Printf("[EMAIL] Attempt %d/%d failed for %s: %v", attempt, maxRetries, to, err)
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
			continue
		}
		return nil
	}
	return fmt.Errorf("email failed after %d attempts: %w", maxRetries, lastErr)
}

// sendWelcomeEmail renders and dispatches the welcome email.
func sendWelcomeEmail(user *User) {
	html, err := renderTemplate(welcomeEmailTpl, map[string]string{
		"Username": user.Username,
		"Email":    user.Email,
		"Date":     user.CreatedAt.Format("2 Jan 2006"),
	})
	if err != nil {
		log.Printf("[EMAIL] Failed to render welcome template: %v", err)
		return
	}
	go SendEmailWithRetry(user.Email, "Welcome to Pawtner Hope Foundation 🐾", html, 3)
}

// sendDonationReceipt renders and dispatches the donation receipt email.
func sendDonationReceipt(donation Donation, receipt Receipt) {
	html, err := renderTemplate(receiptEmailTpl, map[string]string{
		"DonorName":     donation.DonorName,
		"DonorEmail":    donation.DonorEmail,
		"Amount":        fmt.Sprintf("%.2f", donation.Amount),
		"ReceiptID":     receipt.ReceiptID,
		"DonationID":    donation.ID,
		"TransactionID": donation.TransactionID,
		"Date":          donation.CreatedAt.Format("2 Jan 2006, 3:04 PM"),
	})
	if err != nil {
		log.Printf("[EMAIL] Failed to render receipt template: %v", err)
		return
	}
	go SendEmailWithRetry(donation.DonorEmail, "Donation Receipt — Pawtner Hope Foundation 🐾", html, 3)
}

// ── MongoDB helpers ───────────────────────────────────────────────────────────

func petsColl() *mongo.Collection {
	if mongoDB == nil {
		return nil
	}
	return mongoDB.Collection("pets")
}
func usersColl() *mongo.Collection {
	if mongoDB == nil {
		return nil
	}
	return mongoDB.Collection("users")
}
func donationsColl() *mongo.Collection {
	if mongoDB == nil {
		return nil
	}
	return mongoDB.Collection("donations")
}

func bookingsColl() *mongo.Collection {
	if mongoDB == nil {
		return nil
	}
	return mongoDB.Collection("services")
}

func reviewsColl() *mongo.Collection {
	if mongoDB == nil {
		return nil
	}
	return mongoDB.Collection("service_reviews")
}

func contactsColl() *mongo.Collection {
	if mongoDB == nil {
		return nil
	}
	return mongoDB.Collection("contact_messages")
}

func inquiriesColl() *mongo.Collection {
	if mongoDB == nil {
		return nil
	}
	return mongoDB.Collection("inquiries")
}

func syncPetToDB(pet Pet) {
	if petsColl() == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		opts := options.Replace().SetUpsert(true)
		if _, err := petsColl().ReplaceOne(ctx, bson.M{"id": pet.ID}, pet, opts); err != nil {
			log.Printf("[MONGO] syncPetToDB error: %v", err)
		}
	}()
}

func deletePetFromDB(petID string) {
	if petsColl() == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := petsColl().DeleteOne(ctx, bson.M{"id": petID}); err != nil {
			log.Printf("[MONGO] deletePetFromDB error: %v", err)
		}
	}()
}

func syncUserToDB(user User) {
	if usersColl() == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		opts := options.Replace().SetUpsert(true)
		if _, err := usersColl().ReplaceOne(ctx, bson.M{"id": user.ID}, user, opts); err != nil {
			log.Printf("[MONGO] syncUserToDB error: %v", err)
		}
	}()
}

func syncDonationToDB(donation Donation) error {
	if donationsColl() == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opts := options.Replace().SetUpsert(true)
	_, err := donationsColl().ReplaceOne(ctx, bson.M{"id": donation.ID}, donation, opts)
	if err != nil {
		log.Printf("[MONGO] syncDonationToDB error: %v", err)
	}
	return err
}

func syncBookingToDB(booking ServiceBooking) error {
	if bookingsColl() == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opts := options.Replace().SetUpsert(true)
	_, err := bookingsColl().ReplaceOne(ctx, bson.M{"id": booking.ID}, booking, opts)
	if err != nil {
		log.Printf("[MONGO] syncBookingToDB error: %v", err)
	}
	return err
}

func syncReviewToDB(review ServiceReview) error {
	if reviewsColl() == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opts := options.Replace().SetUpsert(true)
	_, err := reviewsColl().ReplaceOne(ctx, bson.M{"id": review.ID}, review, opts)
	if err != nil {
		log.Printf("[MONGO] syncReviewToDB error: %v", err)
	}
	return err
}

func syncContactMessageToDB(contact ContactForm) error {
	if contactsColl() == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	doc := bson.M{
		"name":    contact.Name,
		"email":   contact.Email,
		"purpose": contact.Purpose,
		"message": contact.Message,
		"sentAt":  contact.SentAt,
	}
	_, err := contactsColl().InsertOne(ctx, doc)
	if err != nil {
		log.Printf("[MONGO] syncContactMessageToDB error: %v", err)
	}
	return err
}

func syncInquiryToDB(inquiry AdoptionInquiry) error {
	if inquiriesColl() == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opts := options.Replace().SetUpsert(true)
	_, err := inquiriesColl().ReplaceOne(ctx, bson.M{"id": inquiry.ID}, inquiry, opts)
	if err != nil {
		log.Printf("[MONGO] syncInquiryToDB error: %v", err)
	}
	return err
}

// loadFromMongoDB seeds in-memory data from MongoDB collections on startup.
// If a collection is empty it falls back to whatever initializeData() put there.
func loadFromMongoDB() {
	if mongoDB == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Pets
	if cur, err := petsColl().Find(ctx, bson.D{}); err == nil {
		var dbPets []Pet
		if err := cur.All(ctx, &dbPets); err == nil && len(dbPets) > 0 {
			mu.Lock()
			pets = dbPets
			petsByID = make(map[string]*Pet)
			statusCounts = make(map[string]int)
			petsByBreed = make(map[string][]string)
			for i := range pets {
				petsByID[pets[i].ID] = &pets[i]
				statusCounts[pets[i].Status]++
				petsByBreed[pets[i].Breed] = append(petsByBreed[pets[i].Breed], pets[i].ID)
			}
			mu.Unlock()
			log.Printf("[MONGO] Loaded %d pets", len(pets))
		} else if err == nil {
			// Collection is empty — push sample data to MongoDB so it persists
			log.Println("[MONGO] No pets in DB, seeding sample data")
			for _, p := range pets {
				syncPetToDB(p)
			}
		}
	}

	// Users
	if cur, err := usersColl().Find(ctx, bson.D{}); err == nil {
		var dbUsers []User
		if err := cur.All(ctx, &dbUsers); err == nil && len(dbUsers) > 0 {
			mu.Lock()
			users = dbUsers
			usersByEmail = make(map[string]*User)
			hasAdmin := false
			for i := range users {
				usersByEmail[users[i].Email] = &users[i]
				if users[i].IsAdmin {
					hasAdmin = true
				}
			}
			// Always ensure a default admin account exists
			if !hasAdmin {
				adminUser := User{
					ID:        "usr-admin",
					Email:     "admin@pawtner.com",
					Username:  "admin",
					Password:  hashPassword("admin123"),
					Role:      "admin",
					IsAdmin:   true,
					CreatedAt: time.Now(),
					IsActive:  true,
				}
				users = append(users, adminUser)
				usersByEmail[adminUser.Email] = &users[len(users)-1]
				syncUserToDB(adminUser)
			}
			mu.Unlock()
			log.Printf("[MONGO] Loaded %d users", len(users))
		}
	}

	// Donations
	if cur, err := donationsColl().Find(ctx, bson.D{}); err == nil {
		var dbDonations []Donation
		if err := cur.All(ctx, &dbDonations); err == nil && len(dbDonations) > 0 {
			mu.Lock()
			donations = dbDonations
			mu.Unlock()
			log.Printf("[MONGO] Loaded %d donations", len(donations))
		}
	}

	// Bookings
	if cur, err := bookingsColl().Find(ctx, bson.D{}); err == nil {
		var dbBookings []ServiceBooking
		if err := cur.All(ctx, &dbBookings); err == nil && len(dbBookings) > 0 {
			mu.Lock()
			bookings = dbBookings
			bookingsByID = make(map[string]*ServiceBooking)
			for i := range bookings {
				bookingsByID[bookings[i].ID] = &bookings[i]
			}
			mu.Unlock()
			log.Printf("[MONGO] Loaded %d bookings", len(bookings))
		}
	}

	// Service Reviews
	if cur, err := reviewsColl().Find(ctx, bson.D{}); err == nil {
		var dbReviews []ServiceReview
		if err := cur.All(ctx, &dbReviews); err == nil && len(dbReviews) > 0 {
			mu.Lock()
			serviceReviews = dbReviews
			reviewsByID = make(map[string]*ServiceReview)
			for i := range serviceReviews {
				reviewsByID[serviceReviews[i].ID] = &serviceReviews[i]
			}
			recalculateServiceReviewStats()
			mu.Unlock()
			log.Printf("[MONGO] Loaded %d service reviews", len(serviceReviews))
		}
	}

	// Contact Messages
	if cur, err := contactsColl().Find(ctx, bson.D{}); err == nil {
		var dbContacts []ContactForm
		if err := cur.All(ctx, &dbContacts); err == nil && len(dbContacts) > 0 {
			mu.Lock()
			contactMessages = dbContacts
			mu.Unlock()
			log.Printf("[MONGO] Loaded %d contact messages", len(contactMessages))
		}
	}

	// Inquiries
	if cur, err := inquiriesColl().Find(ctx, bson.D{}); err == nil {
		var dbInquiries []AdoptionInquiry
		if err := cur.All(ctx, &dbInquiries); err == nil && len(dbInquiries) > 0 {
			mu.Lock()
			inquiries = dbInquiries
			mu.Unlock()
			log.Printf("[MONGO] Loaded %d inquiries", len(inquiries))
		}
	}
}

// generateOTP returns a zero-padded 6-digit numeric code.
func generateOTP() string {
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

// ── OTP email template ────────────────────────────────────────────────────────

const otpEmailTpl = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Verify Email</title></head>
<body style="margin:0;padding:0;background:#faf8f5;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#faf8f5;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(44,36,22,.08);">
        <tr><td style="background:linear-gradient(135deg,#d4a574,#b8844f);padding:36px 48px;text-align:center;">
          <div style="font-size:36px;margin-bottom:8px;">🐾</div>
          <h1 style="margin:0;color:#fff;font-size:24px;font-weight:700;">Email Verification</h1>
          <p style="margin:8px 0 0;color:rgba(255,255,255,.8);font-size:14px;">Pawtner Hope Foundation</p>
        </td></tr>
        <tr><td style="padding:40px 48px;text-align:center;">
          <p style="margin:0 0 8px;color:#555;font-size:15px;line-height:1.7;">Hi <strong>{{.Username}}</strong>! Use the code below to verify your email address.</p>
          <p style="margin:0 0 28px;color:#888;font-size:13px;">This code expires in <strong>5 minutes</strong>.</p>
          <div style="display:inline-block;background:#fdf6ef;border:2px dashed #d4a574;border-radius:16px;padding:24px 48px;margin-bottom:28px;">
            <p style="margin:0;font-size:42px;font-weight:800;letter-spacing:10px;color:#b8844f;font-family:monospace;">{{.Code}}</p>
          </div>
          <p style="margin:0;color:#aaa;font-size:12px;">If you didn't request this, you can safely ignore this email.</p>
        </td></tr>
        <tr><td style="background:#f5f0eb;padding:20px 48px;text-align:center;">
          <p style="margin:0;color:#aaa;font-size:12px;">© 2024 Pawtner Hope Foundation</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`

// 5. FUNCTIONS AND ERROR HANDLING
func SearchPets(query string, filters []Filterable) ([]Pet, error) {
	if query == "" && len(filters) == 0 {
		return nil, errors.New("search query or filters required")
	}

	mu.Lock()
	petsCopy := make([]Pet, len(pets))
	copy(petsCopy, pets)
	mu.Unlock()

	var result []Pet
	if query != "" {
		for _, p := range petsCopy {
			nameLower := strings.ToLower(p.Name)
			speciesLower := strings.ToLower(p.Species)
			breedLower := strings.ToLower(p.Breed)
			qLower := strings.ToLower(query)
			if strings.Contains(nameLower, qLower) ||
				strings.Contains(speciesLower, qLower) ||
				strings.Contains(breedLower, qLower) {
				result = append(result, p)
			}
		}
	} else {
		result = petsCopy
	}

	if len(filters) > 0 {
		result = ApplyFilters(result, filters)
	}

	return result, nil
}

func emailWorker(jobs <-chan NotificationJob) {
	for job := range jobs {
		SendEmailWithRetry(job.To, job.Subject, job.Body, 3)
	}
}

const emailWorkerCount = 3

func paymentProcessor(donationQueue <-chan Donation, confirmations chan<- PaymentConfirmation) {
	for donation := range donationQueue {
		time.Sleep(50 * time.Millisecond)
		confirmation := PaymentConfirmation{
			DonationID:    donation.ID,
			Success:       true,
			TransactionID: fmt.Sprintf("txn-%d", time.Now().UnixNano()),
		}
		confirmations <- confirmation

		// Only auto-send receipt for mobile UPI deeplink payments.
		// Desktop donors must request a receipt via email.
		if donation.PaymentViaDeeplink {
			go func(d Donation) {
				receipt := GenerateReceipt(d)
				sendDonationReceipt(d, receipt)
			}(donation)
		} else {
			log.Printf("[INFO] Desktop donation from %s — receipt not auto-sent (request required)", donation.DonorEmail)
		}
	}
}

func confirmationListener(confirmations <-chan PaymentConfirmation) {
	for confirmation := range confirmations {
		mu.Lock()
		for i := range donations {
			if donations[i].ID == confirmation.DonationID {
				if confirmation.Success {
					donations[i].Status = "Completed"
					donations[i].TransactionID = confirmation.TransactionID
				} else {
					donations[i].Status = "Failed"
				}
				break
			}
		}
		mu.Unlock()
		log.Printf("[PAYMENT] Processed: %s - Success: %v", confirmation.DonationID, confirmation.Success)
	}
}

func startWorkers() {
	// 11. GOROUTINES AND CHANNELS
	for i := 0; i < emailWorkerCount; i++ {
		go emailWorker(notificationCh)
	}
	go paymentProcessor(paymentCh, paymentConfirmCh)
	go confirmationListener(paymentConfirmCh)
	log.Printf("[WORKER-POOL] Email workers started: %d", emailWorkerCount)
}

// HTTP Handlers

// Panic recovery middleware
func recoverPanic(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("[PANIC RECOVERED] %v for request %s %s", err, r.Method, r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false,
					"message": "Internal server error",
				})
			}
		}()
		next(w, r)
	}
}

// 6. INTERFACE - http.HandlerFunc implements http.Handler
func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

// Safe file serving with error handling
func serveHTMLFile(filename string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			log.Printf("[ERROR] File not found: %s", filename)
			http.Error(w, "Page not found", http.StatusNotFound)
			return
		}
		http.ServeFile(w, r, filename)
	}
}

// Safe JSON response with error handling
func respondJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[ERROR] Failed to encode JSON response: %v", err)
	}
}

// Error response helper
func respondError(w http.ResponseWriter, statusCode int, message string) {
	log.Printf("[ERROR] HTTP %d: %s", statusCode, message)
	respondJSON(w, statusCode, map[string]interface{}{
		"success": false,
		"message": message,
	})
}

func getPetsHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	species := query.Get("species")
	status := query.Get("status")
	search := query.Get("q")

	var result []Pet

	// 2. CONTROL FLOW
	if search != "" {
		var filters []Filterable
		if species != "" {
			filters = append(filters, SpeciesFilter{Species: species})
		}
		if status != "" {
			filters = append(filters, StatusFilter{Status: status})
		}
		var err error
		result, err = SearchPets(search, filters)
		if err != nil {
			result = pets
		}
	} else if species == "" && status == "" {
		result = pets
	} else {
		var filters []Filterable
		if species != "" {
			filters = append(filters, SpeciesFilter{Species: species})
		}
		if status != "" {
			filters = append(filters, StatusFilter{Status: status})
		}
		result = ApplyFilters(pets, filters)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"count":   len(result),
		"data":    result,
	})
}

func getPetByIDHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/pets/")
	petID := path

	pet, exists := petsByID[petID]

	// 2. CONTROL FLOW
	if !exists {
		respondError(w, http.StatusNotFound, "Pet not found")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    pet,
	})
}

func addPetHandler(w http.ResponseWriter, r *http.Request) {
	var newPet Pet

	// 8. JSON MARSHAL AND UNMARSHAL
	if err := json.NewDecoder(r.Body).Decode(&newPet); err != nil {
		log.Printf("[ERROR] Failed to decode pet JSON: %v", err)
		respondError(w, http.StatusBadRequest, "Invalid JSON data")
		return
	}
	defer r.Body.Close()

	valid, validationErrors := validatePet(newPet)
	if !valid {
		log.Printf("[ERROR] Pet validation failed: %v", validationErrors)
		respondJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"message": "Validation failed",
			"errors":  validationErrors,
		})
		return
	}

	newPet.ImageURL = strings.TrimSpace(newPet.ImageURL)
	newPet.ID = fmt.Sprintf("pet-%03d", len(pets)+1)
	newPet.CreatedAt = time.Now()

	mu.Lock()
	pets = append(pets, newPet)
	petsByID[newPet.ID] = &pets[len(pets)-1]
	statusCounts[newPet.Status]++
	petsByBreed[newPet.Breed] = append(petsByBreed[newPet.Breed], newPet.ID)
	mu.Unlock()

	syncPetToDB(newPet)
	log.Printf("[INFO] Pet added: ID=%s, Name=%s, Species=%s", newPet.ID, newPet.Name, newPet.Species)
	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "Pet added successfully",
		"data":    newPet,
	})
}

func updatePetHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/pets/")
	petID := path

	var update Pet

	// 8. JSON MARSHAL AND UNMARSHAL
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		log.Printf("[ERROR] Failed to decode update JSON: %v", err)
		respondError(w, http.StatusBadRequest, "Invalid JSON data")
		return
	}
	defer r.Body.Close()

	// 5. FUNCTIONS AND ERROR HANDLING
	pet, err := UpdatePet(petID, update)
	if err != nil {
		if errors.Is(err, ErrPetNotFound) {
			respondError(w, http.StatusNotFound, err.Error())
		} else {
			respondError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	log.Printf("[INFO] Pet updated: ID=%s", petID)
	syncPetToDB(*pet)
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Pet updated successfully",
		"data":    pet,
	})
}

func deletePetHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/pets/")
	petID := path

	// 5. FUNCTIONS AND ERROR HANDLING
	if err := DeletePet(petID); err != nil {
		if errors.Is(err, ErrPetNotFound) {
			respondError(w, http.StatusNotFound, err.Error())
		} else {
			respondError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	log.Printf("[INFO] Pet deleted: ID=%s", petID)
	deletePetFromDB(petID)
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Pet deleted successfully",
	})
}

func getServicesHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	category := query.Get("category")

	var result []Service

	// 2. CONTROL FLOW and LOOPING
	if category == "" {
		result = services
	} else {
		for _, service := range services {
			if service.Category == category {
				result = append(result, service)
			}
		}
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"count":   len(result),
		"data":    result,
	})
}

func getBookingsHandler(w http.ResponseWriter, _ *http.Request) {
	if coll := bookingsColl(); coll != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cur, err := coll.Find(ctx, bson.D{})
		if err == nil {
			var result []ServiceBooking
			if err2 := cur.All(ctx, &result); err2 == nil {
				if result == nil {
					result = []ServiceBooking{}
				}
				respondJSON(w, http.StatusOK, map[string]interface{}{
					"success": true,
					"count":   len(result),
					"data":    result,
				})
				return
			}
		}
	}
	mu.Lock()
	result := make([]ServiceBooking, len(bookings))
	copy(result, bookings)
	mu.Unlock()
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"count":   len(result),
		"data":    result,
	})
}

func getServiceReviewsHandler(w http.ResponseWriter, r *http.Request) {
	serviceID := strings.TrimSpace(r.URL.Query().Get("serviceId"))

	if coll := reviewsColl(); coll != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		filter := bson.D{}
		if serviceID != "" {
			filter = bson.D{{Key: "serviceId", Value: serviceID}}
		}
		cur, err := coll.Find(ctx, filter)
		if err == nil {
			var result []ServiceReview
			if err2 := cur.All(ctx, &result); err2 == nil {
				if result == nil {
					result = []ServiceReview{}
				}
				respondJSON(w, http.StatusOK, map[string]interface{}{
					"success": true,
					"count":   len(result),
					"data":    result,
				})
				return
			}
		}
	}

	mu.Lock()
	defer mu.Unlock()

	result := make([]ServiceReview, 0, len(serviceReviews))
	for _, review := range serviceReviews {
		if serviceID == "" || review.ServiceID == serviceID {
			result = append(result, review)
		}
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"count":   len(result),
		"data":    result,
	})
}

func createBookingHandler(w http.ResponseWriter, r *http.Request) {
	var booking ServiceBooking

	if err := json.NewDecoder(r.Body).Decode(&booking); err != nil {
		log.Printf("[ERROR] Failed to decode booking JSON: %v", err)
		respondError(w, http.StatusBadRequest, "Invalid JSON data")
		return
	}
	defer r.Body.Close()

	// Validate required fields
	if booking.ServiceID == "" || booking.OwnerName == "" || booking.Email == "" {
		respondError(w, http.StatusBadRequest, "Service ID, owner name, and email are required")
		return
	}

	if booking.Date != "" {
		selectedDate, err := time.Parse("2006-01-02", booking.Date)
		if err != nil {
			respondError(w, http.StatusBadRequest, "Invalid date format. Use YYYY-MM-DD")
			return
		}
		now := time.Now()
		today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		if selectedDate.Before(today) {
			respondError(w, http.StatusBadRequest, "Date cannot be in the past")
			return
		}
	}

	if booking.Time != "" {
		selectedTime, err := time.Parse("15:04", booking.Time)
		if err != nil {
			respondError(w, http.StatusBadRequest, "Invalid time format. Use HH:MM")
			return
		}
		minutes := selectedTime.Hour()*60 + selectedTime.Minute()
		if minutes < 9*60 || minutes > 21*60 {
			respondError(w, http.StatusBadRequest, "Time must be between 09:00 and 21:00")
			return
		}
	}

	booking.ID = fmt.Sprintf("book-%03d", len(bookings)+1)
	booking.BookedAt = time.Now()
	booking.Status = "Pending"

	mu.Lock()
	bookings = append(bookings, booking)
	bookingsByID[booking.ID] = &bookings[len(bookings)-1]
	if stats, exists := serviceStats[booking.ServiceID]; exists {
		stats["bookings"] = stats["bookings"].(int) + 1
	}
	mu.Unlock()

	if err := syncBookingToDB(booking); err != nil {
		mu.Lock()
		bookings = bookings[:len(bookings)-1]
		delete(bookingsByID, booking.ID)
		if stats, exists := serviceStats[booking.ServiceID]; exists {
			stats["bookings"] = stats["bookings"].(int) - 1
		}
		mu.Unlock()
		respondError(w, http.StatusInternalServerError, "Failed to save booking. Please try again.")
		return
	}

	if smtpUser != "" {
		go func(b ServiceBooking) {
			notificationCh <- NotificationJob{
				To:      smtpUser,
				Subject: "New Service Booking Inquiry",
				Body: fmt.Sprintf(
					"New booking inquiry received.\n\nOwner: %s\nEmail: %s\nPhone: %s\nService: %s\nDate: %s\nTime: %s\nNotes: %s\nID: %s",
					b.OwnerName,
					b.Email,
					b.Phone,
					b.ServiceID,
					b.Date,
					b.Time,
					b.Notes,
					b.ID,
				),
				JobType: "booking-admin",
			}
		}(booking)
	}

	log.Printf("[INFO] Booking created: ID=%s, Service=%s, Owner=%s", booking.ID, booking.ServiceID, booking.OwnerName)
	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "Booking created successfully",
		"data":    booking,
	})
}

func createServiceReviewHandler(w http.ResponseWriter, r *http.Request) {
	var review ServiceReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON data")
		return
	}
	defer r.Body.Close()

	review.BookingID = strings.TrimSpace(review.BookingID)
	review.ServiceID = strings.TrimSpace(review.ServiceID)
	review.ReviewerName = strings.TrimSpace(review.ReviewerName)
	review.Email = normalizeEmail(review.Email)
	review.Comment = strings.TrimSpace(review.Comment)

	if review.BookingID == "" || review.ServiceID == "" || review.ReviewerName == "" || review.Email == "" || review.Comment == "" {
		respondError(w, http.StatusBadRequest, "Booking ID, service, name, email and comment are required")
		return
	}
	if review.Rating < 1 || review.Rating > 5 {
		respondError(w, http.StatusBadRequest, "Rating must be between 1 and 5")
		return
	}

	mu.Lock()
	booking, exists := bookingsByID[review.BookingID]
	if !exists {
		mu.Unlock()
		respondError(w, http.StatusBadRequest, "Booking not found")
		return
	}
	if booking.Email != review.Email {
		mu.Unlock()
		respondError(w, http.StatusBadRequest, "Review email must match the booking email")
		return
	}
	if booking.ServiceID != review.ServiceID {
		mu.Unlock()
		respondError(w, http.StatusBadRequest, "Selected service does not match the booking")
		return
	}
	for _, existing := range serviceReviews {
		if existing.BookingID == review.BookingID {
			mu.Unlock()
			respondError(w, http.StatusConflict, "A review for this booking already exists")
			return
		}
	}

	review.ID = fmt.Sprintf("rev-%03d", len(serviceReviews)+1)
	review.CreatedAt = time.Now()
	serviceReviews = append(serviceReviews, review)
	reviewsByID[review.ID] = &serviceReviews[len(serviceReviews)-1]
	recalculateServiceReviewStats()
	mu.Unlock()

	if err := syncReviewToDB(review); err != nil {
		mu.Lock()
		delete(reviewsByID, review.ID)
		serviceReviews = serviceReviews[:len(serviceReviews)-1]
		recalculateServiceReviewStats()
		mu.Unlock()
		respondError(w, http.StatusInternalServerError, "Failed to save review. Please try again.")
		return
	}

	if smtpUser != "" {
		notificationCh <- NotificationJob{
			To:      smtpUser,
			Subject: "New Service Review Submitted",
			Body: fmt.Sprintf(
				"New service review received.\n\nBooking ID: %s\nService: %s\nReviewer: %s\nEmail: %s\nRating: %d/5\nComment: %s",
				review.BookingID,
				review.ServiceID,
				review.ReviewerName,
				review.Email,
				review.Rating,
				review.Comment,
			),
			JobType: "review-admin",
		}
	}

	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "Review submitted successfully",
		"data":    review,
	})
}

func updateBookingReviewHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/bookings/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 2 || parts[1] != "review" || parts[0] == "" {
		respondError(w, http.StatusBadRequest, "Invalid booking review endpoint")
		return
	}
	bookingID := parts[0]

	var req struct {
		Status      string `json:"status"`
		ReviewNotes string `json:"reviewNotes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	defer r.Body.Close()

	req.Status = strings.TrimSpace(req.Status)
	req.ReviewNotes = strings.TrimSpace(req.ReviewNotes)
	if req.Status != "Pending" && req.Status != "Approved" && req.Status != "Rejected" {
		respondError(w, http.StatusBadRequest, "Invalid booking status")
		return
	}

	adminUser, ok := requireAdmin(w, r)
	if !ok {
		return
	}

	var oldBooking ServiceBooking
	var updated ServiceBooking
	found := false

	mu.Lock()
	for i := range bookings {
		if bookings[i].ID == bookingID {
			oldBooking = bookings[i]
			bookings[i].Status = req.Status
			bookings[i].ReviewNotes = req.ReviewNotes
			bookings[i].ReviewedAt = time.Now()
			bookings[i].ReviewedBy = adminUser.Email
			updated = bookings[i]
			found = true
			break
		}
	}
	mu.Unlock()

	if !found {
		respondError(w, http.StatusNotFound, "Booking not found")
		return
	}

	if err := syncBookingToDB(updated); err != nil {
		mu.Lock()
		for i := range bookings {
			if bookings[i].ID == bookingID {
				bookings[i] = oldBooking
				break
			}
		}
		mu.Unlock()
		respondError(w, http.StatusInternalServerError, "Failed to persist booking review")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Booking review updated",
		"data":    updated,
	})
}

func submitContactHandler(w http.ResponseWriter, r *http.Request) {
	var contact ContactForm

	if err := json.NewDecoder(r.Body).Decode(&contact); err != nil {
		log.Printf("[ERROR] Failed to decode contact JSON: %v", err)
		respondError(w, http.StatusBadRequest, "Invalid JSON data")
		return
	}
	defer r.Body.Close()

	// Validate required fields
	if contact.Name == "" || contact.Email == "" || contact.Message == "" {
		respondError(w, http.StatusBadRequest, "Name, email, and message are required")
		return
	}

	contact.SentAt = time.Now()
	mu.Lock()
	contactMessages = append(contactMessages, contact)
	mu.Unlock()

	if err := syncContactMessageToDB(contact); err != nil {
		mu.Lock()
		contactMessages = contactMessages[:len(contactMessages)-1]
		mu.Unlock()
		respondError(w, http.StatusInternalServerError, "Failed to save your message. Please try again.")
		return
	}

	log.Printf("[INFO] Contact message received from: %s (%s)", contact.Name, contact.Email)

	// 10. CONCURRENCY
	go func() {
		notificationCh <- NotificationJob{
			To:      contact.Email,
			Subject: "Thank you for contacting Pawtner Hope",
			Body:    fmt.Sprintf("Dear %s, we received your message and will get back to you soon.", contact.Name),
			JobType: "contact",
		}
	}()

	if smtpUser != "" {
		go func(c ContactForm) {
			notificationCh <- NotificationJob{
				To:      smtpUser,
				Subject: "New Contact Enquiry",
				Body: fmt.Sprintf(
					"New contact enquiry received.\n\nName: %s\nEmail: %s\nPurpose: %s\nMessage: %s\nSent At: %s",
					c.Name,
					c.Email,
					c.Purpose,
					c.Message,
					c.SentAt.Format(time.RFC1123),
				),
				JobType: "contact-admin",
			}
		}(contact)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Message sent successfully",
	})
}

func getContactMessagesHandler(w http.ResponseWriter, _ *http.Request) {
	if coll := contactsColl(); coll != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cur, err := coll.Find(ctx, bson.D{})
		if err == nil {
			var result []ContactForm
			if err2 := cur.All(ctx, &result); err2 == nil {
				if result == nil {
					result = []ContactForm{}
				}
				respondJSON(w, http.StatusOK, map[string]interface{}{
					"success": true,
					"count":   len(result),
					"data":    result,
				})
				return
			}
		}
	}
	mu.Lock()
	result := make([]ContactForm, len(contactMessages))
	copy(result, contactMessages)
	mu.Unlock()
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"count":   len(result),
		"data":    result,
	})
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Password string `json:"password"`
	}

	now := time.Now()
	requestIP := getRequestIP(r)
	if allowed, resetAt := consumeRateLimit(registerRateLimitByIP, requestIP, registerRateLimitPerIP, now); !allowed {
		respondError(w, http.StatusTooManyRequests, fmt.Sprintf("Too many account creation attempts from this IP. Try again after %s.", resetAt.Format(time.RFC3339)))
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[ERROR] Failed to decode registration JSON: %v", err)
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	defer r.Body.Close()

	req.Email = normalizeEmail(req.Email)
	req.Username = strings.TrimSpace(req.Username)
	if req.Email == "" || req.Username == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "Email, username and password are required")
		return
	}

	mu.Lock()
	_, alreadyExists := usersByEmail[req.Email]
	_, pendingExists := pendingRegs[req.Email]
	mu.Unlock()
	if alreadyExists || pendingExists {
		respondError(w, http.StatusConflict, ErrUserAlreadyExists.Error())
		return
	}

	code := generateOTP()
	pending := &PendingRegistration{
		Email:          req.Email,
		Username:       req.Username,
		HashedPassword: hashPassword(req.Password),
		Code:           code,
		ExpiresAt:      time.Now().Add(5 * time.Minute),
	}
	mu.Lock()
	pendingRegs[req.Email] = pending
	mu.Unlock()

	// Send OTP email asynchronously
	go func() {
		html, err := renderTemplate(otpEmailTpl, map[string]string{
			"Username": req.Username,
			"Code":     code,
		})
		if err != nil {
			log.Printf("[EMAIL] Failed to render OTP template: %v", err)
			return
		}
		SendEmailWithRetry(req.Email, "Your Pawtner Hope Verification Code 🐾", html, 3)
	}()

	log.Printf("[INFO] OTP sent to %s (expires in 5 min)", req.Email)
	respondJSON(w, http.StatusAccepted, map[string]interface{}{
		"success": true,
		"message": "Verification code sent to your email. It expires in 5 minutes.",
	})
}

func verifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	defer r.Body.Close()

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.Code = strings.TrimSpace(req.Code)

	mu.Lock()
	pending, exists := pendingRegs[req.Email]
	mu.Unlock()

	if !exists {
		respondError(w, http.StatusBadRequest, "No pending registration for this email. Please sign up again.")
		return
	}
	if time.Now().After(pending.ExpiresAt) {
		mu.Lock()
		delete(pendingRegs, req.Email)
		mu.Unlock()
		respondError(w, http.StatusBadRequest, "Verification code has expired. Please sign up again.")
		return
	}
	if req.Code != pending.Code {
		respondError(w, http.StatusBadRequest, "Invalid verification code.")
		return
	}

	// Create user with pre-hashed password
	user := User{
		ID:        fmt.Sprintf("usr-%03d", len(users)+1),
		Email:     pending.Email,
		Username:  pending.Username,
		Password:  pending.HashedPassword,
		Role:      "user",
		CreatedAt: time.Now(),
		IsActive:  true,
	}

	mu.Lock()
	users = append(users, user)
	usersByEmail[user.Email] = &users[len(users)-1]
	delete(pendingRegs, req.Email)
	mu.Unlock()

	syncUserToDB(user)
	sendWelcomeEmail(&user)
	log.Printf("[INFO] User verified and created: %s (%s)", user.Username, user.Email)

	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "Account created successfully! You can now log in.",
		"data":    user,
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	now := time.Now()
	requestIP := getRequestIP(r)
	if allowed, resetAt := consumeRateLimit(loginRateLimitByIP, requestIP, loginRateLimitPerIP, now); !allowed {
		respondError(w, http.StatusTooManyRequests, fmt.Sprintf("Too many login attempts from this IP. Try again after %s.", resetAt.Format(time.RFC3339)))
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[ERROR] Failed to decode login JSON: %v", err)
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	defer r.Body.Close()

	req.Email = normalizeEmail(req.Email)
	if lockedUntil := currentLoginLockout(req.Email, now); !lockedUntil.IsZero() {
		respondError(w, http.StatusTooManyRequests, ErrAccountLocked.Error())
		return
	}

	// 5. FUNCTIONS AND ERROR HANDLING
	token, err := Login(req.Email, req.Password)
	if err != nil {
		if errors.Is(err, ErrTokenGeneration) {
			respondError(w, http.StatusInternalServerError, "Failed to issue auth token")
			return
		}
		if req.Email != "" {
			if lockedUntil := recordFailedLoginAttempt(req.Email, now); !lockedUntil.IsZero() {
				log.Printf("[WARN] Account temporarily locked due to failed login attempts: %s", req.Email)
				respondError(w, http.StatusTooManyRequests, ErrAccountLocked.Error())
				return
			}
		}
		log.Printf("[WARN] Failed login attempt for: %s", req.Email)
		attemptsUsed := 0
		attemptsRemaining := loginFailureLimit
		if req.Email != "" {
			attemptsUsed = failedLoginAttemptCount(req.Email)
			attemptsRemaining = max(loginFailureLimit-attemptsUsed, 0)
		}
		respondJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success":             false,
			"message":             err.Error(),
			"attemptsUsed":        attemptsUsed,
			"attemptLimit":        loginFailureLimit,
			"attemptsRemaining":   attemptsRemaining,
			"lockoutDurationMins": int(loginLockoutDuration / time.Minute),
		})
		return
	}

	if req.Email != "" {
		clearFailedLoginAttempts(req.Email)
	}
	log.Printf("[INFO] User logged in: %s", req.Email)
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Login successful",
		"data":    token,
	})
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == "" {
		respondError(w, http.StatusUnauthorized, "Missing token")
		return
	}
	user, err := ValidateToken(tokenStr)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"id":        user.ID,
			"email":     user.Email,
			"username":  user.Username,
			"role":      user.Role,
			"isadmin":   user.IsAdmin,
			"createdAt": user.CreatedAt,
		},
	})
}

func createAdoptionInquiryHandler(w http.ResponseWriter, r *http.Request) {
	var inquiry AdoptionInquiry

	// 8. JSON MARSHAL AND UNMARSHAL
	if err := json.NewDecoder(r.Body).Decode(&inquiry); err != nil {
		log.Printf("[ERROR] Failed to decode adoption inquiry JSON: %v", err)
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	defer r.Body.Close()

	if inquiry.PetID == "" || inquiry.AdopterName == "" || inquiry.Email == "" {
		respondError(w, http.StatusBadRequest, "PetID, adopter name and email are required")
		return
	}

	inquiry.ID = fmt.Sprintf("inq-%03d", len(inquiries)+1)
	inquiry.Status = "Pending"
	inquiry.CreatedAt = time.Now()

	mu.Lock()
	inquiries = append(inquiries, inquiry)
	mu.Unlock()

	if err := syncInquiryToDB(inquiry); err != nil {
		mu.Lock()
		inquiries = inquiries[:len(inquiries)-1]
		mu.Unlock()
		respondError(w, http.StatusInternalServerError, "Failed to save adoption inquiry. Please try again.")
		return
	}

	log.Printf("[INFO] Adoption inquiry: Pet=%s, Adopter=%s (%s)", inquiry.PetID, inquiry.AdopterName, inquiry.Email)

	// 10. CONCURRENCY
	go func() {
		notificationCh <- NotificationJob{
			To:      inquiry.Email,
			Subject: "Adoption Inquiry Received - Pawtner Hope",
			Body:    fmt.Sprintf("Dear %s, your adoption inquiry for pet %s has been received.", inquiry.AdopterName, inquiry.PetID),
			JobType: "adoption",
		}
	}()

	if smtpUser != "" {
		go func(i AdoptionInquiry) {
			notificationCh <- NotificationJob{
				To:      smtpUser,
				Subject: "New Adoption Enquiry",
				Body: fmt.Sprintf(
					"New adoption enquiry received.\n\nPet ID: %s\nAdopter: %s\nEmail: %s\nPhone: %s\nMessage: %s\nInquiry ID: %s",
					i.PetID,
					i.AdopterName,
					i.Email,
					i.Phone,
					i.Message,
					i.ID,
				),
				JobType: "adoption-admin",
			}
		}(inquiry)
	}

	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": "Adoption inquiry submitted successfully",
		"data":    inquiry,
	})
}

func getAdoptionInquiriesHandler(w http.ResponseWriter, _ *http.Request) {
	if coll := inquiriesColl(); coll != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cur, err := coll.Find(ctx, bson.D{})
		if err == nil {
			var result []AdoptionInquiry
			if err2 := cur.All(ctx, &result); err2 == nil {
				if result == nil {
					result = []AdoptionInquiry{}
				}
				respondJSON(w, http.StatusOK, map[string]interface{}{
					"success": true,
					"count":   len(result),
					"data":    result,
				})
				return
			}
		}
	}
	mu.Lock()
	result := make([]AdoptionInquiry, len(inquiries))
	copy(result, inquiries)
	mu.Unlock()
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"count":   len(result),
		"data":    result,
	})
}

func updateAdoptionInquiryStatusHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/adoptions/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 2 || parts[1] != "status" || parts[0] == "" {
		respondError(w, http.StatusBadRequest, "Invalid adoption status endpoint")
		return
	}
	inquiryID := parts[0]

	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	defer r.Body.Close()

	req.Status = strings.TrimSpace(req.Status)
	if req.Status != "Pending" && req.Status != "Approved" && req.Status != "Rejected" {
		respondError(w, http.StatusBadRequest, "Invalid status")
		return
	}

	var oldStatus string
	var oldPetStatus string
	var updated AdoptionInquiry
	var petID string
	found := false

	mu.Lock()
	for i := range inquiries {
		if inquiries[i].ID == inquiryID {
			oldStatus = inquiries[i].Status
			inquiries[i].Status = req.Status
			updated = inquiries[i]
			petID = inquiries[i].PetID
			found = true
			break
		}
	}
	mu.Unlock()

	if !found {
		respondError(w, http.StatusNotFound, "Adoption inquiry not found")
		return
	}

	if err := syncInquiryToDB(updated); err != nil {
		mu.Lock()
		for i := range inquiries {
			if inquiries[i].ID == inquiryID {
				inquiries[i].Status = oldStatus
				break
			}
		}
		mu.Unlock()
		respondError(w, http.StatusInternalServerError, "Failed to persist inquiry status")
		return
	}

	mu.Lock()
	if pet, exists := petsByID[petID]; exists {
		oldPetStatus = pet.Status
		switch req.Status {
		case "Approved":
			pet.Status = "Adopted"
			statusCounts[oldPetStatus]--
			statusCounts["Adopted"]++
		case "Pending", "Rejected":
			pet.Status = "Available"
			statusCounts[oldPetStatus]--
			statusCounts["Available"]++
		}
		syncPetToDB(*pet)
	}
	mu.Unlock()

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Inquiry status updated",
		"data":    updated,
	})
}

func createDonationHandler(w http.ResponseWriter, r *http.Request) {
	var donation Donation

	// 8. JSON MARSHAL AND UNMARSHAL
	if err := json.NewDecoder(r.Body).Decode(&donation); err != nil {
		log.Printf("[ERROR] Failed to decode donation JSON: %v", err)
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	defer r.Body.Close()

	// 5. FUNCTIONS AND ERROR HANDLING
	receipt, err := ProcessDonation(&donation)
	if err != nil {
		log.Printf("[ERROR] Donation processing failed: %v", err)
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	log.Printf("[INFO] Donation received: ₹%.2f from %s (%s) deeplink=%v",
		donation.Amount, donation.DonorName, donation.DonorEmail, donation.PaymentViaDeeplink)

	// 11. GOROUTINES AND CHANNELS — send to payment processor
	go func(d Donation) {
		paymentCh <- d
	}(donation)

	receiptHint := ""
	if !donation.PaymentViaDeeplink {
		receiptHint = "Donation recorded. A receipt can be requested by emailing pawtnerhopefoundation@gmail.com."
	} else {
		receiptHint = "Donation recorded. A receipt has been sent to " + donation.DonorEmail + "."
	}

	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true,
		"message": receiptHint,
		"data":    receipt,
	})
}

func getDonationsHandler(w http.ResponseWriter, _ *http.Request) {
	if coll := donationsColl(); coll != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cur, err := coll.Find(ctx, bson.D{})
		if err == nil {
			var result []Donation
			if err2 := cur.All(ctx, &result); err2 == nil {
				if result == nil {
					result = []Donation{}
				}
				respondJSON(w, http.StatusOK, map[string]interface{}{
					"success": true,
					"count":   len(result),
					"data":    result,
				})
				return
			}
		}
	}
	mu.Lock()
	result := make([]Donation, len(donations))
	copy(result, donations)
	mu.Unlock()
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"count":   len(result),
		"data":    result,
	})
}

func getStatisticsHandler(w http.ResponseWriter, r *http.Request) {
	stats := calculateStatistics()
	stats["serverVersion"] = serverVersion
	stats["uptime"] = time.Since(serverStartTime).String()
	stats["serviceStats"] = serviceStats

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"data":    stats,
	})
}

func main() {
	// Load .env before anything else so SMTP credentials are available.
	loadEnv(".env")
	smtpUser = os.Getenv("GMAIL_USER")
	smtpPass = os.Getenv("GMAIL_PASS")
	if smtpUser != "" {
		log.Printf("[SMTP] Email configured for: %s", smtpUser)
	} else {
		log.Println("[SMTP] No GMAIL_USER set \u2014 emails will be skipped")
	}

	initializeData()
	startWorkers()

	mongoURI := os.Getenv("MONGODB_URI")
	if mongoURI == "" {
		log.Println("⚠ MONGODB_URI not set, running without database")
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		log.Println("Connecting to MongoDB...")
		client, err := mongo.Connect(options.Client().ApplyURI(mongoURI))
		if err != nil {
			log.Printf("Failed to connect to MongoDB: %v", err)
		} else {
			defer func() {
				if err := client.Disconnect(context.Background()); err != nil {
					log.Println("Error disconnecting from MongoDB:", err)
				}
			}()

			if err := client.Ping(ctx, nil); err != nil {
				log.Printf("Failed to ping MongoDB: %v", err)
			} else {
				log.Println("✓ Successfully connected to MongoDB!")
				mongoClient = client
				mongoDB = client.Database("pawtner-hope")
				loadFromMongoDB()
			}
		}
	}

	// Serve HTML files with error handling
	http.HandleFunc("/", recoverPanic(serveHTMLFile("index.html")))
	http.HandleFunc("/about", recoverPanic(serveHTMLFile("index.html")))
	http.HandleFunc("/service.html", recoverPanic(serveHTMLFile("service.html")))
	http.HandleFunc("/adoption.html", recoverPanic(serveHTMLFile("adoption.html")))
	http.HandleFunc("/donate.html", recoverPanic(serveHTMLFile("donate.html")))
	http.HandleFunc("/auth.html", recoverPanic(serveHTMLFile("auth.html")))
	http.HandleFunc("/admin.html", recoverPanic(serveHTMLFile("admin.html")))
	http.HandleFunc("/dashboard.html", recoverPanic(serveHTMLFile("dashboard.html")))
	http.HandleFunc("/pet-images.js", recoverPanic(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		http.ServeFile(w, r, "pet-images.js")
	}))
	http.HandleFunc("/favicon.svg", recoverPanic(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "favicon.svg")
	}))
	http.HandleFunc("/favicon.ico", recoverPanic(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		http.ServeFile(w, r, "favicon.svg")
	}))

	http.HandleFunc("/api/pets", recoverPanic(enableCORS(func(w http.ResponseWriter, r *http.Request) {
		// 2. CONTROL FLOW
		switch r.Method {
		case "GET":
			getPetsHandler(w, r)
		case "POST":
			if _, ok := requireAdmin(w, r); !ok {
				return
			}
			addPetHandler(w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})))

	http.HandleFunc("/api/pets/", recoverPanic(enableCORS(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			getPetByIDHandler(w, r)
		case "PUT":
			if _, ok := requireAdmin(w, r); !ok {
				return
			}
			updatePetHandler(w, r)
		case "DELETE":
			if _, ok := requireAdmin(w, r); !ok {
				return
			}
			deletePetHandler(w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})))

	http.HandleFunc("/api/services", recoverPanic(enableCORS(getServicesHandler)))
	http.HandleFunc("/api/bookings", recoverPanic(enableCORS(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			if _, ok := requireAdmin(w, r); !ok {
				return
			}
			getBookingsHandler(w, r)
		case "POST":
			createBookingHandler(w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})))
	http.HandleFunc("/api/reviews", recoverPanic(enableCORS(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			getServiceReviewsHandler(w, r)
		case "POST":
			createServiceReviewHandler(w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})))
	http.HandleFunc("/api/bookings/", recoverPanic(enableCORS(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT":
			updateBookingReviewHandler(w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})))
	http.HandleFunc("/api/contact", recoverPanic(enableCORS(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			if _, ok := requireAdmin(w, r); !ok {
				return
			}
			getContactMessagesHandler(w, r)
		case "POST":
			submitContactHandler(w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})))
	http.HandleFunc("/api/statistics", recoverPanic(enableCORS(getStatisticsHandler)))

	http.HandleFunc("/api/auth/register", recoverPanic(enableCORS(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			registerHandler(w, r)
		} else {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})))

	http.HandleFunc("/api/auth/login", recoverPanic(enableCORS(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			loginHandler(w, r)
		} else {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})))

	http.HandleFunc("/api/auth/verify", recoverPanic(enableCORS(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			verifyEmailHandler(w, r)
		} else {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})))

	http.HandleFunc("/api/auth/me", recoverPanic(enableCORS(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			meHandler(w, r)
		} else {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})))

	http.HandleFunc("/api/adoptions", recoverPanic(enableCORS(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			if _, ok := requireAdmin(w, r); !ok {
				return
			}
			getAdoptionInquiriesHandler(w, r)
		case "POST":
			createAdoptionInquiryHandler(w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})))

	http.HandleFunc("/api/adoptions/", recoverPanic(enableCORS(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		if _, ok := requireAdmin(w, r); !ok {
			return
		}
		updateAdoptionInquiryStatusHandler(w, r)
	})))

	http.HandleFunc("/api/donations", recoverPanic(enableCORS(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			if _, ok := requireAdmin(w, r); !ok {
				return
			}
			getDonationsHandler(w, r)
		case "POST":
			createDonationHandler(w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})))

	log.Println("==============================================")
	log.Println("🐾 Pawtner Hope Foundation Server")
	log.Println("==============================================")
	log.Printf("Version: %s\n", serverVersion)
	log.Printf("Initialized with %d pets\n", len(pets))
	log.Printf("Initialized with %d services\n", len(services))
	log.Println("==============================================")
	log.Println("Default admin login:")
	log.Println("  Email:    admin@pawtner.com")
	log.Println("  Password: admin123")
	log.Println("==============================================")
	log.Println("API Endpoints:")
	log.Println("  GET    /api/pets              - Get all pets")
	log.Println("  GET    /api/pets/:id          - Get pet by ID")
	log.Println("  POST   /api/pets              - Add new pet")
	log.Println("  PUT    /api/pets/:id          - Update pet")
	log.Println("  DELETE /api/pets/:id          - Delete pet")
	log.Println("  GET    /api/services          - Get all services")
	log.Println("  GET    /api/bookings          - Get all bookings")
	log.Println("  POST   /api/bookings          - Create booking")
	log.Println("  GET    /api/reviews           - Get service reviews")
	log.Println("  POST   /api/reviews           - Create service review")
	log.Println("  POST   /api/contact           - Submit contact form")
	log.Println("  GET    /api/statistics        - Get statistics")
	log.Println("  POST   /api/auth/register     - Register user")
	log.Println("  POST   /api/auth/login        - Login user")
	log.Println("  GET    /api/adoptions         - Get adoption inquiries")
	log.Println("  POST   /api/adoptions         - Submit adoption inquiry")
	log.Println("  GET    /api/donations         - Get donations")
	log.Println("  POST   /api/donations         - Process donation")
	log.Println("==============================================")
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server starting on :%s", port)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
