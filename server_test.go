package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// 9. UNIT TEST CASES

func TestMain(m *testing.M) {
	initializeData()
	startWorkers()
	os.Exit(m.Run())
}

// Test authentication logic, token generation, password validation

func TestHashPassword(t *testing.T) {
	h1 := hashPassword("secret")
	h2 := hashPassword("secret")
	if h1 == h2 {
		t.Error("bcrypt hashes should be different due to salting")
	}
	if h1 == "secret" {
		t.Error("hash should not equal plaintext")
	}
	if !checkPassword(h1, "secret") {
		t.Error("hash should validate the original password")
	}
	if checkPassword(h1, "wrong") {
		t.Error("hash should reject a wrong password")
	}
}

func TestRegister(t *testing.T) {
	initializeData()

	user, err := Register("test@example.com", "testuser", "pass123")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if user.Email != "test@example.com" {
		t.Errorf("expected email test@example.com, got %s", user.Email)
	}
	if user.Password == "pass123" {
		t.Error("password should be stored hashed")
	}
	if !user.IsActive {
		t.Error("new user should be active")
	}

	_, err = Register("test@example.com", "other", "pass456")
	if err != ErrUserAlreadyExists {
		t.Errorf("expected ErrUserAlreadyExists, got %v", err)
	}

	_, err = Register("", "user", "pass")
	if err == nil {
		t.Error("expected error for empty email")
	}
}

func TestLogin(t *testing.T) {
	initializeData()
	Register("login@example.com", "loginuser", "mypassword")

	token, err := Login("login@example.com", "mypassword")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if token.Token == "" {
		t.Error("token should not be empty")
	}
	if token.UserID == "" {
		t.Error("token UserID should not be empty")
	}

	_, err = Login("login@example.com", "wrongpassword")
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}

	_, err = Login("notfound@example.com", "mypassword")
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}

	_, err = Login("", "")
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestValidateToken(t *testing.T) {
	initializeData()
	Register("token@example.com", "tokenuser", "tokenpass")
	token, _ := Login("token@example.com", "tokenpass")

	user, err := ValidateToken(token.Token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}
	if user.Email != "token@example.com" {
		t.Errorf("expected email token@example.com, got %s", user.Email)
	}

	_, err = ValidateToken("invalid-token-xyz")
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials for invalid token, got %v", err)
	}

	_, err = ValidateToken("")
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials for empty token, got %v", err)
	}
}

// Test pet CRUD operations, validation logic

func TestValidatePet(t *testing.T) {
	valid, errs := validatePet(Pet{Name: "Max", Species: "Dog", Age: 3, Status: "Available"})
	if !valid {
		t.Errorf("expected valid pet, got errors: %v", errs)
	}

	valid, errs = validatePet(Pet{Species: "Dog", Age: 3, Status: "Available"})
	if valid {
		t.Error("expected invalid pet with missing name")
	}
	if len(errs) == 0 {
		t.Error("expected validation errors for missing name")
	}

	valid, errs = validatePet(Pet{Name: "Max", Species: "Dog", Age: -1, Status: "Available"})
	if valid {
		t.Error("expected invalid pet with negative age")
	}

	valid, errs = validatePet(Pet{Name: "Max", Species: "Dog", Age: 3, Status: "Unknown"})
	if valid {
		t.Error("expected invalid pet with bad status")
	}
	_ = errs
}

func TestUpdatePet(t *testing.T) {
	initializeData()

	pet, err := UpdatePet("pet-001", Pet{Name: "Maximus"})
	if err != nil {
		t.Fatalf("UpdatePet failed: %v", err)
	}
	if pet.Name != "Maximus" {
		t.Errorf("expected name Maximus, got %s", pet.Name)
	}

	_, err = UpdatePet("pet-999", Pet{Name: "Ghost"})
	if err != ErrPetNotFound {
		t.Errorf("expected ErrPetNotFound, got %v", err)
	}
}

func TestDeletePet(t *testing.T) {
	initializeData()

	err := DeletePet("pet-003")
	if err != nil {
		t.Fatalf("DeletePet failed: %v", err)
	}

	if _, exists := petsByID["pet-003"]; exists {
		t.Error("pet-003 should have been removed from map")
	}

	err = DeletePet("pet-003")
	if err != ErrPetNotFound {
		t.Errorf("expected ErrPetNotFound on second delete, got %v", err)
	}
}

func TestGetPetByID(t *testing.T) {
	initializeData()

	pet, exists := petsByID["pet-001"]
	if !exists {
		t.Fatal("pet-001 should exist after initializeData")
	}
	if pet.Name != "Max" {
		t.Errorf("expected Max, got %s", pet.Name)
	}

	_, exists = petsByID["pet-999"]
	if exists {
		t.Error("pet-999 should not exist")
	}
}

// Test payment processing, receipt generation

func TestProcessDonation(t *testing.T) {
	initializeData()

	donation := &Donation{
		DonorName:     "Jane Doe",
		DonorEmail:    "jane@example.com",
		Amount:        500.00,
		PaymentMethod: "UPI",
	}
	receipt, err := ProcessDonation(donation)
	if err != nil {
		t.Fatalf("ProcessDonation failed: %v", err)
	}
	if receipt.ReceiptID == "" {
		t.Error("receipt ID should not be empty")
	}
	if receipt.Amount != 500.00 {
		t.Errorf("expected amount 500.00, got %.2f", receipt.Amount)
	}
	if donation.Status != "Completed" {
		t.Errorf("expected status Completed, got %s", donation.Status)
	}

	_, err = ProcessDonation(&Donation{DonorName: "A", DonorEmail: "a@b.com", Amount: -100, PaymentMethod: "UPI"})
	if err != ErrInvalidPayment {
		t.Errorf("expected ErrInvalidPayment for negative amount, got %v", err)
	}

	_, err = ProcessDonation(&Donation{DonorName: "", DonorEmail: "a@b.com", Amount: 100, PaymentMethod: "UPI"})
	if err == nil {
		t.Error("expected error for missing donor name")
	}

	_, err = ProcessDonation(&Donation{DonorName: "A", DonorEmail: "a@b.com", Amount: 100, PaymentMethod: ""})
	if err == nil {
		t.Error("expected error for missing payment method")
	}
}

func TestGenerateReceipt(t *testing.T) {
	donation := Donation{
		ID:        "don-001",
		DonorName: "John",
		Amount:    1000.00,
	}
	receipt := GenerateReceipt(donation)
	if receipt.DonationID != "don-001" {
		t.Errorf("expected DonationID don-001, got %s", receipt.DonationID)
	}
	if receipt.Amount != 1000.00 {
		t.Errorf("expected amount 1000.00, got %.2f", receipt.Amount)
	}
	if receipt.Message == "" {
		t.Error("receipt message should not be empty")
	}
	if receipt.ReceiptID == "" {
		t.Error("receipt ID should not be empty")
	}
}

// Test search accuracy, filter combinations

func TestSpeciesFilter(t *testing.T) {
	initializeData()
	f := SpeciesFilter{Species: "Dog"}
	result := f.Filter(pets)
	for _, p := range result {
		if p.Species != "Dog" {
			t.Errorf("expected Dog, got %s", p.Species)
		}
	}
	if len(result) == 0 {
		t.Error("expected at least one dog in sample data")
	}
	if f.Name() != "SpeciesFilter" {
		t.Errorf("unexpected filter name: %s", f.Name())
	}
}

func TestStatusFilter(t *testing.T) {
	initializeData()
	f := StatusFilter{Status: "Available"}
	result := f.Filter(pets)
	for _, p := range result {
		if p.Status != "Available" {
			t.Errorf("expected Available, got %s", p.Status)
		}
	}
	if f.Name() != "StatusFilter" {
		t.Errorf("unexpected filter name: %s", f.Name())
	}
}

func TestAgeRangeFilter(t *testing.T) {
	initializeData()
	f := AgeRangeFilter{Min: 2, Max: 3}
	result := f.Filter(pets)
	for _, p := range result {
		if p.Age < 2 || p.Age > 3 {
			t.Errorf("age %d outside range [2,3]", p.Age)
		}
	}
	if f.Name() != "AgeRangeFilter" {
		t.Errorf("unexpected filter name: %s", f.Name())
	}
}

func TestApplyFilters(t *testing.T) {
	initializeData()
	filters := []Filterable{
		SpeciesFilter{Species: "Dog"},
		StatusFilter{Status: "Available"},
	}
	result := ApplyFilters(pets, filters)
	for _, p := range result {
		if p.Species != "Dog" || p.Status != "Available" {
			t.Errorf("filter mismatch: species=%s status=%s", p.Species, p.Status)
		}
	}
}

func TestSearchPets(t *testing.T) {
	initializeData()

	result, err := SearchPets("Max", nil)
	if err != nil {
		t.Fatalf("SearchPets failed: %v", err)
	}
	if len(result) == 0 {
		t.Error("expected to find Max")
	}

	result, err = SearchPets("dog", nil)
	if err != nil {
		t.Fatalf("SearchPets by species failed: %v", err)
	}
	if len(result) == 0 {
		t.Error("expected dogs in results")
	}

	_, err = SearchPets("", nil)
	if err == nil {
		t.Error("expected error for empty query with no filters")
	}

	result, err = SearchPets("", []Filterable{SpeciesFilter{Species: "Cat"}})
	if err != nil {
		t.Fatalf("SearchPets with filter failed: %v", err)
	}
	for _, p := range result {
		if p.Species != "Cat" {
			t.Errorf("expected Cat, got %s", p.Species)
		}
	}
}

// Test email delivery, retry mechanism

func TestSendEmail(t *testing.T) {
	emailShouldFail = false
	err := SendEmail("test@example.com", "Subject", "Body")
	if err != nil {
		t.Errorf("SendEmail should succeed: %v", err)
	}

	err = SendEmail("", "Subject", "Body")
	if err != ErrEmailFailed {
		t.Errorf("expected ErrEmailFailed for empty to, got %v", err)
	}

	err = SendEmail("test@example.com", "", "Body")
	if err != ErrEmailFailed {
		t.Errorf("expected ErrEmailFailed for empty subject, got %v", err)
	}
}

func TestSendEmailWithRetry(t *testing.T) {
	emailShouldFail = false
	err := SendEmailWithRetry("test@example.com", "Hello", "Body", 3)
	if err != nil {
		t.Errorf("SendEmailWithRetry should succeed: %v", err)
	}

	emailShouldFail = true
	err = SendEmailWithRetry("test@example.com", "Hello", "Body", 3)
	if err == nil {
		t.Error("expected error when email should fail")
	}
	emailShouldFail = false
}

// Test email delivery, retry mechanism

func TestCORSMiddleware(t *testing.T) {
	handler := enableCORS(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("OPTIONS", "/api/pets", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for OPTIONS, got %d", rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("expected Access-Control-Allow-Origin: *")
	}

	req = httptest.NewRequest("GET", "/api/pets", nil)
	rr = httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for GET, got %d", rr.Code)
	}
}

func TestGetPetsHandler(t *testing.T) {
	initializeData()
	startWorkers()

	req := httptest.NewRequest("GET", "/api/pets", nil)
	rr := httptest.NewRecorder()
	getPetsHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["success"] != true {
		t.Error("expected success true")
	}
}

func TestAddPetHandler(t *testing.T) {
	initializeData()
	startWorkers()

	body := bytes.NewBufferString(`{"name":"Buddy","species":"Dog","breed":"Labrador","age":2,"status":"Available"}`)
	req := httptest.NewRequest("POST", "/api/pets", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	addPetHandler(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rr.Code)
	}

	body = bytes.NewBufferString(`{"species":"Dog","age":2,"status":"Available"}`)
	req = httptest.NewRequest("POST", "/api/pets", body)
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	addPetHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing name, got %d", rr.Code)
	}
}

func TestRegisterHandler(t *testing.T) {
	initializeData()

	body := bytes.NewBufferString(`{"email":"handler@test.com","username":"handleruser","password":"pass123"}`)
	req := httptest.NewRequest("POST", "/api/auth/register", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	registerHandler(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d", rr.Code)
	}

	body = bytes.NewBufferString(`{"email":"handler@test.com","username":"handleruser","password":"pass123"}`)
	req = httptest.NewRequest("POST", "/api/auth/register", body)
	rr = httptest.NewRecorder()
	registerHandler(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409 for duplicate email, got %d", rr.Code)
	}
}

func TestVerifyEmailCreatesUserAndUpdatesStatistics(t *testing.T) {
	initializeData()

	body := bytes.NewBufferString(`{"email":"verified@test.com","username":"verifieduser","password":"pass123"}`)
	req := httptest.NewRequest("POST", "/api/auth/register", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	registerHandler(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for registration start, got %d", rr.Code)
	}

	if got := calculateStatistics()["totalUsers"].(int); got != 1 {
		t.Fatalf("expected totalUsers to remain 1 before verification, got %d", got)
	}

	mu.Lock()
	pending := pendingRegs["verified@test.com"]
	mu.Unlock()
	if pending == nil {
		t.Fatal("expected pending registration to exist")
	}

	verifyBody := bytes.NewBufferString(`{"email":"verified@test.com","code":"` + pending.Code + `"}`)
	verifyReq := httptest.NewRequest("POST", "/api/auth/verify", verifyBody)
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyRR := httptest.NewRecorder()
	verifyEmailHandler(verifyRR, verifyReq)

	if verifyRR.Code != http.StatusCreated {
		t.Fatalf("expected 201 after verification, got %d", verifyRR.Code)
	}

	if got := calculateStatistics()["totalUsers"].(int); got != 2 {
		t.Fatalf("expected totalUsers to become 2 after verification, got %d", got)
	}
}

func TestUpdateBookingReviewHandlerPersistsReview(t *testing.T) {
	initializeData()

	bookingBody := bytes.NewBufferString(`{"serviceId":"svc-001","petName":"Max","ownerName":"Casey","email":"casey@example.com","phone":"9999999999","date":"2099-12-31","time":"10:30","notes":"Needs gentle handling"}`)
	bookingReq := httptest.NewRequest("POST", "/api/bookings", bookingBody)
	bookingReq.Header.Set("Content-Type", "application/json")
	bookingRR := httptest.NewRecorder()
	createBookingHandler(bookingRR, bookingReq)

	if bookingRR.Code != http.StatusCreated {
		t.Fatalf("expected 201 when creating booking, got %d", bookingRR.Code)
	}

	var createdResp struct {
		Data ServiceBooking `json:"data"`
	}
	if err := json.NewDecoder(bookingRR.Body).Decode(&createdResp); err != nil {
		t.Fatalf("failed to decode created booking: %v", err)
	}

	adminToken, err := Login("admin@pawtner.com", "admin123")
	if err != nil {
		t.Fatalf("failed to log in as admin: %v", err)
	}

	reviewBody := bytes.NewBufferString(`{"status":"Approved","reviewNotes":"Confirmed schedule with the owner."}`)
	reviewReq := httptest.NewRequest("PUT", "/api/bookings/"+createdResp.Data.ID+"/review", reviewBody)
	reviewReq.Header.Set("Content-Type", "application/json")
	reviewReq.Header.Set("Authorization", "Bearer "+adminToken.Token)
	reviewRR := httptest.NewRecorder()
	updateBookingReviewHandler(reviewRR, reviewReq)

	if reviewRR.Code != http.StatusOK {
		t.Fatalf("expected 200 when reviewing booking, got %d", reviewRR.Code)
	}

	var reviewResp struct {
		Data ServiceBooking `json:"data"`
	}
	if err := json.NewDecoder(reviewRR.Body).Decode(&reviewResp); err != nil {
		t.Fatalf("failed to decode booking review: %v", err)
	}

	if reviewResp.Data.Status != "Approved" {
		t.Fatalf("expected updated status Approved, got %s", reviewResp.Data.Status)
	}
	if reviewResp.Data.ReviewNotes != "Confirmed schedule with the owner." {
		t.Fatalf("expected review notes to be persisted, got %q", reviewResp.Data.ReviewNotes)
	}
	if reviewResp.Data.ReviewedBy != "admin@pawtner.com" {
		t.Fatalf("expected reviewedBy admin@pawtner.com, got %q", reviewResp.Data.ReviewedBy)
	}
	if reviewResp.Data.ReviewedAt.IsZero() {
		t.Fatal("expected reviewedAt to be set")
	}

	mu.Lock()
	defer mu.Unlock()
	stored := bookingsByID[createdResp.Data.ID]
	if stored == nil {
		t.Fatal("expected reviewed booking in bookingsByID")
	}
	if stored.Status != "Approved" || stored.ReviewNotes != "Confirmed schedule with the owner." {
		t.Fatalf("stored booking review not updated: %+v", *stored)
	}
}

func TestCreateServiceReviewHandlerPersistsReviewAndStats(t *testing.T) {
	initializeData()

	bookingBody := bytes.NewBufferString(`{"serviceId":"svc-001","petName":"Milo","ownerName":"Jordan","email":"jordan@example.com","phone":"9999999999","date":"2099-12-31","time":"11:00","notes":"First visit"}`)
	bookingReq := httptest.NewRequest("POST", "/api/bookings", bookingBody)
	bookingReq.Header.Set("Content-Type", "application/json")
	bookingRR := httptest.NewRecorder()
	createBookingHandler(bookingRR, bookingReq)

	if bookingRR.Code != http.StatusCreated {
		t.Fatalf("expected 201 when creating booking, got %d", bookingRR.Code)
	}

	var bookingResp struct {
		Data ServiceBooking `json:"data"`
	}
	if err := json.NewDecoder(bookingRR.Body).Decode(&bookingResp); err != nil {
		t.Fatalf("failed to decode created booking: %v", err)
	}

	adminToken, err := Login("admin@pawtner.com", "admin123")
	if err != nil {
		t.Fatalf("failed to log in as admin: %v", err)
	}

	reviewBookingReq := httptest.NewRequest(
		"PUT",
		"/api/bookings/"+bookingResp.Data.ID+"/review",
		bytes.NewBufferString(`{"status":"Approved","reviewNotes":"Completed successfully."}`),
	)
	reviewBookingReq.Header.Set("Content-Type", "application/json")
	reviewBookingReq.Header.Set("Authorization", "Bearer "+adminToken.Token)
	reviewBookingRR := httptest.NewRecorder()
	updateBookingReviewHandler(reviewBookingRR, reviewBookingReq)

	if reviewBookingRR.Code != http.StatusOK {
		t.Fatalf("expected 200 when approving booking, got %d", reviewBookingRR.Code)
	}

	serviceReviewReq := httptest.NewRequest(
		"POST",
		"/api/reviews",
		bytes.NewBufferString(`{"bookingId":"`+bookingResp.Data.ID+`","serviceId":"svc-001","reviewerName":"Jordan","email":"jordan@example.com","rating":5,"comment":"Very caring team."}`),
	)
	serviceReviewReq.Header.Set("Content-Type", "application/json")
	serviceReviewRR := httptest.NewRecorder()
	createServiceReviewHandler(serviceReviewRR, serviceReviewReq)

	if serviceReviewRR.Code != http.StatusCreated {
		t.Fatalf("expected 201 when creating review, got %d", serviceReviewRR.Code)
	}

	var reviewResp struct {
		Data ServiceReview `json:"data"`
	}
	if err := json.NewDecoder(serviceReviewRR.Body).Decode(&reviewResp); err != nil {
		t.Fatalf("failed to decode created review: %v", err)
	}

	if reviewResp.Data.Rating != 5 || reviewResp.Data.BookingID != bookingResp.Data.ID {
		t.Fatalf("unexpected review response: %+v", reviewResp.Data)
	}

	stats := calculateStatistics()
	if got := stats["totalReviews"].(int); got != 1 {
		t.Fatalf("expected totalReviews to be 1, got %d", got)
	}
	if got := serviceStats["svc-001"]["reviews"].(int); got != 1 {
		t.Fatalf("expected svc-001 reviews to be 1, got %d", got)
	}
	if got := serviceStats["svc-001"]["rating"].(float64); got != 5 {
		t.Fatalf("expected svc-001 rating to be 5, got %.2f", got)
	}
}

func TestCreateServiceReviewHandlerRejectsDuplicateBookingReview(t *testing.T) {
	initializeData()

	bookingBody := bytes.NewBufferString(`{"serviceId":"svc-001","petName":"Milo","ownerName":"Jordan","email":"jordan@example.com","phone":"9999999999","date":"2099-12-31","time":"11:00","notes":"First visit"}`)
	bookingReq := httptest.NewRequest("POST", "/api/bookings", bookingBody)
	bookingReq.Header.Set("Content-Type", "application/json")
	bookingRR := httptest.NewRecorder()
	createBookingHandler(bookingRR, bookingReq)

	if bookingRR.Code != http.StatusCreated {
		t.Fatalf("expected 201 when creating booking, got %d", bookingRR.Code)
	}

	var bookingResp struct {
		Data ServiceBooking `json:"data"`
	}
	if err := json.NewDecoder(bookingRR.Body).Decode(&bookingResp); err != nil {
		t.Fatalf("failed to decode created booking: %v", err)
	}

	firstReviewReq := httptest.NewRequest(
		"POST",
		"/api/reviews",
		bytes.NewBufferString(`{"bookingId":"`+bookingResp.Data.ID+`","serviceId":"svc-001","reviewerName":"Jordan","email":"jordan@example.com","rating":5,"comment":"Very caring team."}`),
	)
	firstReviewReq.Header.Set("Content-Type", "application/json")
	firstReviewRR := httptest.NewRecorder()
	createServiceReviewHandler(firstReviewRR, firstReviewReq)

	if firstReviewRR.Code != http.StatusCreated {
		t.Fatalf("expected 201 for first review, got %d", firstReviewRR.Code)
	}

	secondReviewReq := httptest.NewRequest(
		"POST",
		"/api/reviews",
		bytes.NewBufferString(`{"bookingId":"`+bookingResp.Data.ID+`","serviceId":"svc-001","reviewerName":"Jordan","email":"jordan@example.com","rating":4,"comment":"Second review should fail."}`),
	)
	secondReviewReq.Header.Set("Content-Type", "application/json")
	secondReviewRR := httptest.NewRecorder()
	createServiceReviewHandler(secondReviewRR, secondReviewReq)

	if secondReviewRR.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate booking review, got %d", secondReviewRR.Code)
	}
}

func TestLoginHandlerLocksAccountAfterTwoFailures(t *testing.T) {
	initializeData()
	_, err := Register("lock@test.com", "lockuser", "pass123")
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	type loginErrorResponse struct {
		AttemptsUsed      int `json:"attemptsUsed"`
		AttemptLimit      int `json:"attemptLimit"`
		AttemptsRemaining int `json:"attemptsRemaining"`
	}

	for i := 0; i < loginFailureLimit-1; i++ {
		body := bytes.NewBufferString(`{"email":"lock@test.com","password":"wrongpass"}`)
		req := httptest.NewRequest("POST", "/api/auth/login", body)
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "198.51.100.20:1234"
		rr := httptest.NewRecorder()
		loginHandler(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, rr.Code)
		}

		if i == 0 {
			var payload loginErrorResponse
			if err := json.NewDecoder(rr.Body).Decode(&payload); err != nil {
				t.Fatalf("failed to decode login error response: %v", err)
			}
			if payload.AttemptsUsed != 1 || payload.AttemptLimit != loginFailureLimit || payload.AttemptsRemaining != loginFailureLimit-1 {
				t.Fatalf("unexpected attempt payload: %+v", payload)
			}
		}
	}

	body := bytes.NewBufferString(`{"email":"lock@test.com","password":"wrongpass"}`)
	req := httptest.NewRequest("POST", "/api/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.20:1234"
	rr := httptest.NewRecorder()
	loginHandler(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d should trigger lockout: expected 429, got %d", loginFailureLimit, rr.Code)
	}

	body = bytes.NewBufferString(`{"email":"lock@test.com","password":"pass123"}`)
	req = httptest.NewRequest("POST", "/api/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.5:4567"
	rr = httptest.NewRecorder()
	loginHandler(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("locked account should stay blocked, got %d", rr.Code)
	}

	mu.Lock()
	loginAttemptsByEmail["lock@test.com"].LockedUntil = time.Now().Add(-time.Second)
	mu.Unlock()

	body = bytes.NewBufferString(`{"email":"lock@test.com","password":"pass123"}`)
	req = httptest.NewRequest("POST", "/api/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.5:4567"
	rr = httptest.NewRecorder()
	loginHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 after lockout expiry, got %d", rr.Code)
	}
}

func TestLoginHandlerRateLimitsByIP(t *testing.T) {
	initializeData()
	_, err := Register("ratelimit@test.com", "rateuser", "pass123")
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	for i := 0; i < loginRateLimitPerIP; i++ {
		body := bytes.NewBufferString(`{"email":"ratelimit@test.com","password":"pass123"}`)
		req := httptest.NewRequest("POST", "/api/auth/login", body)
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.0.2.50:9999"
		rr := httptest.NewRecorder()
		loginHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("attempt %d: expected 200, got %d", i+1, rr.Code)
		}
	}

	body := bytes.NewBufferString(`{"email":"ratelimit@test.com","password":"pass123"}`)
	req := httptest.NewRequest("POST", "/api/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.50:9999"
	rr := httptest.NewRecorder()
	loginHandler(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d login requests from one IP, got %d", loginRateLimitPerIP, rr.Code)
	}
}

func TestRegisterHandlerRateLimitsByIP(t *testing.T) {
	initializeData()

	for i := 0; i < registerRateLimitPerIP; i++ {
		body := bytes.NewBufferString(
			`{"email":"user` + string(rune('a'+i)) + `@test.com","username":"user` + string(rune('a'+i)) + `","password":"pass123"}`,
		)
		req := httptest.NewRequest("POST", "/api/auth/register", body)
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "198.51.100.77:8080"
		rr := httptest.NewRecorder()
		registerHandler(rr, req)

		if rr.Code != http.StatusAccepted {
			t.Fatalf("attempt %d: expected 202, got %d", i+1, rr.Code)
		}
	}

	body := bytes.NewBufferString(`{"email":"overflow@test.com","username":"overflow","password":"pass123"}`)
	req := httptest.NewRequest("POST", "/api/auth/register", body)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.77:8080"
	rr := httptest.NewRecorder()
	registerHandler(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after %d registrations from one IP, got %d", registerRateLimitPerIP, rr.Code)
	}
}

func TestCreateDonationHandler(t *testing.T) {
	initializeData()
	startWorkers()

	body := bytes.NewBufferString(`{"donorName":"Bob","donorEmail":"bob@test.com","amount":1000,"paymentMethod":"Card"}`)
	req := httptest.NewRequest("POST", "/api/donations", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	createDonationHandler(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", rr.Code)
	}

	body = bytes.NewBufferString(`{"donorName":"Bob","donorEmail":"bob@test.com","amount":-50,"paymentMethod":"Card"}`)
	req = httptest.NewRequest("POST", "/api/donations", body)
	rr = httptest.NewRecorder()
	createDonationHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for negative amount, got %d", rr.Code)
	}
}

func TestUpdateAdoptionInquiryStatusHandler(t *testing.T) {
	initializeData()
	inquiries = append(inquiries, AdoptionInquiry{
		ID:          "inq-test-001",
		PetID:       "pet-001",
		AdopterName: "Test User",
		Email:       "test@example.com",
		Status:      "Pending",
	})

	body := bytes.NewBufferString(`{"status":"Approved"}`)
	req := httptest.NewRequest("PUT", "/api/adoptions/inq-test-001/status", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	updateAdoptionInquiryStatusHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	if inquiries[len(inquiries)-1].Status != "Approved" {
		t.Fatalf("expected inquiry status to be Approved, got %s", inquiries[len(inquiries)-1].Status)
	}
}

func TestUpdateAdoptionInquiryStatusHandlerInvalidStatus(t *testing.T) {
	initializeData()
	inquiries = append(inquiries, AdoptionInquiry{
		ID:          "inq-test-002",
		PetID:       "pet-001",
		AdopterName: "Test User",
		Email:       "test@example.com",
		Status:      "Pending",
	})

	body := bytes.NewBufferString(`{"status":"Done"}`)
	req := httptest.NewRequest("PUT", "/api/adoptions/inq-test-002/status", body)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	updateAdoptionInquiryStatusHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}

	if inquiries[len(inquiries)-1].Status != "Pending" {
		t.Fatalf("status should remain Pending on invalid update, got %s", inquiries[len(inquiries)-1].Status)
	}
}

// Test middleware behavior, routing logic
