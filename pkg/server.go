package pkg

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"multicraft-microservice/internal/db"
)

type Server struct {
	DB *gorm.DB
}

func (s *Server) IsUserEmpty(user db.User) bool {
	return user == db.User{}
}

func (s *Server) FindUser(username string) (db.User, error) {
	var user db.User
	result := s.DB.First(&user, "username = ?", username)
	if result.Error != nil {
		return db.User{}, result.Error
	}
	if s.IsUserEmpty(user) {
		return db.User{}, nil
	}
	return user, nil
}

func (s *Server) MigrateSchemes() {
	s.DB.AutoMigrate(&db.User{})
	log.Println("Migration successful")
}

func (s *Server) RegistrationUser(username, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user := db.User{
		Username: username,
		Password: string(hashedPassword),
	}

	var count int64
	s.DB.Model(&db.User{}).Where("username = ?", username).Count(&count)
	if count == 0 {
		if err := s.DB.Create(&user).Error; err != nil {
			return err
		}
		log.Println("User created.")
	} else {
		return fmt.Errorf("user already exists")
	}
	return nil
}

func (s *Server) LoginUser(username, password string) (db.User, error) {
	user, err := s.FindUser(username)
	if err != nil {
		return db.User{}, err
	}
	if s.IsUserEmpty(user) {
		return db.User{}, fmt.Errorf("user not found")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return db.User{}, fmt.Errorf("invalid password")
	}

	log.Println("Login successful")
	return user, nil
}

func (s *Server) EditUsername(oldUsername, newUsername string) error {
	user, err := s.FindUser(oldUsername)
	if err != nil {
		return err
	}
	if s.IsUserEmpty(user) {
		return fmt.Errorf("user not found")
	}
	if len(newUsername) >= 6 {
		s.DB.Model(&user).Update("Username", newUsername)
		log.Println("Username updated.")
	} else {
		return fmt.Errorf("username must be at least 6 characters long")
	}
	return nil
}

func (s *Server) EditUsernameAndPassword(oldUsername, newUsername, password string) error {
	user, err := s.FindUser(oldUsername)
	if err != nil {
		return err
	}
	if s.IsUserEmpty(user) {
		return fmt.Errorf("user not found")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	s.DB.Model(&user).Updates(db.User{Username: newUsername, Password: string(hashedPassword)})
	return nil
}

func (s *Server) RegisterUserHandler(w http.ResponseWriter, r *http.Request) {
	var user struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if err := s.RegistrationUser(user.Username, user.Password); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

func (s *Server) LoginUserHandler(w http.ResponseWriter, r *http.Request) {
	var user struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	loggedInUser, err := s.LoginUser(user.Username, user.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(loggedInUser)
}

func (s *Server) EditUsernameHandler(w http.ResponseWriter, r *http.Request) {
	var usernames struct {
		OldUsername string `json:"old_username"`
		NewUsername string `json:"new_username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&usernames); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if err := s.EditUsername(usernames.OldUsername, usernames.NewUsername); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(usernames)
}

func (s *Server) EditUsernameAndPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var user struct {
		OldUsername string `json:"old_username"`
		NewUsername string `json:"new_username"`
		Password    string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if err := s.EditUsernameAndPassword(user.OldUsername, user.NewUsername, user.Password); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

func (s *Server) Start(addr string) error {
	router := mux.NewRouter()
	router.HandleFunc("/register", s.RegisterUserHandler).Methods("POST")
	router.HandleFunc("/login", s.LoginUserHandler).Methods("POST")
	router.HandleFunc("/edit-username", s.EditUsernameHandler).Methods("PUT")
	router.HandleFunc("/edit-username-password", s.EditUsernameAndPasswordHandler).Methods("PUT")

	return http.ListenAndServe(addr, router)
}
