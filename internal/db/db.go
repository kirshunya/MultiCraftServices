package db

import (
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"log"
	funct "multicraft-microservice/fuct"
)

func FindUser(username string, db gorm.DB) User {
	var user User
	db.Find(&user, "username = ?", username)
	if IsUserEmpty(user) {
		log.Fatal("User not found.")
	}
	return user
}

func IsUserEmpty(user User) bool {
	return user == User{}
}

func MigrateSchemes(db gorm.DB, user User) {
	db.AutoMigrate(&User{})
	log.Println("Migration successful")
}

func ConnectToDB() {
	dsn := "freedb_abobus:Vfb&mDMpc9n#@6B@tcp(sql.freedb.tech:3306)/freedb_multicraft?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to the database: ", err)
	}

	log.Println("Connection successful")

	db.AutoMigrate(&User{})
}

func RegistrationUser(username, password string, db gorm.DB) {
	hashedPassword := funct.HashingPassword(password)

	user := User{
		Username: username,
		Password: string(hashedPassword),
	}

	var count int64
	db.Model(&User{}).Where("username = ?", username).Count(&count)
	if count == 0 {
		if err := db.Create(&user).Error; err != nil {
			log.Fatal("Error of registration:", err)
		}
		log.Println("User created.")
	} else {
		log.Println("User already exist.")
	}
}

func LoginUser(username, password string, db gorm.DB) User {
	user := FindUser(username, db)

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		log.Fatal("Invalid password.")
	}

	log.Println("Login successful")

	return user
}

func EditUsername(oldUsername, newUsername string, db gorm.DB) {
	user := FindUser(oldUsername, db)
	if len(newUsername) >= 6 {
		db.Model(&user).Update("Username", newUsername)
		log.Println("Username updated.")
	} else {
		log.Println("Username must be 6 characters long.")
	}
}

func EditUsernameAndPassword(oldUsername, newUsername, password string, db gorm.DB) {
	user := FindUser(oldUsername, db)
	hashedPassword := funct.HashingPassword(password)
	db.Model(&user).Updates(User{Username: newUsername, Password: hashedPassword})
}
