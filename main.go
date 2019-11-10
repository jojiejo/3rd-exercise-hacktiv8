package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var encryptionKey = "something-very-secret"
var loggedUserSession = sessions.NewCookieStore([]byte(encryptionKey))
var message Message

func init() {
	loggedUserSession.Options = &sessions.Options{
		// change domain to match your machine. Can be localhost
		// IF the Domain name doesn't match, your session will be EMPTY!
		Domain:   "localhost",
		Path:     "/",
		MaxAge:   3600 * 3, // 3 hours
		HttpOnly: true,
	}
}

type DisplayedUser struct {
	ID        int    `json:"id"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
}

type User struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	Password  string `json:"password"`
}

type Message struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type MessageWithData struct {
	Success bool            `json:"success"`
	Message string          `json:"message"`
	Data    []DisplayedUser `json:"data"`
}

func pageIndex(w http.ResponseWriter, r *http.Request) {
	var tmpl = template.Must(template.ParseFiles(
		"views/index.html",
	))

	err := tmpl.ExecuteTemplate(w, "index", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func signIn(w http.ResponseWriter, r *http.Request) {
	var user User
	var dbPassword []byte
	var privilege string
	var id string

	w.Header().Set("Content-Type", "application/json")

	_ = json.NewDecoder(r.Body).Decode(&user)

	db, err := sql.Open("mysql", "root:@/user?charset=utf8")
	defer db.Close()
	checkErr(err)

	row, err := db.Query("SELECT id, password, privilege FROM `user` WHERE email = ? LIMIT 0, 1", user.Email)
	checkErr(err)

	for row.Next() {
		err = row.Scan(&id, &dbPassword, &privilege)
		checkErr(err)
	}

	if err := bcrypt.CompareHashAndPassword(dbPassword, []byte(user.Password)); err != nil {
		message.Success = false
		message.Message = "Wrong username / password."
	} else {
		session, err := loggedUserSession.Get(r, "authentication")
		if err != nil {
			message.Success = false
			message.Message = "Session error."
		}
		session.Values["email"] = user.Email
		session.Values["privilege"] = privilege
		session.Values["id"] = id

		err = session.Save(r, w)
		if err != nil {
			message.Success = false
			message.Message = "Could not create new session."
		}

		message.Success = true
		message.Message = "Your email is authenticated successfully."
	}

	json.NewEncoder(w).Encode(message)
}

func signOut(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	session, _ := loggedUserSession.Get(r, "authentication")

	// remove the username
	session.Values["email"] = ""
	session.Values["privilege"] = ""
	session.Values["id"] = ""
	err := session.Save(r, w)

	if err != nil {
		message.Success = true
		message.Message = "Failed to log out selected account."
	} else {
		message.Success = true
		message.Message = "Your account has been logged out successfully."
	}

	json.NewEncoder(w).Encode(&message)
}

func pageSignUp(w http.ResponseWriter, r *http.Request) {
	var tmpl = template.Must(template.ParseFiles(
		"views/signup.html",
	))

	err := tmpl.ExecuteTemplate(w, "signup", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func signUp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user User

	_ = json.NewDecoder(r.Body).Decode(&user)

	if m, _ := regexp.MatchString("^([\\w\\.\\_]{2,10})@(\\w{1,}).([a-z]{2,4})$", user.Email); !m {
		message.Success = false
		message.Message = "Email format does not match."

		json.NewEncoder(w).Encode(&message)
		return
	}

	db, err := sql.Open("mysql", "root:@/user?charset=utf8")
	defer db.Close()
	checkErr(err)

	password := []byte(user.Password)
	hashedPassword, err := bcrypt.GenerateFromPassword(password, 10)
	checkErr(err)

	stmt, err := db.Prepare("INSERT INTO `user` VALUES (null, ?, ?, ?, ?, ?)")
	checkErr(err)

	_, err = stmt.Exec(user.FirstName, user.LastName, user.Email, string(hashedPassword), "user")
	checkErr(err)

	if err != nil {
		message.Success = false
		message.Message = "Failed to register your account."
	} else {
		message.Success = true
		message.Message = "Your registration has been completed successfully."
	}

	json.NewEncoder(w).Encode(&message)
}

func mainPage(w http.ResponseWriter, r *http.Request) {
	conditionsMap := map[string]interface{}{}
	session, _ := loggedUserSession.Get(r, "authentication")

	if session != nil {
		conditionsMap["Email"] = session.Values["email"]
		conditionsMap["Privilege"] = session.Values["privilege"]
		conditionsMap["ID"] = session.Values["id"]
	}

	var tmpl = template.Must(template.ParseFiles(
		"views/main_page.html",
	))

	err := tmpl.ExecuteTemplate(w, "main_page", conditionsMap)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	var message MessageWithData

	w.Header().Set("Content-Type", "application/json")

	db, err := sql.Open("mysql", "root:@/user?charset=utf8")
	defer db.Close()
	checkErr(err)

	rows, err := db.Query("SELECT id, first_name, last_name, email FROM `user`")
	checkErr(err)

	var displayedUsers []DisplayedUser

	for rows.Next() {
		var id int
		var firstName string
		var lastName string
		var email string
		err = rows.Scan(&id, &firstName, &lastName, &email)
		checkErr(err)

		displayedUsers = append(displayedUsers, DisplayedUser{id, firstName, lastName, email})
	}

	message.Success = true
	message.Message = "Success fetching data."
	message.Data = displayedUsers

	json.NewEncoder(w).Encode(&message)
}

func getUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]

	var message MessageWithData

	w.Header().Set("Content-Type", "application/json")

	db, err := sql.Open("mysql", "root:@/user?charset=utf8")
	defer db.Close()
	checkErr(err)

	rows, err := db.Query("SELECT id, first_name, last_name, email FROM `user` WHERE id = ?", id)
	checkErr(err)

	var displayedUsers []DisplayedUser

	for rows.Next() {
		var id int
		var firstName string
		var lastName string
		var email string
		err = rows.Scan(&id, &firstName, &lastName, &email)
		checkErr(err)

		displayedUsers = append(displayedUsers, DisplayedUser{id, firstName, lastName, email})
	}

	message.Success = true
	message.Message = "Success fetching data."
	message.Data = displayedUsers

	json.NewEncoder(w).Encode(&message)
}

func putUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user User

	params := mux.Vars(r)
	id := params["id"]

	_ = json.NewDecoder(r.Body).Decode(&user)
	db, err := sql.Open("mysql", "root:@/user?charset=utf8")
	defer db.Close()
	checkErr(err)

	password := []byte(user.Password)
	hashedPassword, err := bcrypt.GenerateFromPassword(password, 10)
	checkErr(err)

	stmt, err := db.Prepare("UPDATE `user` SET first_name = ?, last_name = ?, email = ?, password = ? WHERE id = ?")
	checkErr(err)

	_, err = stmt.Exec(user.FirstName, user.LastName, user.Email, string(hashedPassword), id)
	checkErr(err)

	if err != nil {
		message.Success = false
		message.Message = "Failed to update selected account."
	} else {
		message.Success = true
		message.Message = "The update process has been completed successfully."
	}

	json.NewEncoder(w).Encode(&message)
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	params := mux.Vars(r)
	id := params["id"]

	db, err := sql.Open("mysql", "root:@/user?charset=utf8")
	defer db.Close()
	checkErr(err)

	stmt, err := db.Prepare("DELETE FROM `user` WHERE id = ?")
	checkErr(err)

	_, err = stmt.Exec(id)
	checkErr(err)

	if err != nil {
		message.Success = false
		message.Message = "Failed to delete selected account."
	} else {
		message.Success = true
		message.Message = "The delete process has been completed successfully."
	}

	json.NewEncoder(w).Encode(&message)
}

func main() {
	router := mux.NewRouter()

	router.HandleFunc("/", pageIndex).Methods("GET")
	router.HandleFunc("/signin", signIn).Methods("POST")
	router.HandleFunc("/signout", signOut).Methods("GET")
	router.HandleFunc("/signup", pageSignUp).Methods("GET")
	router.HandleFunc("/signup", signUp).Methods("POST")
	router.HandleFunc("/mainpage", mainPage).Methods("GET")
	router.HandleFunc("/users", getUsers).Methods("GET")
	router.HandleFunc("/user/{id}", getUser).Methods("GET")
	router.HandleFunc("/user", signUp).Methods("POST")
	router.HandleFunc("/user/{id}", putUser).Methods("PUT")
	router.HandleFunc("/user/{id}", deleteUser).Methods("DELETE")
	fmt.Println("Web Service Started")

	err := http.ListenAndServe(":8000", router)
	if err != nil {
		log.Fatal("Error running service: ", err)
	}
}

func checkErr(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
