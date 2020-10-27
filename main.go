package main

import (
	"awesomeProject/tool"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
)

type User struct {
	ID int `json:"id"`
	Email string `json:"email"`
	Password string `json:"password"`
}

type JWT struct {
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"message"`
}

func createToken(user User) (string, error) {
	var err error

	secret := "secret"

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss": "__init__",
	})

	spew.Dump(token)
	tokenString, err := token.SignedString([]byte(secret))

	fmt.Println("-----------------------")
	fmt.Println("tokenString", tokenString)

	if err != nil {
		log.Fatal(err)
	}

	return tokenString, nil
}

func errorInResponse(w http.ResponseWriter, status int, error Error){
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
	return
}

func responseByJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
	return
}

func signup(w http.ResponseWriter, r *http.Request) {
	var user User
	var error Error

	fmt.Println(r.Body)
	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		error.Message = "Emailは必須です"
		errorInResponse(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "パスワードは必須です"
		errorInResponse(w, http.StatusBadRequest, error)
		return
	}

	fmt.Println(user)

	fmt.Println("----------------")
	//spew.Dump(user)

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("パスワード: ", user.Password)
	fmt.Println("ハッシュ化されたパスワード", hash)

	user.Password = string(hash)
	fmt.Println("コンバート後のパスワード: ", user.Password)

	sql_query := "INSERT INTO USERS(EMAIL, PASSWORD) VALUES($1, $2) RETURNING ID;"
	err = db.QueryRow(sql_query, user.Email, user.Password).Scan(&user.ID)

	if err != nil {
		error.Message = "サーバーエラー"
		errorInResponse(w, http.StatusInternalServerError, error)
		return
	}

	user.Password = ""
	w.Header().Set("Content-Type", "application/json")

	responseByJSON(w, user)

	w.Write([]byte("successfully called signup"))
}

func login(w http.ResponseWriter, r *http.Request) {
	var user User
	var error Error
	var jwt JWT

	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		error.Message = "Emailは必須です"
		errorInResponse(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "パスワードは必須です"
		errorInResponse(w, http.StatusBadRequest, error)
		return
	}

	password := user.Password
	fmt.Println("password: ", password)

	row := db.QueryRow("SELECT * FROM USERS WHERE email=$1;", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)

	if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "ユーザーが存在しません"
			errorInResponse(w, http.StatusBadRequest, error)
		} else {
			log.Fatal(err)
		}
	}

	hasedPassword := user.Password
	fmt.Println("hasedPassword: ", hasedPassword)

	err = bcrypt.CompareHashAndPassword([]byte(hasedPassword), []byte(password))

	if err != nil {
		error.Message = "無効なパスワードです"
		errorInResponse(w, http.StatusUnauthorized, error)
		return
	}

	token, err := createToken(user)
	if err != nil {
		log.Fatal(err)
	}

	w.WriteHeader(http.StatusOK)
	jwt.Token = token

	responseByJSON(w, jwt)
}

var db *sql.DB


func main() {
	i := tool.Info{}

	pgUrl, err := pq.ParseURL(i.GetDBUrl())

	if err != nil {
		log.Fatal()
	}

	db, err = sql.Open("postgres", pgUrl)
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()

	if err != nil {
		log.Fatal(err)
	}

	router := mux.NewRouter()

	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")

	log.Println("サーバー起動: 8000 port で受信")

	log.Fatal(http.ListenAndServe(":8000", router))
}