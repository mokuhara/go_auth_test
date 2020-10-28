package main

import (
	"awesomeProject/tool"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strings"
	"time"
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

const (
	secret = "VgHIOzK076FnCHA3NYgrJ2fZdfr9y5RRV5XBgwqvgNzNNop/7jC7Bg=="
	userIDKey = "user_id"
	iatKey =    "iat"
	expKey =    "exp"
	lifetime =  30 * time.Minute
)

type Auth struct {
	UserID int
	Iat    int64
}

func Generate(userID int, now time.Time) (string, error){
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		userIDKey: userID,
		iatKey:    now.Unix(),
		expKey:    now.Add(lifetime).Unix(),
	})

	return token.SignedString([]byte(secret))
}


func tokenVerify(r *http.Request) (string, string) {
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")
		fmt.Println("bearerToken: ", bearerToken)

		if len(bearerToken) == 2 {
			authToken := bearerToken[1]

			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("エラーが発生しました。")
				}
				return []byte(secret), nil
			})

			if error != nil {
				return "",  "failed token parse"
			}

			if token.Valid {
				return "ok", ""

			} else {
				return "",  "failed token valid"
			}
		} else {
			return "","invalid token"
		}
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
		error.Message = "require email"
		errorInResponse(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "require password"
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

	user.Password = string(hash)

	sql_query := "INSERT INTO USERS(EMAIL, PASSWORD) VALUES($1, $2) RETURNING ID;"
	err = db.QueryRow(sql_query, user.Email, user.Password).Scan(&user.ID)

	if err != nil {
		error.Message = "sever error"
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
		error.Message = "require email"
		errorInResponse(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		error.Message = "require password"
		errorInResponse(w, http.StatusBadRequest, error)
		return
	}

	password := user.Password
	fmt.Println("password: ", password)

	row := db.QueryRow("SELECT * FROM USERS WHERE email=$1;", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)

	if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "no match user"
			errorInResponse(w, http.StatusBadRequest, error)
		} else {
			log.Fatal(err)
		}
	}

	hasedPassword := user.Password
	fmt.Println("hasedPassword: ", hasedPassword)

	err = bcrypt.CompareHashAndPassword([]byte(hasedPassword), []byte(password))

	if err != nil {
		error.Message = "invalid password"
		errorInResponse(w, http.StatusUnauthorized, error)
		return
	}

	token, err := Generate(user.ID, time.Now())
	if err != nil {
		log.Fatal(err)
	}

	w.WriteHeader(http.StatusOK)
	jwt.Token = token

	responseByJSON(w, jwt)
}

var db *sql.DB

func hoge(w http.ResponseWriter, r *http.Request){
	ok, _ := tokenVerify(r)
	if ok != "ok" {
		errorInResponse(w, http.StatusBadRequest, Error{Message: "invalid token"})
		return
	}
	w.Write([]byte("successfully verify token"))
}

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
	router.HandleFunc("/hoge", hoge).Methods("GET")

	log.Println("server start. listen to 8000 port")

	log.Fatal(http.ListenAndServe(":8000", router))
}