package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator/v10"
	_ "github.com/lib/pq"
	"github.com/minio/minio-go/v7"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
	"myproj/database"
	"myproj/minio-client"
	"net/http"
	"strings"
	"time"
)

var key = []byte("hwq436u425g32r3555")

type AuthUser struct {
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type User struct {
	Username string `json:"username"`
	Email    string `json:"email" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type Token struct {
	ID    uint   `json:"id"`
	Email string `json:"email"`
	jwt.StandardClaims
}

func (user User) hash_password() string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(user.Password), 14)
	fmt.Println(1 << 14)
	return string(hash)
}

type ErrorResponse struct {
	Message any `json:"message"`
}

func MethodNotAllowed(allowed_method string, response http.ResponseWriter) {
	var errorMessage ErrorResponse
	errorMessage.Message = fmt.Sprintf("Only %v method allowed", allowed_method)
	response.WriteHeader(http.StatusMethodNotAllowed)
	errorResponse, _ := json.Marshal(errorMessage)
	response.Write(errorResponse)
	fmt.Fprint(response)
}

func IncorrectData(errorText []string, response http.ResponseWriter) {
	var errorMessage ErrorResponse
	errorMessage.Message = errorText
	response.WriteHeader(http.StatusUnprocessableEntity)
	errorResponse, _ := json.Marshal(errorMessage)
	response.Write(errorResponse)
	fmt.Fprint(response)
}

func CustomError(errorText string, errorStatus int, response http.ResponseWriter) {
	var errorMessage ErrorResponse
	errorMessage.Message = errorText
	response.WriteHeader(errorStatus)
	errorResponse, _ := json.Marshal(errorMessage)
	response.Write(errorResponse)
	fmt.Fprint(response)
}

func loadBody2[T any](response http.ResponseWriter, request *http.Request, errorStatus int) (T, error) {
	var loadStruct T
	err := json.NewDecoder(request.Body).Decode(&loadStruct)
	if err != nil {
		http.Error(response, err.Error(), errorStatus)
		return loadStruct, err
	}
	validate := validator.New()
	if err := validate.Struct(loadStruct); err != nil {
		var errs validator.ValidationErrors
		errors.As(err, &errs)
		lenErrorsMsg := len(errs)
		var errorsMsg = make([]string, lenErrorsMsg)
		for i, fieldErr := range errs {
			errorMsg := fmt.Sprintf("field %s: %s", fieldErr.Field(), fieldErr.Tag())
			errorsMsg[i] = errorMsg
		}
		IncorrectData(errorsMsg, response)
		return loadStruct, err
	}
	return loadStruct, err
}

func ValidateToken(bearerToken string) (*jwt.Token, error) {
	tokenString := strings.Split(bearerToken, " ")[1]
	token, err := jwt.ParseWithClaims(tokenString, &Token{}, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})
	return token, err
}

func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearerToken := r.Header.Get("Authorization")
		token, err := ValidateToken(bearerToken)

		if err != nil {
			if errors.Is(err, jwt.ErrSignatureInvalid) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !token.Valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		user := token.Claims.(*Token)
		ctx := r.Context()
		request := r.WithContext(context.WithValue(ctx, "user_id", user.ID))
		next.ServeHTTP(w, request)
	})
}

func signUp(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		MethodNotAllowed("POST", response)
		return
	}
	validatedUser, err := loadBody2[User](response, request, http.StatusBadRequest)
	if err != nil {
		return
	}
	hashedPassword := validatedUser.hash_password()
	db := database.InitDbConnect()
	if db == nil {
		CustomError("Database error", http.StatusInternalServerError, response)
		return
	}
	newUser := database.UserDB{
		Email:    validatedUser.Email,
		Password: hashedPassword,
		Username: validatedUser.Username,
	}
	db.Create(&newUser)
	response.WriteHeader(http.StatusCreated)
	fmt.Fprint(response)

}

func signIn(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		MethodNotAllowed("POST", response)
		return
	}

	validatedAuth, err := loadBody2[AuthUser](response, request, http.StatusUnauthorized)
	if err != nil {
		return
	}

	var user database.UserDB
	db := database.InitDbConnect()
	if db == nil {
		http.Error(response, "Database error", http.StatusInternalServerError)
		return
	}
	query := db.First(&user, "email = ?", validatedAuth.Email)
	if query.Error != nil {
		fmt.Println(query.Error)
		http.Error(response, "Unknown email", http.StatusUnauthorized)
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(validatedAuth.Password))
	if err != nil {
		http.Error(response, "Incorrect password", http.StatusUnauthorized)
		return
	}

	var tokenClaim = Token{
		ID:    user.ID,
		Email: user.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenClaim)
	tokenString, err := token.SignedString(key)

	// Отдаем токен клиенту
	response.Write([]byte(tokenString))
	fmt.Fprint(response)
}

func uploadFile(response http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		MethodNotAllowed("POST", response)
		return
	}
	userId := request.Context().Value("user_id").(uint)

	err := request.ParseMultipartForm(10 << 20) // maxMemory 32MB
	if err != nil {
		fmt.Println(err)
		CustomError("File size more than available", http.StatusBadRequest, response)
		return
	}

	file, h, err := request.FormFile("photo")
	if err != nil {
		fmt.Println(err)
		CustomError("unknown file", http.StatusBadRequest, response)
		return
	}

	client, err := minio_client.GetMinioClient()
	if err != nil {
		fmt.Println(err)
		CustomError("Can't connect to minio", http.StatusInternalServerError, response)
		return
	}

	_, err = client.PutObject(
		context.Background(),
		minio_client.MinioBucket,
		minio_client.MinioFolder+h.Filename,
		file,
		h.Size,
		minio.PutObjectOptions{ContentType: "application/octet-stream"})
	if err != nil {
		fmt.Println(err)
		response.WriteHeader(http.StatusInternalServerError)
		return
	}

	db := database.InitDbConnect()
	if db == nil {
		http.Error(response, "Database error", http.StatusInternalServerError)
		return
	}
	newFile := database.FileDB{
		UserId:   userId,
		Filepath: h.Filename,
	}
	db.Create(&newFile)

	var resp struct {
		Filepath string `json:"filepath"`
	}
	resp.Filepath = fmt.Sprintf("http://%s/%s/%s%s", minio_client.GetMinioEndpoint(), minio_client.MinioBucket, minio_client.MinioFolder, h.Filename)
	filepathResponse, _ := json.Marshal(resp)
	response.Write(filepathResponse)
	fmt.Fprint(response)
}

func getFiles(response http.ResponseWriter, request *http.Request) {
	if request.Method != "GET" {
		MethodNotAllowed("GET", response)
		return
	}
	userId := request.Context().Value("user_id").(uint)

	var files []database.FileDB
	db := database.InitDbConnect()
	if db == nil {
		http.Error(response, "Database error", http.StatusInternalServerError)
		return
	}
	db.Find(&files, "user_id = ?", userId)
	responseFiles := make([]string, len(files))
	for i, file := range files {
		responseFiles[i] = fmt.Sprintf("http://%s/%s/%s%s", minio_client.GetMinioEndpoint(), minio_client.MinioBucket, minio_client.MinioFolder, file.Filepath)
	}
	filepathResponse, _ := json.Marshal(responseFiles)
	response.Write(filepathResponse)
	fmt.Fprint(response)
}

func main() {
	Migration()
	mux := http.NewServeMux()

	mux.HandleFunc("/sign-up/", signUp)
	mux.HandleFunc("/sign-in/", signIn)

	uploadHandler := http.HandlerFunc(uploadFile)
	getFileHandler := http.HandlerFunc(getFiles)
	mux.Handle("/upload-file/", jwtMiddleware(uploadHandler))
	mux.Handle("/get-user-files/", jwtMiddleware(getFileHandler))

	// Start the server on port 8000
	fmt.Println("Server started: http://localhost:8000")
	err := http.ListenAndServe(":8000", mux)
	if err != nil {
		fmt.Println("Error starting server:", err)
	}
}
