package todo

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/sebastianhafstrom/system/internal/logger"
)

type Todo struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Description *string `json:"description,omitempty"`
	Completed   bool    `json:"completed"`
	CreatedAt   string  `json:"created_at,omitempty"`
}

func ListTodos(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	log := logger.Logger
	log.Info("Listing todos")
	rows, err := db.Query("SELECT * FROM todos")
	if err != nil {
		log.Error("failed to lost todos", "error", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var todos []Todo
	for rows.Next() {
		var t Todo
		if err := rows.Scan(&t.ID, &t.Title, &t.Description, &t.Completed, &t.CreatedAt); err != nil {
			log.Error("failed to scan todo", "error", err)
			continue
		}
		todos = append(todos, t)
	}

	json.NewEncoder(w).Encode(todos)
}

func GetTodo(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	log := logger.Logger

	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "missing todo ID", http.StatusBadRequest)
		return
	}

	var t Todo
	err := db.QueryRow("SELECT * FROM todos WHERE id = $1", id).Scan(&t.ID, &t.Title, &t.Description, &t.Completed, &t.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "todo not found", http.StatusNotFound)
			return
		}
		log.Error("failed to get todo", "error", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(t)
}

func CreateTodo(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	log := logger.Logger

	var t Todo
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		log.Error("failed to decode todo", "error", err)
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if t.Title == "" {
		http.Error(w, "title is required", http.StatusBadRequest)
		return
	}

	t.ID = uuid.NewString()
	err := db.QueryRow("INSERT INTO todos (id, title, completed) VALUES ($1, $2, $3) RETURNING id", t.ID, t.Title, t.Completed).Scan(&t.ID)
	if err != nil {
		log.Error("failed to create todo", "error", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(t)
}

func DeleteTodo(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	log := logger.Logger

	id := mux.Vars(r)["id"]
	if id == "" {
		http.Error(w, "missing todo ID", http.StatusBadRequest)
		return
	}

	result, err := db.Exec("DELETE FROM todos WHERE id = $1", id)
	if err != nil {
		log.Error("failed to delete todo", "error", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error("failed to get rows affected", "error", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	if rowsAffected == 0 {
		http.Error(w, "todo not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	log.Info("todo deleted successfully", "id", id)
}
