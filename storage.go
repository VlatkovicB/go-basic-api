package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type Storage interface {
	CreateAccount(*Account) error
	DeleteAccount(int) error
	UpdateAccount(*Account) error
	GetAccountByID(int) (*Account, error)
	GetAccounts() ([]*Account, error)
	GetAccountByNumber(int) (*Account, error)
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore() (*PostgresStore, error) {
	connStr := "user=postgres dbname=gobank password=postgres port=5433 sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &PostgresStore{
		db: db,
	}, nil
}

func (s *PostgresStore) Init() error {
	return s.createAccountTable()
}

func (s *PostgresStore) createAccountTable() error {
	query := `CREATE TABLE IF NOT EXISTS accounts (
		id serial primary key,
		first_name varchar(255),
		last_name varchar(255),
		password varchar(255),
		number serial,
		balance integer,
		created_at timestamp
	);`

	_, err := s.db.Exec(query)

	return err
}

func (s *PostgresStore) CreateAccount(acc *Account) error {
	q, err := s.db.Prepare(`
	INSERT INTO accounts (first_name, last_name, password,  balance, number, created_at) 
	VALUES ($1, $2, $3, $4, $5, $6)`)
	if err != nil {
		return err
	}

	defer q.Close()

	_, err = q.Exec(acc.FirstName, acc.LastName, acc.EncryptedPassword, acc.Balance, acc.Number, acc.CreatedAt)

	if err != nil {
		log.Fatal()
	}

	return nil
}

func (s *PostgresStore) DeleteAccount(id int) error {
	_, err := s.db.Query("DELETE FROM accounts WHERE id = $1", id)
	return err
}

func (s *PostgresStore) UpdateAccount(*Account) error {
	return nil
}

func (s *PostgresStore) GetAccountByID(id int) (*Account, error) {
	rows, err := s.db.Query("SELECT * FROM accounts WHERE id= $1", id)

	if err != nil {
		return nil, err
	}

	for rows.Next() {

		return scanIntoAccount(rows)
	}

	return nil, fmt.Errorf("account %d not found", id)
}

func (s *PostgresStore) GetAccounts() ([]*Account, error) {
	rows, err := s.db.Query(`SELECT * FROM accounts`)

	if err != nil {
		log.Fatal()
	}

	defer rows.Close()

	// An album slice to hold data from returned rows.
	accounts := []*Account{}

	for rows.Next() {
		acc, err := scanIntoAccount(rows)

		if err != nil {
			return nil, err
		}

		accounts = append(accounts, acc)
	}

	return accounts, nil
}

func (s *PostgresStore) GetAccountByNumber(number int) (*Account, error) {
	rows, err := s.db.Query(`SELECT * FROM accounts WHERE number = $1`, number)

	if err != nil {
		log.Fatal()
	}

	defer rows.Close()

	for rows.Next() {

		return scanIntoAccount(rows)
	}

	return nil, fmt.Errorf("account %d not found", number)
}

func scanIntoAccount(rows *sql.Rows) (*Account, error) {
	account := new(Account)
	err := rows.Scan(
		&account.ID,
		&account.FirstName,
		&account.LastName,
		&account.EncryptedPassword,
		&account.Number,
		&account.Balance,
		&account.CreatedAt)

	return account, err
}
