package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/gr0gu/cerberus/internal/storage"
)

func main() {
	dbPath := flag.String("db", "data/cerberus.db", "Path to SQLite database file")
	reset := flag.Bool("reset", true, "Delete existing database before seeding")
	flag.Parse()

	if *reset {
		log.Printf("Resetting database at %s...", *dbPath)
		_ = os.Remove(*dbPath)
		_ = os.Remove(*dbPath + "-wal")
		_ = os.Remove(*dbPath + "-shm")
	}

	store, err := storage.New(*dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	if err := store.SeedMockData(context.Background()); err != nil {
		log.Fatalf("Failed to seed mock data: %v", err)
	}

	log.Printf("Mock data successfully seeded into %s", *dbPath)
}
