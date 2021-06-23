package main

import (
	"log"
	"os"

	"github.com/go-pg/pg/v10"
	migrations "github.com/robinjoseph08/go-pg-migrations/v3"
)

const directory = "migrate"

func main() {
	db := pg.Connect(&pg.Options{
		Addr:     "localhost:5432",
		User:     "admin",
		Database: "admin",
		Password: "",
	})

	err := migrations.Run(db, directory, os.Args)
	if err != nil {
		log.Fatalln(err)
	}
}
