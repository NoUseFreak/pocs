package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
)

func New(id string) *Mod {
	mod := &Mod{
		ID:       id,
		Children: []*Mod{},
	}

	parts := strings.SplitN(id, "@", 2)
	mod.Package = parts[0]
	if len(parts) > 1 {
		mod.Version = parts[1]
	} else {
		mod.Version = "undefined"
	}

	return mod
}

type Mod struct {
	ID       string `json:"id"`
	Package  string `json:"package"`
	Version  string `json:"version"`
	Children []*Mod `json:"children"`
}

func (m *Mod) put(mod *Mod) bool {
	if m.ID == mod.ID {
		m.Children = append(m.Children, mod.Children...)
		return true
	}
	for i := range m.Children {
		if m.Children[i].put(mod) {
			return true
		}
	}

	return false
}

func main() {
	// check if there is somethinig to read on STDIN
	stat, _ := os.Stdin.Stat()

	if ((stat.Mode() & os.ModeCharDevice) == 0) == false {
		log.Fatal("No input on STDIN")
	}
	mods := []*Mod{}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		base := parseMod(scanner.Text())
		found := false

		for i := range mods {
			if !found && mods[i].put(&base) {
				found = true
			}
		}
		if !found {
			mods = append(mods, &base)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	for i := range mods {
		mods[i].print("", "")
		//printJson(mods[i])
	}

}

func (mod Mod) printJson() {
	modsJson, err := json.MarshalIndent(mod, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(modsJson))
}

func (mod Mod) print(prefix, childPrefix string) {
	fmt.Println(prefix + mod.Package)

	for i := range mod.Children {
		if i == len(mod.Children)-1 {
			mod.Children[i].print(childPrefix+"└── ", childPrefix+"    ")
		} else {
			mod.Children[i].print(childPrefix+"├──", childPrefix+"│   ")
		}
	}
}

func parseMod(mod string) Mod {
	parts := strings.SplitN(mod, " ", 2)

	m := New(parts[0])
	m.Children = []*Mod{New(parts[1])}
	return *m
}
