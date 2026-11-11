// Benign Go program for garble (VALIDATION §84): prints the five benchmark canaries. Built with
// `garble -literals -tiny build` (literal obfuscation: each string is rebuilt at run time by an
// inline XOR/shuffle/split decoder; -tiny drops position info and panic messages; names hashed).
package main

import "fmt"

//go:noinline
func show(s string) { fmt.Println(s) }

func main() {
	show("canary::alpha::7f3c-config-endpoint")
	show("canary::bravo::build-id-20261018")
	show("canary::charlie::/opt/app/resources/data.bin")
	show("canary::delta::feature-flag-telemetry-off")
	show("canary::echo::schema-version-4")
}
