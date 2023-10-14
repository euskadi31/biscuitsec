package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/biscuit-auth/biscuit-go/v2/parser"
	"github.com/davecgh/go-spew/spew"
)

var (
	publicKeyString  = "iWlbYg08RKVFTobd/O5U9UOkgtc4vyp6I3eOXLRp7AE="
	privateKeyString = "0KezCI5JQSZSKVw1rDmq/eOdIPirEttdvz3g+8Pf/3+JaVtiDTxEpUVOht387lT1Q6SC1zi/Knojd45ctGnsAQ=="
)

func main() {
	privateKey, err := base64.StdEncoding.DecodeString(privateKeyString)
	if err != nil {
		panic(err)
	}

	authority, err := parser.FromStringBlockWithParams(`
	user(1233);
	category({all});
	operation({write});`, map[string]biscuit.Term{
		"read":  biscuit.String("read"),
		"write": biscuit.String("write"),
		"all":   biscuit.String("@all"),
	})
	if err != nil {
		panic(fmt.Errorf("failed to parse authority block: %w", err))
	}

	builder := biscuit.NewBuilder(privateKey)
	if err := builder.AddBlock(authority); err != nil {
		panic(fmt.Errorf("failed to add authority block: %w", err))
	}

	b, err := builder.Build()
	if err != nil {
		panic(fmt.Errorf("failed to build biscuit: %w", err))
	}

	token, err := b.Serialize()
	if err != nil {
		panic(fmt.Errorf("failed to serialize biscuit: %w", err))
	}

	tokenBased := base64.URLEncoding.EncodeToString(token)

	fmt.Printf("Token: %s\n", tokenBased)

	b, err = biscuit.Unmarshal(token)
	if err != nil {
		panic(fmt.Errorf("failed to unmarshal biscuit: %w", err))
	}

	publicKey, err := base64.StdEncoding.DecodeString(publicKeyString)
	if err != nil {
		panic(fmt.Errorf("failed to decode public key: %w", err))
	}

	authorizer, err := b.Authorizer(ed25519.PublicKey(publicKey))
	if err != nil {
		panic(fmt.Errorf("failed to create authorizer: %w", err))
	}
	/*
		fu, err := parser.New().Fact(`user(1233)`, map[string]biscuit.Term{})
		if err != nil {
			panic(fmt.Errorf("failed to create fact: %w", err))
		}

		authorizer.AddFact(fu)
	*/
	authorizer.AddPolicy(biscuit.DefaultAllowPolicy)

	rule, err := parser.FromStringRule(`data($id) <- user($id)`)
	if err != nil {
		panic(fmt.Errorf("failed to create rule: %w", err))
	}

	fmt.Print(authorizer.PrintWorld())

	facts, err := authorizer.Query(rule)
	if err != nil {
		panic(fmt.Errorf("failed to query rule: %w", err))
	}

	spew.Dump(facts)

	err = authorizer.Authorize()
	if err != nil {
		panic(fmt.Errorf("failed to authorize: %w", err))
	}
}
