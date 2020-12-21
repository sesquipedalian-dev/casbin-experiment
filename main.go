package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2"
)

const (
	modelFile  = "config/model.conf"
	policyFile = "config/policy.csv"
)

type User struct {
	AccountId   string
	Permissions []string
}

type Data struct {
	AccountId string
}

func UserHasPermission(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return false, errors.New("expected 2 args")
	}

	user, ok := args[0].(User)
	if !ok {
		return false, errors.New("first arg not User")
	}

	permission, ok := args[1].(string)
	if !ok {
		return false, errors.New("second arg not string (permission)")
	}

	for _, userPermission := range user.Permissions {
		if userPermission == permission {
			return true, nil
		}

	}
	return false, nil
}

func UserResourceAccountIdMatch(resources map[string]Data) func(args ...interface{}) (interface{}, error) {
	return func(args ...interface{}) (interface{}, error) {

		if len(args) != 3 {
			return false, errors.New("expected 3 args")
		}

		user, ok := args[0].(User)
		if !ok {
			return false, errors.New("first arg not User")
		}

		resourcePath, ok := args[1].(string)
		if !ok {
			return false, errors.New("second arg not string (permission)")
		}

		split := strings.Split(resourcePath, "/")
		resourceId := split[len(split)-1]

		// resourceType, ok := args[2].(string)
		// if !ok {
		// 	return false, errors.New("third arg not string(resource type)")
		// }

		resource, ok := resources[resourceId]
		if !ok {
			return false, nil
		}

		match := user.AccountId == resource.AccountId
		fmt.Printf("UserResourceAccountIdMatch evaluation %v %v %v %v %v\n ", user, resourcePath, resourceId, resource, match)
		return match, nil
	}
}

func main() {
	enforcer, err := casbin.NewEnforcer(modelFile, policyFile)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Hello, World %v\n", enforcer)

	enforcer.AddFunction("userHasPermission", UserHasPermission)

	data := Data{
		AccountId: "baz",
	}
	resources := map[string]Data{
		"foo": data,
	}
	enforcer.AddFunction("userResourceAccountIdMatch", UserResourceAccountIdMatch(resources))

	sub := User{
		AccountId: "bar",
		Permissions: []string{
			"read_api_logs",
			"some_other_thing",
		},
	}
	obj := "/api_logs/foo"
	act := "read"

	ok, explain, err := enforcer.EnforceEx(sub, obj, act)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Was it OK for %v to do %v to %v? %t\n and then %v\n and then %v\n", sub, act, obj, ok, data, explain)

	obj = "/api_logs"
	ok, explain, err = enforcer.EnforceEx(sub, obj, act)
	if err != nil {
		panic(err)
	}

	fmt.Printf("222 Was it OK for %v to do %v to %v? %t\n and then %v\n and then %v\n", sub, act, obj, ok, data, explain)

	sub.AccountId = data.AccountId
	obj = "/api_logs/foo"

	ok, explain, err = enforcer.EnforceEx(sub, obj, act)
	if err != nil {
		panic(err)
	}

	fmt.Printf("333 Was it OK for %v to do %v to %v? %t\n and then %v\n and then %v\n", sub, act, obj, ok, data, explain)

}
