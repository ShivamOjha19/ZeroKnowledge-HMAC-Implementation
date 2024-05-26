package main

import (
	"fmt"
	HMAC_env "tmp/src/HMAC/core"
	seed_env "tmp/src/SeedGeneration/core"
)

//import test_ut "tmp/src/SeedGeneration/utils"

func main() {
	//fmt.Println(val1.Test2)
	var my_seed = seed_env.NewSeedGenerator("jack").Generate()
	var obj = HMAC_env.NewHMACClient("seed_env", my_seed, 1)
	obj.InitDecryptDict()


	fmt.Println("Example 1 code running")
fmt.Println("Example 2 code running")
fmt.Println("Example 3 code running")
fmt.Println("Running HMAC and SeedGeneration test")

}
