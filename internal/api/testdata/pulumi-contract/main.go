package main

import "github.com/pulumi/pulumi/sdk/v3/go/pulumi"

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		ctx.Export("ready", pulumi.String("yes"))
		return nil
	})
}
