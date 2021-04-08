import * as aws from "@pulumi/aws"
import { AWSPrincipal } from "@pulumi/aws/iam"
import * as pulumi from "@pulumi/pulumi"
import * as merge from "deepmerge"

import { PolicyDocument } from "../iam"


interface KeyArgs extends aws.kms.KeyArgs {
    /** Extend aws.s3.KeyArgs to disable properties we control */
    policy?: never,
}



export class Key extends pulumi.ComponentResource {
    /**
     * Creates a new KMS key
     */
    readonly resource: aws.kms.Key

    private policy: PolicyDocument
    private encryptPrincipal?: AWSPrincipal
    private decryptPrincipal?: AWSPrincipal

    constructor(name: string, args: { accountId: string, keyArgs?: KeyArgs }, opts?: pulumi.ResourceOptions) {
        const inputs: pulumi.Inputs = { options: opts }
        super("lazy-aws:kms:Key", name, inputs, opts)

        // add default statement to key policy
        this.policy = new PolicyDocument(name)
            .addStatement({
                Sid: "Enable IAM User Permissions",
                Effect: "Allow",
                Action: "kms:*",
                Resource: "*",
                Principal: { AWS: `arn:aws:iam::${args.accountId}:root` }
            })

        // create key
        let keyArgs = { policy: this.policy.json }
        if (args.keyArgs) {
            keyArgs = merge(keyArgs, args.keyArgs)
        }
        this.resource = new aws.kms.Key(name, keyArgs, opts)
    }

    private getEncryptStatement(principal?: AWSPrincipal): aws.iam.PolicyStatement {
        let stmt: aws.iam.PolicyStatement = {
            Sid: "Encrypt",
            Effect: "Allow",
            Action: ["kms:Encrypt"],
            Resource: ["*"]
        }
        if (principal) {
            stmt = merge(stmt, { "Principal": principal })
        }
        return stmt
    }

    private getDecryptStatement(principal?: AWSPrincipal): aws.iam.PolicyStatement {
        let stmt: aws.iam.PolicyStatement = {
            Sid: "Decrypt",
            Effect: "Allow",
            Action: ["kms:Decrypt", "kms:GenerateDataKey"],
            Resource: ["*"]
        }
        if (principal) {
            stmt = merge(stmt, { "Principal": principal })
        }
        return stmt
    }

    public grantEncryptToPrincipal(principal: AWSPrincipal) {
        if (!this.encryptPrincipal) {
            this.encryptPrincipal = principal
            const stmt = this.getEncryptStatement(this.encryptPrincipal)
            this.policy.addStatement(stmt)
            return
        }

        merge(this.encryptPrincipal, principal)
    }

    public grantDecryptToPrincipal(principal: AWSPrincipal) {
        if (!this.decryptPrincipal) {
            this.decryptPrincipal = principal
            this.policy.addStatement(this.getDecryptStatement(this.decryptPrincipal))
            return
        }

        merge(this.decryptPrincipal, principal)
    }
}
