import * as aws from "@pulumi/aws"
import { AWSPrincipal } from "@pulumi/aws/iam"
import * as pulumi from "@pulumi/pulumi"
import * as merge from "deepmerge"

import { Key } from "../kms"
import { PolicyDocument } from "../iam"


interface BucketArgs extends aws.s3.BucketArgs {
    /** Extend aws.s3.BucketArgs to disable properties we control */
    policy?: never,
    serverSideEncryptionConfiguration?: never,
}

export interface EncryptedBucketArgs {
    kmsKey: Key,
    // passthrough BucketArgs to aws.s3.Bucket
    bucketArgs?: BucketArgs
}

export class EncryptedBucket extends pulumi.ComponentResource {
    /**
     * Creates a new S3 bucket with encryption enabled.
     */
    readonly resource: aws.s3.Bucket

    private kmsKey: Key
    private name: string
    private opts?: pulumi.ResourceOptions
    private _policy?: PolicyDocument
    private readPrincipal?: AWSPrincipal
    private writePrincipal?: AWSPrincipal

    constructor(name: string, args: EncryptedBucketArgs, opts?: pulumi.ResourceOptions) {
        super("lazy-aws:s3:EncryptedBucket", name, args, opts)

        this.kmsKey = args.kmsKey
        this.name = name
        this.opts = opts

        // create s3 bucket
        let bucketArgs = {
            serverSideEncryptionConfiguration: {
                rule: {
                    applyServerSideEncryptionByDefault: {
                        kmsMasterKeyId: args.kmsKey.resource.arn,
                        sseAlgorithm: "aws:kms"
                    }
                }
            }
        }
        if (args.bucketArgs) {
            bucketArgs = merge(bucketArgs, args.bucketArgs)
        }
        this.resource = new aws.s3.Bucket(name, bucketArgs, opts)
    }

    private get policy() {
        /**
         * Ensure policy document is initalized before accessing
         */
        if (!this._policy) {
            this._policy = new PolicyDocument(this.name)
            const policyAttachment = new aws.s3.BucketPolicy(
                `${this.name}-policy`,
                {
                    bucket: this.resource.id,
                    policy: this._policy.json
                },
                this.opts)
        }
        return this._policy
    }

    private generateReadStatement(principal?: AWSPrincipal): aws.iam.PolicyStatement {
        let stmt: aws.iam.PolicyStatement = {
            Sid: "Read",
            Effect: "Allow",
            Action: ["s3:ListBucket", "s3:GetObject"],
            Resource: [
                this.resource.arn,
                pulumi.interpolate`${this.resource.arn}/*`
            ],
        }
        if (principal) {
            stmt = merge(stmt, { "Principal": principal })
        }
        return stmt
    }

    private generateWriteStatement(principal?: AWSPrincipal): aws.iam.PolicyStatement {
        let stmt: aws.iam.PolicyStatement = {
            Sid: "Write",
            Effect: "Allow",
            Action: "s3:PutObject",
            Resource: pulumi.interpolate`${this.resource.arn}/*`,
        }
        if (principal) {
            stmt = merge(stmt, { "Principal": principal })
        }
        return stmt
    }

    private addReadPrincipal(principal: AWSPrincipal) {
        if (!this.readPrincipal) {
            this.readPrincipal = principal
            this.policy.addStatement(this.generateReadStatement(this.readPrincipal))
            return
        }

        merge(this.readPrincipal, principal)
    }

    private addWritePrincipal(principal: AWSPrincipal) {
        if (!this.writePrincipal) {
            this.writePrincipal = principal
            this.policy.addStatement(this.generateWriteStatement(this.writePrincipal))
            return
        }

        merge(this.writePrincipal, principal)
    }

    public grantReadOnlyToPrincipal(principal: AWSPrincipal) {
        this.addReadPrincipal(principal)
        this.kmsKey.grantDecryptToPrincipal(principal)
        return this
    }

    public grantReadWriteToPrincipal(principal: AWSPrincipal) {
        this.addReadPrincipal(principal)
        this.addWritePrincipal(principal)
        this.kmsKey.grantDecryptToPrincipal(principal)
        this.kmsKey.grantEncryptToPrincipal(principal)
        return this
    }
}
