import * as aws from "@pulumi/aws"
import * as pulumi from "@pulumi/pulumi"


interface PolicyDocumentProviderArgs {
    statements: pulumi.Unwrap<aws.iam.PolicyStatement>[]
}

class PolicyDocumentProvider implements pulumi.dynamic.ResourceProvider {
    private name: string

    constructor(name: string) {
        this.name = name
    }

    async create(args: PolicyDocumentProviderArgs) {
        const doc: pulumi.Unwrap<aws.iam.PolicyDocument> = {
            Version: "2012-10-17",
            Statement: args.statements
        }
        return {
            id: this.name,
            outs: {
                json: JSON.stringify(doc)
            }
        }
    }

    async update(id: pulumi.ID, olds: PolicyDocumentProviderArgs, news: PolicyDocumentProviderArgs) {
        const doc: pulumi.Unwrap<aws.iam.PolicyDocument> = {
            Version: "2012-10-17",
            Statement: news.statements
        }
        return {
            id: this.name,
            outs: {
                json: JSON.stringify(doc)
            }
        }
    }
}


export class PolicyDocument extends pulumi.dynamic.Resource {
    /**
     * Creates an IAM policy document from a set of statements
     */
    public json!: pulumi.Output<string>

    private statements: aws.iam.PolicyStatement[]

    constructor(name: string, opts?: pulumi.CustomResourceOptions) {
        let stmts: aws.iam.PolicyStatement[] = []
        super(new PolicyDocumentProvider(name), name,
            { statements: stmts, json: undefined }, opts)

        this.statements = stmts
    }

    public addStatement(statement: aws.iam.PolicyStatement) {
        this.statements.push(statement)
        return this
    }
}