This terraform file creates various resources with misconfigurations that will be detected.
These misconfigurations are all benign, in that it is only a new resource (no sensitive data in it)
that is misconfigured, and the misconfigurations are mostly only allowing a single account (000000000000) some sort of access.

To create a single resource, you can use: 

```
terraform apply --target aws_sqs_queue_policy.bad
```

The list of possible resources are:
- aws_sqs_queue_policy.bad
- aws_snapshot_create_volume_permission.bad
- aws_ami_launch_permission.bad
- aws_iam_user_login_profile.bad
- aws_s3_bucket.bad
- aws_redshift_cluster.bad
- aws_instance.bad
- aws_security_group.bad
- aws_elb.bad