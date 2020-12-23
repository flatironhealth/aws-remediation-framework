import json
from shared import get_session_for_account, fetch_all_accounts, send_notification

from policyuniverse.policy import Policy
from policyuniverse.statement import Statement


def audit(resource, remediate=False):
    is_compliant = True
    if resource["type"] != "ecs_task":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "ecs_task_set", resource["type"]
            )
        )

    # Get a session in the account where this resource is
    ecs = get_session_for_account(resource["account"], resource["region"], "ecs")

    ## In order to check if ECS is public, we need to perform an ENI lookup against EC2
    ec2 = get_session_for_account(resource["account"], resource["region"], "ec2")

    ecs_is_public = False

    try:
        ## List all ECS Clusters
        ecs_clusters =  ecs.list_clusters()

        ## Now get all cluster ARNs from ECS clusters json
        cluster_arns = ecs_clusters["clusterArns"]

        ## For each cluster list all tasks and find noncompliant tasks.
        non_compliant_tasks = []
        task_cluster = ""
        for cluster in cluster_arns:
            all_cluster_tasks = ecs.list_tasks(cluster=cluster)["taskArns"]
            for task_ in all_cluster_tasks:
                ecs_tasks = ecs.describe_tasks(cluster=cluster,tasks=[task_])["tasks"]
                print("ECS TASK: {}".format(ecs_tasks))
                # Check if ENI is public
                for task in ecs_tasks:
                    # for each Task, look for the ElasticNetworkInterface (ENI) attachement and if there is, then check if ENI is public
                    eni_is_public = False
                    for attachment in task["attachments"]:
                        if attachment["type"] == "ElasticNetworkInterface":
                            eni_id = ""
                            for el in attachment["details"]:
                                if el["name"] == "networkInterfaceId":
                                    eni_id = el["value"]
                            eni_desc = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
                            ## Determine if ENI is public:
                            for eni in eni_desc["NetworkInterfaces"]:
                                # If there is a public IP assignment to the ENI, then the ENI is considered public
                                if eni["Association"]["PublicIp"] != "":
                                    ecs_is_public = True
                                    task_cluster = cluster
                                    task_data = {
                                        "cluster": cluster,
                                        "taskArn": task["taskArn"]
                                    }
                                    non_compliant_tasks.append(task_data)
                                    break

    except Exception as e:
        print(e)
        print("No ECS Tasks: {}".format(resource["id"]))


    if ecs_is_public:
        is_compliant = False

        # Remediate every issue found in non_compliant_tasks
        for bad_task in non_compliant_tasks:
            issue = "ECS Task {} is public via public IP Assignment".format(bad_task["taskArn"])
            if remediate:
                is_compliant = remediation_make_ecs_task_private(bad_task["taskArn"],ecs,bad_task["cluster"])
                if not is_compliant:
                        issue += " - Not remediated"
            send_notification(issue, "", resource)

    if is_compliant:
        print("ECS is private: {}".format(resource["id"]))

    return is_compliant


def remediation_make_ecs_task_private(task_arn, ecs, cluster):
    try:
        # Kill the task
        ecs.stop_task(
            cluster=cluster,
            task=task_arn,
            reason='Task non-compliant - task is public. Disable Public IP Assignment before task is run/started.'
        )
    except Exception as e:
        print(e)
        return False
    return True
