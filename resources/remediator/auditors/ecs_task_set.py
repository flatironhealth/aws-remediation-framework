import json
from shared import get_session_for_account, fetch_all_accounts, send_notification

from policyuniverse.policy import Policy
from policyuniverse.statement import Statement


def audit(resource, remediate=False):
    is_compliant = True
    if resource["type"] != "ecs_task_set":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "ecs_task_set", resource["type"]
            )
        )

    # Get a session in the account where this resource is
    ecs = get_session_for_account(resource["account"], resource["region"], "ecs")

    ecs_is_public = False

    try:
        ## List all ECS Clusters
        ecs_clusters =  ecs.list_clusters()

        ## Now get all cluster ARNs from ECS clusters json
        cluster_arns = ecs_clusters["clusterArns"]

        ## For each cluster  X Service: try to find the named taskSet
        identified_cluster = ""
        identified_service = ""
        task_sets_to_audit = []
        for cluster in cluster_arns:
            print("ECS: Cluster ARN {}".format(cluster))
            ## Get the ServiceARNs for each Cluster

            paginator = ecs.get_paginator('list_services')
            resp = paginator.paginate(cluster=cluster)
            service_arns = resp['serviceArns']
            while 'nextToken' in resp:
                resp = paginator.paginate( cluster=cluster, nextToken=resp['nextToken'])
                service_arns = service_arns + resp['serviceArns']


            ## Now Loop through every possible cluster arn x service arn for the the possible ECS Task Set:
            for service in service_arns:
                temp_task_set = ecs.describe_task_sets(
                    cluster = cluster,
                    service = service,
                    task_sets = [
                        resource['id']
                        ]
                )['taskSets']
                if len(temp_task_set) > 0:
                    identified_cluster = cluster
                    identified_service = service
                    task_sets_to_audit+=temp_task_set


        ## Using the task set that was identified
        ## Audit the task set to make sure that the there is no public ip assignment.
        ## If public ip is assigned then the only thing that can be done
        ## is deleting the task set
        bad_task_sets = []
        for task_set in task_sets_to_audit:
            if task_set['networkConfiguration']['awsvpcConfiguration']['assignPublicIp'] == 'ENABLED':
                bad_task_sets.append(task_set["id"])
                ecs_is_public = True

    except Exception as e:
        print(e)
        print("No ECS Task Set Definition: {}".format(resource["id"]))


    if ecs_is_public:
        is_compliant = False

        for bad_task_set in bad_task_sets:
            issue = "ECS Task Set {} is public via Public IP Assignment".format(resource["id"])
            if remediate:
                is_compliant = remediation_delete_task_set(resource,bad_task_set,ecs,identified_cluster,identified_service)
                if not is_compliant:
                    issue += " - Not remediated"
            send_notification(issue, "", resource)

    if is_compliant:
        print("ECS is private: {}".format(resource["id"]))

    return is_compliant

## The remediation is to delete the offending task set
def remediation_delete_task_set(resource, task_set, ecs, cluster,service):
    try:
        # Delete the task set
        ecs.delete_task_set(
            cluster=cluster,
            service=service,
            taskSet=task_set,
            force=True
        )
    except Exception as e:
        print(e)
        return False
    return True
