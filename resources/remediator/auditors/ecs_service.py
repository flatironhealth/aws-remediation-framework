import json
from shared import get_session_for_account, fetch_all_accounts, send_notification

from policyuniverse.policy import Policy
from policyuniverse.statement import Statement


def audit(resource, remediate=False):
    is_compliant = True
    if resource["type"] != "ecs_service":
        raise Exception(
            "Mismatched type. Expected {} but received {}".format(
                "ecs_service", resource["type"]
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

        ## For each cluster, try to find the named service
        ecs_description = []
        service_cluster = ""
        for cluster in cluster_arns:
            svc_description = ecs.describe_services(
                cluster = cluster,
                services = [resource["id"]]
            )
            ## If the services array contains an object then set ecs_description to the services array of the cluster
            ## Set cluster variable to the cluster ARN
            if len(svc_description['services']) > 0:
                ecs_description = svc_description['services']
                service_cluster = cluster

        for ecs_svc in ecs_description:
            if ecs_svc['networkConfiguration']['awsvpcConfiguration']['assignPublicIp'] == 'ENABLED':
                ecs_is_public = True

    except Exception as e:
        print(e)
        print("No ECS Services Definition: {}".format(resource["id"]))


    if ecs_is_public:
        is_compliant = False

        issue = "ECS {} is public via Public IP".format(resource["id"])
        if remediate:
            for ecs_svc in ecs_description:
                is_compliant = remediation_make_ecs_private(resource, ecs, service_cluster,ecs_svc['networkConfiguration']['awsvpcConfiguration'])
                if not is_compliant:
                    issue += " - Not remediated"
        send_notification(issue, "", resource)

    if is_compliant:
        print("ECS is private: {}".format(resource["id"]))

    return is_compliant


def remediation_make_ecs_private(resource, ecs, cluster, networkConfiguration):
    try:
        ecs.update_service(
            cluster= cluster,
            service = resource['id'],
            forceNewDeployment=True,
            networkConfiguration = {
                'awsvpcConfiguration': {
                    'subnets': networkConfiguration['subnets'],
                    'securityGroups': networkConfiguration['securityGroups'],
                    'assignPublicIp':'DISABLED'
                }
            }
        )
    except Exception as e:
        print(e)
        return False
    return True
