#!/usr/bin/env python

import os
import sys
import pprint

from jira import JIRA, JIRAError

awsRemediationDescriptionMapping = {
    
}

class awssRemediationJira(object):
    def __init__(
        self,
        server="https://flatironhealth.atlassian.net",
        board="SEGTEST", # TODO Change this to a board that is monitored
        access_token=None,
        access_token_secret=None,
        consumer_key=None,
        key_cert=None,
        api_token=None,
    ):
        options = {"server": server}
        self.jira = None
        self.board = board

        oauth_dict = {}
        if access_token and access_token_secret and consumer_key and key_cert:
            key_cert_data = (
                open(os.path.expanduser(key_cert), "r").read()
                if os.path.isfile(os.path.expanduser(key_cert))
                else key_cert.replace("\\n", "\n")
            )

            oauth_dict = {
                "access_token": access_token,
                "access_token_secret": access_token_secret,
                "consumer_key": consumer_key,
                "key_cert": key_cert_data,
            }

            self.jira = JIRA(options, oauth=oauth_dict)

        elif api_token:
            creds = (
                self._get_api_token(api_token)
                if os.path.isfile(api_token)
                else api_token.split(":")
            )

            self.jira = JIRA(options, basic_auth=(tuple(creds)))

        if not getattr(self, "jira"):
            raise JIRAError("JIRA unable to be initialized")

    @staticmethod
    def _get_api_token(path):
        with open(path) as f:
            creds = f.readlines()[0].strip().split(":")
            return creds

    # def view_ticket(self, id):
    #     dat = self.get_ticket(id)

    # def get_ticket(self, id):
    #     if id.startswith(self.board):
    #         id = id.replace("{}-".format(self.board), "")
    #     return self.jira.issue("{}-{}".format(self.board, id))

    def create_issue(self, title, metadata, epic=None, board=None):
        if not board:
            board = self.board

        issue_dict = {
            "project": board,
            "summary": title,
            "description": self._create_description(metadata),
            "issuetype": {"name": "Bug"},
        }
        issue = self.jira.create_issue(fields=issue_dict)
        issue.update(labels=["AWS Misconfiguration", "Remediation Framework"])
        if epic:
            issue.update(fields={"customfield_10007": epic})
        return issue

    @staticmethod
    def _create_description(metadata):
        description = ""
        return description

    # def update_issue(self, jiraTicket, status):
    #     if jiraTicket and self.jira:
    #         issue_obj = self.jira.issue(jiraTicket)
    #         to_do = self.jira.find_transitionid_by_name(issue_obj, "To Do")
    #         done = self.jira.find_transitionid_by_name(issue_obj, "Done")
    #         _status_map = {
    #             "Open": {"transition_id": to_do},
    #             "Resolved": {"transition_id": done,},
    #             "FalsePositive": {"transition_id": done,},
    #             "Duplicate": {"transition_id": done,},
    #         }
    #         if status not in _status_map.keys():
    #             ret["msg"] = "Invalid status"
    #             return ret

    #         mapped_status = _status_map.get(status)
    #         self.jira.transition_issue(issue_obj, mapped_status["transition_id"])

    #     return {
    #         "status": "success",
    #         "msg": "%s has been set to %s" % (jiraTicket, mapped_status),
    #     }