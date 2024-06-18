#!/usr/bin/env python3

import datetime
import flask
import hmac
import json
import os
import pprint
import subprocess
import sys
import requests
from flask import Flask
from github import Github
from dotenv import dotenv_values

DEBUG = False  # True
SHA1 = 'sha1'

def debug_log(msg):
    """Log event data to app.log"""
    if DEBUG:
        with open('app.log', 'a') as fh:
            timestamp = datetime.datetime.now().strftime("%Y%m%d-T%H:%M:%S")
            fh.write('DEBUG [' + timestamp + '] ' + msg + '\n')

class PullRequest(object):
    """Pull request object."""

    def __init__(self, pr_data, repo=None):
        """Constructor."""
        self.author = pr_data['user']['login']
        self.head_sha = pr_data['head']['sha']
        self.id = pr_data['number']
        self.repo = repo

    def __str__(self):
        """String represenation of this instance."""
        fields = ['id', 'author', 'head_sha', 'repo']
        return ', '.join(x + '=' + str(getattr(self, x)) for x in fields)


def verify_request(request):
    """
    Verify request by checking webhook secret in request header.
    Webhook secret must also be available in $GITHUB_APP_SECRET_TOKEN environment variable.
    """
    # see https://docs.github.com/en/developers/webhooks-and-events/securing-your-webhooks

    webhook_secret_from_env = dotenv_values(".env")["GITHUB_APP_SECRET_TOKEN"]
    if webhook_secret_from_env is None:
        error("Webhook secret is not available via $GITHUB_APP_SECRET_TOKEN!")

    header_signature = request.headers.get('X-Hub-Signature')
    # if no signature is found, the request is forbidden
    if header_signature is None:
        log("Missing signature in request header => 403")
        flask.abort(403)
    else:
        signature_type, signature = header_signature.split('=')
        if signature_type == SHA1:
            # see https://docs.python.org/3/library/hmac.html
            mac = hmac.new(webhook_secret_from_env.encode(), msg=request.data, digestmod=SHA1)
            if hmac.compare_digest(str(mac.hexdigest()), str(signature)):
                log("Request verified: signature OK!")
            else:
                log("Faulty signature in request header => 403")
                flask.abort(403)
        else:
            # we only know how to verify a SHA1 signature
            log("Uknown type of signature (%s) => 501" % signature_type)
            flask.abort(501)


def handle_pr_label_event(gh, request, pr):
    """
    Handle adding of a label to a pull request.
    """
    # debug_log("Request body: %s" % pprint.pformat(request.json))

    action = request.json['action']
    label_name = request.json['label']['name']
    user = request.json['sender']['login']

    log("%(repo)s PR #%(id)s %(action)s by %(user)s: %(label)s" % {
        'action': action,
        'repo': pr.repo,
        'id': pr.id,
        'label': label_name,
        'user': user,
    })

    # hostname = os.environ.get('HOSTNAME', 'UNKNOWN_HOSTNAME')
    hostname = dotenv_values(".env")["HOSTNAME"]

    # only react if label was added by @boegel, is a 'test:*' label, and matches current host
    if action == 'labeled' and user == 'wwweert123' and label_name == hostname:
        # and label_name.startswith('test:' + hostname)
        repo = gh.get_repo(pr.repo)
        issue = repo.get_issue(pr.id)

        pr_target_account = request.json['repository']['owner']['login']

        cmd = [
            'eb',
            '--from-pr',
            str(pr.id),
            '--robot',
            '--force',
            '--upload-test-report',
        ]

        if pr_target_account != 'easybuilders':
            cmd.extend([
                '--pr-target-account',
                pr_target_account,
            ])

        log("Testing %s PR #%d by request of %s by running: %s" % (pr.repo, pr.id, user, ' '.join(cmd)))

        msg_lines = [
            "Fine, fine, I'm on it.",
            "Started command: `%s`" % ' '.join(cmd),
        ]

        issue.create_comment('\n'.join(msg_lines))

        process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        process
        stderr, stdout, exit_code = process.stderr, process.stdout, process.returncode

        log("Command '%s' completed, exit code %s" % (' '.join(cmd), exit_code))
        log("Stdout:\n" + stdout)
        log("Stderr:\n" + stderr)
    log("label event detected")


def handle_pr_event(gh, request):
    """
    Dummy handler for pull request events
    """
    # Log the event details
    log("Handling pull request event")
    log("Request headers: %s" % pprint.pformat(request.headers))
    # log("Request body: %s" % pprint.pformat(request.json))
    
    # Extract some data from the request body for demonstration
    try:
        event_data = request.json
        action = event_data.get('action', 'unknown')
        pr_number = event_data.get('number', 'unknown')
        repo_full_name = request.json['repository']['full_name']
        pr = PullRequest(request.json['pull_request'], repo=request.json['repository']['full_name'])
        log("Pull Request action: %s, number: %s" % (action, pr_number))

        # Add a comment to the pull request
        if action == "reopened":
            comment = "Thank you for your pull request! We will review it soon."
        elif action == "closed":
            comment = ":("
        elif action == "labeled":
            handle_pr_label_event(gh, request, pr)
            comment = "Labeled"
        else:
            comment = "Unrecognized action"

        add_comment_to_pr(gh, repo_full_name, pr_number, comment)
    except Exception as e:
        log("Error parsing request body: %s" % str(e))
    
    # Return a success response
    response_data = {'status': 'success', 'message': 'Pull request event handled'}
    response_object = json.dumps(response_data)
    return flask.Response(response_object, status=200, mimetype='application/json')


def add_comment_to_pr(gh, repo_full_name, pr_number, comment):
    """
    Add a comment to the pull request
    """
    gh_token = dotenv_values(".env")["GITHUB_TOKEN"]
    url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
    headers = {
        'Authorization': f'token {gh_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    payload = {
        'body': comment
    }

    response = requests.post(url, headers=headers, json=payload)
    
    if response.status_code == 201:
        log("Successfully added comment to pull request")
    else:
        log(f"Failed to add comment to pull request: {response.status_code}, {response.text}")


# Dummy log function for demonstration
def log(message):
    print(message)


def handle_event(gh, request):
    """
    Handle event
    """
    event_handlers = {
        # 'check_run': handle_check_run_event,
        # 'check_suite': handle_check_suite_event,
        # 'ping': handle_ping_event,
        'pull_request': handle_pr_event,
        # 'workflow_run': handle_workflow_run_event,
    }
    event_type = request.headers["X-GitHub-Event"]

    event_handler = event_handlers.get(event_type)
    if event_handler:
        log("Event type: %s" % event_type)
        # log("Request headers: %s" % pprint.pformat(request.headers))
        # log("Request body: %s" % pprint.pformat(request.json))
        event_handler(gh, request)
    else:
        log("Unsupported event type: %s" % event_type)
        response_data = {'Unsupported event type': event_type}
        response_object = json.dumps(response_data, default=lambda obj: obj.__dict__)
        return flask.Response(response_object, status=400, mimetype='application/json')


def create_app(gh):
    """
    Create Flask app.
    """

    app = Flask(__name__)

    @app.route('/', methods=['POST'])
    def main():
        log("%s request received!" % flask.request.method)
        verify_request(flask.request)
        handle_event(gh, flask.request)
        return ''

    return app


def main():
    """Main function."""

    gh = Github(dotenv_values(".env")["GITHUB_TOKEN"])
    return create_app(gh)


if __name__ == '__main__':
    app = main()
    app.run()