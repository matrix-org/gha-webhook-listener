# gha-webhook-listener

Simple flask listener which will wait for Github webhook pokes, and when it
gets one, downloads an artifact and unpacks it.

Based on [a Buildkite version](https://github.com/matrix-org/buildkite-webhook-listener).

## Github setup

Go to the project “Settings”, in the “Webhooks” section, and click on the “Add webhook” button.
Make sure you set the “Content type” to `application/json`.
The “Secret” is what you’ll pass as `--webhook-token` to the listener.
Choose the “Let me select individual events” option and check *only* the “Workflow runs” box.


## Command-line options

The API token passed as `--api-token` on the command line should be a 
[Personal Access Token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) 
with `repo` access, from a Github user that can read the repository.

For more details, see `--help`.

TODO: add a hook so that we can do more complex unpacking.
