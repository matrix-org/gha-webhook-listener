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

| Option             | Short | Default                 | Description                                                                                                                 |
|--------------------|-------|-------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| --port             | -p    | 4000                    | The port to listen on for requests from Github                                                                              |
| --extract          | -e    | ./extracted             | The location to extract .tar.gz files to                                                                                    |
| --archive-name     | -a    | content.tar.gz          | The name of the .tar.gz file within the artifact                                                                            |
| --symlink          | -s    | ./latest                | Write a symlink to this location pointing to the extracted tarball. New builds will keep overwriting this symlink           |
| --webhook-token    |       |                         | Only accept pokes signed with this Github token                                                                             |
| --api-token        |       |                         | API access token for Github. Requires repo scope                                                                            |
| --branch-name      |       | master                  | Branch to accept build notifications for. Notifications for other branches will be ignored                                  |
| --org              |       |                         | Lock down to this Github org                                                                                                |
| --workflow-pattern |       |                         | Define a regex which workflow names must match                                                                              |
| --artifact-pattern |       | merged-content-artifact | Define a regex which artifact names must match                                                                              |
| --keep-versions    |       |                         | Retain only this number of versions on disk. Set to a positive integer                                                      |

The API token passed as `--api-token` on the command line should be a 
[Personal Access Token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) 
with `repo` access, from a Github user that can read the repository.

For more details, see `--help`.

TODO: add a hook so that we can do more complex unpacking.
