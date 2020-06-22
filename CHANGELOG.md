## 1.1.0 (06 June 2020)
### Changes
- Added the ability for the plugin to authenticate and handle requests from source control clients such as the git CLI and SourceTree

## 1.2.0 (22 June 2020)
### Changes
- Now external clients such as git CLI can connect with SCM Manager using Identification Tokens which can be issued and managed by the user. This change makes possible client connections from users which originate "outside" of the configured provider (ex. GitHub --> Keycloak --> SCM Manager) 