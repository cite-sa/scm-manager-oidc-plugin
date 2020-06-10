# scm-auth-oidc-plugin
This is an SCM Manager plugin that gives the possibility for user registration and authentication using an external OpenID Connect Provider. 
For testing and integration purposes, we have validated the setup using the Keycloak Identity and Access Management software (https://www.keycloak.org/).
## Configuration
Once installed from the plugins manager panel, you can configure it to use your provider of choice by giving the following information (You can find the configuration form at config -> General, at the menu on the left side of the screen).

 - **Provider URL** : The URL from the provider that contains the endpoints for authentication (.well-known).
 - **Client ID** : The client id from the provider.
 - **Client Secret** : The client secret used from the provider to identify and authorize the client.
 - **User Identifier** : Which user information from the provider is going to be used as a unique identifier by SCM. It can be "*Username*", "*Email*" or "*SubjectID* (Default)".
 - **Admin Role Name** : Which client role from the provider user account is going to determine if a user must have admin access to SCM. <b>[IMPORTANT]</b> Administrator accounts that originate from the provider admin claims, will always have global elevated rights regardless of the SCM permission settings. All these accounts, will become members of an *Administrator* group created from the plugin, for easier management and tracking.
## Deployment
This plugin has been tested working with **Keycloak v9.0.2** OpenID Connect Provider and is targeting version **2.0.0** of **SCM Manager** (https://www.scm-manager.org/).

To deploy and test your own plugin after changes you might have made to this code, go to your project's folder and run the following Maven commands.

    mvn install
    mvn smp:run

Currently there is no support for "offline" plugin installations using the generated packages (.smp) as it was for the previous version of SCM Manager. Plugins are only available through the Plugin Center.

### Testing

The OpenID Connect authentication process is getting tested using [MockServer](https://www.mock-server.com/). The test server is getting started and stopped automatically by JUnit, while the application is in the testing phase. No external configuration is required.

You can run the tests separately by using the command:

    mvn test
## Future Considerations and Improvements

 - SCM Manager 2 is currently under heavy development. We will make sure that the plugin will remain functional after future changes to the platform.
 - **Federated Sign out**. Add the ability for the provider to inform the SCM Manager for possible user logouts or session expiration, so that the scm session terminates too.
 - **Multiple Providers**. Add the ability to have more than one providers configured. (Possibly being used at the same time?).
 - Have the ability to use the **local xml** based users too at the sign in process.

## License
This project is licensed under the MIT License. See `LICENSE.txt` for details.