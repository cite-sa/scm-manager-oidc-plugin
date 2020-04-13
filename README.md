# scm-auth-oidc-plugin
This is an SCM Manager plugin that gives the possibility for user registration and authentication using an external OpenID Connect Provider. 
For testing and integration purposes, we have validated the setup using the Keycloak Identity and Access Management software (https://www.keycloak.org/).
## Configuration
Once installed from the plugins manager panel, you can configure it to use your provider of choice by giving the following information (You can find the configuration form at config -> General, at the menu on the left side of the screen).

 - **Provider URL** : The URL from the provider that contains the endpoints for authentication (.well-known).
 - **Client ID** : The client id from the provider.
 - **Client Secret** : The client secret used from the provider to identify and authorize the client.
 - **User Identifier** : Which user information from the provider is going to be used as a unique identifier by SCM. It can be "*Username*", "*Email*" or "*SubjectID* (Default)".
 - **Admin Role Name** : Which client role from the provider user account is going to determine if a user must have admin access to SCM. <b>[IMPORTANT]</b> It will override the scm admin setting.
## Deployment
This plugin has been tested working with **Keycloak v9.0.2** OpenID Connect Provider and is targeting version **1.60** of **SCM Manager** (https://www.scm-manager.org/).

To deploy and test your own plugin after changes you might have made to this code, go to your project's folder and run the following Maven plugin provided by SCM Manager.

    mvn scmp:package

If you get an error, you can alternatively find it and run it through your IDE's Maven panel.

Then go to your target folder, find the generated package file (.scmp), upload it to your own scm manager server instance by the "Install Package" button at the top left of the plugin manager page and restart your app.

You can configure your logging settings at `src/main/resources/conf/logback.xml` file.

###Testing

The OpenID Connect authentication process is getting tested using [MockServer](https://www.mock-server.com/). The test server is getting started and stopped automatically by JUnit, while the application is in the testing phase. No external configuration is required.

You can run the tests by using the command:

    mvn test
## Future Considerations and Improvements

 - **Federated Sign out**. Add the ability for the provider to inform the SCM Manager for possible user logouts or session expiration, so that the scm session terminates too.
 - **Multiple Providers**. Add the ability to have more than one providers configured. (Possibly being used at the same time?).
 - Have the ability to use the **local xml** based users too at the sing in process.

## License
This project is licensed under the MIT License. See `LICENSE.txt` for details.

